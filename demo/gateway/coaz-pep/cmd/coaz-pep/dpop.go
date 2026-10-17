package main

// DPoP sender-constraint at the gateway (RFC 9449), rewritten in pf-agentic-identity. The upstream check compared the
// proof's jwk thumbprint with cnf.jkt but never verified the proof's signature - anyone holding a stolen token could
// name the victim's public key in a proof header and pass - nor ath, htu, the proof's age or its replay.
//
// A token bound to a key (cnf.jkt) is refused unless presented as DPoP with a proof that:
//   - is a JWS typ dpop+jwt, ES256/RS256/PS256, signed by the public key in its jwk header (no private members);
//   - names that key, whose RFC 7638 thumbprint is the token's cnf.jkt;
//   - has htm = the request's method and htu = <dpop_htu_base><path> (route context; the URL the client used,
//     which the gateway's own address is not), with no query or fragment;
//   - has ath = base64url(SHA-256(access token));
//   - was issued within DPOP_MAX_AGE_SECONDS (default 60) and is not from the future beyond 5 s;
//   - has a jti not seen before within that window.
// A bound token presented as Bearer is refused whatever the route says (RFC 9449 §7.1); require_dpop refuses an
// unbound one too.

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"
)

var dpopMaxAge = func() time.Duration {
	if n, err := strconv.Atoi(os.Getenv("DPOP_MAX_AGE_SECONDS")); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 60 * time.Second
}()

type replayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

var dpopReplay = &replayCache{seen: map[string]time.Time{}}

// fresh records jti and says whether it was new; entries are kept for the proofs' acceptance window.
func (c *replayCache) fresh(jti string, until time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, exp := range c.seen {
		if exp.Before(now) {
			delete(c.seen, k)
		}
	}
	if _, dup := c.seen[jti]; dup {
		return false
	}
	c.seen[jti] = until
	return true
}

func cnfJkt(claims map[string]any) string {
	if cnf, ok := claims["cnf"].(map[string]any); ok {
		jkt, _ := cnf["jkt"].(string)
		return jkt
	}
	return ""
}

func checkDpop(pep string, conf pepConfig, scheme, method, path, token string, headers map[string]string,
	claims map[string]any) *authv3.CheckResponse {
	bound := cnfJkt(claims)
	if bound == "" && !conf.requireDpop {
		return nil
	}
	fail := func(reason string) *authv3.CheckResponse {
		log.Printf("[%s] DPoP refused: %s", pep, reason)
		return denySimple(pep, typev3.StatusCode_Unauthorized, codes.Unauthenticated, reason,
			map[string]string{"WWW-Authenticate": `DPoP error="invalid_dpop_proof", algs="ES256 RS256 PS256"`})
	}
	if bound == "" {
		return fail("A DPoP-bound access token is required (the token has no cnf.jkt).")
	}
	if scheme != "dpop" {
		return fail("The access token is DPoP-bound: present it with the DPoP scheme, not Bearer.")
	}
	if err := verifyDpopProof(headers["dpop"], conf, method, path, token, bound); err != nil {
		return fail("DPoP proof refused: " + err.Error())
	}
	return nil
}

func verifyDpopProof(proof string, conf pepConfig, method, path, token, bound string) error {
	if proof == "" || strings.Contains(proof, ",") {
		return errors.New("exactly one DPoP header is required")
	}
	header := jwtHeader(proof)
	claims := jwtClaims(proof)
	if header == nil || claims == nil {
		return errors.New("unreadable proof")
	}
	if typ, _ := header["typ"].(string); !strings.EqualFold(typ, "dpop+jwt") {
		return fmt.Errorf("typ %q is not dpop+jwt", typ)
	}
	jwk, _ := header["jwk"].(map[string]any)
	if jwk == nil {
		return errors.New("no jwk in the proof header")
	}
	for _, private := range []string{"d", "p", "q", "dp", "dq", "qi", "k"} {
		if _, ok := jwk[private]; ok {
			return errors.New("the proof's jwk carries private key material")
		}
	}
	if thumb := jwkThumbprint(jwk); thumb == "" || thumb != bound {
		return errors.New("the proof's key is not the one the token is bound to (cnf.jkt)")
	}
	key, err := publicKey(jwk)
	if err != nil {
		return fmt.Errorf("the proof's jwk: %v", err)
	}
	alg, _ := header["alg"].(string)
	if err := verifyJWS(proof, alg, key); err != nil {
		return fmt.Errorf("signature: %v", err)
	}
	if claimString(claims, "htm") != method {
		return fmt.Errorf("htm %q is not %s", claimString(claims, "htm"), method)
	}
	htu := claimString(claims, "htu")
	if strings.ContainsAny(htu, "?#") {
		return errors.New("htu carries a query or fragment")
	}
	if conf.dpopHTUBase != "" {
		if want := strings.TrimRight(conf.dpopHTUBase, "/") + path; htu != want {
			return fmt.Errorf("htu %q is not %s", htu, want)
		}
	} else if !strings.HasSuffix(htu, path) {
		return fmt.Errorf("htu %q does not end in %s", htu, path)
	}
	sum := sha256.Sum256([]byte(token))
	if ath := claimString(claims, "ath"); ath != b64urlEncode(sum[:]) {
		return errors.New("ath is not the hash of the presented access token")
	}
	iat, ok := claims["iat"].(float64)
	if !ok {
		return errors.New("no iat")
	}
	issued := time.Unix(int64(iat), 0)
	if age := time.Since(issued); age > dpopMaxAge || age < -5*time.Second {
		return fmt.Errorf("issued %s ago, outside the %s window", age.Round(time.Second), dpopMaxAge)
	}
	jti := claimString(claims, "jti")
	if jti == "" {
		return errors.New("no jti")
	}
	if !dpopReplay.fresh(bound+"|"+jti, issued.Add(dpopMaxAge+5*time.Second)) {
		return errors.New("jti replayed")
	}
	return nil
}
