package main

// Access-token verification at the PEP (added in pf-agentic-identity; the upstream PEP only decodes tokens).
//
// The gateway in front (agentgateway) can verify JWTs itself, but its jwtAuth policy removes the Authorization
// header once it has, so neither this PEP nor the resource behind it would see the token. Verifying here keeps the
// token on the request and puts the check where the decision is made.
//
// Environment (verification is on when TOKEN_JWKS_URL is set):
//   TOKEN_JWKS_URL   the authorisation server's JWKS, e.g. https://<issuer>/pf/JWKS
//   TOKEN_ISSUER     required iss
//   TOKEN_AUDIENCE   required aud (one of the token's audiences)
//   TOKEN_CA_FILE    optional PEM bundle trusted besides the system roots (a private network's CA)
//   TOKEN_TYP        required typ header, default at+jwt ("" to accept any)

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type tokenVerifier struct {
	jwksURL, issuer, audience, typ string
	httpc                          *http.Client

	mu        sync.Mutex
	keys      map[string]any // kid -> *rsa.PublicKey | *ecdsa.PublicKey
	fetchedAt time.Time
}

func newTokenVerifier() (*tokenVerifier, error) {
	url := os.Getenv("TOKEN_JWKS_URL")
	if url == "" {
		return nil, nil
	}
	v := &tokenVerifier{jwksURL: url, issuer: os.Getenv("TOKEN_ISSUER"), audience: os.Getenv("TOKEN_AUDIENCE"),
		typ: envOr("TOKEN_TYP", "at+jwt")}
	if v.issuer == "" || v.audience == "" {
		return nil, errors.New("TOKEN_JWKS_URL is set, so TOKEN_ISSUER and TOKEN_AUDIENCE are required")
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if f := os.Getenv("TOKEN_CA_FILE"); f != "" {
		pem, err := os.ReadFile(f)
		if err != nil || !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("TOKEN_CA_FILE %s: no certificates read", f)
		}
	}
	v.httpc = &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	return v, nil
}

// key returns the key for kid, refetching the JWKS when it is unknown (a rotation) but at most every 30 s.
func (v *tokenVerifier) key(kid string) (any, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if k, ok := v.keys[kid]; ok && time.Since(v.fetchedAt) < 10*time.Minute {
		return k, nil
	}
	if time.Since(v.fetchedAt) > 30*time.Second || v.keys == nil {
		if err := v.fetch(); err != nil {
			return nil, err
		}
	}
	if k, ok := v.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("no key %q at %s", kid, v.jwksURL)
}

func (v *tokenVerifier) fetch() error {
	resp, err := v.httpc.Get(v.jwksURL)
	if err != nil {
		return fmt.Errorf("JWKS %s: %w", v.jwksURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS %s answered %d", v.jwksURL, resp.StatusCode)
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("JWKS %s: %w", v.jwksURL, err)
	}
	keys := map[string]any{}
	for _, j := range set.Keys {
		kid, _ := j["kid"].(string)
		if use, _ := j["use"].(string); use != "" && use != "sig" {
			continue
		}
		if k, err := publicKey(j); err == nil && kid != "" {
			keys[kid] = k
		}
	}
	v.keys, v.fetchedAt = keys, time.Now()
	return nil
}

func publicKey(j map[string]any) (any, error) {
	str := func(k string) []byte { s, _ := j[k].(string); b, _ := b64urlDecode(s); return b }
	switch j["kty"] {
	case "RSA":
		n, e := new(big.Int).SetBytes(str("n")), new(big.Int).SetBytes(str("e"))
		if n.Sign() == 0 || !e.IsInt64() {
			return nil, errors.New("bad RSA key")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		if j["crv"] != "P-256" {
			return nil, errors.New("unsupported curve")
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(str("x")),
			Y: new(big.Int).SetBytes(str("y"))}, nil
	}
	return nil, errors.New("unsupported key type")
}

// verify checks the token's signature, type, issuer, audience and lifetime; the error says which failed.
func (v *tokenVerifier) verify(token string) error {
	if err := v.verifySignature(token, v.typ); err != nil {
		return err
	}
	return v.verifyClaims(jwtClaims(token))
}

// verifySignature checks a compact JWS's typ (when typ is not "") and its signature against the JWKS.
func (v *tokenVerifier) verifySignature(token, typ string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("not a compact JWS")
	}
	header := jwtHeader(token)
	if header == nil {
		return errors.New("unreadable header")
	}
	alg, _ := header["alg"].(string)
	kid, _ := header["kid"].(string)
	if got, _ := header["typ"].(string); typ != "" && !strings.EqualFold(strings.TrimPrefix(strings.ToLower(got), "application/"), typ) {
		return fmt.Errorf("typ %q is not %s", got, typ)
	}
	key, err := v.key(kid)
	if err != nil {
		return err
	}
	if err := verifyJWS(token, alg, key); err != nil {
		return fmt.Errorf("signature does not verify with key %q", kid)
	}
	return nil
}

// verifyJWS checks a compact JWS's signature under key with alg (RS256, PS256 or ES256, matched to the key's type).
func verifyJWS(token, alg string, key any) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("not a compact JWS")
	}
	sig, err := b64urlDecode(parts[2])
	if err != nil {
		return errors.New("unreadable signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch k := key.(type) {
	case *rsa.PublicKey:
		switch alg {
		case "RS256":
			return rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], sig)
		case "PS256":
			return rsa.VerifyPSS(k, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		return fmt.Errorf("alg %q not accepted for an RSA key", alg)
	case *ecdsa.PublicKey:
		if alg != "ES256" || len(sig) != 64 {
			return fmt.Errorf("alg %q not accepted for an EC key", alg)
		}
		if !ecdsa.Verify(k, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			return errors.New("bad signature")
		}
		return nil
	}
	return errors.New("unsupported key")
}

func (v *tokenVerifier) verifyClaims(claims map[string]any) error {
	if iss, _ := claims["iss"].(string); iss != v.issuer {
		return fmt.Errorf("iss %q is not %s", iss, v.issuer)
	}
	audOK := false
	switch aud := claims["aud"].(type) {
	case string:
		audOK = aud == v.audience
	case []any:
		for _, a := range aud {
			audOK = audOK || a == v.audience
		}
	}
	if !audOK {
		return fmt.Errorf("aud %v does not include %s", claims["aud"], v.audience)
	}
	now := float64(time.Now().Unix())
	exp, ok := claims["exp"].(float64)
	if !ok || exp < now-30 {
		return errors.New("expired or no exp")
	}
	if nbf, ok := claims["nbf"].(float64); ok && nbf > now+30 {
		return errors.New("not yet valid")
	}
	return nil
}
