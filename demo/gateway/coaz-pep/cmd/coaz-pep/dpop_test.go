package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func ecJWK(k *ecdsa.PrivateKey, private bool) map[string]any {
	pad := func(b *big.Int) string { buf := make([]byte, 32); b.FillBytes(buf); return b64urlEncode(buf) }
	j := map[string]any{"kty": "EC", "crv": "P-256", "x": pad(k.X), "y": pad(k.Y)}
	if private {
		j["d"] = pad(k.D)
	}
	return j
}

func es256(t *testing.T, header, claims map[string]any, signer *ecdsa.PrivateKey) string {
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := b64urlEncode(h) + "." + b64urlEncode(c)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, signer, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + b64urlEncode(sig)
}

func TestVerifyDpopProof(t *testing.T) {
	instance, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	attacker, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bound := jwkThumbprint(ecJWK(instance, false))
	conf := pepConfig{dpopHTUBase: "https://rs.example:8446"}
	const token = "eyJ.access.token"
	sum := sha256.Sum256([]byte(token))
	ath := b64urlEncode(sum[:])

	proof := func(edit func(h, c map[string]any), signer *ecdsa.PrivateKey) string {
		h := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": ecJWK(instance, false)}
		c := map[string]any{"htm": "POST", "htu": "https://rs.example:8446/mcp/v1", "iat": time.Now().Unix(),
			"jti": b64urlEncode([]byte(time.Now().String())), "ath": ath}
		if edit != nil {
			edit(h, c)
		}
		return es256(t, h, c, signer)
	}

	good := proof(nil, instance)
	if err := verifyDpopProof(good, conf, "POST", "/mcp/v1", token, bound); err != nil {
		t.Fatalf("valid proof refused: %v", err)
	}
	if err := verifyDpopProof(good, conf, "POST", "/mcp/v1", token, bound); err == nil || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("replayed proof accepted: %v", err)
	}

	cases := map[string]struct {
		proof  string
		method string
		want   string
	}{
		"victim's key, attacker's signature": {proof(nil, attacker), "POST", "signature"},
		"attacker's own key":                 {proof(func(h, _ map[string]any) { h["jwk"] = ecJWK(attacker, false) }, attacker), "POST", "cnf.jkt"},
		"private key in jwk":                 {proof(func(h, _ map[string]any) { h["jwk"] = ecJWK(instance, true) }, instance), "POST", "private"},
		"wrong typ":                          {proof(func(h, _ map[string]any) { h["typ"] = "JWT" }, instance), "POST", "typ"},
		"wrong method":                       {proof(nil, instance), "GET", "htm"},
		"wrong htu":                          {proof(func(_, c map[string]any) { c["htu"] = "https://evil.example/mcp/v1" }, instance), "POST", "htu"},
		"htu with query":                     {proof(func(_, c map[string]any) { c["htu"] = "https://rs.example:8446/mcp/v1?x=1" }, instance), "POST", "query"},
		"another token's ath":                {proof(func(_, c map[string]any) { c["ath"] = "AAAA" }, instance), "POST", "ath"},
		"stale":                              {proof(func(_, c map[string]any) { c["iat"] = time.Now().Add(-10 * time.Minute).Unix() }, instance), "POST", "window"},
		"no jti":                             {proof(func(_, c map[string]any) { delete(c, "jti") }, instance), "POST", "jti"},
	}
	for name, tc := range cases {
		err := verifyDpopProof(tc.proof, conf, tc.method, "/mcp/v1", token, bound)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want an error about %q, got %v", name, tc.want, err)
		}
	}
}
