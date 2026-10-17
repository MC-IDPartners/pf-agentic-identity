package main

// Shared Signals receiver (added in pf-agentic-identity): the PEP polls a stream from an SSF transmitter
// (PingFederate's) and refuses tokens for subjects it has been told about, at once - not when the resource's caches
// and the agent's registration run out. Poll delivery (RFC 8936), so the transmitter never has to reach the PEP.
//
// What the events do to a token whose sub (or client_id) is the event's subject:
//   caep session-revoked   tokens issued at or before the event are refused; a token issued after it is not
//   risc account-disabled  every token is refused, until
//   risc account-enabled   which lifts it
// Subjects: iss_sub (iss must be the tokens' issuer, TOKEN_ISSUER) or opaque (the id is the client_id).
// Every SET is verified against the token JWKS (TOKEN_JWKS_URL) and its iss must be the transmitter's.
//
// Environment (the receiver is on when SSF_CONFIGURATION_URL is set; it needs TOKEN_JWKS_URL):
//   SSF_CONFIGURATION_URL  the transmitter's /.well-known/ssf-configuration, as this PEP reaches it
//   SSF_CONNECT_BASE       optional: replaces the transmitter's issuer origin in its endpoints (reached inside)
//   SSF_TOKEN_ENDPOINT     the authorisation server's token endpoint, as this PEP reaches it
//   SSF_TOKEN_AUDIENCE     the client assertion's aud (default: the transmitter's issuer + /as/token.oauth2)
//   SSF_CLIENT_ID          the receiver's client (ssf.manage), private_key_jwt
//   SSF_CLIENT_KEY_FILE    its private JWK (RSA, PS256)
//   SSF_POLL_SECONDS       default 2

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	evSessionRevoked  = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
	evAccountDisabled = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"
	evAccountEnabled  = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
	pollDelivery      = "urn:ietf:rfc:8936"
)

type revocation struct {
	disabled  bool      // account-disabled: everything refused
	cutoff    time.Time // session-revoked: tokens issued at or before this refused
	eventType string
	at        time.Time
}

type ssfReceiver struct {
	configURL, connectBase, tokenEndpoint, tokenAudience, clientID, tokenIssuer string
	key                                                                         *rsa.PrivateKey
	kid                                                                         string
	poll                                                                        time.Duration
	tokens                                                                      *tokenVerifier
	httpc                                                                       *http.Client

	issuer      string // the transmitter's, from its configuration
	configEP    string
	pollURL     string
	accessToken string
	tokenExp    time.Time

	mu      sync.Mutex
	revoked map[string]revocation
}

func newSSFReceiver(tokens *tokenVerifier) (*ssfReceiver, error) {
	cfg := os.Getenv("SSF_CONFIGURATION_URL")
	if cfg == "" {
		return nil, nil
	}
	if tokens == nil {
		return nil, errors.New("SSF_CONFIGURATION_URL needs TOKEN_JWKS_URL: SETs are verified against it")
	}
	r := &ssfReceiver{configURL: cfg, connectBase: strings.TrimRight(os.Getenv("SSF_CONNECT_BASE"), "/"),
		tokenEndpoint: os.Getenv("SSF_TOKEN_ENDPOINT"), tokenAudience: os.Getenv("SSF_TOKEN_AUDIENCE"),
		clientID: os.Getenv("SSF_CLIENT_ID"), tokenIssuer: tokens.issuer, tokens: tokens, httpc: tokens.httpc,
		poll: 2 * time.Second, revoked: map[string]revocation{}}
	if d, err := time.ParseDuration(envOr("SSF_POLL_SECONDS", "2") + "s"); err == nil && d > 0 {
		r.poll = d
	}
	if r.tokenEndpoint == "" || r.clientID == "" {
		return nil, errors.New("SSF_TOKEN_ENDPOINT and SSF_CLIENT_ID are required with SSF_CONFIGURATION_URL")
	}
	raw, err := os.ReadFile(os.Getenv("SSF_CLIENT_KEY_FILE"))
	if err != nil {
		return nil, fmt.Errorf("SSF_CLIENT_KEY_FILE: %w", err)
	}
	var jwk map[string]any
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, fmt.Errorf("SSF_CLIENT_KEY_FILE: %w", err)
	}
	if r.key, err = rsaPrivateKey(jwk); err != nil {
		return nil, fmt.Errorf("SSF_CLIENT_KEY_FILE: %w", err)
	}
	r.kid, _ = jwk["kid"].(string)
	return r, nil
}

func rsaPrivateKey(j map[string]any) (*rsa.PrivateKey, error) {
	num := func(k string) *big.Int { s, _ := j[k].(string); b, _ := b64urlDecode(s); return new(big.Int).SetBytes(b) }
	if j["kty"] != "RSA" || num("d").Sign() == 0 {
		return nil, errors.New("not an RSA private JWK")
	}
	k := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: num("n"), E: int(num("e").Int64())}, D: num("d"),
		Primes: []*big.Int{num("p"), num("q")}}
	k.Precompute()
	return k, k.Validate()
}

// refused says whether a token is refused by a signal, and why.
func (r *ssfReceiver) refused(claims map[string]any) (string, bool) {
	if r == nil {
		return "", false
	}
	subject := claimString(claims, "client_id")
	if subject == "" {
		subject = claimString(claims, "sub")
	}
	r.mu.Lock()
	rev, ok := r.revoked[subject]
	r.mu.Unlock()
	if !ok {
		return "", false
	}
	if rev.disabled {
		return fmt.Sprintf("%s is disabled (%s at %s)", subject, shortEvent(rev.eventType), rev.at.UTC().Format(time.RFC3339)), true
	}
	iat, _ := claims["iat"].(float64)
	if !rev.cutoff.IsZero() && int64(iat) <= rev.cutoff.Unix() {
		return fmt.Sprintf("%s's tokens issued up to %s are revoked (%s)", subject, rev.cutoff.UTC().Format(time.RFC3339),
			shortEvent(rev.eventType)), true
	}
	return "", false
}

func shortEvent(t string) string { return t[strings.LastIndex(t, "/")+1:] }

// run keeps the stream polled, starting over after any failure.
func (r *ssfReceiver) run() {
	for {
		if err := r.session(); err != nil {
			log.Printf("ssf: %v; retrying in 10s", err)
		}
		time.Sleep(10 * time.Second)
	}
}

func (r *ssfReceiver) session() error {
	if err := r.discover(); err != nil {
		return err
	}
	if err := r.ensureStream(); err != nil {
		return err
	}
	log.Printf("ssf: polling %s every %s as %s (transmitter %s)", r.pollURL, r.poll, r.clientID, r.issuer)
	var acks []string
	for {
		next, err := r.pollOnce(acks)
		if err != nil {
			return err
		}
		acks = next
		if len(acks) == 0 {
			time.Sleep(r.poll)
		}
	}
}

func (r *ssfReceiver) reach(u string) string {
	if r.connectBase == "" || r.issuer == "" {
		return u
	}
	return strings.Replace(u, strings.TrimRight(r.issuer, "/"), r.connectBase, 1)
}

func (r *ssfReceiver) discover() error {
	var cfg struct {
		Issuer        string `json:"issuer"`
		Configuration string `json:"configuration_endpoint"`
	}
	if err := r.getJSON(r.configURL, "", &cfg); err != nil {
		return fmt.Errorf("transmitter configuration: %w", err)
	}
	if cfg.Issuer == "" || cfg.Configuration == "" {
		return errors.New("transmitter configuration lacks issuer or configuration_endpoint")
	}
	r.issuer, r.configEP = cfg.Issuer, r.reach(cfg.Configuration)
	if r.tokenAudience == "" {
		r.tokenAudience = strings.TrimRight(r.issuer, "/") + "/as/token.oauth2"
	}
	return nil
}

func (r *ssfReceiver) bearer() (string, error) {
	if r.accessToken != "" && time.Until(r.tokenExp) > 30*time.Second {
		return r.accessToken, nil
	}
	now := time.Now()
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	assertion, err := r.sign(map[string]any{"iss": r.clientID, "sub": r.clientID, "aud": r.tokenAudience,
		"jti": b64urlEncode(jti), "iat": now.Unix(), "exp": now.Add(60 * time.Second).Unix()})
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"ssf.manage"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {assertion}}
	resp, err := r.httpc.PostForm(r.tokenEndpoint, form)
	if err != nil {
		return "", fmt.Errorf("token: %w", err)
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &tok) != nil || tok.AccessToken == "" {
		return "", fmt.Errorf("token: HTTP %d %s", resp.StatusCode, truncate(string(body), 200))
	}
	r.accessToken, r.tokenExp = tok.AccessToken, now.Add(time.Duration(tok.ExpiresIn)*time.Second)
	return r.accessToken, nil
}

func (r *ssfReceiver) sign(claims map[string]any) (string, error) {
	h, _ := json.Marshal(map[string]any{"alg": "PS256", "kid": r.kid, "typ": "JWT"})
	c, _ := json.Marshal(claims)
	input := b64urlEncode(h) + "." + b64urlEncode(c)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPSS(rand.Reader, r.key, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		return "", err
	}
	return input + "." + b64urlEncode(sig), nil
}

// ensureStream finds this receiver's poll stream, or creates one.
func (r *ssfReceiver) ensureStream() error {
	tok, err := r.bearer()
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if err := r.getJSON(r.configEP, tok, &raw); err == nil {
		var many []map[string]any
		var one map[string]any
		if json.Unmarshal(raw, &many) != nil && json.Unmarshal(raw, &one) == nil && one != nil {
			many = []map[string]any{one}
		}
		for _, s := range many {
			if u := pollEndpoint(s); u != "" {
				r.pollURL = r.reach(u)
				return nil
			}
		}
	}
	body, _ := json.Marshal(map[string]any{
		"delivery":         map[string]any{"method": pollDelivery},
		"events_requested": []string{evSessionRevoked, evAccountDisabled, evAccountEnabled},
		"description":      "gateway PEP (coaz-pep): revocations",
	})
	var created map[string]any
	if err := r.postJSON(r.configEP, tok, body, &created); err != nil {
		return fmt.Errorf("create stream: %w", err)
	}
	u := pollEndpoint(created)
	if u == "" {
		return errors.New("create stream: no poll endpoint in the answer")
	}
	r.pollURL = r.reach(u)
	log.Printf("ssf: created stream %v", created["stream_id"])
	return nil
}

func pollEndpoint(stream map[string]any) string {
	d, _ := stream["delivery"].(map[string]any)
	if m, _ := d["method"].(string); m != pollDelivery {
		return ""
	}
	u, _ := d["endpoint_url"].(string)
	return u
}

// pollOnce acknowledges acks, takes what is waiting, and returns the jtis to acknowledge next.
func (r *ssfReceiver) pollOnce(acks []string) ([]string, error) {
	tok, err := r.bearer()
	if err != nil {
		return nil, err
	}
	req := map[string]any{"maxEvents": 50, "returnImmediately": true}
	if len(acks) > 0 {
		req["ack"] = acks
	}
	body, _ := json.Marshal(req)
	var answer struct {
		Sets map[string]string `json:"sets"`
	}
	if err := r.postJSON(r.pollURL, tok, body, &answer); err != nil {
		return nil, fmt.Errorf("poll: %w", err)
	}
	next := make([]string, 0, len(answer.Sets))
	for jti, set := range answer.Sets {
		if err := r.handle(set); err != nil {
			log.Printf("ssf: SET %s refused: %v", jti, err)
		}
		next = append(next, jti) // acknowledged either way: a SET that fails verification will not pass later
	}
	return next, nil
}

func (r *ssfReceiver) handle(set string) error {
	if err := r.tokens.verifySignature(set, "secevent+jwt"); err != nil {
		return err
	}
	claims := jwtClaims(set)
	if iss, _ := claims["iss"].(string); iss != r.issuer {
		return fmt.Errorf("iss %q is not the transmitter's", iss)
	}
	events, _ := claims["events"].(map[string]any)
	for eventType, raw := range events {
		event, _ := raw.(map[string]any)
		subject, _ := claims["sub_id"].(map[string]any)
		if s, ok := event["subject"].(map[string]any); ok && subject == nil {
			subject = s
		}
		key, err := r.subjectKey(subject)
		if err != nil {
			return err
		}
		when := time.Now()
		if ts, ok := event["event_timestamp"].(float64); ok {
			when = time.Unix(int64(ts), 0)
		} else if iat, ok := claims["iat"].(float64); ok {
			when = time.Unix(int64(iat), 0)
		}
		r.mu.Lock()
		switch eventType {
		case evAccountDisabled:
			r.revoked[key] = revocation{disabled: true, eventType: eventType, at: when}
		case evAccountEnabled:
			delete(r.revoked, key)
		case evSessionRevoked:
			rev := r.revoked[key]
			if when.After(rev.cutoff) {
				rev.cutoff = when
			}
			if !rev.disabled {
				rev.eventType, rev.at = eventType, when
			}
			r.revoked[key] = rev
		default:
			r.mu.Unlock()
			continue
		}
		r.mu.Unlock()
		log.Printf("ssf: %s for %s (event at %s)", shortEvent(eventType), key, when.UTC().Format(time.RFC3339))
	}
	return nil
}

func (r *ssfReceiver) subjectKey(subject map[string]any) (string, error) {
	switch subject["format"] {
	case "iss_sub":
		iss, _ := subject["iss"].(string)
		sub, _ := subject["sub"].(string)
		if iss != r.tokenIssuer {
			return "", fmt.Errorf("iss_sub subject from %q, not this PEP's token issuer", iss)
		}
		return sub, nil
	case "opaque":
		id, _ := subject["id"].(string)
		return id, nil
	}
	return "", fmt.Errorf("subject format %v not handled", subject["format"])
}

func (r *ssfReceiver) getJSON(u, bearer string, out any) error {
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	return r.do(req, bearer, out)
}

func (r *ssfReceiver) postJSON(u, bearer string, body []byte, out any) error {
	req, _ := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return r.do(req, bearer, out)
}

func (r *ssfReceiver) do(req *http.Request, bearer string, out any) error {
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := r.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized {
		r.accessToken = ""
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: HTTP %d %s", req.Method, req.URL, resp.StatusCode, truncate(string(body), 200))
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	return json.Unmarshal(body, out)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
