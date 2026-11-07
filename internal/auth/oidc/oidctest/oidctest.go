// Package oidctest is an in-process fake OpenID Connect provider for tests.
//
// It implements discovery, JWKS, an auto-approving authorization endpoint,
// a token endpoint that enforces PKCE S256 and authenticates the client
// (private_key_jwt per RFC 7523, or client_secret), refresh with rotation,
// userinfo, token revocation (RFC 7009) and an end-session endpoint. Knobs let tests emit malicious or
// broken responses: unsigned or HMAC-signed tokens, unknown keys, wrong
// claims, missing roles, a different subject on refresh, revoked refresh
// tokens, refreshes without an id_token, and altered discovery documents.
package oidctest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

var b64 = base64.RawURLEncoding

// SignMode selects how ID tokens are signed.
type SignMode int

// Signing modes.
const (
	SignRS256          SignMode = iota // correct signature with the published key
	SignNone                           // alg "none", empty signature
	SignHS256PublicKey                 // HS256 keyed with the provider's public key PEM
	SignUnknownKey                     // RS256 with an unpublished key under the published kid
)

// Knobs control the provider's behavior. Change them with Provider.Set.
type Knobs struct {
	Subject string
	SID     string
	// Claims are merged into every ID token and userinfo response.
	Claims map[string]any
	Sign   SignMode
	// MutateIDToken edits ID token claims after defaults are applied.
	MutateIDToken func(claims map[string]any)
	// MutateHeader edits the ID token JOSE header.
	MutateHeader         func(hdr map[string]any)
	OmitIDTokenOnRefresh bool
	OmitRefreshToken     bool
	// RefreshSubject overrides sub in refreshed ID tokens and userinfo.
	RefreshSubject string
	// RefreshClaims replaces Claims for refreshed tokens and userinfo.
	RefreshClaims map[string]any
	// AuthorizeError makes /authorize redirect back with this error code.
	AuthorizeError string
	// IssParam adds "iss" to the authorization response (RFC 9207); a
	// non-empty WrongIssParam sends that value instead.
	IssParam      bool
	WrongIssParam string
	// TokenEndpointDown makes the token endpoint answer 503.
	TokenEndpointDown bool
	// UserinfoClaims, when set, replaces the claims userinfo returns.
	UserinfoClaims map[string]any
}

// Options configure a new provider.
type Options struct {
	ClientID     string
	ClientSecret string           // accept client_secret_basic/post when set
	ClientKey    crypto.PublicKey // accept private_key_jwt when set
	// Discovery edits the discovery document (e.g. drop capabilities).
	Discovery func(doc map[string]any)
	// IssuerPath is appended to the server URL to form the issuer.
	IssuerPath string
	// TLS serves the provider over HTTPS with a test certificate.
	TLS bool
	// Now overrides the clock used for token timestamps.
	Now func() time.Time
}

// Assertion is a client assertion the token endpoint accepted.
type Assertion struct {
	Header map[string]any
	Claims map[string]any
}

// Provider is the fake OP.
type Provider struct {
	Issuer string
	srv    *httptest.Server
	opts   Options

	key     *rsa.PrivateKey
	other   *rsa.PrivateKey
	kid     string
	pubPEM  []byte
	tokenEP string

	mu           sync.Mutex
	knobs        Knobs
	redirectURIs []string
	codes        map[string]*codeGrant
	refresh      map[string]*refreshGrant
	access       map[string]map[string]any
	jtis         map[string]bool
	assertions   []Assertion
	tokenCalls   int
	logouts      []url.Values
	revocations  []string
}

type codeGrant struct {
	clientID, redirectURI, challenge, nonce string
	created                                 time.Time
}

type refreshGrant struct {
	sub, sid string
	revoked  bool
}

// New starts a provider; it is closed when the test ends.
func New(t testing.TB, opts Options) *Provider {
	t.Helper()
	if opts.ClientID == "" {
		opts.ClientID = "dropr-test"
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{
		opts:    opts,
		key:     key,
		other:   other,
		kid:     "test-key-1",
		pubPEM:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
		codes:   map[string]*codeGrant{},
		refresh: map[string]*refreshGrant{},
		access:  map[string]map[string]any{},
		jtis:    map[string]bool{},
		knobs: Knobs{
			Subject: "user-123",
			SID:     "op-session-1",
			Claims:  map[string]any{"name": "Alice Example", "roles": []any{"Dropr.User"}},
		},
	}
	mux := http.NewServeMux()
	if opts.TLS {
		p.srv = httptest.NewTLSServer(mux)
	} else {
		p.srv = httptest.NewServer(mux)
	}
	t.Cleanup(p.srv.Close)
	p.Issuer = p.srv.URL + opts.IssuerPath
	p.tokenEP = p.Issuer + "/token"
	prefix := opts.IssuerPath
	mux.HandleFunc("GET "+prefix+"/.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET "+prefix+"/jwks", p.jwks)
	mux.HandleFunc("GET "+prefix+"/authorize", p.authorize)
	mux.HandleFunc("POST "+prefix+"/token", p.token)
	mux.HandleFunc("GET "+prefix+"/userinfo", p.userinfo)
	mux.HandleFunc("GET "+prefix+"/logout", p.logout)
	mux.HandleFunc("POST "+prefix+"/revoke", p.revoke)
	return p
}

// Set changes knobs under the provider's lock.
func (p *Provider) Set(f func(k *Knobs)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f(&p.knobs)
}

// AllowRedirect registers a redirect URI (exact match).
func (p *Provider) AllowRedirect(uri string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.redirectURIs = append(p.redirectURIs, uri)
}

// RevokeRefreshTokens revokes every refresh token issued so far, as a
// provider does for a disabled user or "revoke sessions".
func (p *Provider) RevokeRefreshTokens() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, g := range p.refresh {
		g.revoked = true
	}
}

// Assertions returns the accepted client assertions.
func (p *Provider) Assertions() []Assertion {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.assertions)
}

// TokenCalls returns how many token requests were received.
func (p *Provider) TokenCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tokenCalls
}

// Logouts returns the query parameters of end-session requests.
func (p *Provider) Logouts() []url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.logouts)
}

// Revocations returns the tokens received by the revocation endpoint from
// an authenticated client.
func (p *Provider) Revocations() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.revocations)
}

// PublicKeyPEM returns the signing public key as PEM.
func (p *Provider) PublicKeyPEM() []byte { return p.pubPEM }

// SignIDToken signs arbitrary claims with the provider's real key (for
// tests that need hand-crafted tokens).
func (p *Provider) SignIDToken(claims map[string]any) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.signLocked(map[string]any{"alg": "RS256", "kid": p.kid, "typ": "JWT"}, claims, SignRS256)
}

func (p *Provider) discovery(w http.ResponseWriter, _ *http.Request) {
	doc := map[string]any{
		"issuer":                                           p.Issuer,
		"authorization_endpoint":                           p.Issuer + "/authorize",
		"token_endpoint":                                   p.tokenEP,
		"jwks_uri":                                         p.Issuer + "/jwks",
		"userinfo_endpoint":                                p.Issuer + "/userinfo",
		"end_session_endpoint":                             p.Issuer + "/logout",
		"revocation_endpoint":                              p.Issuer + "/revoke",
		"response_types_supported":                         []string{"code"},
		"subject_types_supported":                          []string{"public"},
		"id_token_signing_alg_values_supported":            []string{"RS256"},
		"code_challenge_methods_supported":                 []string{"plain", "S256"},
		"token_endpoint_auth_methods_supported":            []string{"private_key_jwt", "client_secret_basic", "client_secret_post"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"RS256", "PS256", "ES256"},
		"grant_types_supported":                            []string{"authorization_code", "refresh_token"},
		"scopes_supported":                                 []string{"openid", "profile", "offline_access"},
		"frontchannel_logout_supported":                    true,
		"frontchannel_logout_session_supported":            true,
	}
	if p.opts.Discovery != nil {
		p.opts.Discovery(doc)
	}
	writeJSON(w, http.StatusOK, doc)
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := p.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": p.kid,
		"n": b64.EncodeToString(pub.N.Bytes()),
		"e": b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p.mu.Lock()
	defer p.mu.Unlock()
	redirect := q.Get("redirect_uri")
	if q.Get("client_id") != p.opts.ClientID || !slices.Contains(p.redirectURIs, redirect) {
		http.Error(w, "invalid client or redirect_uri", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
		len(q.Get("code_challenge")) != 43 || q.Get("state") == "" || q.Get("nonce") == "" ||
		!slices.Contains(strings.Fields(q.Get("scope")), "openid") {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	back, _ := url.Parse(redirect)
	bq := back.Query()
	bq.Set("state", q.Get("state"))
	if p.knobs.IssParam || p.knobs.WrongIssParam != "" {
		iss := p.Issuer
		if p.knobs.WrongIssParam != "" {
			iss = p.knobs.WrongIssParam
		}
		bq.Set("iss", iss)
	}
	if p.knobs.AuthorizeError != "" {
		bq.Set("error", p.knobs.AuthorizeError)
	} else {
		code := randToken()
		p.codes[code] = &codeGrant{
			clientID: q.Get("client_id"), redirectURI: redirect,
			challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), created: p.now(),
		}
		bq.Set("code", code)
	}
	back.RawQuery = bq.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenCalls++
	if p.knobs.TokenEndpointDown {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := p.authenticateClient(r); err != nil {
		oauthErr(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		p.redeemCode(w, r)
	case "refresh_token":
		p.redeemRefresh(w, r)
	default:
		oauthErr(w, http.StatusBadRequest, "unsupported_grant_type")
	}
}

func (p *Provider) redeemCode(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	g, ok := p.codes[f.Get("code")]
	delete(p.codes, f.Get("code")) // single use
	if !ok || p.now().Sub(g.created) > time.Minute || g.redirectURI != f.Get("redirect_uri") || g.clientID != p.opts.ClientID {
		oauthErr(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	v := f.Get("code_verifier")
	sum := sha256.Sum256([]byte(v))
	if len(v) < 43 || len(v) > 128 || subtle.ConstantTimeCompare([]byte(b64.EncodeToString(sum[:])), []byte(g.challenge)) != 1 {
		oauthErr(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	p.issueTokens(w, p.knobs.Subject, p.knobs.SID, g.nonce, false)
}

func (p *Provider) redeemRefresh(w http.ResponseWriter, r *http.Request) {
	rt := r.PostForm.Get("refresh_token")
	g, ok := p.refresh[rt]
	if !ok || g.revoked {
		oauthErr(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	// Rotation with reuse detection: the old token becomes invalid.
	g.revoked = true
	sub := g.sub
	if p.knobs.RefreshSubject != "" {
		sub = p.knobs.RefreshSubject
	}
	p.issueTokens(w, sub, g.sid, "", true)
}

func (p *Provider) claimsFor(sub string, refresh bool) map[string]any {
	src := p.knobs.Claims
	if refresh && p.knobs.RefreshClaims != nil {
		src = p.knobs.RefreshClaims
	}
	c := maps.Clone(src)
	if c == nil {
		c = map[string]any{}
	}
	c["sub"] = sub
	return c
}

func (p *Provider) issueTokens(w http.ResponseWriter, sub, sid, nonce string, refresh bool) {
	now := p.now()
	claims := p.claimsFor(sub, refresh)
	claims["iss"] = p.Issuer
	claims["aud"] = p.opts.ClientID
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(5 * time.Minute).Unix()
	claims["sid"] = sid
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if p.knobs.MutateIDToken != nil {
		p.knobs.MutateIDToken(claims)
	}
	hdr := map[string]any{"alg": "RS256", "kid": p.kid, "typ": "JWT"}
	switch p.knobs.Sign {
	case SignNone:
		hdr["alg"] = "none"
	case SignHS256PublicKey:
		hdr["alg"] = "HS256"
	}
	if p.knobs.MutateHeader != nil {
		p.knobs.MutateHeader(hdr)
	}
	at := randToken()
	ui := p.claimsFor(sub, refresh)
	if p.knobs.UserinfoClaims != nil {
		ui = maps.Clone(p.knobs.UserinfoClaims)
		ui["sub"] = sub
	}
	p.access[at] = ui
	resp := map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": 300}
	if !refresh || !p.knobs.OmitIDTokenOnRefresh {
		resp["id_token"] = p.signLocked(hdr, claims, p.knobs.Sign)
	}
	if !p.knobs.OmitRefreshToken {
		rt := randToken()
		p.refresh[rt] = &refreshGrant{sub: sub, sid: sid}
		resp["refresh_token"] = rt
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

func (p *Provider) signLocked(hdr, claims map[string]any, mode SignMode) string {
	h, _ := json.Marshal(hdr)
	c, _ := json.Marshal(claims)
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
	var sig []byte
	switch mode {
	case SignNone:
		return input + "."
	case SignHS256PublicKey:
		m := hmac.New(sha256.New, p.pubPEM)
		m.Write([]byte(input))
		sig = m.Sum(nil)
	case SignUnknownKey:
		d := sha256.Sum256([]byte(input))
		sig, _ = rsa.SignPKCS1v15(rand.Reader, p.other, crypto.SHA256, d[:])
	default:
		d := sha256.Sum256([]byte(input))
		sig, _ = rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, d[:])
	}
	return input + "." + b64.EncodeToString(sig)
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	at, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	p.mu.Lock()
	claims, found := p.access[at]
	p.mu.Unlock()
	if !ok || !found {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, claims)
}

func (p *Provider) revoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthErr(w, http.StatusBadRequest, "invalid_request")
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.authenticateClient(r); err != nil {
		oauthErr(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	tok := r.PostForm.Get("token")
	if g, ok := p.refresh[tok]; ok {
		g.revoked = true
	}
	p.revocations = append(p.revocations, tok)
	w.WriteHeader(http.StatusOK) // RFC 7009 §2.2: also for unknown tokens
}

func (p *Provider) logout(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.logouts = append(p.logouts, r.URL.Query())
	p.mu.Unlock()
	_, _ = w.Write([]byte("logged out"))
}

// authenticateClient verifies client_secret or a private_key_jwt assertion.
func (p *Provider) authenticateClient(r *http.Request) error {
	f := r.PostForm
	if f.Get("client_assertion_type") != "" {
		if p.opts.ClientKey == nil || f.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
			return errors.New("private_key_jwt not enabled")
		}
		if f.Get("client_secret") != "" || r.Header.Get("Authorization") != "" {
			return errors.New("multiple client authentication methods")
		}
		hdr, claims, err := verifyJWS(f.Get("client_assertion"), p.opts.ClientKey)
		if err != nil {
			return err
		}
		now := p.now().Unix()
		exp, _ := claims["exp"].(float64)
		iat, _ := claims["iat"].(float64)
		jti, _ := claims["jti"].(string)
		switch {
		case claims["iss"] != p.opts.ClientID || claims["sub"] != p.opts.ClientID:
			return errors.New("iss/sub")
		case !audContains(claims["aud"], p.tokenEP):
			return errors.New("aud")
		case int64(exp) <= now || int64(exp)-now > 300 || int64(exp)-int64(iat) > 300:
			return errors.New("exp")
		case jti == "" || p.jtis[jti]:
			return errors.New("jti replay")
		case f.Get("client_id") != "" && f.Get("client_id") != p.opts.ClientID:
			return errors.New("client_id")
		}
		p.jtis[jti] = true
		p.assertions = append(p.assertions, Assertion{Header: hdr, Claims: claims})
		return nil
	}
	if p.opts.ClientSecret == "" {
		return errors.New("client_secret not enabled")
	}
	id, secret, ok := r.BasicAuth()
	if ok {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = f.Get("client_id"), f.Get("client_secret")
	}
	if id != p.opts.ClientID || subtle.ConstantTimeCompare([]byte(secret), []byte(p.opts.ClientSecret)) != 1 {
		return errors.New("bad secret")
	}
	return nil
}

func audContains(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		return slices.Contains(a, any(want))
	}
	return false
}

func verifyJWS(tok string, pub crypto.PublicKey) (hdr, claims map[string]any, err error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("malformed JWS")
	}
	hb, err1 := b64.DecodeString(parts[0])
	cb, err2 := b64.DecodeString(parts[1])
	sig, err3 := b64.DecodeString(parts[2])
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(cb, &claims); err != nil {
		return nil, nil, err
	}
	d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch hdr["alg"] {
	case "RS256":
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, nil, errors.New("key type")
		}
		err = rsa.VerifyPKCS1v15(k, crypto.SHA256, d[:], sig)
	case "PS256":
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, nil, errors.New("key type")
		}
		err = rsa.VerifyPSS(k, crypto.SHA256, d[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "ES256":
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 {
			return nil, nil, errors.New("key type")
		}
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(k, d[:], r, s) {
			err = errors.New("bad signature")
		}
	default:
		return nil, nil, fmt.Errorf("alg %v not allowed", hdr["alg"])
	}
	return hdr, claims, err
}

func randToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return b64.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func oauthErr(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": "fake provider: " + code})
}

func (p *Provider) now() time.Time {
	if p.opts.Now != nil {
		return p.opts.Now()
	}
	return time.Now()
}

// RootCAs returns a pool trusting the provider's TLS certificate (TLS mode).
func (p *Provider) RootCAs() *x509.CertPool {
	pool := x509.NewCertPool()
	if c := p.srv.Certificate(); c != nil {
		pool.AddCert(c)
	}
	return pool
}
