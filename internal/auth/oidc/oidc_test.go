package oidc_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scttpr/dropr/internal/auth/oidc"
	"github.com/scttpr/dropr/internal/auth/oidc/oidctest"
	"github.com/scttpr/dropr/internal/auth/session"
	"github.com/scttpr/dropr/internal/config"
	"github.com/scttpr/dropr/internal/store"
	"github.com/scttpr/dropr/internal/store/storetest"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type pages struct {
	mu   sync.Mutex
	last string
}

func (p *pages) set(s string) { p.mu.Lock(); p.last = s; p.mu.Unlock() }
func (p *pages) get() string  { p.mu.Lock(); defer p.mu.Unlock(); return p.last }

func (p *pages) SignInError(w http.ResponseWriter, _ *http.Request, status int, msg string) {
	p.set("error")
	http.Error(w, "error: "+msg, status)
}

func (p *pages) Forbidden(w http.ResponseWriter, _ *http.Request) {
	p.set("forbidden")
	http.Error(w, "forbidden", http.StatusForbidden)
}

func (p *pages) CallbackLanding(w http.ResponseWriter, _ *http.Request) {
	p.set("landing")
	_, _ = io.WriteString(w, "landing")
}

type setup struct {
	clientAuth  string
	key         crypto.Signer
	withCert    bool
	production  bool
	discovery   func(map[string]any)
	cfg         func(*config.OIDC)
	allowPKCE   bool
	requiredTID string
}

type harness struct {
	t        *testing.T
	op       *oidctest.Provider
	rp       *oidc.Provider
	st       *store.Store
	sessions *session.Manager
	clk      *clock
	pages    *pages
	srv      *httptest.Server
	client   *http.Client
	cert     *x509.Certificate
	warnings []string
}

func newKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func selfSigned(t *testing.T, k crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "dropr-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newHarness(t *testing.T, s setup) (*harness, error) {
	t.Helper()
	clk := &clock{t: time.Now().Truncate(time.Second)}
	if s.clientAuth == "" {
		s.clientAuth = config.ClientAuthPrivateKeyJWT
	}
	opOpts := oidctest.Options{ClientID: "dropr", Discovery: s.discovery, Now: clk.Now, IssuerPath: "/realms/test", TLS: s.production}
	if s.clientAuth == config.ClientAuthPrivateKeyJWT {
		if s.key == nil {
			s.key = newKey(t)
		}
		opOpts.ClientKey = s.key.Public()
	} else {
		opOpts.ClientSecret = "dev-secret"
	}
	op := oidctest.New(t, opOpts)

	h := &harness{t: t, op: op, clk: clk, pages: &pages{}, st: storetest.New(t)}
	handler := http.NotFoundHandler()
	h.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(h.srv.Close)

	cfg := &config.OIDC{
		Issuer:                op.Issuer,
		ClientID:              "dropr",
		ClientAuth:            s.clientAuth,
		ClientKeyID:           "dropr-key",
		Scopes:                []string{"openid", "profile"},
		RoleClaim:             "roles",
		RoleClaimPath:         []string{"roles"},
		RequiredRole:          "Dropr.User",
		DisplayClaim:          "name",
		RevalidateDur:         15 * time.Minute,
		RedirectURL:           h.srv.URL + "/auth/callback",
		PostLogoutURL:         h.srv.URL + "/login",
		ClientKey:             s.key,
		ClientSecret:          "dev-secret",
		AllowUnadvertisedPKCE: s.allowPKCE,
	}
	if s.requiredTID != "" {
		cfg.RequiredClaims = map[string]string{"tid": s.requiredTID}
	}
	if s.withCert {
		h.cert = selfSigned(t, s.key)
		cfg.ClientCert = h.cert
	}
	if s.cfg != nil {
		s.cfg(cfg)
	}
	op.AllowRedirect(cfg.RedirectURL)

	var err error
	h.sessions, err = session.NewManager(h.st, bytes.Repeat([]byte{9}, 32), session.Config{Now: clk.Now}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h.rp, h.warnings, err = oidc.New(t.Context(), oidc.Options{
		OIDC: cfg, Production: s.production, PublicOrigin: h.srv.URL,
		RefreshKey: bytes.Repeat([]byte{9}, 32), Store: h.st, Sessions: h.sessions,
		Pages: h.pages, Now: clk.Now, HTTPClient: opClient(op), Logger: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/login", h.rp.HandleLogin)
	mux.HandleFunc("GET /auth/callback", h.rp.HandleCallback)
	mux.HandleFunc("POST /auth/logout", h.rp.HandleLogout)
	mux.HandleFunc("GET /auth/frontchannel-logout", h.rp.HandleFrontchannelLogout)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if s := session.FromContext(r.Context()); s != nil {
			_, _ = io.WriteString(w, "user:"+s.UserID())
			return
		}
		http.Error(w, "anon", http.StatusUnauthorized)
	})
	handler = h.sessions.Middleware(h.rp.RevalidateMiddleware(mux))

	jar, _ := cookiejar.New(nil)
	h.client = &http.Client{Jar: jar, Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: op.RootCAs(), MinVersion: tls.VersionTLS12}}}
	return h, nil
}

func mustHarness(t *testing.T, s setup) *harness {
	t.Helper()
	h, err := newHarness(t, s)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *harness) get(path string) (int, string) {
	h.t.Helper()
	req, _ := http.NewRequestWithContext(h.t.Context(), http.MethodGet, h.srv.URL+path, nil)
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// login runs the whole browser flow, following redirects.
func (h *harness) login() (int, string) {
	h.t.Helper()
	return h.get("/auth/login")
}

func (h *harness) loggedIn() bool {
	h.t.Helper()
	code, body := h.get("/")
	return code == http.StatusOK && strings.HasPrefix(body, "user:")
}

func (h *harness) userCount() int {
	h.t.Helper()
	users, err := h.st.ListUsers(h.t.Context())
	if err != nil {
		h.t.Fatal(err)
	}
	return len(users)
}

func (h *harness) cookie(name string) *http.Cookie {
	u, _ := url.Parse(h.srv.URL)
	for _, c := range h.client.Jar.Cookies(u) {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestLoginPrivateKeyJWTWithCert(t *testing.T) {
	t.Parallel()
	h := mustHarness(t, setup{withCert: true})
	code, body := h.login()
	if code != http.StatusOK || body != "landing" {
		t.Fatalf("login: %d %q", code, body)
	}
	if !h.loggedIn() || h.userCount() != 1 {
		t.Fatal("no session after login")
	}
	if h.cookie(oidc.StateCookieName) != nil {
		t.Error("state cookie not deleted by callback")
	}
	u, err := h.st.UserByIdentity(t.Context(), h.op.Issuer, "user-123")
	if err != nil || u.DisplayName != "Alice Example" {
		t.Fatalf("user: %+v %v", u, err)
	}

	as := h.op.Assertions()
	if len(as) != 1 {
		t.Fatalf("assertions: %d", len(as))
	}
	a := as[0]
	thumb := sha256.Sum256(h.cert.Raw)
	if a.Header["alg"] != "PS256" || a.Header["kid"] != "dropr-key" || a.Header["typ"] != "JWT" ||
		a.Header["x5t#S256"] != base64.RawURLEncoding.EncodeToString(thumb[:]) {
		t.Errorf("assertion header: %v", a.Header)
	}
	if _, ok := a.Header["x5t"]; ok {
		t.Error("SHA-1 x5t sent without opt-in")
	}
	exp, iat := a.Claims["exp"].(float64), a.Claims["iat"].(float64)
	if a.Claims["iss"] != "dropr" || a.Claims["sub"] != "dropr" || a.Claims["aud"] != h.op.Issuer+"/token" ||
		exp-iat > 300 || exp <= iat || a.Claims["jti"] == "" {
		t.Errorf("assertion claims: %v", a.Claims)
	}
}

func TestLoginES256AndRS256(t *testing.T) {
	t.Parallel()
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h := mustHarness(t, setup{key: ec})
	if code, _ := h.login(); code != http.StatusOK || !h.loggedIn() {
		t.Fatal("ES256 login failed")
	}
	if h.op.Assertions()[0].Header["alg"] != "ES256" {
		t.Error("wrong alg")
	}
	h2 := mustHarness(t, setup{cfg: func(c *config.OIDC) { c.ClientAssertionAlg = "RS256" }})
	if code, _ := h2.login(); code != http.StatusOK || !h2.loggedIn() {
		t.Fatal("RS256 login failed")
	}
	if h2.op.Assertions()[0].Header["alg"] != "RS256" {
		t.Error("configured alg ignored")
	}
}

func TestLoginClientSecretDev(t *testing.T) {
	t.Parallel()
	h := mustHarness(t, setup{clientAuth: config.ClientAuthSecret})
	if code, body := h.login(); code != http.StatusOK || !h.loggedIn() {
		t.Fatalf("client_secret login failed: %d %s", code, body)
	}
}

func TestIDTokenNegative(t *testing.T) {
	t.Parallel()
	type tc struct {
		knobs   func(k *oidctest.Knobs)
		setup   setup
		outcome string // "error" or "forbidden"
	}
	cases := map[string]tc{
		"alg none":            {knobs: func(k *oidctest.Knobs) { k.Sign = oidctest.SignNone }, outcome: "error"},
		"HS256 with pub key":  {knobs: func(k *oidctest.Knobs) { k.Sign = oidctest.SignHS256PublicKey }, outcome: "error"},
		"unknown signing key": {knobs: func(k *oidctest.Knobs) { k.Sign = oidctest.SignUnknownKey }, outcome: "error"},
		"wrong iss": {knobs: func(k *oidctest.Knobs) {
			k.MutateIDToken = func(c map[string]any) { c["iss"] = "https://evil.example" }
		}, outcome: "error"},
		"iss with trailing slash": {knobs: func(k *oidctest.Knobs) {
			k.MutateIDToken = func(c map[string]any) { c["iss"] = c["iss"].(string) + "/" }
		}, outcome: "error"},
		"wrong aud": {knobs: func(k *oidctest.Knobs) {
			k.MutateIDToken = func(c map[string]any) { c["aud"] = "someone-else" }
		}, outcome: "error"},
		"wrong nonce": {knobs: func(k *oidctest.Knobs) {
			k.MutateIDToken = func(c map[string]any) { c["nonce"] = "replayed" }
		}, outcome: "error"},
		"missing nonce": {knobs: func(k *oidctest.Knobs) {
			k.MutateIDToken = func(c map[string]any) { delete(c, "nonce") }
		}, outcome: "error"},
		"wrong azp": {knobs: func(k *oidctest.Knobs) {
			k.MutateIDToken = func(c map[string]any) { c["azp"] = "other-client" }
		}, outcome: "error"},
		"multi aud without azp": {knobs: func(k *oidctest.Knobs) {
			k.MutateIDToken = func(c map[string]any) { c["aud"] = []any{"dropr", "other"} }
		}, outcome: "error"},
		"expired": {knobs: func(k *oidctest.Knobs) {
			k.MutateIDToken = func(c map[string]any) { c["exp"] = c["iat"].(int64) - 120 }
		}, outcome: "error"},
		"missing exp": {knobs: func(k *oidctest.Knobs) {
			k.MutateIDToken = func(c map[string]any) { delete(c, "exp") }
		}, outcome: "error"},
		"iat in future": {knobs: func(k *oidctest.Knobs) {
			k.MutateIDToken = func(c map[string]any) { c["iat"] = c["iat"].(int64) + 600 }
		}, outcome: "error"},
		"nbf in future": {knobs: func(k *oidctest.Knobs) {
			k.MutateIDToken = func(c map[string]any) { c["nbf"] = c["iat"].(int64) + 600 }
		}, outcome: "error"},
		"empty sub": {knobs: func(k *oidctest.Knobs) {
			k.MutateIDToken = func(c map[string]any) { c["sub"] = "" }
		}, outcome: "error"},
		"missing role": {knobs: func(k *oidctest.Knobs) {
			k.Claims = map[string]any{"name": "Mallory"}
		}, outcome: "forbidden"},
		"other role only": {knobs: func(k *oidctest.Knobs) {
			k.Claims = map[string]any{"roles": []any{"Dropr.Admin", "dropr.user"}}
		}, outcome: "forbidden"},
		"role not string": {knobs: func(k *oidctest.Knobs) {
			k.Claims = map[string]any{"roles": []any{map[string]any{"name": "Dropr.User"}}}
		}, outcome: "forbidden"},
		"required claim mismatch": {knobs: func(k *oidctest.Knobs) {
			k.Claims["tid"] = "other-tenant"
		}, setup: setup{requiredTID: "tenant-1"}, outcome: "forbidden"},
		"required claim missing": {setup: setup{requiredTID: "tenant-1"}, outcome: "forbidden"},
		"required claim wrong type": {knobs: func(k *oidctest.Knobs) {
			k.Claims["tid"] = []any{"tenant-1"}
		}, setup: setup{requiredTID: "tenant-1"}, outcome: "forbidden"},
		"no refresh token": {knobs: func(k *oidctest.Knobs) { k.OmitRefreshToken = true }, outcome: "error"},
		"authorize error":  {knobs: func(k *oidctest.Knobs) { k.AuthorizeError = "access_denied" }, outcome: "error"},
		"wrong iss param":  {knobs: func(k *oidctest.Knobs) { k.WrongIssParam = "https://evil.example" }, outcome: "error"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := mustHarness(t, c.setup)
			if c.knobs != nil {
				h.op.Set(func(k *oidctest.Knobs) {
					k.Claims = map[string]any{"name": "Alice Example", "roles": []any{"Dropr.User"}}
					c.knobs(k)
				})
			}
			code, body := h.login()
			if code == http.StatusOK || h.pages.get() != c.outcome {
				t.Fatalf("got %d %q (page %q), want %s", code, body, h.pages.get(), c.outcome)
			}
			if h.loggedIn() {
				t.Fatal("session created despite failure")
			}
			if c.outcome == "forbidden" && h.userCount() != 0 {
				t.Fatal("account created for unauthorized user")
			}
		})
	}
}

func TestIDTokenPositiveVariants(t *testing.T) {
	t.Parallel()
	cases := map[string]func(k *oidctest.Knobs){
		"role as string": func(k *oidctest.Knobs) { k.Claims = map[string]any{"roles": "Dropr.User"} },
		"multi aud with azp": func(k *oidctest.Knobs) {
			k.MutateIDToken = func(c map[string]any) { c["aud"] = []any{"dropr", "x"}; c["azp"] = "dropr" }
		},
		"small clock skew":     func(k *oidctest.Knobs) { k.MutateIDToken = func(c map[string]any) { c["iat"] = c["iat"].(int64) + 30 } },
		"correct iss param":    func(k *oidctest.Knobs) { k.IssParam = true },
		"required claim match": func(k *oidctest.Knobs) { k.Claims["tid"] = "tenant-1" },
	}
	for name, knobs := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := mustHarness(t, setup{requiredTID: map[bool]string{true: "tenant-1"}[name == "required claim match"]})
			h.op.Set(knobs)
			if code, body := h.login(); code != http.StatusOK || !h.loggedIn() {
				t.Fatalf("login failed: %d %q", code, body)
			}
		})
	}
}

func TestNestedRoleClaim(t *testing.T) {
	t.Parallel()
	h := mustHarness(t, setup{cfg: func(c *config.OIDC) { c.RoleClaimPath = []string{"realm_access", "roles"} }})
	h.op.Set(func(k *oidctest.Knobs) {
		k.Claims = map[string]any{"realm_access": map[string]any{"roles": []any{"offline_access", "Dropr.User"}}}
	})
	if code, _ := h.login(); code != http.StatusOK || !h.loggedIn() {
		t.Fatal("nested role login failed")
	}
}

// noRedirect returns a client that stops at the first redirect, sharing jar.
func (h *harness) noRedirect() *http.Client {
	return &http.Client{Jar: h.client.Jar, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (h *harness) do(c *http.Client, method, u string) *http.Response {
	h.t.Helper()
	req, _ := http.NewRequestWithContext(h.t.Context(), method, u, nil)
	resp, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp
}

// startFlow performs /auth/login and /authorize, returning the callback URL.
func (h *harness) startFlow() string {
	h.t.Helper()
	nr := h.noRedirect()
	resp := h.do(nr, http.MethodGet, h.srv.URL+"/auth/login")
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("login status %d", resp.StatusCode)
	}
	authz := resp.Header.Get("Location")
	au, _ := url.Parse(authz)
	q := au.Query()
	if q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 ||
		len(q.Get("state")) < 43 || len(q.Get("nonce")) < 43 || q.Get("redirect_uri") != h.srv.URL+"/auth/callback" {
		h.t.Fatalf("authorization request: %v", q)
	}
	resp = h.do(nr, http.MethodGet, authz)
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("authorize status %d", resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

func TestStateCookieProperties(t *testing.T) {
	t.Parallel()
	h := mustHarness(t, setup{})
	resp := h.do(h.noRedirect(), http.MethodGet, h.srv.URL+"/auth/login")
	var sc *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == oidc.StateCookieName {
			sc = c
		}
	}
	if sc == nil || !sc.Secure || !sc.HttpOnly || sc.SameSite != http.SameSiteLaxMode || sc.Path != "/" || sc.MaxAge != 600 {
		t.Fatalf("state cookie: %+v", sc)
	}
	// Sealed: no plaintext state/nonce visible.
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if strings.Contains(sc.Value, loc.Query().Get("state")) {
		t.Error("state visible in cookie")
	}
}

func TestCallbackStateFailures(t *testing.T) {
	t.Parallel()
	t.Run("tampered state", func(t *testing.T) {
		t.Parallel()
		h := mustHarness(t, setup{})
		cb, _ := url.Parse(h.startFlow())
		q := cb.Query()
		q.Set("state", strings.Repeat("A", 43))
		cb.RawQuery = q.Encode()
		if resp := h.do(h.noRedirect(), http.MethodGet, cb.String()); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if h.loggedIn() {
			t.Fatal("logged in")
		}
	})
	t.Run("no state cookie (login CSRF)", func(t *testing.T) {
		t.Parallel()
		h := mustHarness(t, setup{})
		cb := h.startFlow()
		// A different browser (fresh jar) receives the victim's callback URL.
		jar, _ := cookiejar.New(nil)
		other := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		if resp := h.do(other, http.MethodGet, cb); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
	t.Run("expired state", func(t *testing.T) {
		t.Parallel()
		h := mustHarness(t, setup{})
		cb := h.startFlow()
		h.clk.Add(11 * time.Minute)
		if resp := h.do(h.noRedirect(), http.MethodGet, cb); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
	t.Run("replayed callback", func(t *testing.T) {
		t.Parallel()
		h := mustHarness(t, setup{})
		cb := h.startFlow()
		if resp := h.do(h.noRedirect(), http.MethodGet, cb); resp.StatusCode != http.StatusOK {
			t.Fatalf("first callback %d", resp.StatusCode)
		}
		if resp := h.do(h.noRedirect(), http.MethodGet, cb); resp.StatusCode == http.StatusOK {
			t.Fatal("callback replay accepted")
		}
	})
	t.Run("forged state cookie", func(t *testing.T) {
		t.Parallel()
		h := mustHarness(t, setup{})
		cb := h.startFlow()
		u, _ := url.Parse(h.srv.URL)
		h.client.Jar.SetCookies(u, []*http.Cookie{{Name: oidc.StateCookieName, Value: base64.RawURLEncoding.EncodeToString(make([]byte, 80)), Path: "/"}})
		if resp := h.do(h.noRedirect(), http.MethodGet, cb); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
}

func TestLoginRotatesExistingSession(t *testing.T) {
	t.Parallel()
	h := mustHarness(t, setup{})
	h.login()
	first := h.cookie(session.CookieName).Value
	h.login()
	second := h.cookie(session.CookieName).Value
	if first == second {
		t.Fatal("session ID not rotated at login")
	}
	u, _ := url.Parse(h.srv.URL)
	h.client.Jar.SetCookies(u, []*http.Cookie{{Name: session.CookieName, Value: first, Path: "/"}})
	if h.loggedIn() {
		t.Fatal("previous session still valid")
	}
}

// Audit 2026-11 A07-3: a browser does not send the SameSite=Strict session
// cookie on the callback, which ends a redirect chain through the provider.
// The session presented at /auth/login is still ended once sign-in succeeds,
// and only then.
func TestLoginEndsPresentedSessionWithoutCallbackCookie(t *testing.T) {
	t.Parallel()
	h := mustHarness(t, setup{})
	h.login()
	first := h.cookie(session.CookieName).Value
	u, _ := url.Parse(h.srv.URL)
	restore := func() {
		h.client.Jar.SetCookies(u, []*http.Cookie{{Name: session.CookieName, Value: first, Path: "/"}})
	}
	drop := func() {
		h.client.Jar.SetCookies(u, []*http.Cookie{{Name: session.CookieName, Value: "x", Path: "/", MaxAge: -1}})
	}

	h.op.Set(func(k *oidctest.Knobs) { k.AuthorizeError = "access_denied" })
	cb := h.startFlow()
	drop()
	h.do(h.noRedirect(), http.MethodGet, cb)
	restore()
	if !h.loggedIn() {
		t.Fatal("a canceled sign-in ended the session")
	}

	h.op.Set(func(k *oidctest.Knobs) { k.AuthorizeError = "" })
	cb = h.startFlow()
	drop()
	if resp := h.do(h.noRedirect(), http.MethodGet, cb); resp.StatusCode != http.StatusOK {
		t.Fatalf("callback status %d", resp.StatusCode)
	}
	if c := h.cookie(session.CookieName); c == nil || c.Value == first || !h.loggedIn() {
		t.Fatal("no new session")
	}
	restore()
	if h.loggedIn() {
		t.Fatal("previous session survived sign-in")
	}
}

func TestRevalidation(t *testing.T) {
	t.Parallel()
	t.Run("success rotates refresh token", func(t *testing.T) {
		t.Parallel()
		h := mustHarness(t, setup{})
		h.login()
		calls := h.op.TokenCalls()
		h.clk.Add(10 * time.Minute)
		if !h.loggedIn() || h.op.TokenCalls() != calls {
			t.Fatal("revalidated too early")
		}
		for i := range 3 {
			h.clk.Add(16 * time.Minute)
			if !h.loggedIn() {
				t.Fatalf("revalidation %d failed", i)
			}
		}
		if got := h.op.TokenCalls() - calls; got != 3 {
			t.Fatalf("expected 3 refreshes, got %d", got)
		}
	})
	kill := map[string]func(h *harness){
		"revoked refresh token": func(h *harness) { h.op.RevokeRefreshTokens() },
		"role removed":          func(h *harness) { h.op.Set(func(k *oidctest.Knobs) { k.RefreshClaims = map[string]any{"name": "x"} }) },
		"different subject":     func(h *harness) { h.op.Set(func(k *oidctest.Knobs) { k.RefreshSubject = "someone-else" }) },
		"provider down":         func(h *harness) { h.op.Set(func(k *oidctest.Knobs) { k.TokenEndpointDown = true }) },
		"bad signature":         func(h *harness) { h.op.Set(func(k *oidctest.Knobs) { k.Sign = oidctest.SignUnknownKey }) },
		"alg none on refresh":   func(h *harness) { h.op.Set(func(k *oidctest.Knobs) { k.Sign = oidctest.SignNone }) },
		"wrong aud on refresh": func(h *harness) {
			h.op.Set(func(k *oidctest.Knobs) { k.MutateIDToken = func(c map[string]any) { c["aud"] = "x" } })
		},
		"no id_token, userinfo lacks role": func(h *harness) {
			h.op.Set(func(k *oidctest.Knobs) {
				k.OmitIDTokenOnRefresh = true
				k.UserinfoClaims = map[string]any{"name": "x"}
			})
		},
		"no id_token, userinfo other sub": func(h *harness) {
			h.op.Set(func(k *oidctest.Knobs) { k.OmitIDTokenOnRefresh = true; k.RefreshSubject = "other" })
		},
	}
	// Only a withdrawn role or required claim is a definitive loss of
	// access: it marks the account and expires its share links (audit I-3,
	// 2026-11b L-2). Every other failure (provider down, revoked refresh
	// token, bad token, other subject) only ends the session.
	losesAccess := map[string]bool{"role removed": true, "no id_token, userinfo lacks role": true}
	for name, breakIt := range kill {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := mustHarness(t, setup{})
			h.login()
			if !h.loggedIn() {
				t.Fatal("login failed")
			}
			users, err := h.st.ListUsers(t.Context())
			if err != nil || len(users) != 1 {
				t.Fatal(len(users), err)
			}
			uid := users[0].ID
			shareID, _, err := h.st.CreateShare(t.Context(), &store.NewShare{OwnerID: uid, Size: 16, Parts: 1, Meta: make([]byte, 20),
				ExpiresAt: h.clk.Now().Add(24 * time.Hour), TokenHash: make([]byte, 32), DefaultQuota: 1 << 30}, h.clk.Now())
			if err != nil {
				t.Fatal(err)
			}
			sessCookie := h.cookie(session.CookieName).Value
			breakIt(h)
			h.clk.Add(16 * time.Minute)
			if h.loggedIn() {
				t.Fatal("session survived failed revalidation")
			}
			active, err := h.st.AccountActive(t.Context(), uid)
			if err != nil || active == losesAccess[name] {
				t.Errorf("account active = %v (%v), want %v", active, err, !losesAccess[name])
			}
			var exp int64
			if err := h.st.DB().R.QueryRowContext(t.Context(), `SELECT expires_at FROM shares WHERE id = ?`, shareID).Scan(&exp); err != nil {
				t.Fatal(err)
			}
			if live := exp > h.clk.Now().Unix(); live == losesAccess[name] {
				t.Errorf("share live = %v, want %v", live, !losesAccess[name])
			}
			// The row is gone, not just hidden.
			u, _ := url.Parse(h.srv.URL)
			h.client.Jar.SetCookies(u, []*http.Cookie{{Name: session.CookieName, Value: sessCookie, Path: "/"}})
			h.op.Set(func(k *oidctest.Knobs) {
				*k = oidctest.Knobs{Subject: "user-123", Claims: map[string]any{"roles": []any{"Dropr.User"}}}
			})
			if h.loggedIn() {
				t.Fatal("killed session usable again")
			}
		})
	}
	t.Run("no id_token, userinfo ok", func(t *testing.T) {
		t.Parallel()
		h := mustHarness(t, setup{})
		h.login()
		h.op.Set(func(k *oidctest.Knobs) { k.OmitIDTokenOnRefresh = true })
		h.clk.Add(16 * time.Minute)
		if !h.loggedIn() {
			t.Fatal("userinfo fallback failed")
		}
	})
	t.Run("concurrent requests refresh once", func(t *testing.T) {
		t.Parallel()
		h := mustHarness(t, setup{})
		h.login()
		calls := h.op.TokenCalls()
		h.clk.Add(16 * time.Minute)
		var wg sync.WaitGroup
		results := make(chan bool, 20)
		for range 20 {
			wg.Go(func() {
				req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, h.srv.URL+"/", nil)
				resp, err := h.client.Do(req)
				if err != nil {
					results <- false
					return
				}
				_ = resp.Body.Close()
				results <- resp.StatusCode == http.StatusOK
			})
		}
		wg.Wait()
		close(results)
		for ok := range results {
			if !ok {
				t.Fatal("a concurrent request lost its session")
			}
		}
		if got := h.op.TokenCalls() - calls; got != 1 {
			t.Fatalf("refresh token redeemed %d times", got)
		}
	})
}

func TestLogout(t *testing.T) {
	t.Parallel()
	h := mustHarness(t, setup{})
	h.login()
	resp := h.do(h.noRedirect(), http.MethodPost, h.srv.URL+"/auth/logout")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Scheme+"://"+loc.Host+loc.Path != h.op.Issuer+"/logout" ||
		loc.Query().Get("client_id") != "dropr" || loc.Query().Get("post_logout_redirect_uri") != h.srv.URL+"/login" {
		t.Errorf("end session redirect: %s", loc)
	}
	if loc.Query().Has("id_token_hint") {
		t.Error("unexpected id_token_hint")
	}
	if h.loggedIn() {
		t.Fatal("session survived logout")
	}
}

// Audit 2026-11 A07-4: logout revokes the refresh token at the provider when
// it advertises a revocation_endpoint, without waiting for it.
func TestLogoutRevokesRefreshToken(t *testing.T) {
	t.Parallel()
	t.Run("advertised", func(t *testing.T) {
		t.Parallel()
		h := mustHarness(t, setup{})
		h.login()
		if resp := h.do(h.noRedirect(), http.MethodPost, h.srv.URL+"/auth/logout"); resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("status %d", resp.StatusCode)
		}
		deadline := time.Now().Add(5 * time.Second)
		for len(h.op.Revocations()) == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if got := h.op.Revocations(); len(got) != 1 || got[0] == "" {
			t.Fatalf("revocations: %q", got)
		}
	})
	t.Run("not advertised", func(t *testing.T) {
		t.Parallel()
		h := mustHarness(t, setup{discovery: func(d map[string]any) { delete(d, "revocation_endpoint") }})
		h.login()
		if resp := h.do(h.noRedirect(), http.MethodPost, h.srv.URL+"/auth/logout"); resp.StatusCode != http.StatusSeeOther || h.loggedIn() {
			t.Fatal("logout failed")
		}
		if got := h.op.Revocations(); len(got) != 0 {
			t.Fatalf("revocations: %q", got)
		}
	})
	t.Run("endpoint down", func(t *testing.T) {
		t.Parallel()
		dead := httptest.NewServer(http.NotFoundHandler())
		dead.Close()
		h := mustHarness(t, setup{discovery: func(d map[string]any) { d["revocation_endpoint"] = dead.URL + "/revoke" }})
		h.login()
		if resp := h.do(h.noRedirect(), http.MethodPost, h.srv.URL+"/auth/logout"); resp.StatusCode != http.StatusSeeOther || h.loggedIn() {
			t.Fatal("logout depends on revocation")
		}
	})
}

func TestFrontchannelLogout(t *testing.T) {
	t.Parallel()
	h := mustHarness(t, setup{})
	h.login()
	nr := h.noRedirect()
	bad := h.srv.URL + "/auth/frontchannel-logout?" + url.Values{"iss": {"https://evil.example"}, "sid": {"op-session-1"}}.Encode()
	if resp := h.do(nr, http.MethodGet, bad); resp.StatusCode != http.StatusBadRequest || !h.loggedIn() {
		t.Fatal("front-channel logout accepted a foreign issuer")
	}
	if resp := h.do(nr, http.MethodGet, h.srv.URL+"/auth/frontchannel-logout?"+url.Values{"iss": {h.op.Issuer}}.Encode()); resp.StatusCode != http.StatusBadRequest {
		t.Fatal("missing sid accepted")
	}
	other := h.srv.URL + "/auth/frontchannel-logout?" + url.Values{"iss": {h.op.Issuer}, "sid": {"another"}}.Encode()
	h.do(nr, http.MethodGet, other)
	if !h.loggedIn() {
		t.Fatal("unrelated sid killed the session")
	}
	good := h.srv.URL + "/auth/frontchannel-logout?" + url.Values{"iss": {h.op.Issuer}, "sid": {"op-session-1"}}.Encode()
	resp := h.do(nr, http.MethodGet, good)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors "+strings.TrimSuffix(h.op.Issuer, "/realms/test")) {
		t.Errorf("csp %q", csp)
	}
	if h.loggedIn() {
		t.Fatal("session survived front-channel logout")
	}
}

func TestDiscoveryAndCapabilities(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		s       setup
		wantErr string
	}{
		"issuer mismatch": {s: setup{discovery: func(d map[string]any) { d["issuer"] = d["issuer"].(string) + "/" }}, wantErr: "issuer"},
		"no S256 (prod)":  {s: setup{production: true, discovery: func(d map[string]any) { d["code_challenge_methods_supported"] = []string{"plain"} }}, wantErr: "PKCE S256"},
		"unadvertised PKCE (prod)": {s: setup{production: true, discovery: func(d map[string]any) { delete(d, "code_challenge_methods_supported") }},
			wantErr: "allow_unadvertised_pkce"},
		"no private_key_jwt": {s: setup{discovery: func(d map[string]any) {
			d["token_endpoint_auth_methods_supported"] = []string{"client_secret_basic"}
		}}, wantErr: "private_key_jwt"},
		"auth methods absent": {s: setup{discovery: func(d map[string]any) { delete(d, "token_endpoint_auth_methods_supported") }}, wantErr: "private_key_jwt"},
		"no refresh (prod)": {s: setup{production: true, discovery: func(d map[string]any) {
			d["grant_types_supported"] = []string{"authorization_code"}
		}}, wantErr: "refresh_token"},
		"HMAC-only id tokens": {s: setup{discovery: func(d map[string]any) {
			d["id_token_signing_alg_values_supported"] = []string{"HS256", "none"}
		}}, wantErr: "asymmetric"},
		"assertion alg not accepted": {s: setup{discovery: func(d map[string]any) {
			d["token_endpoint_auth_signing_alg_values_supported"] = []string{"ES256"}
		}}, wantErr: "client assertions"},
		"no code response type": {s: setup{discovery: func(d map[string]any) { d["response_types_supported"] = []string{"id_token"} }}, wantErr: "code"},
		// Audit 2026-11 I7: go-oidc reads discovery without a bound.
		"oversized discovery": {s: setup{discovery: func(d map[string]any) { d["x_padding"] = strings.Repeat("a", 1<<20) }}, wantErr: "too large"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := newHarness(t, c.s)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("got %v, want %q", err, c.wantErr)
			}
		})
	}

	// Dev mode tolerates capability gaps with warnings; production with
	// allow_unadvertised_pkce accepts Entra-style discovery.
	h := mustHarness(t, setup{discovery: func(d map[string]any) {
		delete(d, "code_challenge_methods_supported")
		d["grant_types_supported"] = []string{"authorization_code"}
	}})
	if len(h.warnings) < 2 {
		t.Errorf("dev warnings: %v", h.warnings)
	}
	h = mustHarness(t, setup{production: true, allowPKCE: true, withCert: true, discovery: func(d map[string]any) {
		delete(d, "code_challenge_methods_supported")
		delete(d, "grant_types_supported")
		delete(d, "token_endpoint_auth_signing_alg_values_supported")
	}})
	if code, _ := h.login(); code != http.StatusOK || !h.loggedIn() {
		t.Fatal("Entra-style login failed")
	}
	if h.op.Assertions()[0].Header["alg"] != "PS256" {
		t.Error("default RSA alg should be PS256 when the provider advertises none")
	}
	if got := h.rp.FormActionOrigins(); len(got) != 1 {
		t.Errorf("form-action origins: %v", got)
	}

	// A bad revocation_endpoint is dropped with a warning, not refused.
	h = mustHarness(t, setup{discovery: func(d map[string]any) { d["revocation_endpoint"] = "/revoke" }})
	if h.rp.Metadata().RevocationEndpoint != "" || !strings.Contains(strings.Join(h.warnings, "\n"), "revocation_endpoint") {
		t.Errorf("invalid revocation_endpoint kept: %v", h.warnings)
	}
}

func TestX5TSHA1OptIn(t *testing.T) {
	t.Parallel()
	h := mustHarness(t, setup{withCert: true, cfg: func(c *config.OIDC) { c.ClientAssertionX5TSHA = true; c.ClientKeyID = "" }})
	h.login()
	a := h.op.Assertions()[0]
	if _, ok := a.Header["x5t"]; !ok {
		t.Error("x5t missing")
	}
	if _, ok := a.Header["kid"]; ok {
		t.Error("kid sent without configuration")
	}
}

func Example_roleClaimPaths() {
	claims := map[string]any{"realm_access": map[string]any{"roles": []any{"Dropr.User"}}, "roles": "Dropr.User"}
	fmt.Println(oidc.HasRole(claims, []string{"realm_access", "roles"}, "Dropr.User"))
	fmt.Println(oidc.HasRole(claims, []string{"roles"}, "Dropr.User"))
	fmt.Println(oidc.HasRole(claims, []string{"groups"}, "Dropr.User"))
	// Output:
	// true
	// true
	// false
}

func opClient(op *oidctest.Provider) *http.Client {
	c := oidc.DefaultHTTPClient()
	c.Transport.(*http.Transport).TLSClientConfig.RootCAs = op.RootCAs()
	return c
}
