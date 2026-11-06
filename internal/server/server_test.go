package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/scttpr/dropr/internal/auth/oidc/oidctest"
	"github.com/scttpr/dropr/internal/blob"
	"github.com/scttpr/dropr/internal/config"
	"github.com/scttpr/dropr/internal/store/storetest"
)

type testEnv struct {
	t      *testing.T
	op     *oidctest.Provider
	srv    *httptest.Server
	client *http.Client
	origin string
	s      *Server
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnvWith(t, testOpts{})
}

// testOpts tune newTestEnvWith.
type testOpts struct {
	extraConfig string // TOML appended before [oidc], e.g. a [limits] table
	diskUsage   blob.DiskUsage
	now         func() time.Time
}

func newTestEnvWith(t *testing.T, o testOpts) *testEnv {
	t.Helper()
	op := oidctest.New(t, oidctest.Options{ClientID: "dropr", ClientSecret: "dev-secret", Now: o.now})
	srv := httptest.NewUnstartedServer(nil)
	t.Cleanup(srv.Close)
	// Dev mode allows http:// only for localhost, so the origin uses "localhost";
	// the client dials the listener directly.
	addr := srv.Listener.Addr().String()
	_, port, _ := net.SplitHostPort(addr)
	origin := "http://localhost:" + port

	dir := t.TempDir()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg, err := config.Parse([]byte(`
mode = "dev"
tls = "proxy"
public_url = "` + origin + `"
data_dir = "` + dir + `"
refresh_key_file = "` + write("refresh", key) + `"
login_label = "Sign in with Test"
` + o.extraConfig + `
[oidc]
issuer = "` + op.Issuer + `"
client_id = "dropr"
client_auth = "client_secret"
client_secret_file = "` + write("secret", []byte("dev-secret\n")) + `"
required_role = "Dropr.User"
scopes = ["openid", "profile"]
`))
	if err != nil {
		t.Fatal(err)
	}
	op.AllowRedirect(cfg.OIDC.RedirectURL)
	s, err := New(t.Context(), Deps{Config: cfg, Store: storetest.New(t), Logger: slog.New(slog.DiscardHandler),
		DiskUsage: o.diskUsage, Now: o.now})
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = s.Handler()
	srv.Start()
	jar, _ := cookiejar.New(nil)
	return &testEnv{t: t, op: op, srv: srv, origin: origin, s: s, client: &http.Client{Jar: jar, Timeout: 30 * time.Second, Transport: dialTo(addr)}}
}

func (e *testEnv) do(method, path string, hdr map[string]string) (*http.Response, string) {
	e.t.Helper()
	req, _ := http.NewRequestWithContext(e.t.Context(), method, e.origin+path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestAnonymousPagesAndHeaders(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	resp, body := e.do(http.MethodGet, "/", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Sign in with Test") || !strings.Contains(body, `href="/auth/login"`) {
		t.Fatalf("home: %d %s", resp.StatusCode, body)
	}
	opOrigin := strings.TrimSuffix(e.op.Issuer, "/")
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' "+opOrigin) {
		t.Errorf("CSP form-action lacks issuer origin: %s", csp)
	}
	for _, h := range []string{"Strict-Transport-Security", "Permissions-Policy", "Cross-Origin-Opener-Policy", "X-Content-Type-Options"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Error("pages must be no-store")
	}

	css := regexp.MustCompile(`href="(/assets/app\.[0-9a-f]+\.css)"`).FindStringSubmatch(body)
	if css == nil {
		t.Fatal("no stylesheet link")
	}
	resp, _ = e.do(http.MethodGet, css[1], nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/css; charset=utf-8" ||
		!strings.Contains(resp.Header.Get("Cache-Control"), "immutable") {
		t.Errorf("asset: %d %v", resp.StatusCode, resp.Header)
	}

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/nope"}, {http.MethodGet, "/assets/missing.js"},
		{http.MethodPost, "/login"}, {http.MethodDelete, "/"}, {http.MethodGet, "/login/extra"},
	} {
		resp, body := e.do(c.method, c.path, map[string]string{"Sec-Fetch-Site": "same-origin"})
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "Page not found") {
			t.Errorf("%s %s: %d", c.method, c.path, resp.StatusCode)
		}
	}
	resp, body = e.do(http.MethodGet, "/healthz", nil)
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(body) != "ok" {
		t.Errorf("healthz: %d %q", resp.StatusCode, body)
	}
}

func TestCSRFBlocksCrossSitePosts(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	for _, hdr := range []map[string]string{
		nil,
		{"Sec-Fetch-Site": "cross-site"},
		{"Origin": "https://evil.example"},
	} {
		resp, body := e.do(http.MethodPost, "/auth/logout", hdr)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "Request blocked") {
			t.Errorf("%v: %d", hdr, resp.StatusCode)
		}
	}
}

func TestLoginDashboardLogout(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	resp, body := e.do(http.MethodGet, "/auth/login", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `http-equiv="refresh" content="0;url=/"`) {
		t.Fatalf("callback landing: %d %s", resp.StatusCode, body)
	}
	// The first sign-in lands on the dashboard: there is no setup step.
	resp, body = e.do(http.MethodGet, "/", nil)
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/" || !strings.Contains(body, `data-page="dashboard"`) ||
		!strings.Contains(body, `Received files (<span id="inbox-count">0</span>)`) || !strings.Contains(body, "Alice Example") {
		t.Fatalf("dashboard: %s %s", resp.Request.URL, body)
	}
	// The browser scopes its request link keys by the account ID.
	if users, err := e.s.store.ListUsers(t.Context()); err != nil || len(users) != 1 ||
		!strings.Contains(body, `data-owner-id="`+users[0].ID+`"`) {
		t.Errorf("dashboard lacks the owner ID: %v", err)
	}
	resp, _ = e.do(http.MethodGet, "/login", nil)
	if resp.Request.URL.Path != "/" {
		t.Error("/login does not redirect signed-in users")
	}
	if resp, _ := e.do(http.MethodGet, "/setup", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("/setup: %d", resp.StatusCode)
	}

	e.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, _ = e.do(http.MethodPost, "/auth/logout", map[string]string{"Origin": e.origin})
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), e.op.Issuer+"/logout?") {
		t.Fatalf("logout: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("post_logout_redirect_uri") != e.origin+"/login" {
		t.Error(loc)
	}
	_, body = e.do(http.MethodGet, "/", nil)
	if !strings.Contains(body, "Sign in with Test") {
		t.Fatal("still signed in after logout")
	}
}

func TestForbiddenWithoutRole(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	e.op.Set(func(k *oidctest.Knobs) { k.Claims = map[string]any{"name": "Mallory"} })
	resp, body := e.do(http.MethodGet, "/auth/login", nil)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "have access") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

func TestAuthRateLimit(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	e.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	limited := false
	for range 15 {
		resp, _ := e.do(http.MethodGet, "/auth/login", nil)
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("auth endpoints not rate limited")
	}
}

func TestTLSConfig(t *testing.T) {
	t.Parallel()
	c := TLSConfig(nil)
	if c.MinVersion != tls.VersionTLS12 {
		t.Error("min version")
	}
	for _, id := range c.CipherSuites {
		name := tls.CipherSuiteName(id)
		if !strings.Contains(name, "GCM") && !strings.Contains(name, "CHACHA20") || !strings.Contains(name, "ECDHE") {
			t.Errorf("non-AEAD or non-PFS suite %s", name)
		}
	}
	if c.CurvePreferences != nil {
		t.Error("curve preferences must stay at Go defaults (X25519MLKEM768)")
	}
}

func TestRedirectHandler(t *testing.T) {
	t.Parallel()
	h := RedirectHandler("https://drop.example.com")
	for in, want := range map[string]string{
		"/":          "https://drop.example.com/",
		"/s/abc?x=1": "https://drop.example.com/s/abc?x=1",
	} {
		r := httptest.NewRequest(http.MethodGet, in, nil)
		r.Host = "evil.example"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != want {
			t.Errorf("%s -> %d %s", in, w.Code, w.Header().Get("Location"))
		}
	}
}

func TestListenUnix(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	sock := filepath.Join(dir, "d.sock")
	ln, err := listen(t.Context(), "unix:"+sock)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(sock)
	if fi.Mode().Perm() != 0o660 {
		t.Errorf("socket mode %v", fi.Mode().Perm())
	}
	_ = ln.Close()
	plain := filepath.Join(dir, "file")
	_ = os.WriteFile(plain, nil, 0o600)
	if _, err := listen(t.Context(), "unix:"+plain); err == nil {
		t.Error("replaced a regular file")
	}
}

// dialTo returns a transport that connects requests for localhost:port to
// the listener at addr (127.0.0.1:port) and everything else normally.
func dialTo(addr string) *http.Transport {
	_, port, _ := net.SplitHostPort(addr)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, target string) (net.Conn, error) {
		if target == "localhost:"+port {
			target = addr
		}
		var d net.Dialer
		return d.DialContext(ctx, network, target)
	}
	return tr
}

// API surfaces answer every error as {"error","message"} JSON; pages keep
// their HTML error pages.
func TestAPIErrorsAreJSON(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	type errBody struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	check := func(name string, resp *http.Response, body []byte, status int, code string) {
		t.Helper()
		var eb errBody
		if resp.StatusCode != status || resp.Header.Get("Content-Type") != "application/json" ||
			json.Unmarshal(body, &eb) != nil || eb.Error != code || eb.Message == "" {
			t.Errorf("%s: %d %q %s", name, resp.StatusCode, resp.Header.Get("Content-Type"), body)
		}
	}
	// Unknown routes and methods.
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/nope"}, {http.MethodGet, "/upload/x/part/1"}, {http.MethodPost, "/dl/x"},
		{http.MethodPatch, "/api/shares"},
	} {
		resp, body := e.api(c.method, c.path, nil, nil)
		check(c.method+" "+c.path, resp, body, http.StatusNotFound, "not_found")
	}
	// Cross-site writes.
	resp, body := e.api(http.MethodPost, "/api/shares", map[string]any{}, map[string]string{"Sec-Fetch-Site": "cross-site"})
	check("csrf", resp, body, http.StatusForbidden, "csrf")
	resp, body = e.api(http.MethodPut, "/upload/x/part/0", []byte("x"), map[string]string{"Sec-Fetch-Site": "", "Origin": "https://evil.example"})
	check("csrf upload", resp, body, http.StatusForbidden, "csrf")
	// Declared body over the route limit (16 KiB for JSON APIs).
	resp, body = e.api(http.MethodPost, "/api/requests", bytes.Repeat([]byte("x"), 32<<10), nil)
	check("body limit", resp, body, http.StatusRequestEntityTooLarge, "too_large")
	// Pages keep HTML.
	resp, page := e.do(http.MethodGet, "/nope", nil)
	if resp.StatusCode != http.StatusNotFound || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") || !strings.Contains(page, "Page not found") {
		t.Errorf("page 404: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
}

func TestPublicRateLimitIsJSONWithRetryAfter(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	var resp *http.Response
	var body []byte
	for range 200 {
		resp, body = e.api(http.MethodPost, "/api/s/AAAAAAAAAAAAAAAAAAAAAA/download", nil, nil)
		if resp.StatusCode == http.StatusTooManyRequests {
			break
		}
	}
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" ||
		resp.Header.Get("Content-Type") != "application/json" || !strings.Contains(string(body), `"error":"rate_limited"`) {
		t.Fatalf("%d %v %s", resp.StatusCode, resp.Header, body)
	}
}
