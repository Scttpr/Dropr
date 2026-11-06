package web

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/scttpr/dropr/internal/store"
)

func newRenderer(t *testing.T) *Renderer {
	t.Helper()
	a, err := LoadAssets(StaticFS())
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRenderer(a, "Sign in with Test", nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var inline = regexp.MustCompile(`(?i)<script(?:\s[^>]*)?>[^<]+</script>|<style|<[^>]+\sstyle=|<[^>]+\son[a-z]+=|javascript:|<img`)

func TestPagesHaveNoInlineCode(t *testing.T) {
	t.Parallel()
	r := newRenderer(t)
	u := &store.User{DisplayName: `<script>alert(1)</script>`}
	for _, page := range pageNames {
		for _, user := range []*store.User{nil, u} {
			w := httptest.NewRecorder()
			r.Render(w, httptest.NewRequest(http.MethodGet, "/", nil), http.StatusOK, page,
				PageData{Title: "T", Message: `<img src=x onerror=alert(1)>`, User: user})
			body := w.Body.String()
			if w.Code != http.StatusOK {
				t.Fatalf("%s: %d %s", page, w.Code, body)
			}
			if inline.MatchString(body) {
				t.Errorf("%s contains inline script/style or unescaped input:\n%s", page, inline.FindString(body))
			}
			if !strings.Contains(body, `href="/assets/app.`) || !strings.Contains(body, `integrity="sha384-`) {
				t.Errorf("%s lacks fingerprinted stylesheet", page)
			}
			if w.Header().Get("Content-Type") != "text/html; charset=utf-8" || w.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("%s headers: %v", page, w.Header())
			}
		}
	}
}

func TestLandingRefreshesToRoot(t *testing.T) {
	t.Parallel()
	r := newRenderer(t)
	w := httptest.NewRecorder()
	r.CallbackLanding(w, httptest.NewRequest(http.MethodGet, "/auth/callback", nil))
	if !strings.Contains(w.Body.String(), `<meta http-equiv="refresh" content="0;url=/">`) {
		t.Fatal(w.Body.String())
	}
	w = httptest.NewRecorder()
	r.Render(w, httptest.NewRequest(http.MethodGet, "/login", nil), http.StatusOK, PageLogin, PageData{})
	if !strings.Contains(w.Body.String(), "Sign in with Test") || strings.Contains(w.Body.String(), "http-equiv") {
		t.Fatal("login page wrong")
	}
}

func TestAssetsManifestAndHandlers(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"app.css":                  {Data: []byte("body{}")},
		"dashboard-ABC123.js":      {Data: []byte("console.log(1)")},
		"sw-XYZ.js":                {Data: []byte("self.addEventListener('fetch',()=>{})")},
		"manifest.json":            {Data: []byte(`{"dashboard.js":"dashboard-ABC123.js","sw.js":"sw-XYZ.js"}`)},
		"chunks/shared-QQQ.js":     {Data: []byte("export{}")},
		"chunks/shared-QQQ.js.map": {Data: []byte("{}")},
	}
	a, err := LoadAssets(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := a.URL("dashboard.js"); u != "/assets/dashboard-ABC123.js" {
		t.Errorf("manifest mapping: %s", u)
	}
	u, _ := a.URL("app.css")
	if !regexp.MustCompile(`^/assets/app\.[0-9a-f]{10}\.css$`).MatchString(u) {
		t.Errorf("fingerprint: %s", u)
	}
	if _, err := a.URL("missing.js"); err == nil {
		t.Error("unknown asset resolved")
	}

	notFound := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	mux := http.NewServeMux()
	mux.Handle("GET /assets/{path...}", a.Handler(notFound))
	mux.Handle("GET /sw.js", a.ServiceWorkerHandler(notFound))

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/assets/dashboard-ABC123.js", nil))
	if w.Code != 200 || w.Header().Get("Content-Type") != "text/javascript; charset=utf-8" ||
		w.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Errorf("asset: %d %v", w.Code, w.Header())
	}
	etag := w.Header().Get("ETag")
	r := httptest.NewRequest(http.MethodGet, "/assets/dashboard-ABC123.js", nil)
	r.Header.Set("If-None-Match", etag)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusNotModified {
		t.Errorf("conditional: %d", w.Code)
	}
	for _, p := range []string{"/assets/app.css", "/assets/manifest.json", "/assets/../web.go", "/assets/nope.js"} {
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code == http.StatusOK {
			t.Errorf("%s served", p)
		}
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sw.js", nil))
	if w.Code != 200 || w.Header().Get("Service-Worker-Allowed") != "/_dl/" || !strings.Contains(w.Body.String(), "fetch") {
		t.Errorf("sw: %d %v", w.Code, w.Header())
	}
	if len(a.Hashes()) != 5 {
		t.Errorf("hashes: %v", a.Hashes())
	}
}

func TestAssetsBadManifest(t *testing.T) {
	t.Parallel()
	for name, m := range map[string]string{
		"not json":     `[`,
		"missing file": `{"a.js":"a-1.js"}`,
		"traversal":    `{"a.js":"../a.js"}`,
	} {
		if _, err := LoadAssets(fstest.MapFS{"manifest.json": {Data: []byte(m)}}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// No manifest at all is fine.
	if _, err := LoadAssets(fstest.MapFS{"x.css": {Data: []byte("x")}}); err != nil {
		t.Error(err)
	}
	if StaticFS() == nil {
		t.Error("no static fs")
	}
}

func TestContentTypeNeverHTML(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"a.html", "a.htm", "a.xhtml", "a"} {
		if ct := contentType(p); strings.Contains(ct, "html") {
			t.Errorf("%s -> %s", p, ct)
		}
	}
}
