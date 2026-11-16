package server

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/scttpr/dropr/internal/httpx"
)

// A configured brand reaches every page; its SVG logo is served with the
// sandbox CSP, while pages keep theirs.
func TestBrandingEndToEnd(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	logo := filepath.Join(dir, "logo.svg")
	if err := os.WriteFile(logo, []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"/>`), 0o644); err != nil {
		t.Fatal(err)
	}
	e := newTestEnvWith(t, testOpts{extraConfig: "[branding]\nname = \"Drop and Care\"\nlogo_file = \"" + logo + "\""})
	resp, body := e.do(http.MethodGet, "/", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "<title>Sign in · Drop and Care</title>") ||
		!strings.Contains(body, "Powered by") {
		t.Fatalf("login page: %d %s", resp.StatusCode, body)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); csp != httpx.CSP(e.s.oidc.FormActionOrigins()) {
		t.Errorf("page CSP changed: %s", csp)
	}
	m := regexp.MustCompile(`<img class="brand-logo brand-logo-light" src="(/assets/brand/logo-[0-9a-f]{8}\.svg)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no logo in %s", body)
	}
	for _, p := range []string{m[1], faviconURL(t, body)} {
		resp, _ = e.do(http.MethodGet, p, nil)
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "image/svg+xml" ||
			resp.Header.Get("Content-Security-Policy") != "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox" ||
			resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: %d %v", p, resp.StatusCode, resp.Header)
		}
	}
	// A share page (anonymous recipients) carries the brand too.
	if _, body := e.do(http.MethodGet, "/s/AAAAAAAAAAAAAAAAAAAAAA", nil); !strings.Contains(body, "Drop and Care") {
		t.Error("dead-link page lacks the brand")
	}
}

func faviconURL(t *testing.T, body string) string {
	t.Helper()
	m := regexp.MustCompile(`<link rel="icon" href="([^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no favicon link")
	}
	return m[1]
}
