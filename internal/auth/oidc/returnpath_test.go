package oidc_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/scttpr/dropr/internal/auth/oidc"
)

func TestReturnPath(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"":                      "/",
		"/":                     "/",
		"/inbox":                "/inbox",
		"/links":                "/links",
		"/inbox?x=1":            "/",
		"/inbox#x":              "/",
		"/inbox/":               "/",
		"/INBOX":                "/",
		"//evil.example":        "/",
		"///evil.example":       "/",
		"https://evil.example/": "/",
		"/\\evil.example":       "/",
		"\\evil":                "/",
		"/auth/login":           "/",
		"/auth/logout":          "/",
		"/s/abc":                "/",
		"%2Finbox":              "/",
		"%2F%2Fevil.example":    "/",
		"/%2F/evil.example":     "/",
		"/inbox%00":             "/",
		"javascript:alert(1)":   "/",
		"/login":                "/",
		"/./inbox":              "/",
		"/links/../auth/logout": "/",
	} {
		if got := oidc.ReturnPath(in); got != want {
			t.Errorf("ReturnPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzReturnPath(f *testing.F) {
	for _, s := range []string{"", "/", "/inbox", "/links", "//evil", "/inbox?x", "https://a/"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		switch got := oidc.ReturnPath(s); got {
		case "/", "/inbox", "/links":
			if got != s && got != "/" {
				t.Fatalf("ReturnPath(%q) = %q", s, got)
			}
		default:
			t.Fatalf("ReturnPath(%q) = %q, outside the closed list", s, got)
		}
	})
}

// The next parameter of /auth/login survives the provider round trip in
// the sealed state cookie and selects the landing page's target; anything
// outside the closed list lands on "/".
func TestLoginReturnsToNext(t *testing.T) {
	t.Parallel()
	for next, want := range map[string]string{
		"":               "/",
		"/inbox":         "/inbox",
		"/links":         "/links",
		"//evil.example": "/",
		"/inbox?x=1":     "/",
	} {
		t.Run(next, func(t *testing.T) {
			t.Parallel()
			h := mustHarness(t, setup{})
			code, body := h.get("/auth/login?next=" + url.QueryEscape(next))
			if code != http.StatusOK || body != "landing" {
				t.Fatalf("login: %d %q", code, body)
			}
			h.pages.mu.Lock()
			got := h.pages.next
			h.pages.mu.Unlock()
			if got != want {
				t.Fatalf("landing next = %q, want %q", got, want)
			}
		})
	}
}
