package server

import (
	"net/http"
	"strings"
	"testing"
)

// noRedirects makes the env's client stop at the first redirect.
func (e *testEnv) noRedirects() {
	e.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
}

func wantRedirect(t *testing.T, what string, resp *http.Response, loc string) {
	t.Helper()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != loc {
		t.Fatalf("%s: %d %q, want 303 %q", what, resp.StatusCode, resp.Header.Get("Location"), loc)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("%s: redirect is cacheable", what)
	}
}

// An owner page reached without a session returns to itself after sign-in.
func TestOwnerPageReturnsAfterSignIn(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	e.noRedirects()
	for _, p := range []string{"/inbox", "/links"} {
		resp, _ := e.do(http.MethodGet, p, nil)
		wantRedirect(t, p, resp, "/login?next=%2F"+p[1:])
	}
	resp, body := e.do(http.MethodGet, "/login?next=%2Finbox", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `href="/auth/login?next=%2finbox"`) {
		t.Fatalf("login page: %d %s", resp.StatusCode, body)
	}
	// Outside the closed list, the button carries no next.
	for _, next := range []string{"%2F%2Fevil.example", "https%3A%2F%2Fevil.example%2F", "%2Fauth%2Flogout"} {
		_, body := e.do(http.MethodGet, "/login?next="+next, nil)
		if !strings.Contains(body, `href="/auth/login"`) || strings.Contains(body, "/auth/login?") {
			t.Errorf("next=%s: %s", next, body)
		}
	}

	e.client.CheckRedirect = nil
	resp, body = e.do(http.MethodGet, "/auth/login?next=%2Finbox", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `http-equiv="refresh" content="0;url=/inbox"`) {
		t.Fatalf("callback landing: %d %s", resp.StatusCode, body)
	}
	// Signed in, /login sends the user on to next.
	e.noRedirects()
	resp, _ = e.do(http.MethodGet, "/login?next=%2Flinks", nil)
	wantRedirect(t, "signed-in /login", resp, "/links")
	resp, _ = e.do(http.MethodGet, "/login?next=%2F%2Fevil.example", nil)
	wantRedirect(t, "signed-in /login, foreign next", resp, "/")
}

// With auto_login, owner pages go straight to the identity provider, but
// /login (where logout lands) and the link pages never do.
func TestAutoLogin(t *testing.T) {
	t.Parallel()
	e := newTestEnvWith(t, testOpts{extraConfig: "auto_login = true"})
	e.noRedirects()
	for p, loc := range map[string]string{
		"/":      "/auth/login",
		"/inbox": "/auth/login?next=%2Finbox",
		"/links": "/auth/login?next=%2Flinks",
	} {
		resp, _ := e.do(http.MethodGet, p, nil)
		wantRedirect(t, p, resp, loc)
	}
	resp, body := e.do(http.MethodGet, "/login", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `href="/auth/login"`) {
		t.Fatalf("/login: %d %s", resp.StatusCode, body)
	}
	for _, p := range []string{"/s/AAAAAAAAAAAAAAAAAAAAAA", "/r/AAAAAAAAAAAAAAAAAAAAAA"} {
		if resp, _ := e.do(http.MethodGet, p, nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}
	if resp, _ := e.do(http.MethodGet, "/healthz", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz: %d", resp.StatusCode)
	}

	// Following the redirects from an owner page ends on that page.
	e.client.CheckRedirect = nil
	resp, body = e.do(http.MethodGet, "/inbox", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `http-equiv="refresh" content="0;url=/inbox"`) {
		t.Fatalf("auto sign-in: %d %s", resp.StatusCode, body)
	}
	resp, body = e.do(http.MethodGet, "/inbox", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `data-page="inbox"`) {
		t.Fatalf("inbox after sign-in: %d %s", resp.StatusCode, body)
	}
}

// limits.auth_rate_per_minute and limits.auth_burst set the sign-in limit.
func TestAuthRateLimitConfigurable(t *testing.T) {
	t.Parallel()
	count := func(extra string) int {
		e := newTestEnvWith(t, testOpts{extraConfig: extra})
		e.noRedirects()
		for i := range 40 {
			if resp, _ := e.do(http.MethodGet, "/auth/login", nil); resp.StatusCode == http.StatusTooManyRequests {
				if resp.Header.Get("Retry-After") == "" {
					t.Error("429 without Retry-After")
				}
				return i
			}
		}
		return -1
	}
	if n := count("[limits]\nauth_rate_per_minute = 1\nauth_burst = 2"); n != 2 {
		t.Errorf("burst 2: limited after %d requests", n)
	}
	if n := count("[limits]\nauth_rate_per_minute = 1\nauth_burst = 30"); n != 30 {
		t.Errorf("burst 30: limited after %d requests", n)
	}
}
