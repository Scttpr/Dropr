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
