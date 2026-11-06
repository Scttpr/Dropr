package server

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/scttpr/dropr/internal/httpx"
)

// Every response type, through the full router, carries the exact security
// header set and the cache policy of its kind (ARCHITECTURE.md §3/§5,
// PAGES.md §9-10).
func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	t.Parallel()
	clk := newClock()
	e := newTestEnvWith(t, testOpts{now: clk.Now})
	e.newOwner()
	expired := e.createShare(e.client, smallSize, map[string]any{"expires_in": "1h"})
	e.uploadAll(expired, randBytes(int(smallSize)))
	clk.Advance(time.Hour + time.Second)
	o := e.newOwner() // the first session idled out
	live := e.createShare(e.client, smallSize, nil)
	e.uploadAll(live, randBytes(int(smallSize)))
	reqID := o.createRequest(map[string]any{"max_files": 1, "max_bytes": smallSize})
	anon := &http.Client{Transport: e.client.Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	iss, _ := url.Parse(e.op.Issuer)
	common := map[string]string{
		"Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
			"worker-src 'self'; manifest-src 'self'; form-action 'self' " + iss.Scheme + "://" + iss.Host + "; " +
			"frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types dropr-sw",
		"Strict-Transport-Security":    "max-age=63072000; includeSubDomains; preload",
		"Referrer-Policy":              "no-referrer",
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Permissions-Policy":           httpx.PermissionsPolicy,
	}
	check := func(label string, resp *http.Response, status int, kind string) {
		t.Helper()
		if resp.StatusCode != status {
			t.Errorf("%s: status %d, want %d", label, resp.StatusCode, status)
		}
		h := resp.Header
		for k, v := range common {
			if got := h.Get(k); got != v {
				t.Errorf("%s: %s = %q, want %q", label, k, got, v)
			}
		}
		for _, k := range []string{"X-Powered-By", "Server", "Access-Control-Allow-Origin", "ETag", "Last-Modified"} {
			allowed := kind == "asset" && (k == "ETag" || k == "Last-Modified")
			if v := h.Get(k); v != "" && !allowed {
				t.Errorf("%s: unexpected %s: %q", label, k, v)
			}
		}
		cc := h.Get("Cache-Control")
		switch kind {
		case "asset":
			if !strings.Contains(cc, "immutable") || !regexp.MustCompile(`max-age=\d{7,}`).MatchString(cc) {
				t.Errorf("%s: Cache-Control = %q", label, cc)
			}
		default:
			if cc != "no-store" {
				t.Errorf("%s: Cache-Control = %q", label, cc)
			}
		}
		ct := h.Get("Content-Type")
		switch {
		case kind == "page" && ct != "text/html; charset=utf-8":
			t.Errorf("%s: Content-Type = %q", label, ct)
		case kind == "api" && !strings.HasPrefix(ct, "application/json"):
			t.Errorf("%s: Content-Type = %q", label, ct)
		}
	}

	_, home := e.do(http.MethodGet, "/", nil)
	css := regexp.MustCompile(`href="(/assets/[^"]+\.css)"`).FindStringSubmatch(home)
	icon := regexp.MustCompile(`href="(/assets/[^"]+\.svg)"`).FindStringSubmatch(home)
	if css == nil || icon == nil {
		t.Fatal("no stylesheet or icon link on the dashboard")
	}

	get := func(c *http.Client, path string) *http.Response {
		resp, _ := e.apiWith(c, http.MethodGet, path, nil, map[string]string{"Sec-Fetch-Site": ""})
		return resp
	}
	post := func(path string, body any, hdr map[string]string) *http.Response {
		resp, _ := e.apiWith(anon, http.MethodPost, path, body, hdr)
		return resp
	}
	cases := []struct {
		label  string
		resp   *http.Response
		status int
		kind   string
	}{
		{"login page", get(anon, "/"), 200, "page"},
		{"/login", get(anon, "/login"), 200, "page"},
		{"share page", get(anon, "/s/"+live.ShareID), 200, "page"},
		{"request page", get(anon, "/r/"+reqID), 200, "page"},
		{"dead link 404", get(anon, "/s/AAAAAAAAAAAAAAAAAAAAAA"), 404, "page"},
		{"dead link 410", get(anon, "/s/"+expired.ShareID), 410, "page"},
		{"malformed link id", get(anon, "/r/not-an-id"), 404, "page"},
		{"404 page", get(anon, "/no/such/page"), 404, "page"},
		{"/_dl fallback", get(anon, "/_dl/AAAAAAAAAAAAAAAAAAAAAA"), 404, "page"},
		{"owner page redirect", get(anon, "/inbox"), 303, "other"},
		{"dashboard (signed in)", get(e.client, "/"), 200, "page"},
		{"links (signed in)", get(e.client, "/links"), 200, "page"},
		{"API 401", get(anon, "/api/shares"), 401, "api"},
		{"API 200 (signed in)", get(e.client, "/api/shares"), 200, "api"},
		{"API 404", post("/api/s/AAAAAAAAAAAAAAAAAAAAAA/download", map[string]any{}, nil), 404, "api"},
		{"API 410", post("/api/s/"+expired.ShareID+"/download", map[string]any{}, nil), 410, "api"},
		{"API 400", post("/api/s/"+live.ShareID+"/download", map[string]any{"nope": 1}, nil), 400, "api"},
		{"API 413", post("/api/r/"+reqID+"/files", map[string]any{"meta": strings.Repeat("A", 40_000)}, nil), 413, "api"},
		{"CSRF 403", post("/api/shares", map[string]any{}, map[string]string{"Sec-Fetch-Site": "cross-site"}), 403, "api"},
		{"upload 401", get(anon, "/upload/AAAAAAAAAAAAAAAAAAAAAA"), 401, "api"},
		{"download bad token", get(anon, "/dl/"+strings.Repeat("A", 43)), 404, "other"},
		{"stylesheet", get(anon, css[1]), 200, "asset"},
		{"icon", get(anon, icon[1]), 200, "asset"},
		{"unknown asset", get(anon, "/assets/nope-12345678.js"), 404, "page"},
		{"healthz", get(anon, "/healthz"), 200, "other"},
		{"auth login redirect", get(anon, "/auth/login"), 302, "other"},
	}
	for _, c := range cases {
		check(c.label, c.resp, c.status, c.kind)
	}
	put, _ := e.apiWith(anon, http.MethodPut, "/login", nil, nil)
	check("unlisted method (404 by contract)", put, 404, "page")

	// A real download: an attachment, ranges, no validators.
	_, b := e.apiWith(anon, http.MethodPost, "/api/s/"+live.ShareID+"/download", map[string]any{}, nil)
	var g struct{ Token string }
	mustJSON(t, b, &g)
	for _, c := range []struct {
		rng    string
		status int
	}{{"", 200}, {"bytes=0-9", 206}, {"bytes=0-1,4-5", 416}} {
		var hdr map[string]string
		if c.rng != "" {
			hdr = map[string]string{"Range": c.rng}
		}
		resp, _ := e.download(anon, g.Token, hdr)
		check("dl "+c.rng, resp, c.status, "other")
		if c.status != 416 {
			for k, v := range map[string]string{"Content-Type": "application/octet-stream",
				"Content-Disposition": `attachment; filename="dropr-download.bin"`, "Accept-Ranges": "bytes"} {
				if resp.Header.Get(k) != v {
					t.Errorf("dl %s: %s = %q", c.rng, k, resp.Header.Get(k))
				}
			}
		}
	}

	// The per-IP rate limit answers 429 with the same headers.
	var limited *http.Response
	for range 200 {
		if resp := get(anon, "/s/AAAAAAAAAAAAAAAAAAAAAA"); resp.StatusCode == http.StatusTooManyRequests {
			limited = resp
			break
		}
	}
	if limited == nil {
		t.Fatal("link pages not rate limited")
	}
	check("429", limited, 429, "other")
	if limited.Header.Get("Retry-After") == "" {
		t.Error("429 without Retry-After")
	}
}
