package httpx

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestSecurityHeaders(t *testing.T) {
	t.Parallel()
	h := SecurityHeaders(HeaderOptions{FormActionOrigins: []string{"https://login.microsoftonline.com", "evil; script-src *"}})(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	want := "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
		"worker-src 'self'; manifest-src 'self'; form-action 'self' https://login.microsoftonline.com; " +
		"frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types dropr-sw"
	if got := w.Header().Get("Content-Security-Policy"); got != want {
		t.Errorf("CSP:\n got %s\nwant %s", got, want)
	}
	for k, v := range map[string]string{
		"Strict-Transport-Security":    "max-age=63072000; includeSubDomains; preload",
		"Referrer-Policy":              "no-referrer",
		"X-Content-Type-Options":       "nosniff",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cache-Control":                "no-store",
		"X-Frame-Options":              "DENY",
	} {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	pp := w.Header().Get("Permissions-Policy")
	for _, s := range []string{"camera=()", "microphone=()", "geolocation=()", "publickey-credentials-get=()", "publickey-credentials-create=()", "clipboard-write=(self)"} {
		if !strings.Contains(pp, s) {
			t.Errorf("Permissions-Policy lacks %s", s)
		}
	}
}

func TestCSRF(t *testing.T) {
	t.Parallel()
	const origin = "https://drop.example.com"
	cases := []struct {
		method string
		hdr    map[string][]string
		ok     bool
	}{
		{http.MethodGet, nil, true},
		{http.MethodHead, map[string][]string{"Sec-Fetch-Site": {"cross-site"}}, true},
		{http.MethodPost, nil, false},
		{http.MethodPost, map[string][]string{"Sec-Fetch-Site": {"same-origin"}}, true},
		{http.MethodPost, map[string][]string{"Sec-Fetch-Site": {"none"}}, true},
		{http.MethodPost, map[string][]string{"Sec-Fetch-Site": {"same-site"}}, false},
		{http.MethodPost, map[string][]string{"Sec-Fetch-Site": {"cross-site"}, "Origin": {origin}}, false},
		{http.MethodPost, map[string][]string{"Sec-Fetch-Site": {"same-origin", "cross-site"}}, false},
		{http.MethodPost, map[string][]string{"Origin": {origin}}, true},
		{http.MethodPost, map[string][]string{"Origin": {"https://drop.example.com.evil.com"}}, false},
		{http.MethodPost, map[string][]string{"Origin": {"null"}}, false},
		{http.MethodPost, map[string][]string{"Origin": {origin + "/"}}, false},
		{http.MethodDelete, map[string][]string{"Origin": {"http://drop.example.com"}}, false},
		{http.MethodPut, map[string][]string{"Sec-Fetch-Site": {"same-origin"}}, true},
		{"PROPFIND", nil, false},
	}
	h := CSRF(origin, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for i, c := range cases {
		r := httptest.NewRequest(c.method, "/", nil)
		for k, vs := range c.hdr {
			for _, v := range vs {
				r.Header.Add(k, v)
			}
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if got := w.Code == http.StatusNoContent; got != c.ok {
			t.Errorf("case %d (%s %v): allowed=%v want %v", i, c.method, c.hdr, got, c.ok)
		}
	}
}

func TestIPResolver(t *testing.T) {
	t.Parallel()
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("::1/128")}
	res := IPResolver{Trusted: trusted, TrustUnixPeer: true}
	cases := []struct {
		remote string
		xff    []string
		want   string
	}{
		{"203.0.113.9:1234", nil, "203.0.113.9"},
		{"203.0.113.9:1234", []string{"1.2.3.4"}, "203.0.113.9"}, // untrusted peer: XFF ignored
		{"10.0.0.2:80", []string{"1.2.3.4"}, "1.2.3.4"},
		{"10.0.0.2:80", []string{"6.6.6.6, 1.2.3.4"}, "1.2.3.4"},             // spoofed left entry ignored
		{"10.0.0.2:80", []string{"6.6.6.6", "1.2.3.4, 10.0.0.3"}, "1.2.3.4"}, // multiple headers, proxy chain
		{"10.0.0.2:80", []string{"10.0.0.9, 10.0.0.3"}, "10.0.0.9"},          // all trusted: leftmost
		{"10.0.0.2:80", []string{"1.2.3.4, garbage"}, "10.0.0.2"},            // malformed stops the walk
		{"10.0.0.2:80", nil, "10.0.0.2"},
		{"[::1]:80", []string{"2001:db8::1"}, "2001:db8::1"},
		{"[::ffff:10.0.0.2]:80", []string{"::ffff:1.2.3.4"}, "1.2.3.4"}, // v4-mapped normalized
		{"@", []string{"1.2.3.4"}, "1.2.3.4"},                           // unix socket peer
		{"", nil, "invalid IP"},
		{"10.0.0.2:80", []string{"fe80::1%eth0"}, "fe80::1"},
	}
	for i, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = c.remote
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := res.Resolve(r).String(); got != c.want {
			t.Errorf("case %d: got %s want %s", i, got, c.want)
		}
	}
	// Without trusted proxies (ACME mode) XFF is always ignored.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.2:80"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := (IPResolver{}).Resolve(r).String(); got != "10.0.0.2" {
		t.Errorf("acme mode trusted XFF: %s", got)
	}
}

func TestRateLimiter(t *testing.T) {
	t.Parallel()
	hasher := NewIPHasher(bytes.Repeat([]byte{3}, 32))
	rl := NewRateLimiter(hasher, 60, 3, 100)
	now := time.Unix(1000, 0)
	rl.now = func() time.Time { return now }
	a := netip.MustParseAddr("198.51.100.7")
	for i := range 3 {
		if ok, _ := rl.Allow(a); !ok {
			t.Fatalf("request %d denied within burst", i)
		}
	}
	ok, wait := rl.Allow(a)
	if ok || wait <= 0 {
		t.Fatal("burst exceeded but allowed")
	}
	if ok, _ := rl.Allow(netip.MustParseAddr("198.51.100.8")); !ok {
		t.Fatal("other client limited")
	}
	now = now.Add(time.Second)
	if ok, _ := rl.Allow(a); !ok {
		t.Fatal("token not refilled")
	}
	// IPv6 clients share a bucket per /64.
	rl6 := NewRateLimiter(hasher, 60, 1, 100)
	rl6.now = rl.now
	rl6.Allow(netip.MustParseAddr("2001:db8:1:2::1"))
	if ok, _ := rl6.Allow(netip.MustParseAddr("2001:db8:1:2:ffff::9")); ok {
		t.Error("same /64 not shared")
	}
	if ok, _ := rl6.Allow(netip.MustParseAddr("2001:db8:1:3::1")); !ok {
		t.Error("different /64 shared")
	}
}

func TestRateLimiterBounded(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(NewIPHasher(make([]byte, 32)), 60, 1, 50)
	for i := range 1000 {
		rl.Allow(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}))
	}
	if n := rl.Len(); n > 50 {
		t.Fatalf("map grew to %d", n)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	t.Parallel()
	rl := NewRateLimiter(NewIPHasher(make([]byte, 32)), 1, 1, 10)
	h := RealIP(IPResolver{}, nil)(rl.Limit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {})))
	do := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "192.0.2.1:5"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if do().Code != http.StatusOK {
		t.Fatal("first request limited")
	}
	w := do()
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("got %d", w.Code)
	}
}

func TestLoggerHidesSecrets(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	hasher := NewIPHasher(make([]byte, 32))
	mux := http.NewServeMux()
	mux.Handle("GET /dl/{token}", Route(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})))
	// An inner middleware copying the request must not lose the pattern.
	inner := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { next.ServeHTTP(w, r.WithContext(r.Context())) })
	}
	h := Chain(mux, RealIP(IPResolver{}, nil), Logger(log, hasher), inner)
	r := httptest.NewRequest(http.MethodGet, "/dl/SECRETTOKEN?code=SECRETCODE", nil)
	r.RemoteAddr = "192.0.2.55:1"
	r.Header.Set("Cookie", "__Host-dropr_session=SECRETCOOKIE")
	h.ServeHTTP(httptest.NewRecorder(), r)
	out := buf.String()
	for _, secret := range []string{"SECRETTOKEN", "SECRETCODE", "SECRETCOOKIE", "192.0.2.55"} {
		if strings.Contains(out, secret) {
			t.Errorf("log contains %s: %s", secret, out)
		}
	}
	if !strings.Contains(out, `"route":"GET /dl/{token}"`) || !strings.Contains(out, `"status":418`) {
		t.Errorf("log lacks route/status: %s", out)
	}
}

func TestRecover(t *testing.T) {
	t.Parallel()
	h := Recover(slog.New(slog.DiscardHandler))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("got %d", w.Code)
	}
	defer func() {
		if recover() == nil {
			t.Error("ErrAbortHandler swallowed")
		}
	}()
	Recover(slog.New(slog.DiscardHandler))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) })).
		ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}

func TestLimitBody(t *testing.T) {
	t.Parallel()
	h := LimitBody(10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, "too big", http.StatusRequestEntityTooLarge)
		}
	}))
	for _, c := range []struct {
		body string
		cl   bool
		want int
	}{{"short", true, 200}, {strings.Repeat("x", 11), true, 413}, {strings.Repeat("x", 11), false, 413}} {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(c.body))
		if !c.cl {
			r.ContentLength = -1
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != c.want {
			t.Errorf("%q: %d want %d", c.body, w.Code, c.want)
		}
	}
}

func FuzzIPResolver(f *testing.F) {
	f.Add("10.0.0.1:80", "1.2.3.4, 10.0.0.2")
	f.Add("@", "::1,,garbage, 2001:db8::1")
	f.Add("[fe80::1%eth0]:1", "fe80::2%lo")
	res := IPResolver{Trusted: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, TrustUnixPeer: true}
	f.Fuzz(func(t *testing.T, remote, xff string) {
		r := &http.Request{RemoteAddr: remote, Header: http.Header{"X-Forwarded-For": {xff}}}
		a := res.Resolve(r)
		if a.IsValid() && (a.Zone() != "" || a.Is4In6()) {
			t.Fatalf("non-normalized address %s", a)
		}
		// The result is either the peer or appears in the header.
		if a.IsValid() {
			peer, _ := peerAddr(remote)
			if a != peer && !strings.Contains(xff, strings.Split(a.String(), "%")[0]) && !strings.Contains(strings.ToLower(xff), a.String()) {
				// Allow normalization differences (e.g. leading zeros) by reparsing entries.
				found := false
				for e := range strings.SplitSeq(xff, ",") {
					if p, err := netip.ParseAddr(strings.TrimSpace(e)); err == nil && p.Unmap().WithZone("") == a {
						found = true
					}
				}
				if !found {
					t.Fatalf("resolved %s from nowhere (remote %q xff %q)", a, remote, xff)
				}
			}
		}
	})
}

func FuzzSameOriginRequest(f *testing.F) {
	f.Add("POST", "same-origin", "")
	f.Add("DELETE", "", "https://drop.example.com")
	f.Fuzz(func(t *testing.T, method, sfs, origin string) {
		r := &http.Request{Method: method, Header: http.Header{}}
		if sfs != "" {
			r.Header.Set("Sec-Fetch-Site", sfs)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		ok := SameOriginRequest(r, "https://drop.example.com")
		safe := method == "GET" || method == "HEAD" || method == "OPTIONS"
		if ok && !safe && sfs != "same-origin" && sfs != "none" && (sfs != "" || origin != "https://drop.example.com") {
			t.Fatalf("allowed %s sfs=%q origin=%q", method, sfs, origin)
		}
	})
}

func TestFailPicksJSONForAPIPaths(t *testing.T) {
	t.Parallel()
	for path, wantJSON := range map[string]bool{"/api/x": true, "/upload/x": true, "/dl/t": true, "/": false, "/apix": false, "/s/x": false} {
		w := httptest.NewRecorder()
		Fail(w, httptest.NewRequest(http.MethodGet, path, nil), ErrBodyTooLarge)
		isJSON := w.Header().Get("Content-Type") == "application/json"
		if w.Code != http.StatusRequestEntityTooLarge || isJSON != wantJSON ||
			(wantJSON && w.Body.String() != `{"error":"too_large","message":"The request is too large."}`+"\n") {
			t.Errorf("%s: %d %q %s", path, w.Code, w.Header().Get("Content-Type"), w.Body)
		}
	}
}

func TestLimitBodyAndRecoverJSON(t *testing.T) {
	t.Parallel()
	h := LimitBody(4)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/x", strings.NewReader("12345")))
	if w.Code != http.StatusRequestEntityTooLarge || !strings.Contains(w.Body.String(), `"too_large"`) {
		t.Errorf("limit: %d %s", w.Code, w.Body)
	}
	p := Recover(slog.New(slog.DiscardHandler))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	w = httptest.NewRecorder()
	p.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/upload/x", nil))
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), `"internal"`) {
		t.Errorf("recover: %d %s", w.Code, w.Body)
	}
}
