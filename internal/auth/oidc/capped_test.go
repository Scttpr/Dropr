package oidc

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Audit 2026-11 I7: every provider response body is capped, with or without
// a Content-Length.
func TestCappedResponses(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if r.URL.Query().Has("chunked") {
			w.Header().Set("Transfer-Encoding", "chunked")
			w.(http.Flusher).Flush()
		}
		_, _ = io.WriteString(w, strings.Repeat("a", n))
	}))
	t.Cleanup(srv.Close)
	c := capResponses(srv.Client())
	for _, tc := range []struct {
		query   string
		tooBig  bool
		wantLen int
	}{
		{"n=10", false, 10},
		{"n=1048576", false, maxProviderResponse},
		{"n=1048576&chunked", false, maxProviderResponse},
		{"n=1048577", true, 0},
		{"n=1048577&chunked", true, 0},
		{"n=3000000&chunked", true, 0},
	} {
		req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/?"+tc.query, nil)
		resp, err := c.Do(req)
		var body []byte
		if err == nil {
			body, err = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
		switch {
		case tc.tooBig && !errors.Is(err, errResponseTooLarge):
			t.Errorf("%s: got %v, want too large", tc.query, err)
		case !tc.tooBig && (err != nil || len(body) != tc.wantLen):
			t.Errorf("%s: %d bytes, %v", tc.query, len(body), err)
		}
	}
}
