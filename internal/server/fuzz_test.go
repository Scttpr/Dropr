package server

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/scttpr/dropr/internal/blob"
	"github.com/scttpr/dropr/internal/httpx"
)

var fuzzLimits = limits{maxFileSize: 5 << 30, defaultExpiry: "7d"}

// FuzzJSONRequests feeds arbitrary bodies to every JSON request decoder and
// validator and checks the invariants of what they accept.
func FuzzJSONRequests(f *testing.F) {
	for _, s := range []string{
		`{"size":1016,"parts":1,"meta":"` + meta() + `","expires_in":"1h","max_downloads":3}`,
		`{"expires_in":"7d","max_files":2,"max_bytes":2032,"single_use":true}`,
		`{"size":16,"parts":1,"meta":"AAAAAAAAAAAAAAAAAAAAAAA","wrapped_key":"` + b64t.EncodeToString(make([]byte, 80)) + `"}`,
		`{"label_meta":"` + b64t.EncodeToString(make([]byte, 60)) + `"}`,
		`{"parts":3}`, `{} {}`, `[]`, `{"size":-1}`, `{"size":1e30}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		var sh shareRequest
		if httpx.DecodeJSONBytesFrom(bytes.NewReader(body), &sh) == nil {
			if v, e := sh.validate(fuzzLimits); e == nil {
				if _, err := blob.NewGeometry(v.geo.Size, v.geo.Parts); err != nil || v.geo.Plain() > fuzzLimits.maxFileSize {
					t.Fatalf("accepted bad geometry %+v", v.geo)
				}
				if len(v.meta) < minMeta || len(v.meta) > maxMeta || v.ttl <= 0 {
					t.Fatalf("accepted share %+v", v)
				}
				if v.maxDownloads != nil && *v.maxDownloads < 1 {
					t.Fatal("accepted max_downloads < 1")
				}
			}
		}
		var rq requestRequest
		if httpx.DecodeJSONBytesFrom(bytes.NewReader(body), &rq) == nil {
			if v, e := rq.validate(fuzzLimits); e == nil && (v.maxFiles < 1 || v.maxFiles > maxRequestFiles || v.maxBytes < blob.TagSize) {
				t.Fatalf("accepted request %+v", v)
			}
		}
		var rf requestFileRequest
		if httpx.DecodeJSONBytesFrom(bytes.NewReader(body), &rf) == nil {
			if v, e := rf.validate(fuzzLimits); e == nil && len(v.wrappedKey) != wrappedKeyLen {
				t.Fatal("accepted wrapped key length")
			}
		}
		var lb labelRequest
		if httpx.DecodeJSONBytesFrom(bytes.NewReader(body), &lb) == nil {
			if l, e := lb.validate(); e == nil && (len(l) < minLabel || len(l) > maxLabel) {
				t.Fatal("accepted label length")
			}
		}
		var fin finalizeRequest
		_ = httpx.DecodeJSONBytesFrom(bytes.NewReader(body), &fin)
	})
}

func FuzzPartNumber(f *testing.F) {
	for _, s := range []string{"0", "1", "3199", "00", "-1", "+1", "99999", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, ok := parsePartNumber(s)
		if ok && (n < 0 || n > 9999 || len(s) > 1 && s[0] == '0') {
			t.Fatalf("%q -> %d", s, n)
		}
	})
}

func TestPublicEndpointsRateLimited(t *testing.T) {
	t.Parallel()
	e := newTestEnv(t)
	limited := false
	for range 60 {
		resp, _ := e.do(http.MethodGet, "/s/AAAAAAAAAAAAAAAAAAAAAA", nil)
		if resp.StatusCode == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("/s/{id} not rate limited")
	}
	// The limiter is shared by the link endpoints.
	if resp, _ := e.api(http.MethodPost, "/api/r/AAAAAAAAAAAAAAAAAAAAAA/files", map[string]any{}, nil); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("/api/r/{id}/files: %d", resp.StatusCode)
	}
}
