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
		`{"size":16,"parts":1,"meta":"` + meta() + `","wrapped_key":"` + b64t.EncodeToString(make([]byte, 80)) + `"}`,
		`{"label_meta":"` + b64t.EncodeToString(make([]byte, minLabel)) + `"}`,
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
				if !onBucket(len(v.meta)-blob.TagSize, maxMetaPadded) || v.ttl <= 0 {
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
			if v, e := rf.validate(fuzzLimits); e == nil && (len(v.wrappedKey) != wrappedKeyLen || !onBucket(len(v.meta)-blob.TagSize, maxMetaPadded)) {
				t.Fatal("accepted wrapped key or meta length")
			}
		}
		var lb labelRequest
		if httpx.DecodeJSONBytesFrom(bytes.NewReader(body), &lb) == nil {
			if l, e := lb.validate(); e == nil && !onBucket(len(l)-labelOverhead, maxLabelPad) {
				t.Fatal("accepted label length")
			}
		}
		var fin finalizeRequest
		_ = httpx.DecodeJSONBytesFrom(bytes.NewReader(body), &fin)
	})
}

// onBucket reports whether n is a padded plaintext length: a power of two in
// [padMin, maxLen] (audit 2026-11b L-8).
func onBucket(n, maxLen int) bool {
	for b := padMin; b <= maxLen; b *= 2 {
		if n == b {
			return true
		}
	}
	return false
}

// Sealed metadata and labels are accepted only on a padded length (audit
// 2026-11b L-8).
func TestPaddedLengths(t *testing.T) {
	for n := 0; n <= 2*maxMeta; n++ {
		s := b64t.EncodeToString(make([]byte, n))
		sh := shareRequest{Size: blob.CipherSize(1), Parts: 1, Meta: s}
		_, e := sh.validate(fuzzLimits)
		if want := onBucket(n-blob.TagSize, maxMetaPadded); (e == nil) != want {
			t.Errorf("meta %d bytes: accepted %v, want %v", n, e == nil, want)
		}
		_, e = (&labelRequest{LabelMeta: s}).validate()
		if want := onBucket(n-labelOverhead, maxLabelPad); (e == nil) != want {
			t.Errorf("label_meta %d bytes: accepted %v, want %v", n, e == nil, want)
		}
	}
	for _, n := range []int{144, 272, 528} {
		if !onBucket(n-blob.TagSize, maxMetaPadded) {
			t.Errorf("meta %d not a bucket", n)
		}
	}
	for _, n := range []int{176, 304} {
		if !onBucket(n-labelOverhead, maxLabelPad) {
			t.Errorf("label_meta %d not a bucket", n)
		}
	}
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
