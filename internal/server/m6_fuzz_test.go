package server

import (
	"net/http"
	"testing"

	"github.com/scttpr/dropr/internal/ids"
)

// FuzzBearer parses arbitrary Authorization headers of upload requests:
// only "Bearer " followed by one canonical 256-bit secret is accepted.
func FuzzBearer(f *testing.F) {
	f.Add("Bearer " + ids.NewSecret())
	f.Add("bearer " + ids.NewSecret())
	f.Add("Bearer  " + ids.NewSecret())
	f.Add("Bearer " + ids.NewSecret() + " x")
	f.Add("Basic Zm9vOmJhcg==")
	f.Fuzz(func(t *testing.T, h string) {
		r, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
		r.Header.Set("Authorization", h)
		tok, ok := bearer(r)
		if ok && (!ids.ValidSecret(tok) || "Bearer "+tok != r.Header.Get("Authorization")) {
			t.Fatalf("accepted %q from %q", tok, h)
		}
	})
}
