package session

import (
	"net/http"
	"testing"

	"github.com/scttpr/dropr/internal/ids"
)

// FuzzCookieID parses arbitrary Cookie headers: it must never panic, and
// only a single, canonical 256-bit session secret is ever returned.
func FuzzCookieID(f *testing.F) {
	f.Add(CookieName + "=" + ids.NewSecret())
	f.Add(CookieName + "=a; " + CookieName + "=b")
	f.Add(CookieName + `="` + ids.NewSecret() + `"`)
	f.Add("x=1; " + CookieName + "=" + ids.NewSecret() + "%3D")
	f.Fuzz(func(t *testing.T, header string) {
		r, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
		r.Header.Set("Cookie", header)
		v, ok := cookieID(r)
		if ok && !ids.ValidSecret(v) {
			t.Fatalf("accepted %q", v)
		}
		if ok && len(r.CookiesNamed(CookieName)) != 1 {
			t.Fatal("accepted a duplicated session cookie")
		}
	})
}
