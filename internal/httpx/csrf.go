package httpx

import (
	"net/http"
)

// CSRF rejects cross-site state-changing requests (ARCHITECTURE.md §3).
//
// For every method other than GET, HEAD and OPTIONS:
//   - Sec-Fetch-Site present: it must be "same-origin" or "none" (user
//     typed/bookmarked); "same-site" is refused because sibling subdomains
//     are not trusted.
//   - Sec-Fetch-Site absent (older browsers, non-browser clients): Origin must
//     equal the public origin exactly.
//   - Both absent: refused.
//
// This complements SameSite=Strict on the session cookie.
func CSRF(publicOrigin string, onReject http.Handler) func(http.Handler) http.Handler {
	if onReject == nil {
		onReject = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "Forbidden", http.StatusForbidden)
		})
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !SameOriginRequest(r, publicOrigin) {
				onReject.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SameOriginRequest reports whether r passes the CSRF policy.
func SameOriginRequest(r *http.Request, publicOrigin string) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	sfs := r.Header.Values("Sec-Fetch-Site")
	if len(sfs) > 1 {
		return false
	}
	if len(sfs) == 1 {
		return sfs[0] == "same-origin" || sfs[0] == "none"
	}
	origins := r.Header.Values("Origin")
	return len(origins) == 1 && origins[0] == publicOrigin
}
