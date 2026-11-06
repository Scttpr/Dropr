package httpx

import (
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// apiPrefixes are the URL spaces whose clients are the browser modules (or
// API clients), never a person: every error there is a JSON APIError.
var apiPrefixes = []string{"/api/", "/upload/", "/dl/"}

// IsAPIPath reports whether p is under /api/, /upload/ or /dl/.
func IsAPIPath(p string) bool {
	for _, pre := range apiPrefixes {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}

// Fail answers with e: a JSON APIError on API paths, plain text (the
// message) elsewhere. It is for middleware that runs before a handler knows
// what kind of response it would give; pages render their own HTML errors.
func Fail(w http.ResponseWriter, r *http.Request, e *APIError) {
	if IsAPIPath(r.URL.Path) {
		WriteError(w, e)
		return
	}
	http.Error(w, e.Message, e.Status)
}

// SetRetryAfter sets Retry-After to wait rounded up to whole seconds (≥ 1).
func SetRetryAfter(w http.ResponseWriter, wait time.Duration) {
	secs := int(math.Ceil(wait.Seconds()))
	w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
}

// Common middleware errors.
var (
	ErrBodyTooLarge = Errorf(http.StatusRequestEntityTooLarge, "too_large", "The request is too large.")
	ErrRateLimited  = Errorf(http.StatusTooManyRequests, "rate_limited", "Too many requests. Please wait a moment and try again.")
	ErrInternal     = Errorf(http.StatusInternalServerError, "internal", "Something went wrong on the server. Please try again.")
	ErrNotFound     = Errorf(http.StatusNotFound, "not_found", "Not found.")
	ErrCrossSite    = Errorf(http.StatusForbidden, "csrf", "This request was blocked because it did not come from this site. Reload the page and try again.")
)
