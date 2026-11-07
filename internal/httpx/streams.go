package httpx

import (
	"net/http"
	"sync"
	"time"
)

// ErrTooManyStreams answers a transfer refused by a StreamLimiter.
var ErrTooManyStreams = Errorf(http.StatusTooManyRequests, "too_many_transfers",
	"Too many uploads or downloads are running. Please try again in a moment.")

// streamV6Bits is the IPv6 prefix a client address is keyed on for the
// stream caps: wider than the rate limiters' /64, so one customer's /56 cannot
// claim 256 times the per-address share of the global slots (audit 2026-11b
// M-1).
const streamV6Bits = 56

// StreamLimiter caps the number of concurrent long-lived requests (part
// uploads, downloads) in total and per key, so trickling connections cannot
// pile up without bound (audit L-4). Limit keys on the client address (keyed
// hash, IPv6 by /56); Acquire takes any key, such as the hash of an upload or
// download capability (audit 2026-11b M-1). Requests over a cap are answered
// 429 with Retry-After at once.
type StreamLimiter struct {
	hasher *IPHasher
	total  int
	perKey int

	mu    sync.Mutex
	cur   int
	byKey map[[16]byte]int
}

// NewStreamLimiter allows total concurrent streams, perKey per client.
func NewStreamLimiter(h *IPHasher, total, perKey int) *StreamLimiter {
	return &StreamLimiter{hasher: h, total: max(total, 1), perKey: max(perKey, 1), byKey: make(map[[16]byte]int)}
}

// Acquire takes a slot for the key and returns its release function, or
// false if a cap is reached.
func (l *StreamLimiter) Acquire(full [32]byte) (release func(), ok bool) {
	var k [16]byte
	copy(k[:], full[:16])
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cur >= l.total || l.byKey[k] >= l.perKey {
		return nil, false
	}
	l.cur++
	l.byKey[k]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.cur--
			if l.byKey[k]--; l.byKey[k] <= 0 {
				delete(l.byKey, k)
			}
		})
	}, true
}

// Active returns the number of streams in progress.
func (l *StreamLimiter) Active() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.cur
}

// RefuseStream answers a stream refused by Acquire: 429 with Retry-After.
func RefuseStream(w http.ResponseWriter, r *http.Request) {
	SetRetryAfter(w, 5*time.Second)
	Fail(w, r, ErrTooManyStreams)
}

// Limit wraps h, keyed by the client IP from RealIP.
func (l *StreamLimiter) Limit(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		release, ok := l.Acquire(l.hasher.SumPrefix(ClientIP(r.Context()), streamV6Bits))
		if !ok {
			RefuseStream(w, r)
			return
		}
		defer release()
		h.ServeHTTP(w, r)
	})
}
