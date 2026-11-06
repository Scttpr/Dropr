package httpx

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// IPHasher maps client addresses to keyed hashes so that neither the rate
// limiter's memory nor the logs ever hold plaintext IPs. IPv6 addresses are
// reduced to their /64, the unit a single client typically controls.
type IPHasher struct {
	key []byte
}

// NewIPHasher returns a hasher with a 32-byte key (derive it from the master
// key with seal.InfoIPHash).
func NewIPHasher(key []byte) *IPHasher { return &IPHasher{key: append([]byte(nil), key...)} }

// Sum returns the keyed hash of a.
func (h *IPHasher) Sum(a netip.Addr) [32]byte {
	m := hmac.New(sha256.New, h.key)
	if a.Is6() && !a.Is4In6() {
		p, _ := a.Prefix(64)
		a = p.Addr()
	}
	b, _ := a.MarshalBinary()
	m.Write(b)
	var out [32]byte
	m.Sum(out[:0])
	return out
}

// Short returns a short hex prefix of the hash for logs ("-" if invalid).
func (h *IPHasher) Short(a netip.Addr) string {
	if !a.IsValid() {
		return "-"
	}
	s := h.Sum(a)
	return hex.EncodeToString(s[:6])
}

// RateLimiter is a per-client token bucket kept in a bounded map.
type RateLimiter struct {
	hasher     *IPHasher
	limit      rate.Limit
	burst      int
	maxEntries int
	idle       time.Duration
	now        func() time.Time

	mu      sync.Mutex
	clients map[[16]byte]*bucket
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

// NewRateLimiter allows perMinute requests per client on average with the
// given burst, tracking at most maxEntries clients.
func NewRateLimiter(h *IPHasher, perMinute float64, burst, maxEntries int) *RateLimiter {
	return &RateLimiter{
		hasher:     h,
		limit:      rate.Limit(perMinute / 60),
		burst:      burst,
		maxEntries: max(maxEntries, 1),
		idle:       10 * time.Minute,
		now:        time.Now,
		clients:    make(map[[16]byte]*bucket),
	}
}

// Allow consumes one token for a and reports whether the request may
// proceed, plus how long to wait otherwise.
func (rl *RateLimiter) Allow(a netip.Addr) (bool, time.Duration) {
	return rl.AllowKey(rl.hasher.Sum(a))
}

// AllowKey is Allow for an arbitrary 32-byte key, such as the hash of a
// session ID (per-session limits). Keys must not be secrets themselves.
func (rl *RateLimiter) AllowKey(full [32]byte) (bool, time.Duration) {
	var k [16]byte
	copy(k[:], full[:16])
	now := rl.now()

	rl.mu.Lock()
	defer rl.mu.Unlock()
	b := rl.clients[k]
	if b == nil {
		if len(rl.clients) >= rl.maxEntries {
			rl.evictLocked(now)
		}
		b = &bucket{lim: rate.NewLimiter(rl.limit, rl.burst)}
		rl.clients[k] = b
	}
	b.seen = now
	r := b.lim.ReserveN(now, 1)
	if !r.OK() {
		return false, time.Minute
	}
	if d := r.DelayFrom(now); d > 0 {
		r.CancelAt(now)
		return false, d
	}
	return true, 0
}

// evictLocked drops idle clients, then arbitrary ones if the map is still
// full. Arbitrary eviction can only make the limiter more lenient for the
// evicted client, never block a legitimate one.
func (rl *RateLimiter) evictLocked(now time.Time) {
	for k, b := range rl.clients {
		if now.Sub(b.seen) > rl.idle {
			delete(rl.clients, k)
		}
	}
	for k := range rl.clients {
		if len(rl.clients) < rl.maxEntries*9/10 {
			break
		}
		delete(rl.clients, k)
	}
}

// Len returns the number of tracked clients.
func (rl *RateLimiter) Len() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.clients)
}

// Limit wraps h with the limiter, keyed by the client IP from RealIP.
// Requests without a resolvable address share one bucket.
func (rl *RateLimiter) Limit(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ok, wait := rl.Allow(ClientIP(r.Context()))
		if !ok {
			SetRetryAfter(w, wait)
			Fail(w, r, ErrRateLimited)
			return
		}
		h.ServeHTTP(w, r)
	})
}
