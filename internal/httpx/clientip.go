package httpx

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
)

// maxForwardedEntries bounds the work done on X-Forwarded-For.
const maxForwardedEntries = 32

type ipKey struct{}

// ClientIP returns the client address resolved by RealIP (invalid if none).
func ClientIP(ctx context.Context) netip.Addr {
	a, _ := ctx.Value(ipKey{}).(netip.Addr)
	return a
}

// WithClientIP returns ctx carrying a.
func WithClientIP(ctx context.Context, a netip.Addr) context.Context {
	return context.WithValue(ctx, ipKey{}, a)
}

// IPResolver determines the real client address.
//
// The TCP peer is the client unless it is a trusted proxy (or the listener is
// a Unix socket, whose peer can only be a local process with access to the
// socket file, i.e. the reverse proxy). For a trusted peer, X-Forwarded-For is
// walked from right to left, skipping trusted proxies; the first untrusted
// address is the client. Unparseable entries stop the walk so a client cannot
// smuggle an arbitrary address past the proxy chain. Entries carrying a port
// ("1.2.3.4:5678", "[2001:db8::1]:443", as some proxies append) are accepted
// for their address (audit 2026-11b L-5). X-Forwarded-Proto and
// X-Forwarded-Host are never used: public_url is authoritative.
type IPResolver struct {
	Trusted []netip.Prefix
	// TrustUnixPeer treats Unix-socket peers as a trusted proxy.
	TrustUnixPeer bool
}

// Resolve returns the client address for r (invalid if undeterminable).
func (res IPResolver) Resolve(r *http.Request) netip.Addr {
	a, _ := res.resolve(r)
	return a
}

// resolve is Resolve; bad reports that a trusted proxy sent an
// X-Forwarded-For entry that could not be parsed, which ended the walk.
func (res IPResolver) resolve(r *http.Request) (client netip.Addr, bad bool) {
	peer, isUnix := peerAddr(r.RemoteAddr)
	trustedPeer := (isUnix && res.TrustUnixPeer) || (peer.IsValid() && res.trusted(peer))
	if !trustedPeer {
		return peer, false
	}
	entries := forwardedFor(r.Header.Values("X-Forwarded-For"))
	client = peer
	for i := len(entries) - 1; i >= 0; i-- {
		a, ok := parseForwarded(entries[i])
		if !ok {
			return client, true
		}
		client = a
		if !res.trusted(a) {
			return a, false
		}
	}
	return client, false
}

// parseForwarded parses one X-Forwarded-For entry: a bare address, a
// bracketed IPv6 address, or either with a port (audit 2026-11b L-5).
func parseForwarded(e string) (netip.Addr, bool) {
	e = strings.TrimSpace(e)
	a, err := netip.ParseAddr(e)
	if err != nil {
		if ap, perr := netip.ParseAddrPort(e); perr == nil {
			a, err = ap.Addr(), nil
		} else if len(e) > 2 && e[0] == '[' && e[len(e)-1] == ']' {
			a, err = netip.ParseAddr(e[1 : len(e)-1])
		}
	}
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

func (res IPResolver) trusted(a netip.Addr) bool {
	for _, p := range res.Trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// forwardedFor flattens X-Forwarded-For header values in order, keeping at
// most the last maxForwardedEntries entries (the ones nearest to us).
func forwardedFor(values []string) []string {
	var out []string
	for _, v := range values {
		for e := range strings.SplitSeq(v, ",") {
			out = append(out, e)
			if len(out) > 4*maxForwardedEntries {
				out = out[len(out)-maxForwardedEntries:]
			}
		}
	}
	if len(out) > maxForwardedEntries {
		out = out[len(out)-maxForwardedEntries:]
	}
	return out
}

// peerAddr parses r.RemoteAddr. Unix-socket connections have an empty or
// "@" remote address.
func peerAddr(remote string) (netip.Addr, bool) {
	if remote == "" || remote == "@" || strings.HasPrefix(remote, "/") {
		return netip.Addr{}, true
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), false
}

// RealIP stores the resolved client address in the request context. With a
// logger, it warns once when the setup looks wrong (audit L-1): a request
// whose client address cannot be determined (a unix-socket proxy that sends
// no X-Forwarded-For), or X-Forwarded-For arriving from a peer that is not a
// trusted proxy (trusted_proxies missing the proxy's address), or a trusted
// proxy sending X-Forwarded-For entries that cannot be parsed (audit 2026-11
// L-5).
func RealIP(res IPResolver, log *slog.Logger) func(http.Handler) http.Handler {
	var noAddr, untrusted, unparsable sync.Once
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			a, bad := res.resolve(r)
			if log != nil {
				if bad {
					unparsable.Do(func() {
						log.Warn("a trusted proxy sent an X-Forwarded-For entry that is not an IP address (or ip:port); such clients get the proxy's address and share its rate-limit bucket; check the reverse proxy's X-Forwarded-For format")
					})
				}
				if !a.IsValid() {
					noAddr.Do(func() {
						log.Warn("cannot determine client addresses: all such clients share one rate-limit bucket; check that the reverse proxy sets X-Forwarded-For and that trusted_proxies / trust_unix_socket_proxy is set")
					})
				} else if r.Header.Get("X-Forwarded-For") != "" && a == res.peer(r) && !res.trustedPeer(r) {
					untrusted.Do(func() {
						log.Warn("X-Forwarded-For received from a peer that is not a trusted proxy and ignored; add the reverse proxy's address to trusted_proxies if it is yours")
					})
				}
			}
			next.ServeHTTP(w, r.WithContext(WithClientIP(r.Context(), a)))
		})
	}
}

func (res IPResolver) peer(r *http.Request) netip.Addr {
	p, _ := peerAddr(r.RemoteAddr)
	return p
}

func (res IPResolver) trustedPeer(r *http.Request) bool {
	p, isUnix := peerAddr(r.RemoteAddr)
	return (isUnix && res.TrustUnixPeer) || (p.IsValid() && res.trusted(p))
}
