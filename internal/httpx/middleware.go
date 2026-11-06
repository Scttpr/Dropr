package httpx

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/scttpr/dropr/internal/ids"
)

// Chain applies middleware so that the first one listed is the outermost.
func Chain(h http.Handler, mw ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}

// DefaultBodyLimit applies to every request body unless a route sets its own
// (JSON APIs: 16 KiB, ARCHITECTURE.md §3).
const DefaultBodyLimit = 16 << 10

// LimitBody caps the request body at n bytes. Reads past the cap fail and the
// server closes the connection after the response.
func LimitBody(n int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > n {
				Fail(w, r, ErrBodyTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}

// Deadlines sets per-request read and write deadlines through
// http.ResponseController. The server has no global WriteTimeout (uploads and
// downloads are long), so every route gets explicit deadlines here; streaming
// routes pass longer ones or extend them as they progress.
func Deadlines(read, write time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rc := http.NewResponseController(w)
			now := time.Now()
			if read > 0 {
				_ = rc.SetReadDeadline(now.Add(read))
			}
			if write > 0 {
				_ = rc.SetWriteDeadline(now.Add(write))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// routeInfo carries the matched route pattern up to the logging middleware.
// ServeMux sets Request.Pattern on the request it receives, which may be a
// copy made by an inner middleware, so the pattern is recorded explicitly.
type routeInfo struct{ pattern string }

type routeKey struct{}

// Route wraps a handler registered under pattern so the request log shows the
// pattern ("GET /s/{id}") instead of the path, which can contain link IDs or
// tokens.
func Route(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ri, ok := r.Context().Value(routeKey{}).(*routeInfo); ok {
			ri.pattern = r.Pattern
		}
		h.ServeHTTP(w, r)
	})
}

type requestIDKey struct{}

// RequestID returns the request's log correlation ID.
func RequestID(ctx context.Context) string {
	s, _ := ctx.Value(requestIDKey{}).(string)
	return s
}

// statusWriter records the status and size. Unwrap lets
// http.ResponseController reach the underlying writer.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Logger logs one line per request: method, route pattern, status, size,
// duration, a keyed-hash prefix of the client IP and a request ID. It never
// logs paths, query strings, headers, cookies or plaintext IPs. It must run
// inside RealIP.
func Logger(log *slog.Logger, hasher *IPHasher) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ri := &routeInfo{}
			rid := ids.New()[:12]
			ctx := context.WithValue(context.WithValue(r.Context(), routeKey{}, ri), requestIDKey{}, rid)
			sw := &statusWriter{ResponseWriter: w}
			defer func() {
				route := ri.pattern
				if route == "" {
					route = "unmatched"
				}
				status := sw.status
				if status == 0 {
					status = http.StatusOK
				}
				log.LogAttrs(ctx, slog.LevelInfo, "request",
					slog.String("method", sanitizeMethod(r.Method)),
					slog.String("route", route),
					slog.Int("status", status),
					slog.Int64("bytes", sw.bytes),
					slog.Duration("dur", time.Since(start)),
					slog.String("ip", hasher.Short(ClientIP(ctx))),
					slog.String("rid", rid),
				)
			}()
			next.ServeHTTP(sw, r.WithContext(ctx))
		})
	}
}

func sanitizeMethod(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		return m
	}
	return "OTHER"
}

func recoverPanic(r *http.Request, log *slog.Logger, w http.ResponseWriter) {
	ctx := r.Context()
	p := recover()
	if p == nil {
		return
	}
	if err, ok := p.(error); ok && errors.Is(err, http.ErrAbortHandler) {
		panic(p)
	}
	log.ErrorContext(ctx, "panic in handler", "panic", p, "stack", string(debug.Stack()))
	w.Header().Set("Connection", "close")
	Fail(w, r, ErrInternal)
}

// Recover turns handler panics into 500 responses and logs the stack.
// http.ErrAbortHandler is re-panicked so net/http aborts the connection
// quietly, as intended.
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer recoverPanic(r, log, w)
			next.ServeHTTP(w, r)
		})
	}
}
