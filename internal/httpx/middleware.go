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

// routeInfo carries the matched route pattern and the authenticated user up
// to the logging middleware. ServeMux sets Request.Pattern on the request it
// receives, which may be a copy made by an inner middleware, so the pattern is
// recorded explicitly; the user is filled in by the session layer through
// SetUser.
type routeInfo struct{ pattern, user string }

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

// SetUser records the authenticated user of the request so the request log
// line names who acted (audit 2026-11b L-9). It is a no-op outside Logger.
func SetUser(ctx context.Context, userID string) {
	if ri, ok := ctx.Value(routeKey{}).(*routeInfo); ok {
		ri.user = userID
	}
}

type requestIDKey struct{}

// RequestID returns the request's log correlation ID.
func RequestID(ctx context.Context) string {
	s, _ := ctx.Value(requestIDKey{}).(string)
	return s
}

// ContextHandler wraps h so every record logged with a request context
// carries that request's ID ("rid"), tying security events such as login or
// logout to the request log line (audit 2026-11b L-9). Records that already
// have a top-level "rid" are left alone.
func ContextHandler(h slog.Handler) slog.Handler { return ctxHandler{h} }

type ctxHandler struct{ slog.Handler }

func (h ctxHandler) Handle(ctx context.Context, r slog.Record) error {
	if rid := RequestID(ctx); rid != "" {
		has := false
		r.Attrs(func(a slog.Attr) bool {
			has = a.Key == "rid"
			return !has
		})
		if !has {
			r = r.Clone()
			r.AddAttrs(slog.String("rid", rid))
		}
	}
	return h.Handler.Handle(ctx, r)
}

func (h ctxHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return ctxHandler{h.Handler.WithAttrs(as)}
}

func (h ctxHandler) WithGroup(name string) slog.Handler {
	return ctxHandler{h.Handler.WithGroup(name)}
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
// duration, a keyed-hash prefix of the client IP, a request ID and, when the
// request carried a session, the user ID (audit 2026-11b L-9). It never
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
				attrs := []slog.Attr{
					slog.String("method", sanitizeMethod(r.Method)),
					slog.String("route", route),
					slog.Int("status", status),
					slog.Int64("bytes", sw.bytes),
					slog.Duration("dur", time.Since(start)),
					slog.String("ip", hasher.Short(ClientIP(ctx))),
					slog.String("rid", rid),
				}
				if ri.user != "" {
					attrs = append(attrs, slog.String("user", ri.user))
				}
				log.LogAttrs(ctx, slog.LevelInfo, "request", attrs...)
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
