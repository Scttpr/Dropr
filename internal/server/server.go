// Package server wires Dropr's HTTP surface: the router, middleware stack,
// page handlers and the listeners for both TLS modes.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/scttpr/dropr/internal/auth/oidc"
	"github.com/scttpr/dropr/internal/auth/passkey"
	"github.com/scttpr/dropr/internal/auth/session"
	"github.com/scttpr/dropr/internal/blob"
	"github.com/scttpr/dropr/internal/config"
	"github.com/scttpr/dropr/internal/httpx"
	"github.com/scttpr/dropr/internal/i18n"
	"github.com/scttpr/dropr/internal/seal"
	"github.com/scttpr/dropr/internal/store"
	"github.com/scttpr/dropr/internal/web"
)

// Default per-request deadlines for ordinary routes. Streaming routes
// (uploads, downloads) register their own and slide them while data flows.
const (
	defaultReadDeadline  = 30 * time.Second
	defaultWriteDeadline = 60 * time.Second
)

// Deps are the server's dependencies.
type Deps struct {
	Config *config.Config
	Store  *store.Store
	Logger *slog.Logger
	// OIDCHTTPClient overrides the client used to reach the provider (tests).
	OIDCHTTPClient *http.Client
	// Now overrides the clock (tests).
	Now func() time.Time
	// DiskUsage overrides the free-space probe of the blob store (tests).
	DiskUsage blob.DiskUsage
}

// Server holds every dependency of the HTTP handlers; routes() maps them to
// the HTTP surface.
type Server struct {
	cfg      *config.Config
	log      *slog.Logger
	store    *store.Store
	sessions *session.Manager
	oidc     *oidc.Provider
	pages    *web.Renderer
	assets   *web.Assets
	hasher   *httpx.IPHasher
	resolver httpx.IPResolver
	authRL   *httpx.RateLimiter
	passkeys *passkey.Service
	blobs    *blob.Store
	now      func() time.Time
	// Per-IP limits of the public (link and transfer) endpoints.
	linkRL   *httpx.RateLimiter // /s, /r, /api/s/.../download, /api/r/.../files
	uploadRL *httpx.RateLimiter // /upload/*
	dlRL     *httpx.RateLimiter // /dl/*
	// Concurrent part uploads and downloads (total and per IP).
	streams *httpx.StreamLimiter
	handler http.Handler
}

// New builds the server. It performs OIDC discovery, so it needs network
// access to the provider.
func New(ctx context.Context, d Deps) (*Server, error) {
	if d.Config == nil || d.Store == nil {
		return nil, errors.New("server: missing dependencies")
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	cfg := d.Config
	s := &Server{cfg: cfg, log: d.Logger, store: d.Store, now: d.Now}

	assets, err := web.LoadAssets(web.StaticFS())
	if err != nil {
		return nil, err
	}
	s.assets = assets
	if s.pages, err = web.NewRenderer(assets, cfg.LoginLabel, d.Logger); err != nil {
		return nil, err
	}
	if s.sessions, err = session.NewManager(d.Store, cfg.RefreshKey, session.Config{Now: d.Now}, d.Logger); err != nil {
		return nil, err
	}
	ipKey, err := seal.Derive(cfg.RefreshKey, seal.InfoIPHash)
	if err != nil {
		return nil, err
	}
	s.hasher = httpx.NewIPHasher(ipKey)
	s.resolver = httpx.IPResolver{
		Trusted:       cfg.TrustedProxyNs,
		TrustUnixPeer: cfg.TLS == config.TLSProxy && (cfg.TrustUnixSocketProxy || len(cfg.TrustedProxyNs) > 0),
	}
	s.authRL = httpx.NewRateLimiter(s.hasher, 30, 10, 100_000)
	s.linkRL = httpx.NewRateLimiter(s.hasher, 60, 30, 100_000)
	s.uploadRL = httpx.NewRateLimiter(s.hasher, 900, 200, 100_000)
	s.dlRL = httpx.NewRateLimiter(s.hasher, 120, 60, 100_000)
	s.streams = httpx.NewStreamLimiter(s.hasher, cfg.Limits.MaxTransfers, cfg.Limits.MaxTransfersPerIP)

	if s.blobs, err = blob.New(BlobDir(cfg), blob.Options{Headroom: cfg.Limits.DiskHeadroomBytes, Usage: d.DiskUsage}); err != nil {
		return nil, err
	}
	if s.passkeys, err = passkey.New(passkey.Options{
		Public:   cfg.Public,
		Origin:   cfg.Origin,
		Store:    d.Store,
		Sessions: s.sessions,
		// Per session: a few ceremonies a minute is plenty for a human.
		Limiter: httpx.NewRateLimiter(s.hasher, 60, 30, 100_000),
		Logger:  d.Logger,
		Now:     d.Now,
	}); err != nil {
		return nil, err
	}

	p, warnings, err := oidc.New(ctx, oidc.Options{
		OIDC:         &cfg.OIDC,
		Production:   cfg.Production(),
		PublicOrigin: cfg.Origin,
		RefreshKey:   cfg.RefreshKey,
		Store:        d.Store,
		Sessions:     s.sessions,
		Pages:        s.pages,
		HTTPClient:   d.OIDCHTTPClient,
		Logger:       d.Logger,
		Now:          d.Now,
	})
	for _, w := range warnings {
		d.Logger.Warn("oidc capability", "warning", w)
	}
	if err != nil {
		return nil, err
	}
	s.oidc = p

	s.handler = httpx.Chain(s.routes(),
		httpx.RealIP(s.resolver, d.Logger),
		httpx.Logger(d.Logger, s.hasher),
		httpx.Recover(d.Logger),
		httpx.SecurityHeaders(httpx.HeaderOptions{FormActionOrigins: p.FormActionOrigins()}),
		httpx.CSRF(cfg.Origin, http.HandlerFunc(s.csrfRejected)),
	)
	return s, nil
}

// Handler returns the root handler.
func (s *Server) Handler() http.Handler { return s.handler }

// Sessions exposes the session manager (jobs, CLI).
func (s *Server) Sessions() *session.Manager { return s.sessions }

// Blobs exposes the blob store (jobs).
func (s *Server) Blobs() *blob.Store { return s.blobs }

// routeOpts tunes one route.
type routeOpts struct {
	session   bool // load the session (and revalidate it)
	bodyLimit int64
	read      time.Duration
	write     time.Duration
	limiter   *httpx.RateLimiter
	streams   bool // count against the concurrent transfer caps
}

type routeOpt func(*routeOpts)

func withSession() routeOpt                      { return func(o *routeOpts) { o.session = true } }
func withLimiter(rl *httpx.RateLimiter) routeOpt { return func(o *routeOpts) { o.limiter = rl } }
func withStreamCap() routeOpt                    { return func(o *routeOpts) { o.streams = true } }
func withBodyLimit(n int64) routeOpt             { return func(o *routeOpts) { o.bodyLimit = n } }
func withDeadlines(read, write time.Duration) routeOpt {
	return func(o *routeOpts) { o.read, o.write = read, write }
}

func (s *Server) handle(mux *http.ServeMux, pattern string, h http.HandlerFunc, opts ...routeOpt) {
	o := routeOpts{bodyLimit: httpx.DefaultBodyLimit, read: defaultReadDeadline, write: defaultWriteDeadline}
	for _, f := range opts {
		f(&o)
	}
	var handler http.Handler = h
	if o.session {
		handler = s.sessions.Middleware(s.oidc.RevalidateMiddleware(handler))
	}
	if o.streams {
		handler = s.streams.Limit(handler)
	}
	if o.limiter != nil {
		handler = o.limiter.Limit(handler)
	}
	handler = httpx.Chain(handler, httpx.Deadlines(o.read, o.write), httpx.LimitBody(o.bodyLimit))
	mux.Handle(pattern, httpx.Route(handler))
}

// routes registers the HTTP surface (ARCHITECTURE.md §3). Anything not
// listed falls through to the 404 page, whatever the method.
func (s *Server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	notFound := http.HandlerFunc(s.pages.NotFound)

	// Pages.
	s.handle(mux, "GET /{$}", s.handleHome, withSession())
	s.handle(mux, "GET /login", s.handleLogin, withSession())
	s.handle(mux, "POST /prefs", web.HandlePrefs)

	// Auth.
	s.handle(mux, "GET /auth/login", s.oidc.HandleLogin, withLimiter(s.authRL))
	s.handle(mux, "GET /auth/callback", s.oidc.HandleCallback, withLimiter(s.authRL))
	s.handle(mux, "POST /auth/logout", s.oidc.HandleLogout, withSession())
	s.handle(mux, "GET /auth/frontchannel-logout", s.oidc.HandleFrontchannelLogout, withLimiter(s.authRL))

	// Static assets.
	s.handle(mux, "GET /assets/{path...}", s.assets.Handler(notFound).ServeHTTP)
	s.handle(mux, "GET /sw.js", s.assets.ServiceWorkerHandler(notFound).ServeHTTP)

	// Operations.
	s.handle(mux, "GET /healthz", s.handleHealth)

	// Pages that need a session redirect to /setup until two passkeys exist.
	s.handle(mux, "GET /setup", s.handleSetup, withSession())
	s.handle(mux, "GET /inbox", s.handleInbox, withSession())
	s.handle(mux, "GET /links", s.handleLinks, withSession())
	s.handle(mux, "GET /s/{id}", s.handleSharePage, withLimiter(s.linkRL))
	s.handle(mux, "GET /r/{id}", s.handleRequestPage, withLimiter(s.linkRL))
	// The service worker's scope: reaching the server here means the worker
	// was not active.
	s.handle(mux, "GET /_dl/{path...}", s.handleDLFallback)

	// Passkeys (session required; begin/finish are rate-limited per session).
	s.handle(mux, "POST /api/passkeys/register/begin", s.passkeys.RegisterBegin, withSession())
	s.handle(mux, "POST /api/passkeys/register/finish", s.passkeys.RegisterFinish, withSession())
	s.handle(mux, "POST /api/passkeys/unlock/begin", s.passkeys.UnlockBegin, withSession())
	s.handle(mux, "POST /api/passkeys/unlock/finish", s.passkeys.UnlockFinish, withSession())
	s.handle(mux, "GET /api/passkeys", s.passkeys.List, withSession())
	s.handle(mux, "DELETE /api/passkeys/{id}", s.passkeys.Delete, withSession())

	// Shares (flow A).
	s.handle(mux, "POST /api/shares", s.handleCreateShare, withSession())
	s.handle(mux, "GET /api/shares", s.handleListShares, withSession())
	s.handle(mux, "DELETE /api/shares/{id}", s.handleDeleteShare, withSession())
	s.handle(mux, "POST /api/s/{id}/download", s.handleShareDownload, withLimiter(s.linkRL))

	// Requests (flow B) and the inbox.
	s.handle(mux, "POST /api/requests", s.handleCreateRequest, withSession())
	s.handle(mux, "GET /api/requests", s.handleListRequests, withSession())
	s.handle(mux, "DELETE /api/requests/{id}", s.handleDeleteRequest, withSession())
	s.handle(mux, "PUT /api/requests/{id}/label", s.handleSetRequestLabel, withSession())
	s.handle(mux, "POST /api/r/{id}/files", s.handleCreateRequestFile, withLimiter(s.linkRL))
	s.handle(mux, "GET /api/inbox", s.handleListInbox, withSession())
	s.handle(mux, "POST /api/inbox/{id}/download", s.handleInboxDownload, withSession())
	s.handle(mux, "DELETE /api/inbox/{id}", s.handleDeleteInbox, withSession())

	// Uploads (shared by both flows). A part body is one ciphertext part;
	// the read deadline slides while it arrives.
	s.handle(mux, "PUT /upload/{upload_id}/part/{n}", s.handlePutPart, withLimiter(s.uploadRL),
		withBodyLimit(blob.PartCipherSize), withDeadlines(partReadTimeout, defaultWriteDeadline), withStreamCap())
	s.handle(mux, "GET /upload/{upload_id}", s.handleUploadStatus, withLimiter(s.uploadRL))
	s.handle(mux, "POST /upload/{upload_id}/finalize", s.handleFinalize, withLimiter(s.uploadRL))

	// Downloads: the write deadline slides while the body flows (up to
	// 100 GB). Inbox tokens also need the owner's unlocked session.
	s.handle(mux, "GET /dl/{token}", s.handleDownload, withLimiter(s.dlRL), withSession(),
		withDeadlines(defaultReadDeadline, blob.WriteTimeout), withStreamCap())

	s.handle(mux, "/", s.notFound)
	return mux
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if session.FromContext(r.Context()) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.pages.Render(w, r, http.StatusOK, web.PageLogin, web.PageData{})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.DB().R.PingContext(ctx); err != nil {
		s.log.ErrorContext(ctx, "health check failed", "err", err)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = fmt.Fprintln(w, "ok")
}

// notFound answers unknown routes: JSON under /api/, /upload/ and /dl/, the
// HTML 404 page elsewhere.
func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	if httpx.IsAPIPath(r.URL.Path) {
		httpx.WriteError(w, httpx.ErrNotFound)
		return
	}
	s.pages.NotFound(w, r)
}

func (s *Server) csrfRejected(w http.ResponseWriter, r *http.Request) {
	if httpx.IsAPIPath(r.URL.Path) {
		httpx.WriteError(w, httpx.ErrCrossSite)
		return
	}
	s.pages.Error(w, r, http.StatusForbidden, i18n.N("Request blocked"),
		i18n.N("This request was blocked because it did not come from this site. Go back and try again."), nil)
}
