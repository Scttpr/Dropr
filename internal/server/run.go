package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/scttpr/dropr/internal/blob"
	"github.com/scttpr/dropr/internal/config"
	"github.com/scttpr/dropr/internal/db"
	"github.com/scttpr/dropr/internal/jobs"
	"github.com/scttpr/dropr/internal/store"
)

// HTTP server limits. There is deliberately no global ReadTimeout or
// WriteTimeout: uploads and downloads of up to 100 GB are long-lived, so
// every route sets its own deadlines (httpx.Deadlines).
const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 32 << 10
	shutdownTimeout   = 30 * time.Second
)

// DBPath returns the database location inside data_dir.
func DBPath(cfg *config.Config) string { return filepath.Join(cfg.DataDir, "dropr.db") }

// BlobDir returns the blob store root inside data_dir.
func BlobDir(cfg *config.Config) string { return filepath.Join(cfg.DataDir, "blobs") }

// NewBlobStore opens the blob store of cfg (admin commands).
func NewBlobStore(cfg *config.Config) (*blob.Store, error) {
	return blob.New(BlobDir(cfg), blob.Options{Headroom: cfg.Limits.DiskHeadroomBytes})
}

// Run serves until ctx is canceled (SIGINT/SIGTERM in main), then shuts
// down gracefully.
func Run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	for _, w := range cfg.Warnings {
		log.Warn("config", "warning", w)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("data_dir: %w", err)
	}
	d, err := db.Open(ctx, DBPath(cfg))
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	st := store.New(d)

	srv, err := New(ctx, Deps{Config: cfg, Store: st, Logger: log})
	if err != nil {
		return err
	}

	runner := jobs.NewRunner(jobs.DefaultInterval, log)
	runner.Add(jobs.Task{Name: "expired-sessions", Run: srv.Sessions().Cleanup})
	for _, t := range jobs.FileTasks(st, srv.Blobs(), nil) {
		runner.Add(t)
	}
	jobsCtx, stopJobs := context.WithCancel(ctx)
	defer stopJobs()
	go runner.Run(jobsCtx)

	hs := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
	}

	ln, err := listen(ctx, cfg.Listen)
	if err != nil {
		return err
	}
	var servers []*http.Server
	errc := make(chan error, 2)

	switch cfg.TLS {
	case config.TLSACME:
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(filepath.Join(cfg.DataDir, "acme")),
			HostPolicy: autocert.HostWhitelist(cfg.Public.Hostname()),
			Email:      cfg.ACMEEmail,
		}
		hs.TLSConfig = TLSConfig(m.GetCertificate)
		servers = append(servers, hs)
		go func() { errc <- serveTLS(hs, ln) }()
		log.Info("listening", "addr", ln.Addr().String(), "tls", "acme", "public_url", cfg.Origin)

		if cfg.RedirectHTTP {
			rs := &http.Server{
				// Challenges over HTTP-01 are answered too; everything else
				// is redirected to the configured origin (never to the Host
				// header).
				Handler:           m.HTTPHandler(RedirectHandler(cfg.Origin)),
				ReadHeaderTimeout: readHeaderTimeout,
				ReadTimeout:       10 * time.Second,
				WriteTimeout:      10 * time.Second,
				IdleTimeout:       30 * time.Second,
				MaxHeaderBytes:    maxHeaderBytes,
				ErrorLog:          hs.ErrorLog,
			}
			rln, err := listen(ctx, cfg.RedirectListen)
			if err != nil {
				_ = ln.Close()
				return err
			}
			servers = append(servers, rs)
			go func() { errc <- serve(rs, rln) }()
			log.Info("listening", "addr", rln.Addr().String(), "purpose", "http-redirect")
		}
	case config.TLSProxy:
		servers = append(servers, hs)
		go func() { errc <- serve(hs, ln) }()
		log.Info("listening", "addr", ln.Addr().String(), "tls", "proxy", "public_url", cfg.Origin)
	}

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		stopJobs()
		return errors.Join(err, shutdown(ctx, servers))
	}
	stopJobs()
	return shutdown(ctx, servers)
}

func shutdown(parent context.Context, servers []*http.Server) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), shutdownTimeout)
	defer cancel()
	var errs []error
	for _, s := range servers {
		errs = append(errs, s.Shutdown(ctx))
	}
	return errors.Join(errs...)
}

func serve(s *http.Server, ln net.Listener) error {
	if err := s.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func serveTLS(s *http.Server, ln net.Listener) error {
	if err := s.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// TLSConfig returns the server TLS configuration: TLS 1.2 minimum, AEAD
// cipher suites with forward secrecy only for TLS 1.2 (TLS 1.3 suites are
// all AEAD and not configurable), and Go's default key exchanges, which
// include the hybrid post-quantum X25519MLKEM768. The ACME TLS-ALPN-01
// protocol is advertised so certificates are obtained over port 443 only.
func TLSConfig(getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: getCert,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		NextProtos: []string{"h2", "http/1.1", "acme-tls/1"},
	}
}

// RedirectHandler sends every plain-HTTP request to the same path on origin.
func RedirectHandler(origin string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := origin + r.URL.EscapedPath()
		if !strings.HasPrefix(target, origin+"/") {
			target = origin + "/"
		}
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		w.Header().Set("Connection", "close")
		http.Redirect(w, r, target, http.StatusMovedPermanently) //nolint:gosec // target is the configured origin plus the request path
	})
}

// listen opens a TCP address or, with the "unix:" prefix, a Unix socket. A
// stale socket file from a previous run is removed; any other file at that
// path is left alone and the call fails.
func listen(ctx context.Context, addr string) (net.Listener, error) {
	var lc net.ListenConfig
	path, ok := strings.CutPrefix(addr, "unix:")
	if !ok {
		return lc.Listen(ctx, "tcp", addr)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("listen: %s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	ln, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	// Owner and group (the reverse proxy) only.
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // the proxy connects through group permission
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}
