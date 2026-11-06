// Package session implements server-side sessions (PLAN.md §5.3).
//
// The cookie __Host-dropr_session holds a random 256-bit ID; the database
// stores only its SHA-256. Sessions expire after 30 minutes of inactivity or
// 8 hours after login, whichever comes first. The ID rotates at login and at
// passkey unlock; the absolute lifetime is measured from the original login
// and survives rotation.
//
// Unlock policy: a passkey unlock (MarkUnlocked) stays valid for the rest of
// the session, i.e. at most the 8 h absolute lifetime and only while the
// session stays active (30 min idle). Rationale: the unwrapped private key
// lives only in browser memory and is lost on reload anyway, so the server
// flag only gates access to wrapped keys and inbox metadata, both useless
// without the passkey's PRF output. Config.UnlockMaxAge tightens this if
// a deployment wants re-prompts. Revalidation failure kills the whole session,
// unlock included.
package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/scttpr/dropr/internal/httpx"
	"github.com/scttpr/dropr/internal/ids"
	"github.com/scttpr/dropr/internal/keyed"
	"github.com/scttpr/dropr/internal/seal"
	"github.com/scttpr/dropr/internal/store"
)

// CookieName is the session cookie. The __Host- prefix forces Secure,
// Path=/ and no Domain, so the cookie is bound to this exact origin.
const CookieName = "__Host-dropr_session"

// Default lifetimes (PLAN.md §5.3).
const (
	DefaultIdleTimeout     = 30 * time.Minute
	DefaultAbsoluteTimeout = 8 * time.Hour
	DefaultTouchEvery      = time.Minute
)

// ErrNoSession means the request carries no valid, live session.
var ErrNoSession = errors.New("session: no valid session")

// Config tunes the manager. Zero values select the defaults.
type Config struct {
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	// TouchEvery throttles last_seen_at writes.
	TouchEvery time.Duration
	// UnlockMaxAge bounds how long a passkey unlock lasts; zero means the
	// session lifetime.
	UnlockMaxAge time.Duration
	// Now overrides the clock in tests.
	Now func() time.Time
}

// Manager issues, loads, rotates and destroys sessions.
type Manager struct {
	st     *store.Store
	rt     *seal.AEAD // refresh-token encryption
	cfg    Config
	logger *slog.Logger
	// locks serializes revalidation and rotation per session (by ID hash).
	locks keyed.Mutex
}

// Session is a live session attached to a request.
type Session struct {
	rec  *store.Session
	User *store.User
}

// UserID returns the owner of the session.
func (s *Session) UserID() string { return s.rec.UserID }

// CreatedAt is the original login time (preserved across rotation).
func (s *Session) CreatedAt() time.Time { return s.rec.CreatedAt }

// RevalidatedAt is the last successful OIDC revalidation (or login).
func (s *Session) RevalidatedAt() time.Time { return s.rec.RevalidatedAt }

// UnlockedAt is the last passkey unlock, if any.
func (s *Session) UnlockedAt() *time.Time { return s.rec.UnlockedAt }

// OIDCSID is the provider session ID ("sid" claim), if any.
func (s *Session) OIDCSID() string { return s.rec.OIDCSID }

// IDHash returns the SHA-256 of the session ID. It is used as the key for
// per-session coordination and as associated data for encrypted fields.
func (s *Session) IDHash() []byte { return s.rec.IDHash }

// NewManager returns a manager. refreshKey is the instance master key; the
// refresh-token encryption key is derived from it.
func NewManager(st *store.Store, refreshKey []byte, cfg Config, logger *slog.Logger) (*Manager, error) {
	rt, err := seal.NewDerived(refreshKey, seal.InfoRefreshToken)
	if err != nil {
		return nil, err
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	if cfg.AbsoluteTimeout <= 0 {
		cfg.AbsoluteTimeout = DefaultAbsoluteTimeout
	}
	if cfg.TouchEvery <= 0 {
		cfg.TouchEvery = DefaultTouchEvery
	}
	if cfg.UnlockMaxAge <= 0 || cfg.UnlockMaxAge > cfg.AbsoluteTimeout {
		cfg.UnlockMaxAge = cfg.AbsoluteTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{st: st, rt: rt, cfg: cfg, logger: logger}, nil
}

func (m *Manager) now() time.Time { return m.cfg.Now().UTC().Truncate(time.Second) }

// NewParams describes a session created at login.
type NewParams struct {
	User         *store.User
	RefreshToken string // may be empty only if the caller accepts no revalidation
	OIDCSID      string
}

// Create issues a brand-new session for a successful login and sets the
// cookie. Any session presented by r is destroyed first, so a pre-login
// session ID (fixation) never survives authentication.
func (m *Manager) Create(ctx context.Context, w http.ResponseWriter, r *http.Request, p NewParams) (*Session, error) {
	if old, ok := cookieID(r); ok {
		if err := m.st.DeleteSession(ctx, ids.Hash(old)); err != nil {
			return nil, fmt.Errorf("session: delete previous: %w", err)
		}
	}
	id := ids.NewSecret()
	now := m.now()
	rec := &store.Session{
		IDHash:        ids.Hash(id),
		UserID:        p.User.ID,
		OIDCSID:       p.OIDCSID,
		CreatedAt:     now,
		LastSeenAt:    now,
		RevalidatedAt: now,
	}
	if p.RefreshToken != "" {
		rec.RefreshTokenEnc = m.rt.Seal([]byte(p.RefreshToken), rec.IDHash)
	}
	if err := m.st.CreateSession(ctx, rec); err != nil {
		return nil, fmt.Errorf("session: create: %w", err)
	}
	m.setCookie(w, id, rec)
	return &Session{rec: rec, User: p.User}, nil
}

// Load returns the live session for r, or ErrNoSession. Expired sessions are
// deleted; sessions of disabled users are refused. last_seen_at is updated at
// most once per TouchEvery.
func (m *Manager) Load(ctx context.Context, r *http.Request) (*Session, error) {
	id, ok := cookieID(r)
	if !ok {
		return nil, ErrNoSession
	}
	hash := ids.Hash(id)
	rec, err := m.st.SessionByHash(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNoSession
	} else if err != nil {
		return nil, err
	}
	now := m.now()
	if m.expired(rec, now) {
		if err := m.st.DeleteSession(ctx, hash); err != nil {
			return nil, err
		}
		return nil, ErrNoSession
	}
	u, err := m.st.UserByID(ctx, rec.UserID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNoSession
	} else if err != nil {
		return nil, err
	}
	if u.DisabledAt != nil {
		if err := m.st.DeleteSession(ctx, hash); err != nil {
			return nil, err
		}
		return nil, ErrNoSession
	}
	if now.Sub(rec.LastSeenAt) >= m.cfg.TouchEvery {
		if err := m.st.TouchSession(ctx, hash, now); err != nil {
			return nil, err
		}
		rec.LastSeenAt = now
	}
	return &Session{rec: rec, User: u}, nil
}

func (m *Manager) expired(rec *store.Session, now time.Time) bool {
	return now.Sub(rec.LastSeenAt) > m.cfg.IdleTimeout ||
		now.Sub(rec.CreatedAt) >= m.cfg.AbsoluteTimeout ||
		rec.LastSeenAt.After(now.Add(time.Minute)) // clock went backwards or row tampered
}

// Rotate replaces the session ID, keeping every other attribute (including
// the original creation time), re-binds the encrypted refresh token to the new
// ID and sets the new cookie. mutate, if non-nil, edits the new record before
// it is stored. The old ID stops working immediately.
//
// Rotation holds the per-session lock that revalidation also takes, and
// builds the new row from the row as stored inside the write transaction,
// never from the possibly stale in-memory copy: a refresh token rotated by a
// concurrent revalidation is carried over, not lost (audit L-5).
func (m *Manager) Rotate(ctx context.Context, w http.ResponseWriter, s *Session, mutate func(*store.Session)) (*Session, error) {
	unlock := m.Lock(s)
	defer unlock()
	id := ids.NewSecret()
	newHash := ids.Hash(id)
	var next *store.Session
	err := m.st.RotateSession(ctx, s.rec.IDHash, func(cur *store.Session) (*store.Session, error) {
		n := *cur
		n.IDHash = newHash
		n.RotatedFrom = cur.IDHash
		n.LastSeenAt = m.now()
		n.RefreshTokenEnc = nil
		if len(cur.RefreshTokenEnc) > 0 {
			pt, err := m.rt.Open(cur.RefreshTokenEnc, cur.IDHash)
			if err != nil {
				return nil, err
			}
			n.RefreshTokenEnc = m.rt.Seal(pt, newHash)
		}
		if mutate != nil {
			mutate(&n)
		}
		next = &n
		return next, nil
	})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrNoSession
		}
		return nil, fmt.Errorf("session: rotate: %w", err)
	}
	m.setCookie(w, id, next)
	return &Session{rec: next, User: s.User}, nil
}

// Lock takes the per-session lock (keyed by the session ID hash) that
// serializes revalidation and rotation, and returns its release function.
func (m *Manager) Lock(s *Session) (unlock func()) {
	return m.locks.Lock(string(s.rec.IDHash))
}

// MarkUnlocked records a successful passkey unlock and rotates the session ID
// (PLAN.md §5.3).
func (m *Manager) MarkUnlocked(ctx context.Context, w http.ResponseWriter, s *Session) (*Session, error) {
	now := m.now()
	return m.Rotate(ctx, w, s, func(n *store.Session) { n.UnlockedAt = &now })
}

// IsUnlocked reports whether the session holds a valid passkey unlock.
func (m *Manager) IsUnlocked(s *Session) bool {
	if s == nil || s.rec.UnlockedAt == nil {
		return false
	}
	age := m.now().Sub(*s.rec.UnlockedAt)
	return age >= -time.Minute && age < m.cfg.UnlockMaxAge
}

// Destroy deletes the session and clears the cookie.
func (m *Manager) Destroy(ctx context.Context, w http.ResponseWriter, s *Session) error {
	ClearCookie(w)
	if s == nil {
		return nil
	}
	return m.st.DeleteSession(ctx, s.rec.IDHash)
}

// RefreshToken decrypts the stored refresh token. It returns "" if none.
func (m *Manager) RefreshToken(s *Session) (string, error) {
	if len(s.rec.RefreshTokenEnc) == 0 {
		return "", nil
	}
	pt, err := m.rt.Open(s.rec.RefreshTokenEnc, s.rec.IDHash)
	if err != nil {
		return "", fmt.Errorf("session: refresh token: %w", err)
	}
	return string(pt), nil
}

// Revalidated records a successful revalidation. newRefreshToken replaces the
// stored token when the provider rotated it (non-empty).
func (m *Manager) Revalidated(ctx context.Context, s *Session, newRefreshToken string) error {
	now := m.now()
	var enc []byte
	if newRefreshToken != "" {
		enc = m.rt.Seal([]byte(newRefreshToken), s.rec.IDHash)
	}
	if err := m.st.UpdateSessionRevalidation(ctx, s.rec.IDHash, enc, now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrNoSession
		}
		return err
	}
	s.rec.RevalidatedAt = now
	if enc != nil {
		s.rec.RefreshTokenEnc = enc
	}
	return nil
}

// Reload re-reads the session row (e.g. after waiting for a concurrent
// revalidation). It returns ErrNoSession if the session is gone.
func (m *Manager) Reload(ctx context.Context, s *Session) (*Session, error) {
	rec, err := m.st.SessionByHash(ctx, s.rec.IDHash)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrNoSession
	} else if err != nil {
		return nil, err
	}
	return &Session{rec: rec, User: s.User}, nil
}

// Kill deletes a session without touching the response (e.g. from a
// background revalidation or when the response is already committed).
func (m *Manager) Kill(ctx context.Context, s *Session) error {
	return m.st.DeleteSession(ctx, s.rec.IDHash)
}

// Cleanup deletes expired sessions and returns how many were removed.
func (m *Manager) Cleanup(ctx context.Context) (int64, error) {
	now := m.now()
	return m.st.DeleteExpiredSessions(ctx, now.Add(-m.cfg.IdleTimeout), now.Add(-m.cfg.AbsoluteTimeout))
}

func (m *Manager) setCookie(w http.ResponseWriter, id string, rec *store.Session) {
	maxAge := int(rec.CreatedAt.Add(m.cfg.AbsoluteTimeout).Sub(m.now()).Seconds())
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    id,
		Path:     "/",
		MaxAge:   max(maxAge, 1),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearCookie expires the session cookie.
func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// cookieID returns the syntactically valid session ID from r, if any. When
// several cookies share the name (e.g. injected by a sibling subdomain, which
// __Host- prevents in compliant browsers), all are ignored.
func cookieID(r *http.Request) (string, bool) {
	cs := r.CookiesNamed(CookieName)
	if len(cs) != 1 {
		return "", false
	}
	v := cs[0].Value
	if !ids.ValidSecret(v) {
		return "", false
	}
	return v, true
}

type ctxKey struct{}

// NewContext returns ctx carrying s.
func NewContext(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, ctxKey{}, s)
}

// FromContext returns the session attached by Middleware, or nil.
func FromContext(ctx context.Context) *Session {
	s, _ := ctx.Value(ctxKey{}).(*Session)
	return s
}

// Middleware loads the session (if any) into the request context. It never
// rejects a request: handlers decide whether a session is required. A cookie
// that does not resolve to a live session is cleared.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := m.Load(r.Context(), r)
		switch {
		case err == nil:
			r = r.WithContext(NewContext(r.Context(), s))
		case errors.Is(err, ErrNoSession):
			if len(r.CookiesNamed(CookieName)) > 0 {
				ClearCookie(w)
			}
		default:
			m.logger.ErrorContext(r.Context(), "session load failed", "err", err)
			httpx.Fail(w, r, httpx.ErrInternal)
			return
		}
		next.ServeHTTP(w, r)
	})
}
