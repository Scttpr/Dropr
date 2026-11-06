package session

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/scttpr/dropr/internal/ids"
	"github.com/scttpr/dropr/internal/store"
	"github.com/scttpr/dropr/internal/store/storetest"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	m    *Manager
	st   *store.Store
	clk  *clock
	user *store.User
}

func newEnv(t *testing.T, cfg Config) *env {
	t.Helper()
	st := storetest.New(t)
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	cfg.Now = clk.Now
	m, err := NewManager(st, bytes.Repeat([]byte{1}, 32), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	u, _, err := st.ProvisionUser(t.Context(), "https://iss", "alice", "Alice", clk.Now())
	if err != nil {
		t.Fatal(err)
	}
	return &env{m: m, st: st, clk: clk, user: u}
}

// login creates a session and returns the cookie set on the response.
func (e *env) login(t *testing.T, r *http.Request) (*Session, *http.Cookie) {
	t.Helper()
	if r == nil {
		r = httptest.NewRequest(http.MethodGet, "/auth/callback", nil)
	}
	w := httptest.NewRecorder()
	s, err := e.m.Create(t.Context(), w, r, NewParams{User: e.user, RefreshToken: "rt-1", OIDCSID: "sid"})
	if err != nil {
		t.Fatal(err)
	}
	return s, sessionCookie(t, w)
}

func sessionCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == CookieName {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func reqWith(c *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if c != nil {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	return r
}

func TestCookieAttributes(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{})
	_, c := e.login(t, nil)
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" {
		t.Errorf("cookie attributes: %+v", c)
	}
	if c.MaxAge <= 0 || c.MaxAge > int((8*time.Hour).Seconds()) {
		t.Errorf("max-age %d", c.MaxAge)
	}
	if !ids.ValidSecret(c.Value) {
		t.Error("cookie value is not a 256-bit secret")
	}
	// Only the hash is stored.
	if _, err := e.st.SessionByHash(t.Context(), []byte(c.Value)); err == nil {
		t.Error("raw ID usable as key")
	}
}

func TestLoadAndTimeouts(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{})
	ctx := t.Context()
	_, c := e.login(t, nil)
	s, err := e.m.Load(ctx, reqWith(c))
	if err != nil || s.UserID() != e.user.ID || s.User.DisplayName != "Alice" {
		t.Fatal(err)
	}
	// Activity within the idle window keeps it alive, up to the absolute limit.
	for range 16 {
		e.clk.Add(29 * time.Minute)
		if _, err := e.m.Load(ctx, reqWith(c)); err != nil {
			t.Fatalf("idle-refreshed session died early at %v: %v", e.clk.Now(), err)
		}
	}
	e.clk.Add(29 * time.Minute) // now past 8 h since login
	if _, err := e.m.Load(ctx, reqWith(c)); !errors.Is(err, ErrNoSession) {
		t.Fatal("absolute timeout not enforced")
	}

	_, c = e.login(t, nil)
	e.clk.Add(31 * time.Minute)
	if _, err := e.m.Load(ctx, reqWith(c)); !errors.Is(err, ErrNoSession) {
		t.Fatal("idle timeout not enforced")
	}
	// The expired row was deleted.
	if _, err := e.st.SessionByHash(ctx, ids.Hash(c.Value)); !errors.Is(err, store.ErrNotFound) {
		t.Error("expired session not deleted")
	}
}

func TestTouchThrottled(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{})
	ctx := t.Context()
	_, c := e.login(t, nil)
	e.clk.Add(30 * time.Second)
	_, _ = e.m.Load(ctx, reqWith(c))
	rec, _ := e.st.SessionByHash(ctx, ids.Hash(c.Value))
	if !rec.LastSeenAt.Equal(rec.CreatedAt) {
		t.Error("touched before throttle interval")
	}
	e.clk.Add(31 * time.Second)
	_, _ = e.m.Load(ctx, reqWith(c))
	rec, _ = e.st.SessionByHash(ctx, ids.Hash(c.Value))
	if rec.LastSeenAt.Equal(rec.CreatedAt) {
		t.Error("not touched after throttle interval")
	}
}

func TestRejectsMalformedAndDuplicateCookies(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{})
	ctx := t.Context()
	_, c := e.login(t, nil)
	for _, v := range []string{"", "x", c.Value + "A", c.Value[:42], c.Value[:42] + "!"} {
		if _, err := e.m.Load(ctx, reqWith(&http.Cookie{Name: CookieName, Value: v})); !errors.Is(err, ErrNoSession) {
			t.Errorf("value %q accepted", v)
		}
	}
	r := reqWith(c)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: ids.NewSecret()})
	if _, err := e.m.Load(ctx, r); !errors.Is(err, ErrNoSession) {
		t.Error("duplicate cookies accepted")
	}
}

func TestCreateDestroysPreviousSession(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{})
	ctx := t.Context()
	_, c1 := e.login(t, nil)
	_, c2 := e.login(t, reqWith(c1))
	if c1.Value == c2.Value {
		t.Fatal("ID not rotated at login")
	}
	if _, err := e.m.Load(ctx, reqWith(c1)); !errors.Is(err, ErrNoSession) {
		t.Error("pre-login session survived login (fixation)")
	}
	if _, err := e.m.Load(ctx, reqWith(c2)); err != nil {
		t.Error(err)
	}
}

func TestRefreshTokenBoundToSession(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{})
	ctx := t.Context()
	a, _ := e.login(t, nil)
	b, _ := e.login(t, nil)
	// Copy a's ciphertext into b's row: it must not decrypt under b's ID.
	b.rec.RefreshTokenEnc = a.rec.RefreshTokenEnc
	if _, err := e.m.RefreshToken(b); err == nil {
		t.Error("refresh token ciphertext not bound to session ID")
	}
	if err := e.m.Revalidated(ctx, a, "rt-2"); err != nil {
		t.Fatal(err)
	}
	re, _ := e.m.Reload(ctx, a)
	if rt, _ := e.m.RefreshToken(re); rt != "rt-2" {
		t.Errorf("rotated refresh token not stored: %q", rt)
	}
	if err := e.m.Revalidated(ctx, re, ""); err != nil {
		t.Fatal(err)
	}
	re, _ = e.m.Reload(ctx, a)
	if rt, _ := e.m.RefreshToken(re); rt != "rt-2" {
		t.Error("empty refresh token replaced the stored one")
	}
}

func TestDisabledUserRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{})
	ctx := t.Context()
	_, c := e.login(t, nil)
	if _, err := e.st.DB().W.ExecContext(ctx, `UPDATE users SET disabled_at = 1 WHERE id = ?`, e.user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Load(ctx, reqWith(c)); !errors.Is(err, ErrNoSession) {
		t.Error("disabled user's session accepted")
	}
}

func TestMiddleware(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{})
	_, c := e.login(t, nil)
	var got *Session
	h := e.m.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = FromContext(r.Context())
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, reqWith(c))
	if got == nil || got.UserID() != e.user.ID {
		t.Fatal("session not in context")
	}
	got = nil
	w = httptest.NewRecorder()
	h.ServeHTTP(w, reqWith(&http.Cookie{Name: CookieName, Value: ids.NewSecret()}))
	if got != nil {
		t.Fatal("unknown session in context")
	}
	if cl := sessionCookie(t, w); cl.MaxAge >= 0 {
		t.Error("stale cookie not cleared")
	}
}

func TestDestroyAndCleanup(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{})
	ctx := t.Context()
	s, c := e.login(t, nil)
	w := httptest.NewRecorder()
	if err := e.m.Destroy(ctx, w, s); err != nil {
		t.Fatal(err)
	}
	if sessionCookie(t, w).MaxAge >= 0 {
		t.Error("cookie not cleared")
	}
	if _, err := e.m.Load(ctx, reqWith(c)); !errors.Is(err, ErrNoSession) {
		t.Error("destroyed session usable")
	}
	e.login(t, nil)
	e.login(t, nil)
	e.clk.Add(time.Hour)
	if n, err := e.m.Cleanup(ctx); err != nil || n != 2 {
		t.Errorf("cleanup: %d %v", n, err)
	}
}
