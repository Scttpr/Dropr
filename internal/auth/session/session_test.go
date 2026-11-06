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

func TestRotateAndUnlock(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{})
	ctx := t.Context()
	s, c := e.login(t, nil)
	if e.m.IsUnlocked(s) {
		t.Fatal("unlocked at login")
	}
	e.clk.Add(10 * time.Minute)
	w := httptest.NewRecorder()
	s2, err := e.m.MarkUnlocked(ctx, w, s)
	if err != nil {
		t.Fatal(err)
	}
	c2 := sessionCookie(t, w)
	if c2.Value == c.Value {
		t.Fatal("ID not rotated at unlock")
	}
	if _, err := e.m.Load(ctx, reqWith(c)); !errors.Is(err, ErrNoSession) {
		t.Error("old ID still valid after rotation")
	}
	loaded, err := e.m.Load(ctx, reqWith(c2))
	if err != nil {
		t.Fatal(err)
	}
	if !e.m.IsUnlocked(loaded) || !e.m.IsUnlocked(s2) {
		t.Error("not unlocked after MarkUnlocked")
	}
	if !loaded.CreatedAt().Equal(s.CreatedAt()) {
		t.Error("rotation reset the absolute lifetime")
	}
	// The refresh token moved with the rotation (re-bound to the new ID).
	rt, err := e.m.RefreshToken(loaded)
	if err != nil || rt != "rt-1" {
		t.Fatalf("refresh token after rotation: %q %v", rt, err)
	}
	// Rotating the dead session fails.
	if _, err := e.m.Rotate(ctx, httptest.NewRecorder(), s, nil); !errors.Is(err, ErrNoSession) {
		t.Errorf("rotating dead session: %v", err)
	}
}

// Audit L-5: a revalidation that stored a rotated refresh token after the
// session was loaded must not be undone by a rotation working from the
// stale in-memory copy.
func TestRotateKeepsConcurrentlyRefreshedToken(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{})
	ctx := t.Context()
	s, _ := e.login(t, nil)
	staleRec := *s.rec // the copy loaded by request A
	// Request B revalidates and the provider rotates the refresh token.
	if err := e.m.Revalidated(ctx, s, "rt-2"); err != nil {
		t.Fatal(err)
	}
	// Request A unlocks (rotates) from its stale copy.
	w := httptest.NewRecorder()
	if _, err := e.m.MarkUnlocked(ctx, w, &Session{rec: &staleRec, User: s.User}); err != nil {
		t.Fatal(err)
	}
	loaded, err := e.m.Load(ctx, reqWith(sessionCookie(t, w)))
	if err != nil {
		t.Fatal(err)
	}
	if rt, err := e.m.RefreshToken(loaded); err != nil || rt != "rt-2" {
		t.Fatalf("refresh token after rotation: %q %v (want the refreshed rt-2)", rt, err)
	}
}

// Audit L-5: rotation waits for a revalidation holding the session lock.
func TestRotateWaitsForSessionLock(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{})
	ctx := t.Context()
	s, _ := e.login(t, nil)
	unlock := e.m.Lock(s)
	done := make(chan error, 1)
	go func() {
		_, err := e.m.MarkUnlocked(ctx, httptest.NewRecorder(), s)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("rotation did not wait for the session lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := e.m.Revalidated(ctx, s, "rt-3"); err != nil {
		t.Fatal(err)
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestUnlockMaxAge(t *testing.T) {
	t.Parallel()
	e := newEnv(t, Config{UnlockMaxAge: 5 * time.Minute})
	ctx := t.Context()
	s, _ := e.login(t, nil)
	s, err := e.m.MarkUnlocked(ctx, httptest.NewRecorder(), s)
	if err != nil {
		t.Fatal(err)
	}
	e.clk.Add(4 * time.Minute)
	if !e.m.IsUnlocked(s) {
		t.Error("unlock expired early")
	}
	e.clk.Add(2 * time.Minute)
	if e.m.IsUnlocked(s) {
		t.Error("unlock outlived UnlockMaxAge")
	}
	if e.m.IsUnlocked(nil) {
		t.Error("nil session unlocked")
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
