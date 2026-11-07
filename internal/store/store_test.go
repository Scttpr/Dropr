package store_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/scttpr/dropr/internal/ids"
	"github.com/scttpr/dropr/internal/store"
	"github.com/scttpr/dropr/internal/store/storetest"
)

var t0 = time.Unix(1_700_000_000, 0).UTC()

func TestProvisionUser(t *testing.T) {
	t.Parallel()
	st := storetest.New(t)
	ctx := t.Context()
	u, created, err := st.ProvisionUser(ctx, "https://iss", "sub1", "  Alice\x00\n ", t0)
	if err != nil || !created || u.DisplayName != "Alice" || !ids.Valid(u.ID) {
		t.Fatalf("%+v %v %v", u, created, err)
	}
	u2, created, err := st.ProvisionUser(ctx, "https://iss", "sub1", "Alice B", t0.Add(time.Hour))
	if err != nil || created || u2.ID != u.ID || u2.DisplayName != "Alice B" {
		t.Fatalf("%+v %v %v", u2, created, err)
	}
	// Same subject, different issuer: a different account.
	u3, created, err := st.ProvisionUser(ctx, "https://other", "sub1", "x", t0)
	if err != nil || !created || u3.ID == u.ID {
		t.Fatal("issuer not part of identity")
	}
	long := strings.Repeat("é", 300)
	u4, _, err := st.ProvisionUser(ctx, "https://iss", "sub2", long, t0)
	if err != nil || len(u4.DisplayName) > 200 || !strings.HasPrefix(long, u4.DisplayName) {
		t.Fatalf("display name not bounded: %d", len(u4.DisplayName))
	}
	if _, _, err := st.ProvisionUser(ctx, "", "s", "", t0); err == nil {
		t.Error("empty issuer accepted")
	}

	got, err := st.FindUser(ctx, u.ID)
	if err != nil || got.ID != u.ID {
		t.Fatal(err)
	}
	if _, err := st.FindUser(ctx, "sub1"); err == nil {
		t.Error("ambiguous subject resolved")
	}
	if got, err := st.FindUser(ctx, "sub2"); err != nil || got.ID != u4.ID {
		t.Error(err)
	}
	if _, err := st.FindUser(ctx, "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Error(err)
	}
	list, err := st.ListUsers(ctx)
	if err != nil || len(list) != 3 {
		t.Fatal(len(list), err)
	}
}

// Audit 2026-11 A03-1: the display name is shown to anonymous uploaders, so
// bidi controls, invisible fillers and C1 controls are removed.
func TestDisplayNameSanitized(t *testing.T) {
	t.Parallel()
	st := storetest.New(t)
	ctx := t.Context()
	r := func(cps ...rune) string { return string(cps) }
	for i, c := range []struct{ in, want string }{
		{"Payroll" + r(0x202e) + "Dept", "PayrollDept"},                                                      // RLO
		{r(0x2066) + "Bob" + r(0x2069, ' ', 0x200f), "Bob"},                                                  // isolates, RLM
		{"A" + r(0x200b) + "l" + r(0xad) + "i" + r(0xfeff) + "ce", "Alice"},                                  // ZWSP, soft hyphen, BOM
		{"Bob" + r(0x3164, 0x2800, 0x115f), "Bob"},                                                           // Hangul fillers, Braille blank
		{"Bob" + r(0x85, 0x9b) + "31m", "Bob31m"},                                                            // C1 (NEL, CSI)
		{"Bob" + r(0x061c, 0x2028, 0x2029), "Bob"},                                                           // ALM, line/paragraph separators
		{" Ada" + r(0xa0, 0x2003, 0x3000) + " Lovelace" + r(0x2003), "Ada Lovelace"},                         // space runs collapse
		{r(0x1f469, 0x200d, 0x1f4bb) + " Dev" + r(0xfe0f), r(0x1f469, 0x200d, 0x1f4bb) + " Dev" + r(0xfe0f)}, // ZWJ, variation selector kept
		{"Zo" + r(0xeb, ' ', 0x3a9, ' ', 0x674e), "Zo" + r(0xeb, ' ', 0x3a9, ' ', 0x674e)},
	} {
		u, _, err := st.ProvisionUser(ctx, "https://iss", "san-"+string(rune('a'+i)), c.in, t0)
		if err != nil {
			t.Fatal(err)
		}
		if u.DisplayName != c.want {
			t.Errorf("%q: got %q, want %q", c.in, u.DisplayName, c.want)
		}
	}
}

func newSession(userID string) *store.Session {
	return &store.Session{
		IDHash: ids.Hash(ids.NewSecret()), UserID: userID, OIDCSID: "sid-1",
		CreatedAt: t0, LastSeenAt: t0, RevalidatedAt: t0, RefreshTokenEnc: []byte("enc"),
	}
}

func TestSessions(t *testing.T) {
	t.Parallel()
	st := storetest.New(t)
	ctx := t.Context()
	u, _, _ := st.ProvisionUser(ctx, "i", "s", "", t0)
	s := newSession(u.ID)
	if err := st.CreateSession(ctx, s); err != nil {
		t.Fatal(err)
	}
	got, err := st.SessionByHash(ctx, s.IDHash)
	if err != nil || got.OIDCSID != "sid-1" || !got.CreatedAt.Equal(t0) {
		t.Fatalf("%+v %v", got, err)
	}

	if err := st.UpdateSessionRevalidation(ctx, s.IDHash, nil, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ = st.SessionByHash(ctx, s.IDHash)
	if string(got.RefreshTokenEnc) != "enc" || !got.RevalidatedAt.Equal(t0.Add(time.Hour)) {
		t.Errorf("nil token must keep the stored one: %+v", got)
	}
	if err := st.UpdateSessionRevalidation(ctx, s.IDHash, []byte("new"), t0); err != nil {
		t.Fatal(err)
	}
	got, _ = st.SessionByHash(ctx, s.IDHash)
	if string(got.RefreshTokenEnc) != "new" {
		t.Error("token not replaced")
	}

	if n, err := st.DeleteSessionsByOIDCSID(ctx, "sid-1"); err != nil || n != 1 {
		t.Errorf("by sid: %d %v", n, err)
	}
	if n, _ := st.DeleteSessionsByOIDCSID(ctx, ""); n != 0 {
		t.Error("empty sid matched")
	}

	// Expiry.
	old := newSession(u.ID)
	old.LastSeenAt = t0.Add(-time.Hour)
	fresh := newSession(u.ID)
	fresh.LastSeenAt = t0.Add(time.Hour)
	ancient := newSession(u.ID)
	ancient.CreatedAt = t0.Add(-9 * time.Hour)
	ancient.LastSeenAt = t0.Add(time.Hour)
	for _, x := range []*store.Session{old, fresh, ancient} {
		if err := st.CreateSession(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	n, err := st.DeleteExpiredSessions(ctx, t0.Add(-30*time.Minute), t0.Add(-8*time.Hour))
	if err != nil || n != 2 {
		t.Fatalf("expired: %d %v", n, err)
	}
	if _, err := st.SessionByHash(ctx, fresh.IDHash); err != nil {
		t.Error("fresh session deleted")
	}
	if n, _ := st.DeleteUserSessions(ctx, u.ID); n != 1 {
		t.Error("user sessions")
	}
}

func TestPurge(t *testing.T) {
	t.Parallel()
	st := storetest.New(t)
	ctx := t.Context()
	u, _, _ := st.ProvisionUser(ctx, "i", "s", "", t0)
	w := st.DB().W
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := w.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	rid, bid, iid := ids.New(), ids.New(), ids.New()
	mustExec(`INSERT INTO requests (id, owner_id, expires_at, max_files, max_bytes, created_at) VALUES (?, ?, 0, 1, 1, 0)`, rid, u.ID)
	mustExec(`INSERT INTO blobs (id, owner_id, parts, size, created_at) VALUES (?, ?, 1, 1, 0)`, bid, u.ID)
	mustExec(`INSERT INTO inbox (id, request_id, owner_id, blob_id, size, meta, wrapped_key, created_at) VALUES (?, ?, ?, ?, 1, x'01', ?, 0)`, iid, rid, u.ID, bid, make([]byte, 80))
	if err := st.CreateSession(ctx, newSession(u.ID)); err != nil {
		t.Fatal(err)
	}
	if blobs, err := st.DeleteUser(ctx, u.ID); err != nil || len(blobs) != 1 || blobs[0] != bid {
		t.Fatal(blobs, err)
	}
	for _, tbl := range []string{"users", "requests", "inbox", "blobs", "sessions"} {
		var n int
		_ = st.DB().R.QueryRowContext(ctx, "SELECT count(*) FROM "+tbl).Scan(&n) //nolint:gosec // fixed names
		if n != 0 {
			t.Errorf("%s not wiped", tbl)
		}
	}
	if _, err := st.DeleteUser(ctx, u.ID); !errors.Is(err, store.ErrNotFound) {
		t.Error(err)
	}
}

func TestMigrateIdentities(t *testing.T) {
	t.Parallel()
	st := storetest.New(t)
	ctx := t.Context()
	a, _, _ := st.ProvisionUser(ctx, "old", "a", "", t0)
	b, _, _ := st.ProvisionUser(ctx, "old", "b", "", t0)
	_, _, _ = st.ProvisionUser(ctx, "new", "taken", "", t0)
	_ = st.CreateSession(ctx, newSession(a.ID))

	// Conflict aborts everything.
	_, err := st.MigrateIdentities(ctx, "old", "new", []store.IdentityMapping{{"a", "A"}, {"b", "taken"}})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("got %v", err)
	}
	if u, _ := st.UserByID(ctx, a.ID); u.Issuer != "old" {
		t.Error("partial migration applied")
	}
	if _, err := st.MigrateIdentities(ctx, "old", "new", []store.IdentityMapping{{"zzz", "Z"}}); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
	n, err := st.MigrateIdentities(ctx, "old", "new", []store.IdentityMapping{{"a", "A"}, {"b", "B"}})
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
	u, _ := st.UserByIdentity(ctx, "new", "A")
	if u == nil || u.ID != a.ID {
		t.Error("ID not preserved")
	}
	if u, _ := st.UserByIdentity(ctx, "new", "B"); u == nil || u.ID != b.ID {
		t.Error("b not migrated")
	}
	list, _ := st.ListUsers(ctx)
	for _, us := range list {
		if us.ID == a.ID && us.Sessions != 0 {
			t.Error("sessions survived migration")
		}
	}
}
