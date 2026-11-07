package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/scttpr/dropr/internal/ids"
	"github.com/scttpr/dropr/internal/store"
	"github.com/scttpr/dropr/internal/store/storetest"
)

// fileOwner provisions an account for the file tests.
func fileOwner(t *testing.T, st *store.Store, sub string) string {
	t.Helper()
	u, _, err := st.ProvisionUser(t.Context(), "https://iss", sub, "Owner", t0)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func newShare(owner string) *store.NewShare {
	return &store.NewShare{OwnerID: owner, Size: 16, Parts: 1, Meta: make([]byte, 20),
		ExpiresAt: t0.Add(24 * time.Hour), TokenHash: ids.Hash(ids.NewSecret()), DefaultQuota: 1 << 40}
}

func newRequestFile(requestID string) *store.NewRequestFile {
	return &store.NewRequestFile{RequestID: requestID, Size: 16, Parts: 1, Meta: make([]byte, 20),
		WrappedKey: make([]byte, 80), TokenHash: ids.Hash(ids.NewSecret()), DefaultQuota: 1 << 40}
}

// Audit 2026-11b M-2: one request link, and one owner, can hold only so many
// uploads in progress; finishing one frees its place.
func TestOpenUploadCaps(t *testing.T) {
	t.Parallel()
	st := storetest.New(t)
	ctx := t.Context()
	owner := fileOwner(t, st, "caps")
	rq := &store.Request{OwnerID: owner, ExpiresAt: t0.Add(24 * time.Hour), MaxFiles: 1000, MaxBytes: 1 << 40, CreatedAt: t0}
	if err := st.CreateRequest(ctx, rq); err != nil {
		t.Fatal(err)
	}
	var first string
	for i := range store.MaxOpenUploadsPerRequest {
		id, err := st.CreateRequestFile(ctx, newRequestFile(rq.ID), t0)
		if err != nil {
			t.Fatalf("upload %d: %v", i, err)
		}
		if first == "" {
			first = id
		}
	}
	if _, err := st.CreateRequestFile(ctx, newRequestFile(rq.ID), t0); !errors.Is(err, store.ErrTooMany) {
		t.Fatalf("one upload past the per-link cap: %v", err)
	}
	u, err := st.UploadByID(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteUpload(ctx, u, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateRequestFile(ctx, newRequestFile(rq.ID), t0); err != nil {
		t.Fatalf("after one upload finished: %v", err)
	}

	// The owner's cap counts share uploads and request uploads together.
	for i := store.MaxOpenUploadsPerRequest; i < store.MaxOpenUploadsPerOwner; i++ {
		if _, _, err := st.CreateShare(ctx, newShare(owner), t0); err != nil {
			t.Fatalf("share %d: %v", i, err)
		}
	}
	if _, _, err := st.CreateShare(ctx, newShare(owner), t0); !errors.Is(err, store.ErrTooMany) {
		t.Fatalf("share past the per-owner cap: %v", err)
	}
	other := &store.Request{OwnerID: owner, ExpiresAt: t0.Add(24 * time.Hour), MaxFiles: 10, MaxBytes: 1 << 20, CreatedAt: t0}
	if err := st.CreateRequest(ctx, other); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateRequestFile(ctx, newRequestFile(other.ID), t0); !errors.Is(err, store.ErrTooMany) {
		t.Fatalf("request upload past the per-owner cap: %v", err)
	}
	// Another owner is not affected.
	if _, _, err := st.CreateShare(ctx, newShare(fileOwner(t, st, "other")), t0); err != nil {
		t.Fatalf("other owner: %v", err)
	}
}

// Audit 2026-11b M-3: an owner's live share and request links are capped;
// expired ones do not count.
func TestLiveLinkCaps(t *testing.T) {
	t.Parallel()
	st := storetest.New(t)
	ctx := t.Context()
	owner := fileOwner(t, st, "links")
	w := st.DB().W
	// Fill up to the caps directly; the last row of each is already expired.
	if _, err := w.ExecContext(ctx, `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?2)
		INSERT INTO requests (id, owner_id, expires_at, max_files, max_bytes, single_use, created_at)
		SELECT printf('r%021d', i), ?1, CASE WHEN i = ?2 THEN ?3 ELSE ?4 END, 1, 16, 0, ?3 FROM n`,
		owner, store.MaxLiveRequests, t0.Unix(), t0.Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ExecContext(ctx, `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?2)
		INSERT INTO blobs (id, owner_id, parts, size, complete, upload_token_hash, created_at)
		SELECT printf('b%021d', i), ?1, 1, 16, 1, NULL, ?3 FROM n`,
		owner, store.MaxLiveShares, t0.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ExecContext(ctx, `INSERT INTO shares (id, owner_id, blob_id, size, meta, expires_at, max_downloads, created_at)
		SELECT 's' || substr(id, 2), owner_id, id, 16, x'00', CASE WHEN id = printf('b%021d', ?2) THEN ?3 ELSE ?4 END, NULL, ?3
		FROM blobs WHERE owner_id = ?1`, owner, store.MaxLiveShares, t0.Unix(), t0.Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	rq := func() *store.Request {
		return &store.Request{OwnerID: owner, ExpiresAt: t0.Add(2 * time.Hour), MaxFiles: 1, MaxBytes: 16, CreatedAt: t0}
	}
	// One place is left: the expired row does not count.
	if err := st.CreateRequest(ctx, rq()); err != nil {
		t.Fatalf("last request link: %v", err)
	}
	if err := st.CreateRequest(ctx, rq()); !errors.Is(err, store.ErrTooMany) {
		t.Fatalf("request link past the cap: %v", err)
	}
	if _, _, err := st.CreateShare(ctx, newShare(owner), t0); err != nil {
		t.Fatalf("last share: %v", err)
	}
	if _, _, err := st.CreateShare(ctx, newShare(owner), t0); !errors.Is(err, store.ErrTooMany) {
		t.Fatalf("share past the cap: %v", err)
	}
}

// Audit 2026-11b A01-2 and I1: an inbox token used without its owner is
// refused before anything is spent, and a share use that serves nothing
// (unsatisfiable Range) does not count a download.
func TestUseDownloadTokenChecksFirst(t *testing.T) {
	t.Parallel()
	st := storetest.New(t)
	ctx := t.Context()
	owner := fileOwner(t, st, "dl")
	rq := &store.Request{OwnerID: owner, ExpiresAt: t0.Add(24 * time.Hour), MaxFiles: 1, MaxBytes: 16, CreatedAt: t0}
	if err := st.CreateRequest(ctx, rq); err != nil {
		t.Fatal(err)
	}
	blobID, err := st.CreateRequestFile(ctx, newRequestFile(rq.ID), t0)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := st.UploadByID(ctx, blobID)
	if err := st.CompleteUpload(ctx, u, t0); err != nil {
		t.Fatal(err)
	}
	files, err := st.InboxByOwner(ctx, owner, t0)
	if err != nil || len(files) != 1 {
		t.Fatal(len(files), err)
	}
	inboxTok := ids.Hash(ids.NewSecret())
	if err := st.CreateInboxToken(ctx, owner, files[0].ID, inboxTok, t0); err != nil {
		t.Fatal(err)
	}
	full := func(size int64) int64 { return size }
	for _, viewer := range []string{"", fileOwner(t, st, "stranger")} {
		for range 5 {
			if _, err := st.UseDownloadToken(ctx, inboxTok, viewer, true, full, t0); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("inbox token used by %q: %v", viewer, err)
			}
		}
	}
	var served int64
	if err := st.DB().R.QueryRowContext(ctx, `SELECT served_bytes FROM dl_tokens WHERE token_hash = ?`, inboxTok).Scan(&served); err != nil || served != 0 {
		t.Fatalf("refused uses spent %d bytes (%v)", served, err)
	}
	if tg, err := st.UseDownloadToken(ctx, inboxTok, owner, true, full, t0); err != nil || tg.Reserved != 16 {
		t.Fatalf("owner: %+v %v", tg, err)
	}

	one := int64(1)
	n := newShare(owner)
	n.MaxDownloads = &one
	shareID, shareBlob, err := st.CreateShare(ctx, n, t0)
	if err != nil {
		t.Fatal(err)
	}
	u, _ = st.UploadByID(ctx, shareBlob)
	if err := st.CompleteUpload(ctx, u, t0); err != nil {
		t.Fatal(err)
	}
	tok := ids.Hash(ids.NewSecret())
	if _, err := st.CreateShareToken(ctx, shareID, tok, t0); err != nil {
		t.Fatal(err)
	}
	nothing := func(int64) int64 { return 0 }
	if _, err := st.UseDownloadToken(ctx, tok, "", true, nothing, t0); err != nil {
		t.Fatal(err)
	}
	sh, err := st.ShareByID(ctx, shareID)
	if err != nil || sh.DownloadCount != 0 {
		t.Fatalf("a use serving nothing counted: %d (%v)", sh.DownloadCount, err)
	}
	if _, err := st.UseDownloadToken(ctx, tok, "", true, full, t0); err != nil {
		t.Fatal(err)
	}
	if sh, _ := st.ShareByID(ctx, shareID); sh.DownloadCount != 1 {
		t.Fatalf("a full download did not count: %d", sh.DownloadCount)
	}
}

// completeShare creates a share of owner and completes its upload.
func completeShare(t *testing.T, st *store.Store, owner string) string {
	t.Helper()
	shareID, blobID, err := st.CreateShare(t.Context(), newShare(owner), t0)
	if err != nil {
		t.Fatal(err)
	}
	u, err := st.UploadByID(t.Context(), blobID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CompleteUpload(t.Context(), u, t0); err != nil {
		t.Fatal(err)
	}
	return shareID
}

// Audit 2026-11b L-2: losing access (role withdrawn, revoke, disable)
// expires the owner's share links for good, deletes their download tokens
// and stops their share uploads in progress; request links only pause, and
// a later login reopens them but not the shares.
func TestLosingAccessExpiresShares(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	for _, c := range []struct {
		name string
		lose func(st *store.Store, owner string) error
	}{
		{"role withdrawn", func(st *store.Store, _ string) error {
			return st.MarkAccessLost(ctx, "https://iss", "lose", t0)
		}},
		{"revoke", func(st *store.Store, owner string) error {
			_, err := st.RevokeUser(ctx, owner, t0)
			return err
		}},
		{"disable", func(st *store.Store, owner string) error {
			_, _, err := st.DisableUser(ctx, owner, t0)
			return err
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			st := storetest.New(t)
			owner := fileOwner(t, st, "lose")
			other := fileOwner(t, st, "keep")
			shareID := completeShare(t, st, owner)
			otherShare := completeShare(t, st, other)
			tok := ids.Hash(ids.NewSecret())
			if _, err := st.CreateShareToken(ctx, shareID, tok, t0); err != nil {
				t.Fatal(err)
			}
			_, pending, err := st.CreateShare(ctx, newShare(owner), t0)
			if err != nil {
				t.Fatal(err)
			}
			rq := &store.Request{OwnerID: owner, ExpiresAt: t0.Add(24 * time.Hour), MaxFiles: 10, MaxBytes: 1 << 20, CreatedAt: t0}
			if err := st.CreateRequest(ctx, rq); err != nil {
				t.Fatal(err)
			}

			if err := c.lose(st, owner); err != nil {
				t.Fatal(err)
			}
			now := t0.Add(time.Second)
			sh, err := st.ShareByID(ctx, shareID)
			if err != nil || sh.ExpiresAt.After(t0) || sh.OwnerActive {
				t.Fatalf("share after losing access: %+v %v", sh, err)
			}
			if _, err := st.CreateShareToken(ctx, shareID, ids.Hash(ids.NewSecret()), now); !errors.Is(err, store.ErrExpired) {
				t.Errorf("token for an expired share: %v", err)
			}
			if _, err := st.UseDownloadToken(ctx, tok, "", true, nil, now); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("outstanding download token: %v", err)
			}
			up, err := st.UploadByID(ctx, pending)
			if err != nil || up.OwnerActive || up.ExpiresAt.After(t0) {
				t.Fatalf("share upload after losing access: %+v %v", up, err)
			}
			if err := st.CompleteUpload(ctx, up, now); !errors.Is(err, store.ErrExpired) {
				t.Errorf("finalize of a share upload after losing access: %v", err)
			}
			if _, err := st.CreateRequestFile(ctx, newRequestFile(rq.ID), now); !errors.Is(err, store.ErrClosed) {
				t.Errorf("request link while access is lost: %v", err)
			}
			// Other owners are untouched.
			if sh, err := st.ShareByID(ctx, otherShare); err != nil || !sh.ExpiresAt.After(now) || !sh.OwnerActive {
				t.Errorf("another owner's share: %+v %v", sh, err)
			}

			if c.name == "disable" {
				if _, err := st.EnableUser(ctx, owner); err != nil {
					t.Fatal(err)
				}
			}
			// Signing in again reopens the request link, not the share.
			if _, _, err := st.ProvisionUser(ctx, "https://iss", "lose", "Owner", now); err != nil {
				t.Fatal(err)
			}
			if _, err := st.CreateRequestFile(ctx, newRequestFile(rq.ID), now); err != nil {
				t.Errorf("request link after signing in again: %v", err)
			}
			if _, err := st.CreateShareToken(ctx, shareID, ids.Hash(ids.NewSecret()), now); !errors.Is(err, store.ErrExpired) {
				t.Errorf("share came back after signing in again: %v", err)
			}
			if _, _, err := st.CreateShare(ctx, newShare(owner), now); err != nil {
				t.Errorf("new share after signing in again: %v", err)
			}
		})
	}
}

// Audit 2026-11b L-2, defense in depth: a share whose owner is marked
// disabled or as having lost access is refused at every step even if it
// escaped expireOwnerShares (here: the flag is set directly).
func TestInactiveOwnerShareRefused(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	for _, col := range []string{"disabled_at", "access_lost_at"} {
		t.Run(col, func(t *testing.T) {
			t.Parallel()
			st := storetest.New(t)
			owner := fileOwner(t, st, "o")
			shareID := completeShare(t, st, owner)
			tok := ids.Hash(ids.NewSecret())
			if _, err := st.CreateShareToken(ctx, shareID, tok, t0); err != nil {
				t.Fatal(err)
			}
			_, pending, err := st.CreateShare(ctx, newShare(owner), t0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.DB().W.ExecContext(ctx, `UPDATE users SET `+col+` = ? WHERE id = ?`, t0.Unix(), owner); err != nil {
				t.Fatal(err)
			}
			if sh, err := st.ShareByID(ctx, shareID); err != nil || sh.OwnerActive || !sh.ExpiresAt.After(t0) {
				t.Fatalf("share: %+v %v", sh, err)
			}
			if _, err := st.CreateShareToken(ctx, shareID, ids.Hash(ids.NewSecret()), t0); !errors.Is(err, store.ErrExpired) {
				t.Errorf("token issue: %v", err)
			}
			if _, err := st.UseDownloadToken(ctx, tok, "", true, nil, t0); !errors.Is(err, store.ErrExpired) {
				t.Errorf("token use: %v", err)
			}
			up, err := st.UploadByID(ctx, pending)
			if err != nil || up.OwnerActive {
				t.Fatalf("upload: %+v %v", up, err)
			}
			if err := st.CompleteUpload(ctx, up, t0); !errors.Is(err, store.ErrExpired) {
				t.Errorf("finalize: %v", err)
			}
			if _, _, err := st.CreateShare(ctx, newShare(owner), t0); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("new share: %v", err)
			}
		})
	}
}

// Audit 2026-11b L-3: disable and enable are idempotent and report unknown
// accounts; enable clears disabled_at only.
func TestDisableEnableUser(t *testing.T) {
	t.Parallel()
	st := storetest.New(t)
	ctx := t.Context()
	owner := fileOwner(t, st, "d")
	if err := st.CreateSession(ctx, &store.Session{IDHash: ids.Hash(ids.NewSecret()), UserID: owner, CreatedAt: t0, LastSeenAt: t0, RevalidatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if n, was, err := st.DisableUser(ctx, owner, t0); err != nil || n != 1 || was {
		t.Fatalf("disable: %d %v %v", n, was, err)
	}
	if n, was, err := st.DisableUser(ctx, owner, t0.Add(time.Hour)); err != nil || n != 0 || !was {
		t.Fatalf("disable again: %d %v %v", n, was, err)
	}
	if u, _ := st.UserByID(ctx, owner); u.DisabledAt == nil || !u.DisabledAt.Equal(t0) {
		t.Errorf("disabled_at: %v", u.DisabledAt)
	}
	// A login does not lift a disable.
	if u, _, err := st.ProvisionUser(ctx, "https://iss", "d", "Owner", t0); err != nil || u.DisabledAt == nil {
		t.Errorf("login lifted the disable: %+v %v", u, err)
	}
	if active, err := st.AccountActive(ctx, owner); err != nil || active {
		t.Errorf("disabled account active: %v %v", active, err)
	}
	if was, err := st.EnableUser(ctx, owner); err != nil || !was {
		t.Fatalf("enable: %v %v", was, err)
	}
	if was, err := st.EnableUser(ctx, owner); err != nil || was {
		t.Fatalf("enable again: %v %v", was, err)
	}
	if active, err := st.AccountActive(ctx, owner); err != nil || !active {
		t.Errorf("enabled account inactive: %v %v", active, err)
	}
	if _, _, err := st.DisableUser(ctx, ids.New(), t0); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("disable unknown: %v", err)
	}
	if _, err := st.EnableUser(ctx, ids.New()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("enable unknown: %v", err)
	}
	if _, err := st.RevokeUser(ctx, ids.New(), t0); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("revoke unknown: %v", err)
	}
}
