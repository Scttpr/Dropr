package store

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/scttpr/dropr/internal/ids"
)

// Link and upload errors.
var (
	// ErrExpired means the link or token has expired.
	ErrExpired = errors.New("store: expired")
	// ErrExhausted means a share link reached its download limit.
	ErrExhausted = errors.New("store: download limit reached")
	// ErrClosed means a single-use request link already received its file.
	ErrClosed = errors.New("store: link closed")
	// ErrFull means a request link's file or byte cap would be exceeded.
	ErrFull = errors.New("store: link full")
	// ErrQuota means the owner's storage quota would be exceeded.
	ErrQuota = errors.New("store: quota exceeded")
	// ErrBadToken means an upload token does not match.
	ErrBadToken = errors.New("store: bad token")
	// ErrTokenSpent means a download token served its whole byte budget.
	ErrTokenSpent = errors.New("store: download token used up")
	// ErrComplete means the upload is already finalized.
	ErrComplete = errors.New("store: upload already complete")
)

// Blob is the database row of an upload.
type Blob struct {
	ID              string
	OwnerID         string
	Parts           int
	Size            int64 // ciphertext bytes
	Complete        bool
	UploadTokenHash []byte
	CreatedAt       time.Time
}

// Share is a share link (flow A).
type Share struct {
	ID            string
	OwnerID       string
	BlobID        string
	Size          int64
	Parts         int
	Meta          []byte
	ExpiresAt     time.Time
	MaxDownloads  *int64
	DownloadCount int64
	CreatedAt     time.Time
	Complete      bool
}

// Request is a request link (flow B).
type Request struct {
	ID            string
	OwnerID       string
	ExpiresAt     time.Time
	MaxFiles      int64
	MaxBytes      int64 // ciphertext bytes
	SingleUse     bool
	FilesReceived int64
	BytesReceived int64 // ciphertext bytes, reserved at file creation
	LabelMeta     []byte
	ClosedAt      *time.Time
	CreatedAt     time.Time
}

// InboxFile is a file received through a request link.
type InboxFile struct {
	ID         string
	RequestID  string
	OwnerID    string
	BlobID     string
	Size       int64
	Parts      int
	Meta       []byte
	WrappedKey []byte
	CreatedAt  time.Time
}

// quotaCheck fails with ErrQuota if owner cannot store size more bytes.
// Every blob counts, complete or still uploading, whichever link it came
// through.
func quotaCheck(ctx context.Context, tx *sql.Tx, ownerID string, size, defaultQuota int64) error {
	var (
		quota sql.NullInt64
		used  int64
	)
	if err := tx.QueryRowContext(ctx, `SELECT quota_bytes FROM users WHERE id = ?`, ownerID).Scan(&quota); err != nil {
		return notFound(err)
	}
	limit := defaultQuota
	if quota.Valid {
		limit = quota.Int64
	}
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(size), 0) FROM blobs WHERE owner_id = ?`, ownerID).Scan(&used); err != nil {
		return err
	}
	if used+size > limit {
		return ErrQuota
	}
	return nil
}

func insertBlob(ctx context.Context, tx *sql.Tx, b *Blob) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO blobs (id, owner_id, parts, size, complete, upload_token_hash, created_at)
		VALUES (?, ?, ?, ?, 0, ?, ?)`, b.ID, b.OwnerID, b.Parts, b.Size, b.UploadTokenHash, unix(b.CreatedAt))
	return err
}

// NewShare describes a share link to create.
type NewShare struct {
	OwnerID      string
	Size         int64
	Parts        int
	Meta         []byte
	ExpiresAt    time.Time
	MaxDownloads *int64
	TokenHash    []byte
	DefaultQuota int64
}

// CreateShare creates a share link and its (empty, incomplete) blob after
// checking the owner's quota. The share stays invisible until the blob is
// complete.
func (s *Store) CreateShare(ctx context.Context, n *NewShare, now time.Time) (shareID, blobID string, err error) {
	shareID, blobID = ids.New(), ids.New()
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := quotaCheck(ctx, tx, n.OwnerID, n.Size, n.DefaultQuota); err != nil {
			return err
		}
		if err := insertBlob(ctx, tx, &Blob{ID: blobID, OwnerID: n.OwnerID, Parts: n.Parts, Size: n.Size,
			UploadTokenHash: n.TokenHash, CreatedAt: now}); err != nil {
			return err
		}
		var maxDL sql.NullInt64
		if n.MaxDownloads != nil {
			maxDL = sql.NullInt64{Int64: *n.MaxDownloads, Valid: true}
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO shares (id, owner_id, blob_id, size, meta, expires_at, max_downloads, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, shareID, n.OwnerID, blobID, n.Size, n.Meta, unix(n.ExpiresAt), maxDL, unix(now))
		return err
	})
	if err != nil {
		return "", "", err
	}
	return shareID, blobID, nil
}

const shareCols = `s.id, s.owner_id, s.blob_id, s.size, b.parts, s.meta, s.expires_at, s.max_downloads, s.download_count, s.created_at, b.complete`

func scanShare(r scanner) (*Share, error) {
	var (
		sh               Share
		expires, created int64
		maxDL            sql.NullInt64
	)
	if err := r.Scan(&sh.ID, &sh.OwnerID, &sh.BlobID, &sh.Size, &sh.Parts, &sh.Meta, &expires, &maxDL,
		&sh.DownloadCount, &created, &sh.Complete); err != nil {
		return nil, notFound(err)
	}
	sh.ExpiresAt = fromUnix(expires)
	sh.CreatedAt = fromUnix(created)
	if maxDL.Valid {
		v := maxDL.Int64
		sh.MaxDownloads = &v
	}
	return &sh, nil
}

// ShareByID returns a complete share (whatever its expiry; callers decide).
// Incomplete shares are ErrNotFound.
func (s *Store) ShareByID(ctx context.Context, id string) (*Share, error) {
	return scanShare(s.db.R.QueryRowContext(ctx, `SELECT `+shareCols+`
		FROM shares s JOIN blobs b ON b.id = s.blob_id WHERE s.id = ? AND b.complete = 1`, id))
}

// SharesByOwner lists the owner's complete, unexpired shares, newest first.
func (s *Store) SharesByOwner(ctx context.Context, ownerID string, now time.Time) ([]*Share, error) {
	rows, err := s.db.R.QueryContext(ctx, `SELECT `+shareCols+`
		FROM shares s JOIN blobs b ON b.id = s.blob_id
		WHERE s.owner_id = ? AND b.complete = 1 AND s.expires_at > ?
		ORDER BY s.created_at DESC, s.id`, ownerID, unix(now))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []*Share{}
	for rows.Next() {
		sh, err := scanShare(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sh)
	}
	return out, rows.Err()
}

// DeleteShare revokes one of the owner's shares, complete or not, deleting
// its blob row (and by cascade the share and its download tokens). It
// returns the blob ID whose files the caller must remove.
func (s *Store) DeleteShare(ctx context.Context, ownerID, id string) (string, error) {
	var blobID string
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT blob_id FROM shares WHERE id = ? AND owner_id = ?`, id, ownerID).Scan(&blobID); err != nil {
			return notFound(err)
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM blobs WHERE id = ?`, blobID)
		return err
	})
	return blobID, err
}

const requestCols = `id, owner_id, expires_at, max_files, max_bytes, single_use, files_received, bytes_received, label_meta, closed_at, created_at`

func scanRequest(r scanner) (*Request, error) {
	var (
		rq               Request
		expires, created int64
		closed           sql.NullInt64
	)
	if err := r.Scan(&rq.ID, &rq.OwnerID, &expires, &rq.MaxFiles, &rq.MaxBytes, &rq.SingleUse, &rq.FilesReceived,
		&rq.BytesReceived, &rq.LabelMeta, &closed, &created); err != nil {
		return nil, notFound(err)
	}
	rq.ExpiresAt = fromUnix(expires)
	rq.CreatedAt = fromUnix(created)
	rq.ClosedAt = fromNullUnix(closed)
	return &rq, nil
}

// CreateRequest inserts a request link (r.ID is assigned).
func (s *Store) CreateRequest(ctx context.Context, r *Request) error {
	r.ID = ids.New()
	_, err := s.db.W.ExecContext(ctx, `INSERT INTO requests (id, owner_id, expires_at, max_files, max_bytes, single_use, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, r.ID, r.OwnerID, unix(r.ExpiresAt), r.MaxFiles, r.MaxBytes, r.SingleUse, unix(r.CreatedAt))
	return err
}

// RequestByID returns a request link (whatever its state; callers decide).
func (s *Store) RequestByID(ctx context.Context, id string) (*Request, error) {
	return scanRequest(s.db.R.QueryRowContext(ctx, `SELECT `+requestCols+` FROM requests WHERE id = ?`, id))
}

// RequestsByOwner lists the owner's unexpired request links, newest first
// (closed single-use links included: their files are still listed).
func (s *Store) RequestsByOwner(ctx context.Context, ownerID string, now time.Time) ([]*Request, error) {
	rows, err := s.db.R.QueryContext(ctx, `SELECT `+requestCols+` FROM requests
		WHERE owner_id = ? AND expires_at > ? ORDER BY created_at DESC, id`, ownerID, unix(now))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []*Request{}
	for rows.Next() {
		rq, err := scanRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rq)
	}
	return out, rows.Err()
}

// SetRequestLabel stores the owner's sealed label on one of their request
// links.
func (s *Store) SetRequestLabel(ctx context.Context, ownerID, id string, label []byte, now time.Time) error {
	res, err := s.db.W.ExecContext(ctx, `UPDATE requests SET label_meta = ? WHERE id = ? AND owner_id = ? AND expires_at > ?`,
		label, id, ownerID, unix(now))
	if err != nil {
		return err
	}
	return requireOne(res)
}

// DeleteRequest revokes one of the owner's request links and every file
// received through it. It returns the blob IDs to remove from disk.
func (s *Store) DeleteRequest(ctx context.Context, ownerID, id string) ([]string, error) {
	var blobs []string
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		var one int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM requests WHERE id = ? AND owner_id = ?`, id, ownerID).Scan(&one); err != nil {
			return notFound(err)
		}
		var err error
		blobs, err = deleteBlobsWhere(ctx, tx, `id IN (SELECT blob_id FROM inbox WHERE request_id = ?)`, id)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM requests WHERE id = ?`, id)
		return err
	})
	return blobs, err
}

// deleteBlobsWhere deletes the blob rows matching cond (cascading to shares,
// inbox rows and download tokens) and returns their IDs.
func deleteBlobsWhere(ctx context.Context, tx *sql.Tx, cond string, args ...any) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `DELETE FROM blobs WHERE `+cond+` RETURNING id`, args...) //nolint:gosec // cond is a constant from this package
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// NewRequestFile describes a file an anonymous uploader starts sending.
type NewRequestFile struct {
	RequestID    string
	Size         int64
	Parts        int
	Meta         []byte
	WrappedKey   []byte
	TokenHash    []byte
	DefaultQuota int64
}

// CreateRequestFile reserves room on a request link and creates the inbox
// row and its incomplete blob, atomically: the file and byte counters are
// incremented here (inside the single write transaction), so concurrent
// uploads can never exceed max_files or max_bytes. Abandoned uploads give
// their reservation back when they are garbage-collected.
func (s *Store) CreateRequestFile(ctx context.Context, n *NewRequestFile, now time.Time) (blobID string, err error) {
	blobID = ids.New()
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		rq, err := scanRequest(tx.QueryRowContext(ctx, `SELECT `+requestCols+` FROM requests WHERE id = ?`, n.RequestID))
		if err != nil {
			return err
		}
		switch {
		case !rq.ExpiresAt.After(now):
			return ErrExpired
		case rq.ClosedAt != nil:
			return ErrClosed
		case rq.FilesReceived+1 > rq.MaxFiles || rq.BytesReceived+n.Size > rq.MaxBytes:
			return ErrFull
		}
		// The owner lost access (role withdrawn, revoked, disabled): the link
		// stops accepting files until they sign in again (audit I-3).
		var active bool
		if err := tx.QueryRowContext(ctx, `SELECT disabled_at IS NULL AND access_lost_at IS NULL FROM users WHERE id = ?`, rq.OwnerID).Scan(&active); err != nil {
			return notFound(err)
		}
		if !active {
			return ErrClosed
		}
		if err := quotaCheck(ctx, tx, rq.OwnerID, n.Size, n.DefaultQuota); err != nil {
			return err
		}
		if err := insertBlob(ctx, tx, &Blob{ID: blobID, OwnerID: rq.OwnerID, Parts: n.Parts, Size: n.Size,
			UploadTokenHash: n.TokenHash, CreatedAt: now}); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO inbox (id, request_id, owner_id, blob_id, size, meta, wrapped_key, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, ids.New(), rq.ID, rq.OwnerID, blobID, n.Size, n.Meta, n.WrappedKey, unix(now)); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE requests SET files_received = files_received + 1, bytes_received = bytes_received + ?
			WHERE id = ?`, n.Size, rq.ID)
		return err
	})
	if err != nil {
		return "", err
	}
	return blobID, nil
}

// Upload is an upload in progress (or finished) with the link it feeds.
type Upload struct {
	Blob
	ShareID   string // set for share uploads
	RequestID string // set for request uploads
	SingleUse bool
	ExpiresAt time.Time // of the link
}

// UploadByID returns the upload with blob ID id. Blobs not attached to any
// link (revoked) are ErrNotFound.
func (s *Store) UploadByID(ctx context.Context, id string) (*Upload, error) {
	var (
		u                  Upload
		created            int64
		shareID, requestID sql.NullString
		shareExp, reqExp   sql.NullInt64
		singleUse          sql.NullBool
	)
	err := s.db.R.QueryRowContext(ctx, `SELECT b.id, b.owner_id, b.parts, b.size, b.complete, b.upload_token_hash, b.created_at,
			s.id, s.expires_at, i.request_id, r.expires_at, r.single_use
		FROM blobs b
		LEFT JOIN shares s ON s.blob_id = b.id
		LEFT JOIN inbox i ON i.blob_id = b.id
		LEFT JOIN requests r ON r.id = i.request_id
		WHERE b.id = ?`, id).Scan(&u.ID, &u.OwnerID, &u.Parts, &u.Size, &u.Complete, &u.UploadTokenHash, &created,
		&shareID, &shareExp, &requestID, &reqExp, &singleUse)
	if err != nil {
		return nil, notFound(err)
	}
	u.CreatedAt = fromUnix(created)
	switch {
	case shareID.Valid:
		u.ShareID = shareID.String
		u.ExpiresAt = fromUnix(shareExp.Int64)
	case requestID.Valid && reqExp.Valid:
		u.RequestID = requestID.String
		u.ExpiresAt = fromUnix(reqExp.Int64)
		u.SingleUse = singleUse.Bool
	default:
		return nil, ErrNotFound
	}
	return &u, nil
}

// CheckToken compares an upload token hash with the stored one in constant
// time. Complete uploads have no token left.
func (u *Upload) CheckToken(hash []byte) bool {
	return len(u.UploadTokenHash) == len(hash) && subtle.ConstantTimeCompare(u.UploadTokenHash, hash) == 1
}

// CompleteUpload marks the blob complete, which makes its share or inbox
// entry visible. The upload token is kept (hashed) so a retried finalize can
// be authenticated and answered idempotently; it no longer authorizes part
// writes. A single-use request link closes on its first completed file. It
// returns ErrComplete if the blob was already complete and ErrNotFound if
// its row is gone.
func (s *Store) CompleteUpload(ctx context.Context, u *Upload, now time.Time) error {
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE blobs SET complete = 1 WHERE id = ? AND complete = 0`, u.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			// Already complete, or deleted meanwhile (revoked or collected).
			var one int
			if err := tx.QueryRowContext(ctx, `SELECT 1 FROM blobs WHERE id = ?`, u.ID).Scan(&one); err != nil {
				return notFound(err)
			}
			return ErrComplete
		}
		if u.RequestID == "" {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE inbox SET created_at = ? WHERE blob_id = ?`, unix(now), u.ID); err != nil {
			return err
		}
		if u.SingleUse {
			_, err = tx.ExecContext(ctx, `UPDATE requests SET closed_at = ? WHERE id = ? AND closed_at IS NULL`, unix(now), u.RequestID)
		}
		return err
	})
}

const inboxCols = `i.id, i.request_id, i.owner_id, i.blob_id, i.size, b.parts, i.meta, i.wrapped_key, i.created_at`

func scanInbox(r scanner) (*InboxFile, error) {
	var (
		f       InboxFile
		created int64
	)
	if err := r.Scan(&f.ID, &f.RequestID, &f.OwnerID, &f.BlobID, &f.Size, &f.Parts, &f.Meta, &f.WrappedKey, &created); err != nil {
		return nil, notFound(err)
	}
	f.CreatedAt = fromUnix(created)
	return &f, nil
}

// liveInbox selects the visible inbox files: completely received, through a
// request link that has not expired. An expired link takes its files with it
// at once, before the cleanup job deletes them. The query binds the time
// after its other parameters.
const liveInbox = ` FROM inbox i JOIN blobs b ON b.id = i.blob_id JOIN requests r ON r.id = i.request_id
	WHERE b.complete = 1 AND r.expires_at > ?`

// InboxByOwner lists the owner's visible received files, newest first.
func (s *Store) InboxByOwner(ctx context.Context, ownerID string, now time.Time) ([]*InboxFile, error) {
	rows, err := s.db.R.QueryContext(ctx, `SELECT `+inboxCols+liveInbox+` AND i.owner_id = ?
		ORDER BY i.created_at DESC, i.id`, unix(now), ownerID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []*InboxFile{}
	for rows.Next() {
		f, err := scanInbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// CountInbox returns the number of visible received files of an owner.
func (s *Store) CountInbox(ctx context.Context, ownerID string, now time.Time) (int, error) {
	var n int
	err := s.db.R.QueryRowContext(ctx, `SELECT count(*)`+liveInbox+` AND i.owner_id = ?`, unix(now), ownerID).Scan(&n)
	return n, err
}

// CountActiveLinks returns the owner's visible share and request links.
func (s *Store) CountActiveLinks(ctx context.Context, ownerID string, now time.Time) (int, error) {
	var n int
	err := s.db.R.QueryRowContext(ctx, `SELECT
		(SELECT count(*) FROM shares s JOIN blobs b ON b.id = s.blob_id WHERE s.owner_id = ?1 AND b.complete = 1 AND s.expires_at > ?2) +
		(SELECT count(*) FROM requests WHERE owner_id = ?1 AND expires_at > ?2)`, ownerID, unix(now)).Scan(&n)
	return n, err
}

// InboxFileByID returns one of the owner's visible received files.
func (s *Store) InboxFileByID(ctx context.Context, ownerID, id string, now time.Time) (*InboxFile, error) {
	return scanInbox(s.db.R.QueryRowContext(ctx, `SELECT `+inboxCols+liveInbox+` AND i.id = ? AND i.owner_id = ?`,
		unix(now), id, ownerID))
}

// DeleteInboxFile deletes one of the owner's received files and returns the
// blob ID to remove from disk. The request link's counters are unchanged:
// they count what the link received.
func (s *Store) DeleteInboxFile(ctx context.Context, ownerID, id string) (string, error) {
	var blobID string
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT blob_id FROM inbox WHERE id = ? AND owner_id = ?`, id, ownerID).Scan(&blobID); err != nil {
			return notFound(err)
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM blobs WHERE id = ?`, blobID)
		return err
	})
	return blobID, err
}

// Download-token lifetimes (ARCHITECTURE.md §3): a token stays valid for
// TokenIdle after its last use, and never longer than TokenMaxAge after it
// was issued (nor past its share's expiry).
const (
	TokenIdle   = time.Hour
	TokenMaxAge = 24 * time.Hour
)

// CreateShareToken issues a download token for a complete share. It fails
// with ErrNotFound, ErrExpired or ErrExhausted (download_count already at
// max_downloads).
func (s *Store) CreateShareToken(ctx context.Context, shareID string, tokenHash []byte, now time.Time) (*Share, error) {
	var sh *Share
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		var err error
		sh, err = scanShare(tx.QueryRowContext(ctx, `SELECT `+shareCols+`
			FROM shares s JOIN blobs b ON b.id = s.blob_id WHERE s.id = ? AND b.complete = 1`, shareID))
		if err != nil {
			return err
		}
		if !sh.ExpiresAt.After(now) {
			return ErrExpired
		}
		if sh.MaxDownloads != nil && sh.DownloadCount >= *sh.MaxDownloads {
			return ErrExhausted
		}
		exp := min(unix(now.Add(TokenIdle)), unix(sh.ExpiresAt))
		_, err = tx.ExecContext(ctx, `INSERT INTO dl_tokens (token_hash, blob_id, share_id, expires_at, counted, created_at)
			VALUES (?, ?, ?, ?, 0, ?)`, tokenHash, sh.BlobID, sh.ID, exp, unix(now))
		return err
	})
	return sh, err
}

// CreateInboxToken issues a download token for one of the owner's visible
// received files. The token never outlives the file's request link.
func (s *Store) CreateInboxToken(ctx context.Context, ownerID, inboxID string, tokenHash []byte, now time.Time) error {
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		var (
			blobID string
			reqExp int64
		)
		err := tx.QueryRowContext(ctx, `SELECT i.blob_id, r.expires_at`+liveInbox+` AND i.id = ? AND i.owner_id = ?`,
			unix(now), inboxID, ownerID).Scan(&blobID, &reqExp)
		if err != nil {
			return notFound(err)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO dl_tokens (token_hash, blob_id, share_id, expires_at, counted, created_at)
			VALUES (?, ?, NULL, ?, 0, ?)`, tokenHash, blobID, min(unix(now.Add(TokenIdle)), reqExp), unix(now))
		return err
	})
}

// DownloadTarget is what a download token grants access to.
type DownloadTarget struct {
	BlobID  string
	OwnerID string
	Size    int64
	Parts   int
	ShareID string // empty for inbox downloads
	// Reserved is the byte count this use reserved against the token's budget.
	Reserved int64
}

// TokenByteBudget is how many ciphertext bytes one download token may serve
// in total: two full copies plus min(size, 1 MiB), enough for a download interrupted
// and resumed any number of times (resumes restart at the last verified
// segment, so they overlap little), but not for unlimited full re-downloads
// (audit L-2).
func TokenByteBudget(size int64) int64 { return 2*size + min(size, 1<<20) }

// UseDownloadToken resolves a download token. When count is set and the
// token was never used, the share's download_count is incremented exactly
// once (refused with ErrExhausted if it already reached max_downloads);
// later uses of the same token, such as Range requests resuming a download,
// never count again. Every use slides the token's expiry, never past its
// share's or request link's expiry (ErrExpired after it). plan (if non-nil)
// returns how many bytes this use will serve given the blob size; they are
// reserved against TokenByteBudget (ErrTokenSpent once it would be
// exceeded) and returned in DownloadTarget.Reserved, so the caller can give
// back what it did not send (RefundDownloadToken).
func (s *Store) UseDownloadToken(ctx context.Context, tokenHash []byte, count bool, plan func(size int64) int64, now time.Time) (*DownloadTarget, error) {
	var t DownloadTarget
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		var (
			shareID           sql.NullString
			expires, created  int64
			counted, complete bool
			shareExp, reqExp  sql.NullInt64
			maxDL, downloads  sql.NullInt64
			served            int64
		)
		err := tx.QueryRowContext(ctx, `SELECT t.blob_id, t.share_id, t.expires_at, t.created_at, t.counted, t.served_bytes,
				b.owner_id, b.size, b.parts, b.complete, s.expires_at, s.max_downloads, s.download_count, r.expires_at
			FROM dl_tokens t JOIN blobs b ON b.id = t.blob_id LEFT JOIN shares s ON s.id = t.share_id
				LEFT JOIN inbox i ON i.blob_id = t.blob_id LEFT JOIN requests r ON r.id = i.request_id
			WHERE t.token_hash = ?`, tokenHash).Scan(&t.BlobID, &shareID, &expires, &created, &counted, &served,
			&t.OwnerID, &t.Size, &t.Parts, &complete, &shareExp, &maxDL, &downloads, &reqExp)
		if err != nil {
			return notFound(err)
		}
		n := unix(now)
		if expires <= n || created+int64(TokenMaxAge/time.Second) <= n || !complete {
			return ErrExpired
		}
		limit := created + int64(TokenMaxAge/time.Second)
		if shareID.Valid {
			t.ShareID = shareID.String
			if !shareExp.Valid {
				return ErrNotFound
			}
			if shareExp.Int64 <= n {
				return ErrExpired
			}
			limit = min(limit, shareExp.Int64)
			if count && !counted {
				res, err := tx.ExecContext(ctx, `UPDATE shares SET download_count = download_count + 1
					WHERE id = ? AND (max_downloads IS NULL OR download_count < max_downloads)`, t.ShareID)
				if err != nil {
					return err
				}
				if k, _ := res.RowsAffected(); k == 0 {
					return ErrExhausted
				}
				if _, err := tx.ExecContext(ctx, `UPDATE dl_tokens SET counted = 1 WHERE token_hash = ?`, tokenHash); err != nil {
					return err
				}
			}
		} else {
			// An inbox token dies with the file's request link.
			if !reqExp.Valid {
				return ErrNotFound
			}
			if reqExp.Int64 <= n {
				return ErrExpired
			}
			limit = min(limit, reqExp.Int64)
		}
		if plan != nil {
			t.Reserved = max(plan(t.Size), 0)
			if served+t.Reserved > TokenByteBudget(t.Size) {
				return ErrTokenSpent
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE dl_tokens SET expires_at = ?, served_bytes = served_bytes + ? WHERE token_hash = ?`,
			min(n+int64(TokenIdle/time.Second), limit), t.Reserved, tokenHash)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// DeleteExpiredDownloadTokens removes tokens past their sliding or absolute
// expiry.
func (s *Store) DeleteExpiredDownloadTokens(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.W.ExecContext(ctx, `DELETE FROM dl_tokens WHERE expires_at <= ? OR created_at <= ?`,
		unix(now), unix(now.Add(-TokenMaxAge)))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteExpiredLinks deletes expired share links and expired request links
// with every file they received (PLAN.md §6: expiring deletes the blobs). It
// returns the blob IDs to remove from disk.
func (s *Store) DeleteExpiredLinks(ctx context.Context, now time.Time) ([]string, error) {
	var blobs []string
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		var err error
		blobs, err = deleteBlobsWhere(ctx, tx, `id IN (SELECT blob_id FROM shares WHERE expires_at <= ?1)
			OR id IN (SELECT i.blob_id FROM inbox i JOIN requests r ON r.id = i.request_id WHERE r.expires_at <= ?1)`, unix(now))
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM requests WHERE expires_at <= ?`, unix(now))
		return err
	})
	return blobs, err
}

// DeleteStaleUploads deletes uploads still incomplete since before, gives
// their reservation back to their request link, and returns the blob IDs to
// remove from disk.
func (s *Store) DeleteStaleUploads(ctx context.Context, before time.Time) ([]string, error) {
	var blobs []string
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE requests SET
				files_received = MAX(0, files_received - (SELECT count(*) FROM inbox i JOIN blobs b ON b.id = i.blob_id
					WHERE i.request_id = requests.id AND b.complete = 0 AND b.created_at < ?1)),
				bytes_received = MAX(0, bytes_received - (SELECT COALESCE(SUM(b.size), 0) FROM inbox i JOIN blobs b ON b.id = i.blob_id
					WHERE i.request_id = requests.id AND b.complete = 0 AND b.created_at < ?1))
			WHERE id IN (SELECT i.request_id FROM inbox i JOIN blobs b ON b.id = i.blob_id WHERE b.complete = 0 AND b.created_at < ?1)`,
			unix(before)); err != nil {
			return err
		}
		var err error
		blobs, err = deleteBlobsWhere(ctx, tx, `complete = 0 AND created_at < ?`, unix(before))
		return err
	})
	return blobs, err
}

// BlobExists reports whether a blob row exists.
func (s *Store) BlobExists(ctx context.Context, id string) (bool, error) {
	var one int
	err := s.db.R.QueryRowContext(ctx, `SELECT 1 FROM blobs WHERE id = ?`, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("store: blob exists: %w", err)
	}
	return true, nil
}

// RefundDownloadToken gives back n reserved bytes a download did not send
// (the client went away or read too slowly).
func (s *Store) RefundDownloadToken(ctx context.Context, tokenHash []byte, n int64) error {
	if n <= 0 {
		return nil
	}
	_, err := s.db.W.ExecContext(ctx, `UPDATE dl_tokens SET served_bytes = MAX(0, served_bytes - ?) WHERE token_hash = ?`, n, tokenHash)
	return err
}

// PendingBlob is an incomplete upload and its declared ciphertext size.
type PendingBlob struct {
	ID   string
	Size int64
}

// IncompleteBlobs lists the uploads still in progress (for the disk-space
// reservation of new uploads).
func (s *Store) IncompleteBlobs(ctx context.Context) ([]PendingBlob, error) {
	rows, err := s.db.R.QueryContext(ctx, `SELECT id, size FROM blobs WHERE complete = 0`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []PendingBlob
	for rows.Next() {
		var p PendingBlob
		if err := rows.Scan(&p.ID, &p.Size); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
