package store

import (
	"context"
	"database/sql"
	"time"
)

// Session is a server-side session row. The session ID itself is never
// stored; IDHash is its SHA-256.
type Session struct {
	IDHash          []byte
	UserID          string
	RefreshTokenEnc []byte
	OIDCSID         string
	CreatedAt       time.Time
	LastSeenAt      time.Time
	RevalidatedAt   time.Time
	UnlockedAt      *time.Time
	RotatedFrom     []byte
}

const sessionCols = `id_hash, user_id, refresh_token_enc, oidc_sid, created_at, last_seen_at, revalidated_at, unlocked_at, rotated_from`

func scanSession(r scanner) (*Session, error) {
	var (
		s                          Session
		sid                        sql.NullString
		created, seen, revalidated int64
		unlocked                   sql.NullInt64
	)
	if err := r.Scan(&s.IDHash, &s.UserID, &s.RefreshTokenEnc, &sid, &created, &seen, &revalidated, &unlocked, &s.RotatedFrom); err != nil {
		return nil, notFound(err)
	}
	s.OIDCSID = sid.String
	s.CreatedAt = fromUnix(created)
	s.LastSeenAt = fromUnix(seen)
	s.RevalidatedAt = fromUnix(revalidated)
	s.UnlockedAt = fromNullUnix(unlocked)
	return &s, nil
}

func nullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func insertSession(ctx context.Context, e execer, s *Session) error {
	_, err := e.ExecContext(ctx, `INSERT INTO sessions (`+sessionCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.IDHash, s.UserID, s.RefreshTokenEnc, nullString(s.OIDCSID), unix(s.CreatedAt), unix(s.LastSeenAt),
		unix(s.RevalidatedAt), nullUnix(s.UnlockedAt), s.RotatedFrom)
	return err
}

// CreateSession inserts a new session.
func (s *Store) CreateSession(ctx context.Context, sess *Session) error {
	return insertSession(ctx, s.db.W, sess)
}

// SessionByHash returns the session with the given ID hash.
func (s *Store) SessionByHash(ctx context.Context, idHash []byte) (*Session, error) {
	return scanSession(s.db.R.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE id_hash = ?`, idHash))
}

// RotateSession atomically replaces the session oldHash with the row build
// returns (which carries the new ID hash). build receives the session as
// currently stored, read inside the write transaction, so fields changed by a
// concurrent writer (such as a refreshed refresh token) are never lost. It
// returns ErrNotFound if the old session is gone, so a concurrently revoked
// session cannot be resurrected by rotation.
func (s *Store) RotateSession(ctx context.Context, oldHash []byte, build func(cur *Session) (*Session, error)) error {
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		cur, err := scanSession(tx.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE id_hash = ?`, oldHash))
		if err != nil {
			return err
		}
		next, err := build(cur)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, oldHash); err != nil {
			return err
		}
		return insertSession(ctx, tx, next)
	})
}

// TouchSession records activity.
func (s *Store) TouchSession(ctx context.Context, idHash []byte, now time.Time) error {
	_, err := s.db.W.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?`, unix(now), idHash)
	return err
}

// UpdateSessionRevalidation stores a refreshed (encrypted) refresh token and
// the revalidation time. A nil token keeps the stored one.
func (s *Store) UpdateSessionRevalidation(ctx context.Context, idHash, refreshTokenEnc []byte, at time.Time) error {
	res, err := s.db.W.ExecContext(ctx, `UPDATE sessions
		SET revalidated_at = ?, refresh_token_enc = COALESCE(?, refresh_token_enc)
		WHERE id_hash = ?`, unix(at), refreshTokenEnc, idHash)
	if err != nil {
		return err
	}
	return requireOne(res)
}

// DeleteSession removes one session.
func (s *Store) DeleteSession(ctx context.Context, idHash []byte) error {
	_, err := s.db.W.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, idHash)
	return err
}

// DeleteUserSessions removes all sessions of a user.
func (s *Store) DeleteUserSessions(ctx context.Context, userID string) (int64, error) {
	res, err := s.db.W.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteSessionsByOIDCSID removes the sessions bound to a provider session ID
// (front-channel logout).
func (s *Store) DeleteSessionsByOIDCSID(ctx context.Context, sid string) (int64, error) {
	if sid == "" {
		return 0, nil
	}
	res, err := s.db.W.ExecContext(ctx, `DELETE FROM sessions WHERE oidc_sid = ?`, sid)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteExpiredSessions removes sessions idle since before idleBefore or
// created before createdBefore.
func (s *Store) DeleteExpiredSessions(ctx context.Context, idleBefore, createdBefore time.Time) (int64, error) {
	res, err := s.db.W.ExecContext(ctx, `DELETE FROM sessions WHERE last_seen_at < ? OR created_at < ?`,
		unix(idleBefore), unix(createdBefore))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// SessionsDueForRevalidation lists sessions not revalidated since before.
func (s *Store) SessionsDueForRevalidation(ctx context.Context, before time.Time, limit int) ([]*Session, error) {
	rows, err := s.db.R.QueryContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE revalidated_at < ? ORDER BY revalidated_at LIMIT ?`,
		unix(before), limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Session
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}
