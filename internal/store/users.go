package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/scttpr/dropr/internal/ids"
)

// User is an account, identified by (Issuer, Subject).
type User struct {
	ID          string
	Issuer      string
	Subject     string
	DisplayName string
	CreatedAt   time.Time
	DisabledAt  *time.Time
	QuotaBytes  *int64
}

const userCols = `id, issuer, subject, display_name, created_at, disabled_at, quota_bytes`

type scanner interface{ Scan(...any) error }

func scanUser(r scanner) (*User, error) {
	var (
		u        User
		created  int64
		disabled sql.NullInt64
		quota    sql.NullInt64
	)
	if err := r.Scan(&u.ID, &u.Issuer, &u.Subject, &u.DisplayName, &created, &disabled, &quota); err != nil {
		return nil, notFound(err)
	}
	u.CreatedAt = fromUnix(created)
	u.DisabledAt = fromNullUnix(disabled)
	if quota.Valid {
		q := quota.Int64
		u.QuotaBytes = &q
	}
	return &u, nil
}

// maxDisplayName bounds the provider-supplied display name.
const maxDisplayName = 200

func cleanDisplayName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > maxDisplayName {
		s = strings.ToValidUTF8(s[:maxDisplayName], "")
	}
	return s
}

// ProvisionUser returns the user for (issuer, subject), creating it just in
// time if needed. The display name is refreshed on every login. created
// reports whether a new account was made.
func (s *Store) ProvisionUser(ctx context.Context, issuer, subject, displayName string, now time.Time) (u *User, created bool, err error) {
	if issuer == "" || subject == "" {
		return nil, false, errors.New("store: empty identity")
	}
	displayName = cleanDisplayName(displayName)
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE issuer = ? AND subject = ?`, issuer, subject)
		u, err = scanUser(row)
		switch {
		case err == nil:
			// A successful login proves access again (audit I-3).
			if _, err := tx.ExecContext(ctx, `UPDATE users SET access_lost_at = NULL WHERE id = ? AND access_lost_at IS NOT NULL`, u.ID); err != nil {
				return err
			}
			if u.DisplayName != displayName {
				if _, err := tx.ExecContext(ctx, `UPDATE users SET display_name = ? WHERE id = ?`, displayName, u.ID); err != nil {
					return err
				}
				u.DisplayName = displayName
			}
			return nil
		case errors.Is(err, ErrNotFound):
			u = &User{ID: ids.New(), Issuer: issuer, Subject: subject, DisplayName: displayName, CreatedAt: fromUnix(unix(now))}
			created = true
			_, err := tx.ExecContext(ctx, `INSERT INTO users (id, issuer, subject, display_name, created_at) VALUES (?, ?, ?, ?, ?)`,
				u.ID, issuer, subject, displayName, unix(now))
			return err
		default:
			return err
		}
	})
	if err != nil {
		return nil, false, fmt.Errorf("store: provision user: %w", err)
	}
	return u, created, nil
}

// UserByID returns a user by ID.
func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	return scanUser(s.db.R.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// UserByIdentity returns a user by (issuer, subject).
func (s *Store) UserByIdentity(ctx context.Context, issuer, subject string) (*User, error) {
	return scanUser(s.db.R.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE issuer = ? AND subject = ?`, issuer, subject))
}

// FindUser resolves an admin-supplied reference: a user ID, or a subject that
// matches exactly one user.
func (s *Store) FindUser(ctx context.Context, ref string) (*User, error) {
	if ids.Valid(ref) {
		u, err := s.UserByID(ctx, ref)
		if err == nil || !errors.Is(err, ErrNotFound) {
			return u, err
		}
	}
	rows, err := s.db.R.QueryContext(ctx, `SELECT `+userCols+` FROM users WHERE subject = ? LIMIT 2`, ref)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var found []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		found = append(found, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	switch len(found) {
	case 0:
		return nil, ErrNotFound
	case 1:
		return found[0], nil
	default:
		return nil, fmt.Errorf("store: subject %q matches several users; use the user ID", ref)
	}
}

// UserSummary is a user with its session count for `dropr user list`.
type UserSummary struct {
	User
	Sessions int
}

// ListUsers returns all users ordered by creation time.
func (s *Store) ListUsers(ctx context.Context) ([]UserSummary, error) {
	rows, err := s.db.R.QueryContext(ctx, `
		SELECT u.id, u.issuer, u.subject, u.display_name, u.created_at, u.disabled_at, u.quota_bytes,
		       (SELECT count(*) FROM sessions s WHERE s.user_id = u.id)
		FROM users u ORDER BY u.created_at, u.id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []UserSummary
	for rows.Next() {
		var (
			us       UserSummary
			created  int64
			disabled sql.NullInt64
			quota    sql.NullInt64
		)
		if err := rows.Scan(&us.ID, &us.Issuer, &us.Subject, &us.DisplayName, &created, &disabled, &quota,
			&us.Sessions); err != nil {
			return nil, err
		}
		us.CreatedAt = fromUnix(created)
		us.DisabledAt = fromNullUnix(disabled)
		if quota.Valid {
			q := quota.Int64
			us.QuotaBytes = &q
		}
		out = append(out, us)
	}
	return out, rows.Err()
}

// DeleteUser removes a user and, by cascade, all their rows (sessions, links,
// inbox, blob rows). It returns the IDs of the blobs whose files the caller
// must remove (gc reconciles any left behind).
func (s *Store) DeleteUser(ctx context.Context, id string) ([]string, error) {
	var blobs []string
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		var one int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id = ?`, id).Scan(&one); err != nil {
			return notFound(err)
		}
		var err error
		if blobs, err = deleteBlobsWhere(ctx, tx, `owner_id = ?`, id); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
		return err
	})
	return blobs, err
}

// IdentityMapping relinks one account from an old subject to a new one.
type IdentityMapping struct {
	OldSubject string
	NewSubject string
}

// MigrateIdentities moves accounts from fromIssuer to toIssuer according to
// mappings, atomically. Accounts keep their ID, so their links and files
// follow. All sessions of migrated users are ended. It fails without changes
// if any old identity is missing or any new identity is already taken.
func (s *Store) MigrateIdentities(ctx context.Context, fromIssuer, toIssuer string, mappings []IdentityMapping) (int, error) {
	n := 0
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		for _, m := range mappings {
			if m.OldSubject == "" || m.NewSubject == "" {
				return errors.New("store: empty subject in mapping")
			}
			var uid string
			err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE issuer = ? AND subject = ?`, fromIssuer, m.OldSubject).Scan(&uid)
			if err != nil {
				return fmt.Errorf("old identity %q: %w", m.OldSubject, notFound(err))
			}
			var taken int
			err = tx.QueryRowContext(ctx, `SELECT 1 FROM users WHERE issuer = ? AND subject = ?`, toIssuer, m.NewSubject).Scan(&taken)
			if err == nil {
				return fmt.Errorf("new identity %q: %w", m.NewSubject, ErrConflict)
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE users SET issuer = ?, subject = ? WHERE id = ?`, toIssuer, m.NewSubject, uid); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, uid); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("store: migrate identities: %w", err)
	}
	return n, nil
}

func requireOne(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkAccessLost records that the account (issuer, subject) lost access at
// the identity provider (role or required claim withdrawn) or was revoked by
// an administrator. Its request links refuse uploads until the next
// successful login clears the mark (ProvisionUser). Unknown identities are
// ignored.
func (s *Store) MarkAccessLost(ctx context.Context, issuer, subject string, now time.Time) error {
	_, err := s.db.W.ExecContext(ctx, `UPDATE users SET access_lost_at = ? WHERE issuer = ? AND subject = ? AND access_lost_at IS NULL`,
		unix(now), issuer, subject)
	return err
}

// MarkAccessLostByID is MarkAccessLost by user ID (`dropr user revoke`).
func (s *Store) MarkAccessLostByID(ctx context.Context, userID string, now time.Time) error {
	_, err := s.db.W.ExecContext(ctx, `UPDATE users SET access_lost_at = COALESCE(access_lost_at, ?) WHERE id = ?`, unix(now), userID)
	return err
}

// AccountActive reports whether the account may still receive files: not
// disabled and not marked as having lost access (audit I-3).
func (s *Store) AccountActive(ctx context.Context, userID string) (bool, error) {
	var ok bool
	err := s.db.R.QueryRowContext(ctx, `SELECT disabled_at IS NULL AND access_lost_at IS NULL FROM users WHERE id = ?`, userID).Scan(&ok)
	return ok, notFound(err)
}
