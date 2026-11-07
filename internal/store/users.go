package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

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

// cleanDisplayName makes the provider-supplied name safe to show to anyone
// holding a request link. It uses the character class of the web client's
// file-name sanitizer (web/src/crypto/meta.ts, audit I-4): controls (C0,
// DEL, C1) and default-ignorable code points (bidi marks, embeddings,
// overrides and isolates, zero-width and invisible separators, BOM, soft
// hyphen, Hangul fillers…) are removed, as are U+061C, U+2028/2029 and the
// Braille blank U+2800. ZWJ/ZWNJ, variation selectors and emoji tag
// characters are kept. Runs of spaces of any width collapse to one ASCII
// space (audit 2026-11 A03-1). Unlike the client, no NFC normalization is
// applied: the server has no Unicode normalization tables.
func cleanDisplayName(s string) string {
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case stripInName(r):
			continue
		case unicode.Is(unicode.Zs, r):
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	s = b.String()
	if len(s) > maxDisplayName {
		s = strings.TrimSpace(strings.ToValidUTF8(s[:maxDisplayName], ""))
	}
	return s
}

// stripInName reports whether r is removed from display names: \p{Cc},
// \p{Default_Ignorable_Code_Point} (derived as in DerivedCoreProperties.txt:
// Other_Default_Ignorable_Code_Point + Cf + Variation_Selector − White_Space −
// U+FFF9..FFFB − U+13430..1343F − Prepended_Concatenation_Mark), U+061C,
// U+2028, U+2029 and U+2800, minus the exceptions kept by the web client.
func stripInName(r rune) bool {
	switch {
	case r == 0x200c || r == 0x200d, // ZWNJ, ZWJ
		unicode.Is(unicode.Variation_Selector, r),
		r >= 0xe0020 && r <= 0xe007f: // emoji tag characters
		return false
	case unicode.Is(unicode.Cc, r),
		r == 0x061c, r == 0x2028, r == 0x2029, r == 0x2800,
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r):
		return true
	case unicode.Is(unicode.Cf, r):
		return (r < 0xfff9 || r > 0xfffb) && (r < 0x13430 || r > 0x1343f) &&
			!unicode.Is(unicode.Prepended_Concatenation_Mark, r)
	}
	return false
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
// the identity provider (role or required claim withdrawn). Its request links
// refuse uploads until the next successful login clears the mark
// (ProvisionUser); its share links expire for good (loseAccess). Unknown
// identities are ignored.
func (s *Store) MarkAccessLost(ctx context.Context, issuer, subject string, now time.Time) error {
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		var uid string
		err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE issuer = ? AND subject = ?`, issuer, subject).Scan(&uid)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		return loseAccess(ctx, tx, uid, now)
	})
}

// RevokeUser is `dropr user revoke`: it ends every session of the user and
// marks the account as having lost access, as MarkAccessLost does, in one
// transaction. It returns the number of sessions ended.
func (s *Store) RevokeUser(ctx context.Context, userID string, now time.Time) (sessions int64, err error) {
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if sessions, err = deleteUserSessions(ctx, tx, userID); err != nil {
			return err
		}
		return loseAccess(ctx, tx, userID, now)
	})
	return sessions, err
}

// DisableUser is `dropr user disable` (audit 2026-11b L-3): a local lockout
// that a login does not undo. It sets disabled_at (kept if already set),
// ends every session of the user and expires their share links
// (expireOwnerShares). Login, session load and request links all refuse a
// disabled account. wasDisabled reports whether it already was.
func (s *Store) DisableUser(ctx context.Context, userID string, now time.Time) (sessions int64, wasDisabled bool, err error) {
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		var disabled sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT disabled_at FROM users WHERE id = ?`, userID).Scan(&disabled); err != nil {
			return notFound(err)
		}
		wasDisabled = disabled.Valid
		if !wasDisabled {
			if _, err := tx.ExecContext(ctx, `UPDATE users SET disabled_at = ? WHERE id = ?`, unix(now), userID); err != nil {
				return err
			}
		}
		if sessions, err = deleteUserSessions(ctx, tx, userID); err != nil {
			return err
		}
		return expireOwnerShares(ctx, tx, userID, now)
	})
	return sessions, wasDisabled, err
}

// EnableUser is `dropr user enable` (audit 2026-11b L-3): it clears
// disabled_at and nothing else. Share links expired by DisableUser stay
// expired. wasDisabled reports whether the account was disabled.
func (s *Store) EnableUser(ctx context.Context, userID string) (wasDisabled bool, err error) {
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		var disabled sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT disabled_at FROM users WHERE id = ?`, userID).Scan(&disabled); err != nil {
			return notFound(err)
		}
		wasDisabled = disabled.Valid
		if !wasDisabled {
			return nil
		}
		_, err := tx.ExecContext(ctx, `UPDATE users SET disabled_at = NULL WHERE id = ?`, userID)
		return err
	})
	return wasDisabled, err
}

// loseAccess sets access_lost_at (kept if already set) and expires the
// owner's share links. It is the one place every "access lost" path goes
// through: role or claim withdrawn at login or revalidation, and `dropr user
// revoke`.
func loseAccess(ctx context.Context, tx *sql.Tx, userID string, now time.Time) error {
	res, err := tx.ExecContext(ctx, `UPDATE users SET access_lost_at = COALESCE(access_lost_at, ?) WHERE id = ?`, unix(now), userID)
	if err != nil {
		return err
	}
	if err := requireOne(res); err != nil {
		return err
	}
	return expireOwnerShares(ctx, tx, userID, now)
}

// expireOwnerShares ends every live share link of an owner who lost access
// (audit 2026-11b L-2): expires_at is brought down to now, so the links are
// dead at once, a later login does not bring them back, and the cleanup job
// deletes their files. The download tokens of those links are deleted, and
// share uploads still in progress die with their link (part writes and
// finalize check its expiry). Request links are left alone: they pause on
// the owner's state and resume at the next login.
func expireOwnerShares(ctx context.Context, tx *sql.Tx, userID string, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `UPDATE shares SET expires_at = ? WHERE owner_id = ? AND expires_at > ?`,
		unix(now), userID, unix(now)); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM dl_tokens WHERE share_id IN (SELECT id FROM shares WHERE owner_id = ?)`, userID)
	return err
}

// ownerActive is the SQL predicate, on a users row u, of an account that may
// still publish and receive files: not disabled and not marked as having
// lost access (audit I-3, 2026-11b L-2).
const ownerActive = `u.disabled_at IS NULL AND u.access_lost_at IS NULL`

// AccountActive reports whether the account may still receive files: not
// disabled and not marked as having lost access (audit I-3).
func (s *Store) AccountActive(ctx context.Context, userID string) (bool, error) {
	var ok bool
	err := s.db.R.QueryRowContext(ctx, `SELECT `+ownerActive+` FROM users u WHERE u.id = ?`, userID).Scan(&ok)
	return ok, notFound(err)
}
