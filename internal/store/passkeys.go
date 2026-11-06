package store

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrKeyMismatch means a passkey registration carried a public key other
// than the account's.
var ErrKeyMismatch = errors.New("store: public key mismatch")

// ErrTooFewPasskeys means deleting a passkey would leave fewer than the
// required minimum.
var ErrTooFewPasskeys = errors.New("store: too few passkeys")

// ErrPasskeysChanged means a passkey registration was authorized for an
// account state (no passkeys yet, or some) that no longer holds.
var ErrPasskeysChanged = errors.New("store: passkeys changed")

// Passkey is a registered WebAuthn credential and the owner private key
// wrapped under its PRF-derived KEK.
type Passkey struct {
	ID             []byte // credential ID
	UserID         string
	Credential     []byte // go-webauthn Credential, JSON
	SignCount      uint32
	WrappedPrivkey []byte
	CreatedAt      time.Time
	LastUsedAt     *time.Time
}

const passkeyCols = //nolint:gosec // column list, not a credential
`id, user_id, credential, sign_count, wrapped_privkey, created_at, last_used_at`

func scanPasskey(r scanner) (*Passkey, error) {
	var (
		p        Passkey
		count    int64
		created  int64
		lastUsed sql.NullInt64
	)
	if err := r.Scan(&p.ID, &p.UserID, &p.Credential, &count, &p.WrappedPrivkey, &created, &lastUsed); err != nil {
		return nil, notFound(err)
	}
	p.SignCount = uint32(min(max(count, 0), 1<<32-1)) //nolint:gosec // clamped
	p.CreatedAt = fromUnix(created)
	p.LastUsedAt = fromNullUnix(lastUsed)
	return &p, nil
}

// WebAuthnHandleSize is the size of the random WebAuthn user handle.
const WebAuthnHandleSize = 32

// WebAuthnHandle returns the user's WebAuthn user handle, creating it on
// first use. It never changes afterwards.
func (s *Store) WebAuthnHandle(ctx context.Context, userID string) ([]byte, error) {
	var h []byte
	err := s.db.R.QueryRowContext(ctx, `SELECT webauthn_handle FROM users WHERE id = ?`, userID).Scan(&h)
	if err != nil {
		return nil, notFound(err)
	}
	if len(h) == WebAuthnHandleSize {
		return h, nil
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT webauthn_handle FROM users WHERE id = ?`, userID).Scan(&h); err != nil {
			return notFound(err)
		}
		if len(h) == WebAuthnHandleSize {
			return nil
		}
		h = make([]byte, WebAuthnHandleSize)
		_, _ = rand.Read(h)
		_, err := tx.ExecContext(ctx, `UPDATE users SET webauthn_handle = ? WHERE id = ?`, h, userID)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("store: webauthn handle: %w", err)
	}
	return h, nil
}

// Passkeys lists a user's passkeys, oldest first.
func (s *Store) Passkeys(ctx context.Context, userID string) ([]*Passkey, error) {
	rows, err := s.db.R.QueryContext(ctx, `SELECT `+passkeyCols+` FROM passkeys WHERE user_id = ? ORDER BY created_at, rowid`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []*Passkey
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CountPasskeys returns how many passkeys a user has.
func (s *Store) CountPasskeys(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.db.R.QueryRowContext(ctx, `SELECT count(*) FROM passkeys WHERE user_id = ?`, userID).Scan(&n)
	return n, err
}

// UserPubkey returns the account's X25519 public key, or ErrNotFound before
// the first passkey registration.
func (s *Store) UserPubkey(ctx context.Context, userID string) ([]byte, error) {
	var pk []byte
	err := s.db.R.QueryRowContext(ctx, `SELECT pubkey FROM user_keys WHERE user_id = ?`, userID).Scan(&pk)
	return pk, notFound(err)
}

// AddPasskey stores a new passkey. The first registration of an account also
// stores pubkey as the account key; later ones must present the identical key
// (compared in constant time) or fail with ErrKeyMismatch. wantFirst states
// which of the two the caller authorized (the initial setup, or an addition
// granted by an existing passkey): any other state fails with
// ErrPasskeysChanged, atomically. A credential ID already registered fails
// with ErrConflict.
func (s *Store) AddPasskey(ctx context.Context, p *Passkey, pubkey []byte, wantFirst bool) error {
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		var cur []byte
		err := tx.QueryRowContext(ctx, `SELECT pubkey FROM user_keys WHERE user_id = ?`, p.UserID).Scan(&cur)
		first := errors.Is(err, sql.ErrNoRows)
		if err != nil && !first {
			return err
		}
		if first != wantFirst {
			return ErrPasskeysChanged
		}
		switch {
		case first:
			if _, err := tx.ExecContext(ctx, `INSERT INTO user_keys (user_id, pubkey) VALUES (?, ?)`, p.UserID, pubkey); err != nil {
				return err
			}
		case subtle.ConstantTimeCompare(cur, pubkey) != 1:
			return ErrKeyMismatch
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO passkeys (`+passkeyCols+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			p.ID, p.UserID, p.Credential, int64(p.SignCount), p.WrappedPrivkey, unix(p.CreatedAt), nullUnix(p.LastUsedAt))
		if err != nil && isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	})
}

func isUniqueViolation(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "UNIQUE constraint failed") ||
		strings.Contains(err.Error(), "PRIMARY KEY constraint failed"))
}

// UpdatePasskeyUse records a successful assertion: the updated credential
// record (flags, counter), its sign count and the time of use.
func (s *Store) UpdatePasskeyUse(ctx context.Context, userID string, id, credential []byte, signCount uint32, at time.Time) error {
	res, err := s.db.W.ExecContext(ctx, `UPDATE passkeys SET credential = ?, sign_count = ?, last_used_at = ? WHERE id = ? AND user_id = ?`,
		credential, int64(signCount), unix(at), id, userID)
	if err != nil {
		return err
	}
	return requireOne(res)
}

// DeletePasskey removes one of a user's passkeys unless fewer than keep would
// remain (ErrTooFewPasskeys). A passkey of another user is ErrNotFound.
func (s *Store) DeletePasskey(ctx context.Context, userID string, id []byte, keep int) error {
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		var one int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM passkeys WHERE id = ? AND user_id = ?`, id, userID).Scan(&one); err != nil {
			return notFound(err)
		}
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM passkeys WHERE user_id = ?`, userID).Scan(&n); err != nil {
			return err
		}
		if n-1 < keep {
			return ErrTooFewPasskeys
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM passkeys WHERE id = ? AND user_id = ?`, id, userID)
		return err
	})
}

// PutCeremony stores the pending WebAuthn ceremony of a session, replacing
// any previous one.
func (s *Store) PutCeremony(ctx context.Context, sessionHash []byte, kind string, data []byte, expires time.Time) error {
	_, err := s.db.W.ExecContext(ctx, `INSERT INTO webauthn_ceremonies (session_hash, kind, data, expires_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (session_hash) DO UPDATE SET kind = excluded.kind, data = excluded.data, expires_at = excluded.expires_at`,
		sessionHash, kind, data, unix(expires))
	return err
}

// TakeCeremony removes and returns the pending ceremony of a session if it
// is of the given kind and not expired. It is single-use: the row is deleted
// whatever the outcome.
func (s *Store) TakeCeremony(ctx context.Context, sessionHash []byte, kind string, now time.Time) ([]byte, error) {
	var (
		gotKind string
		data    []byte
		expires int64
	)
	err := s.db.W.QueryRowContext(ctx, `DELETE FROM webauthn_ceremonies WHERE session_hash = ? RETURNING kind, data, expires_at`,
		sessionHash).Scan(&gotKind, &data, &expires)
	if err != nil {
		return nil, notFound(err)
	}
	if gotKind != kind || expires <= unix(now) {
		return nil, ErrNotFound
	}
	return data, nil
}

// DeleteExpiredCeremonies removes abandoned ceremonies.
func (s *Store) DeleteExpiredCeremonies(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.W.ExecContext(ctx, `DELETE FROM webauthn_ceremonies WHERE expires_at <= ?`, unix(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Passkey management grant purposes (ARCHITECTURE.md §3 "Passkeys").
const (
	GrantAdd    = "add"
	GrantDelete = "delete"
)

// PutPasskeyGrant records a single-use passkey management grant on a
// session, replacing any previous one. target is the credential ID a
// "delete" grant is limited to (nil for "add").
func (s *Store) PutPasskeyGrant(ctx context.Context, sessionHash []byte, purpose string, target []byte, expires time.Time) error {
	_, err := s.db.W.ExecContext(ctx, `INSERT INTO passkey_grants (session_hash, purpose, target, expires_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (session_hash) DO UPDATE SET purpose = excluded.purpose, target = excluded.target, expires_at = excluded.expires_at`,
		sessionHash, purpose, target, unix(expires))
	return err
}

// TakePasskeyGrant consumes the session's grant if it has the given purpose
// and target (compared in constant time) and has not expired, returning its
// expiry. The grant is deleted whatever the outcome; ErrNotFound otherwise.
func (s *Store) TakePasskeyGrant(ctx context.Context, sessionHash []byte, purpose string, target []byte, now time.Time) (time.Time, error) {
	var (
		gotPurpose string
		gotTarget  []byte
		expires    int64
	)
	err := s.db.W.QueryRowContext(ctx, `DELETE FROM passkey_grants WHERE session_hash = ? RETURNING purpose, target, expires_at`,
		sessionHash).Scan(&gotPurpose, &gotTarget, &expires)
	if err != nil {
		return time.Time{}, notFound(err)
	}
	if gotPurpose != purpose || expires <= unix(now) ||
		len(gotTarget) != len(target) || subtle.ConstantTimeCompare(gotTarget, target) != 1 {
		return time.Time{}, ErrNotFound
	}
	return fromUnix(expires), nil
}

// DeleteExpiredPasskeyGrants removes unused grants.
func (s *Store) DeleteExpiredPasskeyGrants(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.W.ExecContext(ctx, `DELETE FROM passkey_grants WHERE expires_at <= ?`, unix(now))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PendingSetupElsewhere reports whether another live session of the user
// has an unexpired registration ceremony in progress (the initial setup
// window of an account without passkeys belongs to the session that
// started it).
func (s *Store) PendingSetupElsewhere(ctx context.Context, userID string, sessionHash []byte, now time.Time) (bool, error) {
	var n int
	err := s.db.R.QueryRowContext(ctx, `SELECT count(*) FROM webauthn_ceremonies c JOIN sessions s ON s.id_hash = c.session_hash
		WHERE s.user_id = ? AND c.session_hash <> ? AND c.kind = 'register' AND c.expires_at > ?`,
		userID, sessionHash, unix(now)).Scan(&n)
	return n > 0, err
}
