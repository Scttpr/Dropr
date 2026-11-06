// Package store holds typed queries for each table. There is no ORM: every
// statement is written out and parameterized.
package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/scttpr/dropr/internal/db"
)

// ErrNotFound is returned when a looked-up row does not exist.
var ErrNotFound = errors.New("store: not found")

// ErrConflict is returned when a write would violate a uniqueness rule.
var ErrConflict = errors.New("store: conflict")

// Store is the repository over the database pools.
type Store struct {
	db *db.DB
}

// New returns a Store over d.
func New(d *db.DB) *Store { return &Store{db: d} }

// DB exposes the underlying database (for jobs and backups).
func (s *Store) DB() *db.DB { return s.db }

func unix(t time.Time) int64 { return t.Unix() }

func fromUnix(v int64) time.Time { return time.Unix(v, 0).UTC() }

func fromNullUnix(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := fromUnix(v.Int64)
	return &t
}

func nullUnix(t *time.Time) sql.NullInt64 {
	if t == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: t.Unix(), Valid: true}
}

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
