// Package db opens Dropr's SQLite database, applies the embedded schema
// migrations and provides online backups.
//
// SQLite allows one writer at a time. To avoid SQLITE_BUSY under concurrent
// load, the database is opened through two pools on the same file:
//
//   - W: exactly one connection, transactions start with BEGIN IMMEDIATE so a
//     writer takes the lock up front instead of failing on upgrade;
//   - R: several query_only connections for reads, which WAL lets run
//     concurrently with the writer.
//
// Every connection uses foreign_keys=ON, busy_timeout and synchronous=NORMAL
// (durable across application crashes; WAL may lose the last transactions on
// power loss, which is acceptable for this workload).
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// DB bundles the writer and reader pools.
type DB struct {
	W    *sql.DB // single-connection writer pool
	R    *sql.DB // read-only pool
	path string
}

const busyTimeoutMS = "10000"

// Open opens (creating if needed) the database file at path and migrates it to
// the latest schema version.
func Open(ctx context.Context, path string) (*DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}
	// Create the file with owner-only permissions before SQLite does (which
	// would use 0644). The -wal and -shm files inherit these permissions.
	f, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // path from config
	if err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}
	_ = f.Close()

	w, err := sql.Open("sqlite", dsn(abs, false))
	if err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)
	w.SetConnMaxLifetime(0)
	w.SetConnMaxIdleTime(0)

	d := &DB{W: w, path: abs}
	if err := w.PingContext(ctx); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("db: open %s: %w", abs, err)
	}
	if err := d.migrate(ctx); err != nil {
		_ = w.Close()
		return nil, err
	}

	r, err := sql.Open("sqlite", dsn(abs, true))
	if err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("db: %w", err)
	}
	n := max(4, runtime.NumCPU())
	r.SetMaxOpenConns(n)
	r.SetMaxIdleConns(n)
	d.R = r
	if err := r.PingContext(ctx); err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("db: %w", err)
	}
	return d, nil
}

func dsn(path string, readOnly bool) string {
	q := url.Values{}
	q.Set("_busy_timeout", busyTimeoutMS)
	q.Set("_foreign_keys", "1")
	q.Set("_journal_mode", "WAL")
	q.Set("_synchronous", "NORMAL")
	q.Add("_pragma", "trusted_schema(0)")
	if readOnly {
		q.Set("_query_only", "1")
	} else {
		q.Set("_txlock", "immediate")
	}
	u := url.URL{Scheme: "file", OmitHost: true, Path: path, RawQuery: q.Encode()}
	return u.String()
}

// Close closes both pools.
func (d *DB) Close() error {
	var errs []error
	if d.R != nil {
		errs = append(errs, d.R.Close())
	}
	if d.W != nil {
		errs = append(errs, d.W.Close())
	}
	return errors.Join(errs...)
}

// Path returns the absolute database file path.
func (d *DB) Path() string { return d.path }

// Tx runs fn in a write transaction (BEGIN IMMEDIATE), committing if fn
// returns nil and rolling back otherwise.
func (d *DB) Tx(ctx context.Context, fn func(*sql.Tx) error) (err error) {
	tx, err := d.W.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Backup writes a consistent, compacted copy of the live database to dest
// using VACUUM INTO. dest must not exist. The copy is written inside a fresh
// 0700 directory next to dest and made 0600 before it is moved into place, so
// it is never readable under the process umask while it is written (audit
// 2026-11 L-10).
func (d *DB) Backup(ctx context.Context, dest string) error {
	abs, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(abs); err == nil {
		return fmt.Errorf("db: backup destination %s already exists", abs)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir, err := os.MkdirTemp(filepath.Dir(abs), ".dropr-backup-")
	if err != nil {
		return fmt.Errorf("db: backup: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	tmp := filepath.Join(dir, "backup.db")
	if _, err := d.W.ExecContext(ctx, "VACUUM INTO ?", tmp); err != nil {
		return fmt.Errorf("db: backup: %w", err)
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return fmt.Errorf("db: backup: %w", err)
	}
	return placeNew(tmp, abs)
}

// placeNew moves src to dst without replacing an existing dst: a hard link
// fails if dst exists. File systems without hard links fall back to a rename
// after a fresh existence check.
func placeNew(src, dst string) error {
	err := os.Link(src, dst)
	switch {
	case err == nil:
		return os.Remove(src)
	case errors.Is(err, os.ErrExist):
		return fmt.Errorf("db: backup destination %s already exists", dst)
	}
	if _, serr := os.Lstat(dst); serr == nil {
		return fmt.Errorf("db: backup destination %s already exists", dst)
	} else if !errors.Is(serr, os.ErrNotExist) {
		return serr
	}
	if err := os.Rename(src, dst); err != nil {
		return fmt.Errorf("db: backup: %w", err)
	}
	return nil
}
