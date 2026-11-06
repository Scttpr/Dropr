package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var ms []migration
	for _, e := range entries {
		name := e.Name()
		num, _, ok := strings.Cut(name, "_")
		if !ok || !strings.HasSuffix(name, ".sql") {
			return nil, fmt.Errorf("db: bad migration file name %q", name)
		}
		v, err := strconv.Atoi(num)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("db: bad migration number in %q", name)
		}
		body, err := fs.ReadFile(migrationFS, "migrations/"+name)
		if err != nil {
			return nil, err
		}
		ms = append(ms, migration{version: v, name: name, sql: string(body)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	for i, m := range ms {
		if m.version != i+1 {
			return nil, fmt.Errorf("db: migrations must be numbered contiguously from 1; found %q at position %d", m.name, i+1)
		}
	}
	return ms, nil
}

// LatestVersion is the schema version this binary migrates to.
func LatestVersion() int {
	ms, err := loadMigrations()
	if err != nil {
		return 0
	}
	return len(ms)
}

func (d *DB) migrate(ctx context.Context) error {
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	if _, err := d.W.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_version (
		version    INTEGER PRIMARY KEY,
		name       TEXT    NOT NULL,
		applied_at INTEGER NOT NULL
	) STRICT`); err != nil {
		return fmt.Errorf("db: create schema_version: %w", err)
	}
	cur, err := d.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	if cur > len(ms) {
		return fmt.Errorf("db: database schema version %d is newer than this binary supports (%d); refusing to downgrade", cur, len(ms))
	}
	for _, m := range ms[cur:] {
		err := d.Tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, m.sql); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO schema_version (version, name, applied_at) VALUES (?, ?, ?)`,
				m.version, m.name, time.Now().Unix())
			return err
		})
		if err != nil {
			return fmt.Errorf("db: migration %s: %w", m.name, err)
		}
	}
	// Verify referential integrity after migrating.
	rows, err := d.W.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return fmt.Errorf("db: foreign_key_check: %w", err)
	}
	defer func() { _ = rows.Close() }()
	if rows.Next() {
		return errors.New("db: foreign key violations present after migration")
	}
	return rows.Err()
}

// SchemaVersion returns the highest applied migration version.
func (d *DB) SchemaVersion(ctx context.Context) (int, error) {
	var v sql.NullInt64
	if err := d.W.QueryRowContext(ctx, "SELECT MAX(version) FROM schema_version").Scan(&v); err != nil {
		return 0, fmt.Errorf("db: read schema version: %w", err)
	}
	return int(v.Int64), nil
}
