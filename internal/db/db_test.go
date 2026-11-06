package db

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func open(t *testing.T) *DB {
	t.Helper()
	d, err := Open(t.Context(), filepath.Join(t.TempDir(), "dropr.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func TestOpenMigratesAndPragmas(t *testing.T) {
	t.Parallel()
	d := open(t)
	ctx := t.Context()
	v, err := d.SchemaVersion(ctx)
	if err != nil || v != LatestVersion() || v < 1 {
		t.Fatalf("version %d %v", v, err)
	}
	for _, p := range []struct{ pragma, want string }{
		{"journal_mode", "wal"}, {"foreign_keys", "1"}, {"synchronous", "1"}, {"busy_timeout", busyTimeoutMS},
	} {
		for name, pool := range map[string]*sql.DB{"W": d.W, "R": d.R} {
			var got string
			if err := pool.QueryRowContext(ctx, "PRAGMA "+p.pragma).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if !strings.EqualFold(got, p.want) {
				t.Errorf("%s %s = %s, want %s", name, p.pragma, got, p.want)
			}
		}
	}
	// The read pool is query-only.
	if _, err := d.R.ExecContext(ctx, "DELETE FROM users"); err == nil {
		t.Error("write through read pool succeeded")
	}
	// Every table is STRICT.
	rows, err := d.R.QueryContext(ctx, "SELECT name, strict FROM pragma_table_list WHERE schema = 'main' AND name NOT LIKE 'sqlite_%'")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	n := 0
	for rows.Next() {
		var name string
		var strict int
		if err := rows.Scan(&name, &strict); err != nil {
			t.Fatal(err)
		}
		n++
		if strict != 1 {
			t.Errorf("table %s is not STRICT", name)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n != 12 {
		t.Errorf("expected 12 tables, got %d", n)
	}
}

func TestReopenIsIdempotentAndDowngradeRefused(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "d.db")
	d, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	d, err = Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.W.ExecContext(ctx, "INSERT INTO schema_version VALUES (999, 'future', 0)"); err != nil {
		t.Fatal(err)
	}
	_ = d.Close()
	if _, err := Open(ctx, path); err == nil || !strings.Contains(err.Error(), "refusing to downgrade") {
		t.Fatalf("got %v", err)
	}
}

func TestConstraintsAndCascade(t *testing.T) {
	t.Parallel()
	d := open(t)
	ctx := t.Context()
	exec := func(q string, args ...any) error {
		_, err := d.W.ExecContext(ctx, q, args...)
		return err
	}
	uid := strings.Repeat("u", 22)
	if err := exec("INSERT INTO users (id, issuer, subject, created_at) VALUES (?, 'i', 's', 0)", uid); err != nil {
		t.Fatal(err)
	}
	// STRICT typing: text in an INTEGER column is refused.
	if err := exec("INSERT INTO users (id, issuer, subject, created_at) VALUES (?, 'i', 's2', 'yesterday')", strings.Repeat("v", 22)); err == nil {
		t.Error("STRICT not enforced")
	}
	// Foreign keys enforced.
	if err := exec("INSERT INTO sessions (id_hash, user_id, created_at, last_seen_at, revalidated_at) VALUES (?, 'nope', 0, 0, 0)", make([]byte, 32)); err == nil {
		t.Error("FK not enforced")
	}
	if err := exec("INSERT INTO sessions (id_hash, user_id, created_at, last_seen_at, revalidated_at) VALUES (?, ?, 0, 0, 0)", make([]byte, 32), uid); err != nil {
		t.Fatal(err)
	}
	bid := strings.Repeat("b", 22)
	if err := exec("INSERT INTO blobs (id, owner_id, parts, size, created_at) VALUES (?, ?, 1, 10, 0)", bid, uid); err != nil {
		t.Fatal(err)
	}
	if err := exec("INSERT INTO shares (id, owner_id, blob_id, size, meta, expires_at, created_at) VALUES (?, ?, ?, 10, x'01', 0, 0)", strings.Repeat("s", 22), uid, bid); err != nil {
		t.Fatal(err)
	}
	if err := exec("DELETE FROM users WHERE id = ?", uid); err != nil {
		t.Fatal(err)
	}
	for _, tbl := range []string{"sessions", "blobs", "shares"} {
		var n int
		if err := d.R.QueryRowContext(ctx, "SELECT count(*) FROM "+tbl).Scan(&n); err != nil { //nolint:gosec // fixed table names
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s not cascaded: %d rows", tbl, n)
		}
	}
}

func TestConcurrentWritesNoBusy(t *testing.T) {
	t.Parallel()
	d := open(t)
	ctx := t.Context()
	var wg sync.WaitGroup
	errs := make(chan error, 128)
	for i := range 64 {
		wg.Go(func() {
			err := d.Tx(ctx, func(tx *sql.Tx) error {
				var n int
				if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&n); err != nil {
					return err
				}
				_, err := tx.ExecContext(ctx, "INSERT INTO users (id, issuer, subject, created_at) VALUES (?, 'i', ?, 0)",
					strings.Repeat(string(rune('A'+i%26)), 21)+string(rune('A'+i/26)), i)
				return err
			})
			errs <- err
			// Concurrent reads too.
			var n int
			errs <- d.R.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&n)
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestTxRollback(t *testing.T) {
	t.Parallel()
	d := open(t)
	ctx := t.Context()
	boom := errors.New("boom")
	err := d.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "INSERT INTO users (id, issuer, subject, created_at) VALUES (?, 'i', 's', 0)", strings.Repeat("r", 22)); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	var n int
	_ = d.R.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&n)
	if n != 0 {
		t.Fatal("not rolled back")
	}
}

func TestBackup(t *testing.T) {
	t.Parallel()
	d := open(t)
	ctx := context.Background()
	if _, err := d.W.ExecContext(ctx, "INSERT INTO users (id, issuer, subject, created_at) VALUES (?, 'i', 's', 0)", strings.Repeat("k", 22)); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "backup.db")
	if err := d.Backup(ctx, dest); err != nil {
		t.Fatal(err)
	}
	if err := d.Backup(ctx, dest); err == nil {
		t.Error("overwrote existing backup")
	}
	b, err := Open(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	var n int
	if err := b.R.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&n); err != nil || n != 1 {
		t.Fatalf("backup content: %d %v", n, err)
	}
}
