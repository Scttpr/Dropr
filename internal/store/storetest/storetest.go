// Package storetest provides a migrated, throwaway database for tests.
package storetest

import (
	"path/filepath"
	"testing"

	"github.com/scttpr/dropr/internal/db"
	"github.com/scttpr/dropr/internal/store"
)

// New returns a Store over a fresh database in t.TempDir().
func New(t testing.TB) *store.Store {
	t.Helper()
	d, err := db.Open(t.Context(), filepath.Join(t.TempDir(), "dropr.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return store.New(d)
}
