package jobs

import (
	"context"
	"errors"
	"time"

	"github.com/scttpr/dropr/internal/blob"
	"github.com/scttpr/dropr/internal/store"
)

// Lifetimes enforced by the file cleanup tasks.
const (
	// StaleUploadAge is how long an upload may stay incomplete.
	StaleUploadAge = 24 * time.Hour
	// OrphanGrace protects blob directories younger than this from the
	// orphan sweep (rows are always created before their directory, so this
	// is only a safety margin).
	OrphanGrace = time.Hour
)

// FileTasks returns the cleanup tasks for links, uploads, tokens and blob
// files (DESIGN.md §4, §6). Rows are deleted first, in one transaction each,
// then the files; files whose removal fails are picked up by the orphan
// sweep on a later run. onPurged, if not nil, is called for every expired
// link deleted, with kind "share" or "request" (audit.PurgeLogger).
func FileTasks(st *store.Store, blobs *blob.Store, now func() time.Time, onPurged func(ctx context.Context, kind, id string)) []Task {
	if now == nil {
		now = time.Now
	}
	remove := func(ids []string, err error) (int64, error) {
		var errs []error
		for _, id := range ids {
			errs = append(errs, blobs.Remove(id))
		}
		return int64(len(ids)), errors.Join(append(errs, err)...)
	}
	return []Task{
		{Name: "expired-links", Run: func(ctx context.Context) (int64, error) {
			p, err := st.DeleteExpiredLinks(ctx, now())
			if err != nil {
				return 0, err
			}
			if onPurged != nil {
				for _, id := range p.Shares {
					onPurged(ctx, "share", id)
				}
				for _, id := range p.Requests {
					onPurged(ctx, "request", id)
				}
			}
			return remove(p.Blobs, nil)
		}},
		{Name: "stale-uploads", Run: func(ctx context.Context) (int64, error) {
			return remove(st.DeleteStaleUploads(ctx, now().Add(-StaleUploadAge)))
		}},
		{Name: "expired-download-tokens", Run: func(ctx context.Context) (int64, error) {
			return st.DeleteExpiredDownloadTokens(ctx, now())
		}},
		{Name: "orphan-blobs", Run: func(ctx context.Context) (int64, error) {
			return SweepOrphans(ctx, st, blobs, now().Add(-OrphanGrace))
		}},
	}
}

// SweepOrphans removes blob directories older than before that have no
// database row (left behind by a crash, `dropr user purge`, a schema
// migration that deleted rows, or a failed removal).
func SweepOrphans(ctx context.Context, st *store.Store, blobs *blob.Store, before time.Time) (int64, error) {
	var n int64
	err := blobs.Walk(ctx, func(id string, mod time.Time) error {
		if mod.After(before) {
			return nil
		}
		ok, err := st.BlobExists(ctx, id)
		if err != nil || ok {
			return err
		}
		if err := blobs.Remove(id); err != nil {
			return err
		}
		n++
		return nil
	})
	return n, err
}
