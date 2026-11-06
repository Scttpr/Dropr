package blob

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/scttpr/dropr/internal/ids"
	"github.com/scttpr/dropr/internal/keyed"
)

// Errors returned by Store.
var (
	// ErrPartSize means a part body did not have its exact expected size.
	ErrPartSize = errors.New("blob: wrong part size")
	// ErrIncomplete means a part is missing or has the wrong size.
	ErrIncomplete = errors.New("blob: incomplete")
	// ErrNoSpace means accepting the upload would leave less free disk space
	// than the configured headroom, or the disk filled up during a write.
	ErrNoSpace = errors.New("blob: not enough free disk space")
)

// DiskUsage reports the space available to the server process and the total
// size of the file system holding path.
type DiskUsage func(path string) (avail, total uint64, err error)

// Options configure a Store.
type Options struct {
	// Headroom is the free space that must remain after accepting an upload.
	// Zero selects max(1 GiB, 5% of the file system).
	Headroom int64
	// Usage overrides the free-space probe (tests). Nil selects statfs(2).
	Usage DiskUsage
}

// Store keeps blobs under one root directory.
type Store struct {
	root     string
	headroom int64
	usage    DiskUsage
	// locks serializes part commits with state changes per blob.
	locks keyed.Mutex
}

const partPrefix = "part"

// New returns a store rooted at dir (created with mode 0700 if needed).
func New(dir string, o Options) (*Store, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("blob: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("blob: %w", err)
	}
	if o.Usage == nil {
		o.Usage = statfs
	}
	return &Store{root: abs, headroom: o.Headroom, usage: o.Usage}, nil
}

// Root returns the root directory.
func (s *Store) Root() string { return s.root }

// dir returns the directory of blob id. id must be a valid identifier, which
// also guarantees it cannot escape the root.
func (s *Store) dir(id string) (string, error) {
	if !ids.Valid(id) {
		return "", fmt.Errorf("blob: invalid id %q", id)
	}
	return filepath.Join(s.root, id[0:2], id[2:4], id), nil
}

func partName(n int) string { return fmt.Sprintf("%s%05d", partPrefix, n) }

// CheckSpace returns ErrNoSpace if storing need more bytes would leave less
// than the headroom free.
func (s *Store) CheckSpace(need int64) error {
	avail, total, err := s.usage(s.root)
	if err != nil {
		return fmt.Errorf("blob: disk usage: %w", err)
	}
	headroom := s.headroom
	if headroom <= 0 {
		headroom = max(1<<30, int64(total/20)) //nolint:gosec // file system sizes fit in int64
	}
	if avail > 1<<62 {
		avail = 1 << 62
	}
	if int64(avail)-need < headroom { //nolint:gosec // clamped above
		return ErrNoSpace
	}
	return nil
}

// WritePart stores part n of blob id from r, which must yield exactly want
// bytes. The part is written to a temporary file, synced and renamed into
// place, so a part is either absent or complete; re-writing a part replaces
// it atomically. On a size mismatch nothing is stored and ErrPartSize is
// returned; reading stops after want+1 bytes.
func (s *Store) WritePart(id string, n int, want int64, r io.Reader) error {
	return s.WritePartIf(context.Background(), id, n, want, r, nil)
}

// WritePartIf is WritePart with a last-moment check: once the body is fully
// written and synced, commit (if non-nil) runs while the blob's lock is
// held, right before the rename. If it fails, nothing is stored and its error
// is returned. Callers that change a blob's state with Locked (finalize)
// thereby never see a part land after their change (audit L-3).
func (s *Store) WritePartIf(ctx context.Context, id string, n int, want int64, r io.Reader, commit func(context.Context) error) (err error) {
	if n < 0 || n >= MaxParts || want < 0 || want > PartCipherSize {
		return ErrPartSize
	}
	dir, err := s.dir(id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return mapNoSpace(err)
	}
	f, err := os.CreateTemp(dir, ".tmp-"+partName(n)+"-*")
	if err != nil {
		return mapNoSpace(err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	written, err := io.Copy(f, io.LimitReader(r, want+1))
	if err != nil {
		return mapNoSpace(err)
	}
	if written != want {
		return ErrPartSize
	}
	if err := f.Sync(); err != nil {
		return mapNoSpace(err)
	}
	if err := f.Close(); err != nil {
		return mapNoSpace(err)
	}
	unlock := s.locks.Lock(id)
	defer unlock()
	if commit != nil {
		if err := commit(ctx); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp, filepath.Join(dir, partName(n))); err != nil {
		return err
	}
	return syncDir(dir)
}

// Locked runs fn while holding blob id's lock, which WritePartIf holds while
// it checks and renames a part into place.
func (s *Store) Locked(ctx context.Context, id string, fn func(context.Context) error) error {
	unlock := s.locks.Lock(id)
	defer unlock()
	return fn(ctx)
}

func mapNoSpace(err error) error {
	if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EDQUOT) {
		return fmt.Errorf("%w: %w", ErrNoSpace, err)
	}
	return err
}

func syncDir(dir string) error {
	d, err := os.Open(dir) //nolint:gosec // path built from a validated id
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

// Present returns the indexes of the parts of g that are stored with their
// exact size, in ascending order.
func (s *Store) Present(id string, g Geometry) ([]int, error) {
	dir, err := s.dir(id)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return []int{}, nil
	} else if err != nil {
		return nil, err
	}
	out := []int{}
	for _, e := range entries {
		n, ok := parsePartName(e.Name())
		if !ok || n >= g.Parts || !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.Size() == g.PartSize(n) {
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out, nil
}

func parsePartName(name string) (int, bool) {
	digits, ok := strings.CutPrefix(name, partPrefix)
	if !ok || len(digits) != 5 {
		return 0, false
	}
	n, err := strconv.Atoi(digits)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// Verify checks that every part of g is stored with its exact size.
func (s *Store) Verify(id string, g Geometry) error {
	dir, err := s.dir(id)
	if err != nil {
		return err
	}
	for n := range g.Parts {
		info, err := os.Stat(filepath.Join(dir, partName(n)))
		if err != nil || !info.Mode().IsRegular() || info.Size() != g.PartSize(n) {
			return fmt.Errorf("%w: part %d", ErrIncomplete, n)
		}
	}
	return nil
}

// Remove deletes blob id from disk and prunes the now-empty shard
// directories. Removing a missing blob is not an error.
func (s *Store) Remove(id string) error {
	dir, err := s.dir(id)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	// Best effort: os.Remove fails on non-empty directories.
	shard2 := filepath.Dir(dir)
	if os.Remove(shard2) == nil {
		_ = os.Remove(filepath.Dir(shard2))
	}
	return nil
}

// Walk calls fn with the id and modification time of every blob directory.
// Entries that are not blob directories are skipped.
func (s *Store) Walk(ctx context.Context, fn func(id string, mod time.Time) error) error {
	l1, err := os.ReadDir(s.root)
	if err != nil {
		return err
	}
	for _, a := range l1 {
		if !a.IsDir() || len(a.Name()) != 2 {
			continue
		}
		l2, err := os.ReadDir(filepath.Join(s.root, a.Name()))
		if err != nil {
			return err
		}
		for _, b := range l2 {
			if !b.IsDir() || len(b.Name()) != 2 {
				continue
			}
			l3, err := os.ReadDir(filepath.Join(s.root, a.Name(), b.Name()))
			if err != nil {
				return err
			}
			for _, c := range l3 {
				id := c.Name()
				if !c.IsDir() || !ids.Valid(id) || id[0:2] != a.Name() || id[2:4] != b.Name() {
					continue
				}
				if err := ctx.Err(); err != nil {
					return err
				}
				info, err := c.Info()
				if err != nil {
					continue
				}
				if err := fn(id, info.ModTime()); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// Open returns a reader over the complete ciphertext of blob id. Every part
// must be present with its exact size.
func (s *Store) Open(id string, g Geometry) (*Reader, error) {
	if err := s.Verify(id, g); err != nil {
		return nil, err
	}
	dir, _ := s.dir(id)
	return &Reader{dir: dir, g: g, cur: -1}, nil
}

// Reader presents the parts of a blob as one contiguous io.ReadSeeker. It
// keeps at most one part file open.
type Reader struct {
	dir string
	g   Geometry
	off int64
	cur int // index of the open part, -1 if none
	f   *os.File
}

// Size returns the ciphertext size.
func (r *Reader) Size() int64 { return r.g.Size }

// Read implements io.Reader.
func (r *Reader) Read(p []byte) (int, error) {
	if r.off >= r.g.Size {
		return 0, io.EOF
	}
	n := int(r.off / PartCipherSize)
	inner := r.off % PartCipherSize
	if n != r.cur {
		if r.f != nil {
			_ = r.f.Close()
			r.f, r.cur = nil, -1
		}
		f, err := os.Open(filepath.Join(r.dir, partName(n)))
		if err != nil {
			return 0, err
		}
		r.f, r.cur = f, n
	}
	remain := r.g.PartSize(n) - inner
	if int64(len(p)) > remain {
		p = p[:remain]
	}
	m, err := r.f.ReadAt(p, inner)
	r.off += int64(m)
	if errors.Is(err, io.EOF) && m == len(p) {
		err = nil
	}
	if err == nil && m < len(p) {
		err = io.ErrUnexpectedEOF
	}
	return m, err
}

// Seek implements io.Seeker.
func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.off + offset
	case io.SeekEnd:
		abs = r.g.Size + offset
	default:
		return 0, errors.New("blob: invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("blob: negative position")
	}
	r.off = abs
	return abs, nil
}

// Close releases the open part file.
func (r *Reader) Close() error {
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f, r.cur = nil, -1
	return err
}

// DiskBytes returns the bytes the files of blob id occupy (parts and
// temporary part files); 0 if it has none.
func (s *Store) DiskBytes(id string) int64 {
	dir, err := s.dir(id)
	if err != nil {
		return 0
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var n int64
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() {
			n += info.Size()
		}
	}
	return n
}
