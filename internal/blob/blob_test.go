package blob

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/scttpr/dropr/internal/ids"
)

func TestGeometry(t *testing.T) {
	t.Parallel()
	for p, c := range map[int64]int64{0: 16, 1: 17, 65536: 65552, 65537: 65569, PartPlainSize: PartCipherSize} {
		if got := CipherSize(p); got != c {
			t.Errorf("CipherSize(%d) = %d, want %d", p, got, c)
		}
		if got, ok := PlainSize(c); !ok || got != p {
			t.Errorf("PlainSize(%d) = %d %v", c, got, ok)
		}
	}
	for _, c := range []int64{-1, 0, 15, 65568, 65553, 2*65552 + 16} {
		if _, ok := PlainSize(c); ok {
			t.Errorf("PlainSize(%d) accepted", c)
		}
	}
	for p := range int64(70000) {
		if got, ok := PlainSize(CipherSize(p)); !ok || got != p {
			t.Fatalf("round trip %d", p)
		}
	}
	cases := []struct {
		size  int64
		parts int
		ok    bool
	}{
		{16, 1, true},
		{16, 2, false},
		{PartCipherSize, 1, true},
		{CipherSize(PartPlainSize + 1), 2, true},
		{CipherSize(PartPlainSize + 1), 1, false},
		{MaxCipherSize, MaxParts, true},
		{CipherSize(100<<30 + 1), MaxParts + 1, false},
		{65568, 1, false},
		{0, 1, false},
	}
	for _, c := range cases {
		g, err := NewGeometry(c.size, c.parts)
		if (err == nil) != c.ok {
			t.Errorf("NewGeometry(%d, %d): %v", c.size, c.parts, err)
		}
		if err == nil && g.PartSize(g.Parts-1) <= 0 {
			t.Errorf("empty last part for %d", c.size)
		}
	}
	g, _ := NewGeometry(CipherSize(PartPlainSize+1), 2)
	if g.PartSize(0) != PartCipherSize || g.PartSize(1) != 17 || g.PartSize(2) != -1 || g.PartSize(-1) != -1 {
		t.Errorf("part sizes %d %d", g.PartSize(0), g.PartSize(1))
	}
	if MaxPlainFor(15) != 0 || MaxPlainFor(16) != 0 || MaxPlainFor(65552) != 65536 || MaxPlainFor(65552+20) != 65536+4 {
		t.Error("MaxPlainFor")
	}
}

func FuzzGeometry(f *testing.F) {
	f.Add(int64(16), 1)
	f.Add(int64(PartCipherSize), 1)
	f.Add(int64(PartCipherSize+17), 2)
	f.Add(MaxCipherSize, MaxParts)
	f.Add(int64(65568), 1)
	f.Fuzz(func(t *testing.T, size int64, parts int) {
		g, err := NewGeometry(size, parts)
		if err != nil {
			if !errors.Is(err, ErrGeometry) {
				t.Fatal(err)
			}
			return
		}
		p, ok := PlainSize(size)
		if !ok || CipherSize(p) != size || g.Plain() != p {
			t.Fatalf("size %d not a ciphertext size", size)
		}
		if parts < 1 || parts > MaxParts {
			t.Fatalf("parts %d", parts)
		}
		var sum int64
		for n := range parts {
			ps := g.PartSize(n)
			if ps <= 0 || ps > PartCipherSize || (n < parts-1 && ps != PartCipherSize) {
				t.Fatalf("part %d size %d", n, ps)
			}
			sum += ps
		}
		if sum != size {
			t.Fatalf("parts sum %d != %d", sum, size)
		}
		if m := MaxPlainFor(size); m != p {
			t.Fatalf("MaxPlainFor(%d) = %d, want %d", size, m, p)
		}
	})
}

func TestParseRange(t *testing.T) {
	t.Parallel()
	const size = 1000
	cases := []struct {
		h          string
		start, end int64
		ok         bool
		err        bool
	}{
		{"", 0, 0, false, false},
		{"bytes=0-", 0, 999, true, false},
		{"bytes=10-19", 10, 19, true, false},
		{"bytes=990-5000", 990, 999, true, false},
		{"bytes=-100", 900, 999, true, false},
		{"bytes=-5000", 0, 999, true, false},
		{"bytes=999-999", 999, 999, true, false},
		{"bytes=1000-", 0, 0, false, true},
		{"bytes=5-4", 0, 0, false, true},
		{"bytes=-0", 0, 0, false, true},
		{"bytes=0-1,5-6", 0, 0, false, true},
		{"bytes=+1-2", 0, 0, false, true},
		{"bytes= 1-2", 1, 2, true, false},
		{"bytes=1", 0, 0, false, true},
		{"items=0-1", 0, 0, false, true},
		{"bytes=99999999999999999999-", 0, 0, false, true},
	}
	for _, c := range cases {
		s, e, ok, err := ParseRange(c.h, size)
		if (err != nil) != c.err || ok != c.ok || (ok && (s != c.start || e != c.end)) {
			t.Errorf("%q: %d-%d ok=%v err=%v", c.h, s, e, ok, err)
		}
	}
}

func FuzzParseRange(f *testing.F) {
	for _, s := range []string{"bytes=0-", "bytes=1-2", "bytes=-5", "bytes=0-1,2-3", "bytes=--1", ""} {
		f.Add(s, int64(100))
	}
	f.Fuzz(func(t *testing.T, h string, size int64) {
		s, e, ok, err := ParseRange(h, size)
		if err != nil && ok {
			t.Fatal("error with range")
		}
		if ok && (s < 0 || e < s || e >= size) {
			t.Fatalf("%q size %d: %d-%d", h, size, s, e)
		}
		if h == "" && (ok || err != nil) {
			t.Fatal("empty header")
		}
	})
}

func newStore(t testing.TB, usage DiskUsage) *Store {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "blobs"), Options{Usage: usage})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func randBytes(n int64) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func TestWriteReadServe(t *testing.T) {
	t.Parallel()
	s := newStore(t, nil)
	id := ids.New()
	g, err := NewGeometry(CipherSize(PartPlainSize+1000), 2)
	if err != nil {
		t.Fatal(err)
	}
	p0, p1 := randBytes(PartCipherSize), randBytes(g.PartSize(1))
	full := append(append([]byte{}, p0...), p1...)

	if err := s.WritePart(id, 1, g.PartSize(1), bytes.NewReader(p1)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Present(id, g); !slices.Equal(got, []int{1}) {
		t.Errorf("present %v", got)
	}
	if err := s.Verify(id, g); !errors.Is(err, ErrIncomplete) {
		t.Errorf("verify incomplete: %v", err)
	}
	// Short and long bodies are refused and leave nothing behind.
	if err := s.WritePart(id, 0, PartCipherSize, bytes.NewReader(p0[:100])); !errors.Is(err, ErrPartSize) {
		t.Errorf("short: %v", err)
	}
	if err := s.WritePart(id, 0, PartCipherSize, io.MultiReader(bytes.NewReader(p0), strings.NewReader("x"))); !errors.Is(err, ErrPartSize) {
		t.Errorf("long: %v", err)
	}
	if got, _ := s.Present(id, g); !slices.Equal(got, []int{1}) {
		t.Errorf("present after bad writes %v", got)
	}
	// Writing twice replaces the part.
	if err := s.WritePart(id, 0, PartCipherSize, bytes.NewReader(randBytes(PartCipherSize))); err != nil {
		t.Fatal(err)
	}
	if err := s.WritePart(id, 0, PartCipherSize, bytes.NewReader(p0)); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(id, g); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(s.Root(), id[0:2], id[2:4], id))
	if len(entries) != 2 {
		t.Errorf("temporary files left: %v", entries)
	}

	r, err := s.Open(id, g)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, full) {
		t.Fatalf("full read: %v", err)
	}
	// Reads across the part boundary after a seek.
	if _, err := r.Seek(PartCipherSize-10, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 30)
	if _, err := io.ReadFull(r, buf); err != nil || !bytes.Equal(buf, full[PartCipherSize-10:PartCipherSize+20]) {
		t.Fatalf("boundary read: %v", err)
	}
	_ = r.Close()

	serve := func(method string, hdr map[string]string) *httptest.ResponseRecorder {
		r, _ := s.Open(id, g)
		defer func() { _ = r.Close() }()
		req := httptest.NewRequest(method, "/dl/x", nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		if sent, plan := Serve(w, req, r, 0), Planned(req, g.Size); sent != plan || (w.Code < 300 && sent != int64(w.Body.Len())) {
			t.Errorf("%s %v: sent %d, planned %d, body %d", method, hdr, sent, plan, w.Body.Len())
		}
		return w
	}
	w := serve(http.MethodGet, nil)
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), full) || w.Header().Get("Last-Modified") != "" || w.Header().Get("ETag") != "" ||
		w.Header().Get("Content-Type") != "application/octet-stream" || !strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment") {
		t.Errorf("full: %d %v", w.Code, w.Header())
	}
	start := int64(PartCipherSize - 5)
	w = serve(http.MethodGet, map[string]string{"Range": "bytes=" + itoa(start) + "-"})
	if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), full[start:]) ||
		w.Header().Get("Content-Range") != "bytes "+itoa(start)+"-"+itoa(g.Size-1)+"/"+itoa(g.Size) {
		t.Errorf("open range: %d %v", w.Code, w.Header())
	}
	w = serve(http.MethodGet, map[string]string{"Range": "bytes=0-1,5-6"})
	if w.Code != http.StatusRequestedRangeNotSatisfiable || w.Header().Get("Content-Range") != "bytes */"+itoa(g.Size) {
		t.Errorf("multi-range: %d", w.Code)
	}
	w = serve(http.MethodGet, map[string]string{"Range": "bytes=5-9", "If-Range": `"x"`})
	if w.Code != http.StatusOK {
		t.Errorf("If-Range: %d", w.Code)
	}
	w = serve(http.MethodHead, nil)
	if w.Code != http.StatusOK || w.Body.Len() != 0 || w.Header().Get("Content-Length") != itoa(g.Size) {
		t.Errorf("HEAD: %d", w.Code)
	}

	// Walk finds it; Remove deletes it and prunes the shards.
	var found []string
	_ = s.Walk(context.Background(), func(id string, _ time.Time) error { found = append(found, id); return nil })
	if !slices.Equal(found, []string{id}) {
		t.Errorf("walk %v", found)
	}
	if err := s.Remove(id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Root(), id[0:2])); !os.IsNotExist(err) {
		t.Error("shard directories left")
	}
	if err := s.Remove(id); err != nil {
		t.Error("removing twice failed")
	}
	if err := s.WritePart("../../etc", 0, 1, strings.NewReader("x")); err == nil {
		t.Error("path traversal accepted")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestCheckSpace(t *testing.T) {
	t.Parallel()
	var avail, total uint64 = 10 << 30, 100 << 30
	s := newStore(t, func(string) (uint64, uint64, error) { return avail, total, nil })
	// Automatic headroom: max(1 GiB, 5%) = 5 GiB.
	if err := s.CheckSpace(4 << 30); err != nil {
		t.Error(err)
	}
	if err := s.CheckSpace(6 << 30); !errors.Is(err, ErrNoSpace) {
		t.Errorf("6 GiB: %v", err)
	}
	total = 1 << 30 // small disk: the 1 GiB floor applies
	if err := s.CheckSpace(9<<30 + 1); !errors.Is(err, ErrNoSpace) {
		t.Errorf("floor: %v", err)
	}
	s.headroom = 1
	if err := s.CheckSpace(10<<30 - 1); err != nil {
		t.Errorf("explicit headroom: %v", err)
	}
}

// BenchmarkWritePart measures part PUT throughput to the store (tmpfs when
// /dev/shm is available).
func BenchmarkWritePart(b *testing.B) {
	dir := b.TempDir()
	if fi, err := os.Stat("/dev/shm"); err == nil && fi.IsDir() {
		if d, err := os.MkdirTemp("/dev/shm", "dropr-bench-"); err == nil {
			dir = d
			b.Cleanup(func() { _ = os.RemoveAll(d) })
		}
	}
	s, err := New(dir, Options{})
	if err != nil {
		b.Fatal(err)
	}
	data := randBytes(PartCipherSize)
	id := ids.New()
	b.SetBytes(PartCipherSize)
	b.ResetTimer()
	for i := range b.N {
		if err := s.WritePart(id, i%MaxParts, PartCipherSize, bytes.NewReader(data)); err != nil {
			b.Fatal(err)
		}
	}
}

// Audit L-4: a transfer averaging less than the minimum rate over a whole
// window is cut; a fast one, or a check with no minimum, never is.
func TestMinimumRate(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	slow := rateCheck{min: 4096, now: clock}
	for i := range 59 {
		if err := slow.add(1000); err != nil {
			t.Fatalf("cut before the window ended (second %d)", i)
		}
		now = now.Add(time.Second)
	}
	now = now.Add(time.Second)
	if err := slow.add(1000); !errors.Is(err, ErrTooSlow) {
		t.Fatalf("60 KB in 60 s at a 4 KiB/s minimum: %v", err)
	}
	fast := rateCheck{min: 4096, now: clock}
	for range 300 {
		if err := fast.add(8192); err != nil {
			t.Fatal("fast transfer cut")
		}
		now = now.Add(time.Second)
	}
	// One byte per minute: the trickle of the audit.
	trickle := rateCheck{min: 1, now: clock}
	_ = trickle.add(1)
	now = now.Add(2 * RateWindow)
	if err := trickle.add(1); !errors.Is(err, ErrTooSlow) {
		t.Fatalf("trickle: %v", err)
	}
	off := rateCheck{now: clock}
	now = now.Add(time.Hour)
	if err := off.add(0); err != nil {
		t.Fatal("disabled check cut a transfer")
	}
}

// Audit L-3: a part whose commit check fails is not stored, and the check
// runs under the blob's lock (Locked waits for it).
func TestWritePartIfCommitUnderLock(t *testing.T) {
	t.Parallel()
	s := newStore(t, nil)
	id := ids.New()
	g, _ := NewGeometry(16, 1)
	refuse := errors.New("finalized")
	if err := s.WritePartIf(t.Context(), id, 0, 16, bytes.NewReader(make([]byte, 16)), func(context.Context) error { return refuse }); !errors.Is(err, refuse) {
		t.Fatalf("commit refusal: %v", err)
	}
	if p, _ := s.Present(id, g); len(p) != 0 || s.DiskBytes(id) != 0 {
		t.Fatalf("refused part stored: %v, %d bytes on disk", p, s.DiskBytes(id))
	}
	inCommit, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s.WritePartIf(t.Context(), id, 0, 16, bytes.NewReader(make([]byte, 16)), func(context.Context) error {
			close(inCommit)
			<-release
			return nil
		})
	}()
	<-inCommit
	locked := make(chan struct{})
	go func() { _ = s.Locked(t.Context(), id, func(context.Context) error { close(locked); return nil }) }()
	select {
	case <-locked:
		t.Fatal("Locked ran while a part commit held the lock")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-locked
	if s.DiskBytes(id) != 16 {
		t.Errorf("disk bytes %d", s.DiskBytes(id))
	}
}
