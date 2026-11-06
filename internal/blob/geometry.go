// Package blob stores encrypted uploads on the local disk (PLAN.md §4).
//
// A blob is the ciphertext of one file, kept as the parts it was uploaded in:
//
//	data_dir/blobs/<id[0:2]>/<id[2:4]>/<id>/part00000 … part03199
//
// The server never sees plaintext. It knows the ciphertext size C declared at
// creation, from which the part geometry follows exactly (FORMAT.md §4.3,
// §4.4), so every part has one acceptable size. Parts are written atomically
// (temporary file, fsync, rename, directory fsync), re-uploading a part
// replaces it, and Reader presents the parts as one contiguous ciphertext for
// single-range HTTP downloads.
package blob

import (
	"errors"
	"fmt"
)

// Geometry constants (FORMAT.md §4).
const (
	SegmentSize       = 65536                                   // plaintext bytes per segment
	TagSize           = 16                                      // AES-GCM tag
	CipherSegmentSize = SegmentSize + TagSize                   // 65 552
	SegmentsPerPart   = 512                                     //
	PartPlainSize     = SegmentsPerPart * SegmentSize           // 32 MiB
	PartCipherSize    = SegmentsPerPart * CipherSegmentSize     // 33 562 624
	MaxParts          = 3200                                    // 100 GiB plaintext
	MaxCipherSize     = int64(MaxParts) * int64(PartCipherSize) // ciphertext of 100 GiB
)

// ErrGeometry reports a declared size or part count that no ciphertext can
// have.
var ErrGeometry = errors.New("blob: invalid ciphertext geometry")

// CipherSize returns the ciphertext size for a plaintext of p bytes
// (p >= 0): p + 16·max(1, ceil(p/65536)).
func CipherSize(p int64) int64 {
	segs := max(1, (p+SegmentSize-1)/SegmentSize)
	return p + TagSize*segs
}

// PlainSize inverts CipherSize. ok is false when c is not the ciphertext size
// of any plaintext (FORMAT.md §4.3 "Inverse").
func PlainSize(c int64) (p int64, ok bool) {
	if c < TagSize {
		return 0, false
	}
	f, r := c/CipherSegmentSize, c%CipherSegmentSize
	var segs int64
	switch {
	case r == 0:
		segs = f
	case r > TagSize, r == TagSize && f == 0:
		segs = f + 1
	default:
		return 0, false
	}
	return c - TagSize*segs, true
}

// PartsFor returns the number of parts of a ciphertext of c bytes
// (ceil(c / PartCipherSize), at least 1).
func PartsFor(c int64) int {
	return int(max(1, (c+PartCipherSize-1)/PartCipherSize))
}

// Geometry is a validated (ciphertext size, part count) pair.
type Geometry struct {
	Size  int64 // ciphertext bytes
	Parts int
}

// NewGeometry validates a client-declared ciphertext size and part count:
// size must be a possible ciphertext size, no larger than the 100 GiB cap,
// and parts must equal PartsFor(size).
func NewGeometry(size int64, parts int) (Geometry, error) {
	if size <= 0 || size > MaxCipherSize {
		return Geometry{}, fmt.Errorf("%w: size %d out of range", ErrGeometry, size)
	}
	if _, ok := PlainSize(size); !ok {
		return Geometry{}, fmt.Errorf("%w: %d is not a ciphertext size", ErrGeometry, size)
	}
	if parts != PartsFor(size) {
		return Geometry{}, fmt.Errorf("%w: %d bytes need %d parts, not %d", ErrGeometry, size, PartsFor(size), parts)
	}
	return Geometry{Size: size, Parts: parts}, nil
}

// Plain returns the plaintext size.
func (g Geometry) Plain() int64 {
	p, _ := PlainSize(g.Size)
	return p
}

// PartSize returns the exact size of part n, or -1 if n is out of range.
func (g Geometry) PartSize(n int) int64 {
	if n < 0 || n >= g.Parts {
		return -1
	}
	if n < g.Parts-1 {
		return PartCipherSize
	}
	return g.Size - int64(g.Parts-1)*PartCipherSize
}

// MaxPlainFor returns the largest plaintext size whose ciphertext fits in c
// bytes (0 if even an empty file does not fit).
func MaxPlainFor(c int64) int64 {
	if c < TagSize {
		return 0
	}
	f, r := c/CipherSegmentSize, c%CipherSegmentSize
	return f*SegmentSize + max(0, r-TagSize)
}
