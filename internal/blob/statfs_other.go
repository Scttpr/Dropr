//go:build !linux

package blob

import "math"

// statfs is not implemented outside Linux (the supported platform): the
// free-space check then always passes and a full disk surfaces as a write
// error instead.
func statfs(string) (avail, total uint64, err error) {
	return math.MaxInt64, math.MaxInt64, nil
}
