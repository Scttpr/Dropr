//go:build linux

package blob

import "syscall"

func statfs(path string) (avail, total uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	bs := uint64(st.Bsize) //nolint:gosec // block size is positive
	return st.Bavail * bs, st.Blocks * bs, nil
}
