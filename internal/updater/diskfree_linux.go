//go:build linux

package updater

import "syscall"

// AvailBytes returns the free space (bytes available to the caller) on the filesystem holding
// dir. ok=false when it can't be determined — callers then SKIP their space guard rather than
// blocking on a stat failure. Used by the update pre-flight and the disk-space diagnostic; the
// router overlay is tiny (~60 MB), so both watch it.
func AvailBytes(dir string) (uint64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return st.Bavail * uint64(st.Bsize), true
}
