//go:build !linux

package updater

import "os"

// AvailBytes can't portably read free space off-Linux (the Windows dev/demo build),
// so it reports "unknown" and the space guard is skipped. The router target is always
// Linux, where diskfree_linux.go provides the real statfs-based reading.
func AvailBytes(dir string) (uint64, bool) { return 0, false }

// fileUsage off Linux: the apparent size, and one name (link counts are not read here).
func fileUsage(fi os.FileInfo) (used, links uint64) { return uint64(fi.Size()), 1 }
