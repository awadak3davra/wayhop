//go:build !linux

package updater

// AvailBytes can't portably read free space off-Linux (the Windows dev/demo build),
// so it reports "unknown" and the space guard is skipped. The router target is always
// Linux, where diskfree_linux.go provides the real statfs-based reading.
func AvailBytes(dir string) (uint64, bool) { return 0, false }
