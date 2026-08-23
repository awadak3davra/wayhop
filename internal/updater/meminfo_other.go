//go:build !linux

package updater

// availMemBytes can't read /proc/meminfo off Linux (dev hosts, tests on non-Linux); report
// unknown so the caller never blocks an install on a measurement it couldn't take. The router
// targets are all Linux, where the real check in meminfo_linux.go applies.
func availMemBytes() (uint64, bool) { return 0, false }
