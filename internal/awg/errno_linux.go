//go:build linux

package awg

import "syscall"

// errnoText names a negative errno that amneziawg-go answered. The daemon and amneziawg-go run on
// the same router, so this build's own table is the right one to read - and it has to be this
// build's: EADDRINUSE is 98 on arm and x86 but 125 on mips.
func errnoText(code int64) string {
	if code >= 0 {
		return ""
	}
	return syscall.Errno(-code).Error()
}
