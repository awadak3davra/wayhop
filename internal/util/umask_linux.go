package util

import "syscall"

// RestrictNewFiles sets the process umask so anything created from here on — including files created
// by CHILD processes — is owner-only. It returns the previous umask and whether it was applied.
//
// It exists for sing-box's cache.db. WayHop writes its own state with an explicit mode (atomicfile
// chmods after opening, so a umask cannot alter it), but the cache is created by the sing-box child
// and lands at 0644 under a default umask. The daemon never opens that file, so its mode is not
// something WayHop can set — the umask the child inherits is the only control there is.
//
// The OpenWrt init script cannot do this in its place: procd receives the instance definition over
// ubus and execs the command from its own process, so the init shell's umask is not the one the
// daemon inherits.
//
// Directories the daemon creates become 0700 rather than 0755. On a router every consumer of them is
// root, so that is the intended outcome; if a separate service user is introduced later, this one
// call is what changes rather than a mode scattered across call sites.
func RestrictNewFiles() (previous int, applied bool) {
	return syscall.Umask(0o077), true
}
