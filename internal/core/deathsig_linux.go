//go:build linux

package core

import (
	"os/exec"
	"syscall"
)

// dieWithDaemon has the kernel SIGKILL the core when the daemon goes, however it goes: an OOM kill,
// a kill -9, a Go fatal error, none of which runs Shutdown. Without it the core outlived the daemon
// (QA-109). It kept routing by the old config with nobody supervising it, a native-only Apply or a
// routing-off Stop could not end it (this supervisor holds no handle to it), and it held the
// cache-file lock, the Clash and mixed ports and the TUN, so the next daemon's core died at every
// start until that daemon's ReapStrays ran. A clean exit already stops the core, so only the
// unclean ones change.
//
// Pdeathsig follows the thread that started the child, not the process (Go issue 27505), and Go
// ends a thread only when a goroutine locked to it exits; WayHop locks none (plugin.runServiceAs
// relies on the same). Should that change, the cost is a core killed early, which the watchdog
// starts again within a tick.
func dieWithDaemon(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
