//go:build linux

package server

import (
	"os"
	"os/exec"
	"syscall"
)

// restartCommand builds the detached command that restarts the wayhop service
// through whichever init system installed it. It returns nil if neither init
// script is present (then the handler reports the feature unavailable).
//
// Detaching matters: the init "restart" stops THIS process, so the restarter must
// live in its own session (Setsid) or it would be killed before it can start the
// new instance. The leading `sleep 1` lets the HTTP 200 flush first.
func restartCommand() *exec.Cmd {
	var script string
	switch {
	case isFile("/etc/init.d/wayhop"): // OpenWrt procd
		script = "/etc/init.d/wayhop restart"
	case isFile("/opt/etc/init.d/S99wayhop"): // Entware busybox sysvinit
		script = "/opt/etc/init.d/S99wayhop restart"
	default:
		return nil
	}
	cmd := exec.Command("/bin/sh", "-c", "sleep 1; "+script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}
