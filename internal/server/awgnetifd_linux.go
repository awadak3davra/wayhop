//go:build linux

package server

import (
	"os"
	"os/exec"
	"syscall"
	"time"
)

// networkRestartCommand is the detached restart of OpenWrt's network service, nil where there is none.
// Its own session (Setsid), so neither the end of the request nor anything that signals the daemon's
// process group stops it halfway; the leading sleep lets the HTTP answer flush before links drop.
func networkRestartCommand() *exec.Cmd {
	if !isFile("/etc/init.d/network") {
		return nil
	}
	cmd := exec.Command("/bin/sh", "-c", "sleep 1; exec /etc/init.d/network restart")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd
}

// fileChangeTime is the inode change time of path: when this router last wrote it, whatever times the
// package that carried it kept.
func fileChangeTime(path string) (time.Time, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)), true // int64(): the fields are int32 on 32-bit targets
}
