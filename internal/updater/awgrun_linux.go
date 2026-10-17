//go:build linux

package updater

import (
	"os/exec"
	"syscall"
)

// setAWGProcessGroup runs the installer in its own process group and makes cancellation signal the
// whole group. The script drives opkg/apk, wget and modprobe; stopping only the shell would leave the
// package manager running on, holding its lock, after the daemon has reported the run as over.
// SIGTERM first so they can clean up; exec's WaitDelay kills the shell if it does not go.
func setAWGProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
}
