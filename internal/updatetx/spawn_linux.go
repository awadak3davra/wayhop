//go:build linux

package updatetx

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// Spawn starts the supervisor in etc with args, in a session of its own so the restart it performs
// (or the package manager's) cannot take it down with the daemon, its output appended to LogFile.
func Spawn(etc string, args ...string) error {
	logf, err := os.OpenFile(LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	cmd := exec.Command("/bin/sh", append([]string{filepath.Join(etc, ScriptFile)}, args...)...)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }() // reaped while this process lives; reparented when it does not
	return nil
}
