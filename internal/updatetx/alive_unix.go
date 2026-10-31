//go:build unix

package updatetx

import (
	"errors"
	"syscall"
)

// processAlive is `kill -0 pid`: no signal is sent, only whether one could be. EPERM means the
// process exists under another user.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
