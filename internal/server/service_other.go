//go:build !linux

package server

import "os/exec"

// restartCommand has no init system to drive off Linux (e.g. the Windows demo),
// so service restart is unavailable; the handler reports 503.
func restartCommand() *exec.Cmd { return nil }
