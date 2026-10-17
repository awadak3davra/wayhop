//go:build !linux

package server

import (
	"os/exec"
	"time"
)

// networkRestartCommand has no OpenWrt network service to drive off Linux (the Windows demo).
func networkRestartCommand() *exec.Cmd { return nil }

// fileChangeTime is unknown off Linux, which leaves netifd's state to what the installer reported.
func fileChangeTime(string) (time.Time, bool) { return time.Time{}, false }
