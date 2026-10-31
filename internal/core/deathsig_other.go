//go:build !linux

package core

import "os/exec"

// dieWithDaemon is Linux-only: the core runs as a child that must die with the daemon only on a
// Linux router, and Pdeathsig exists only there.
func dieWithDaemon(*exec.Cmd) {}
