//go:build !linux

package updater

import "os/exec"

// setAWGProcessGroup off Linux (the Windows/macOS demo build) leaves exec's default: the installer is
// a router script and never runs for real there.
func setAWGProcessGroup(*exec.Cmd) {}
