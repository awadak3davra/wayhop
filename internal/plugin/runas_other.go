//go:build !linux

package plugin

import "os/exec"

// runAs is Linux-only: elsewhere there is no TUN uid exclusion to match.
func runAs(*exec.Cmd, int) {}

// runServiceAs is Linux-only like runAs; a service runs only on a Linux router.
func runServiceAs(*exec.Cmd, int) {}

// reachableFor is Linux-only for the same reason.
func reachableFor(bin string, _ int) (string, error) { return bin, nil }
