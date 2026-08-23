//go:build !linux

package server

import "context"

// probeExitIPViaIface is a no-op off Linux (SO_BINDTODEVICE is a Linux socket option). The dev/
// non-router build always falls back to the endpoint's server IP for the exit grid. The real
// per-egress probe lives in exitips_linux.go and runs on the router.
func probeExitIPViaIface(_ context.Context, _ string) string { return "" }
