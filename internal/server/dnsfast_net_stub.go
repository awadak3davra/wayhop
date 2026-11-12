//go:build !linux

package server

import "wayhop/internal/dnscheck"

// Real fast measurements run on routers. Non-Linux tests inject FastNet instead of opening host sockets.
func newDNSFastNet() dnscheck.FastNet { return nil }
