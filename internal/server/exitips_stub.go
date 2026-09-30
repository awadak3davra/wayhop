//go:build !linux

package server

import (
	"context"
	"net"
)

// probeExitIPViaIface is a no-op off Linux (SO_BINDTODEVICE is a Linux socket option). The dev/
// non-router build always falls back to the endpoint's server IP for the exit grid. The real
// per-egress probe lives in exitips_linux.go and runs on the router.
func probeExitIPViaIface(_ context.Context, _ string, _ int) string { return "" }

// bypassDial is nil off Linux: there is no engine redirect to get past, and a nil dialer leaves a
// direct speed test on the default one.
var bypassDial func(ctx context.Context, network, addr string) (net.Conn, error)

// ifaceDial is nil off Linux, where a socket cannot be bound to an interface: a test that went on
// unbound would measure the default route under the tunnel's name, so there is none.
func ifaceDial(string) func(ctx context.Context, network, addr string) (net.Conn, error) { return nil }

// ipv6Neighbours is nil off Linux: there is no neighbour table to ask, and a device is then known by
// its IPv4 address alone.
func ipv6Neighbours() map[string]string { return nil }

// lineDial is nil off Linux, like bypassDial: nothing redirects there, and the default dialer is the
// line.
var lineDial func(ctx context.Context, network, addr string) (net.Conn, error)

// lineRoute is nil off Linux, where the line leg has no mark to look the route up with.
var lineRoute func(ctx context.Context, addr string) net.IP
