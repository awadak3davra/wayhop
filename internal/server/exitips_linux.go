//go:build linux

package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"
)

// exitIPEchoHosts are the plain-text IP responders a live per-egress probe GETs (through the bound
// interface) to learn that egress's public exit IP. Reused from the single-exit probe's echo set.
// It lives here, with its only consumer: SO_BINDTODEVICE is linux-only, so in the untagged file it
// read as dead code on every other platform and the linter said so on each Windows run.
var exitIPEchoHosts = exitIPEchos

// probeExitIPViaIface GETs an IP echo through a specific kernel interface (SO_BINDTODEVICE), so the
// request egresses out THAT tunnel and the echo reports the tunnel's real public exit IP — even
// when it differs from the endpoint's server address (a NAT'd / multi-hop exit). Router-only:
// SO_BINDTODEVICE needs CAP_NET_RAW (the daemon runs as root on the router). Returns "" on any
// failure so the caller falls back to the endpoint's server IP. Never routes through sing-box; the
// bound socket follows the kernel PBR datapath directly.
func probeExitIPViaIface(ctx context.Context, iface string) string {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
			}); err != nil {
				return err
			}
			return serr
		},
	}
	cl := &http.Client{
		Transport: &http.Transport{DialContext: dialer.DialContext},
		Timeout:   6 * time.Second,
	}
	defer cl.CloseIdleConnections()
	for _, echo := range exitIPEchoHosts {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, echo, nil)
		if err != nil {
			continue
		}
		resp, err := cl.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		_ = resp.Body.Close()
		if ip := validExitIP(string(body)); ip != "" {
			return ip
		}
	}
	return ""
}
