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
// interface) to learn that egress's public exit IP: a responder that is NOT behind Cloudflare
// first, then the single-exit probe's set (which entirely is).
//
// The order matters because an exit that routes Cloudflare's ranges out a separate path answers a
// Cloudflare-fronted echo with THAT path's address. Measured through one tunnel on an AX3000T whose
// VPS sends Cloudflare traffic over WARP: the Cloudflare-fronted echoes reported a Cloudflare-owned
// address — the WARP egress — while the neutral one reported the VPS itself. Both are true for
// their own destination; the neutral responder gives the tunnel's GENERAL egress, which is what the
// tile claims to show. The Cloudflare-fronted ones stay as fallbacks — a measured exit beats none.
//
// It lives here, with its only consumer: SO_BINDTODEVICE is linux-only, so in the untagged file it
// read as dead code on every other platform and the linter said so on each Windows run.
var exitIPEchoHosts = append([]string{"https://checkip.amazonaws.com"}, exitIPEchos...)

// egressControl is a dialer's Control that binds the socket to iface (when set) and gives it mark
// (when not 0). The bind must hold, or the dial fails: a socket left unbound would measure some
// other path under the tunnel's name. The mark fails the dial only when strict. SO_MARK needs
// CAP_NET_ADMIN, and the exit probe and the panel's test would rather have an unmarked connection
// than none (a mark that did not stick leaves the engine's redirect in place, which the exit probe
// detects by comparing the answer against the host's own exit); the bot's speed test would not,
// since an unmarked socket may be carried into the engine and measure a path it does not name.
func egressControl(iface string, mark int, strict bool) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			if iface != "" {
				if serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface); serr != nil {
					return
				}
			}
			if mark != 0 {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark); err != nil && strict {
					serr = err
				}
			}
		}); err != nil {
			return err
		}
		return serr
	}
}

// bypassDial dials past the engine's transparent redirect (see engineBypassMark), so a connection
// the daemon means to make directly leaves by the kernel's own routes: the panel's direct speed
// test. The mark is best-effort there.
var bypassDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second, Control: egressControl("", engineBypassMark, false)}
	return d.DialContext(ctx, over4(network), addr)
}

// lineDial is bypassDial for the bot's measurement of the provider's line, where the mark must
// hold: a socket the engine could redirect would not be the line.
var lineDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 10 * time.Second, Control: egressControl("", engineBypassMark, true)}
	return d.DialContext(ctx, over4(network), addr)
}

// lineRoute is the local address the kernel picks for a line-leg connection to addr, found with a
// UDP socket carrying the same mark: connecting it only looks the route up and sends nothing. A leg
// whose dial failed is still known by the way it would have left.
var lineRoute = func(ctx context.Context, addr string) net.IP {
	d := net.Dialer{Timeout: 5 * time.Second, Control: egressControl("", engineBypassMark, true)}
	c, err := d.DialContext(ctx, "udp4", addr)
	if err != nil {
		return nil
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return a.IP
	}
	return nil
}

// ifaceDial dials out through one kernel tunnel and nothing else: bound to its interface and past
// the engine's redirect, both required. The speed test of one exit uses it, so the test measures
// that tunnel without moving anybody's traffic onto it.
func ifaceDial(iface string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second, Control: egressControl(iface, engineBypassMark, true)}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.DialContext(ctx, over4(network), addr)
	}
}

// probeExitIPViaIface GETs an IP echo through a specific kernel interface (SO_BINDTODEVICE), so the
// request egresses out THAT tunnel and the echo reports the tunnel's real public exit IP — even
// when it differs from the endpoint's server address (a NAT'd / multi-hop exit). An empty iface
// binds nothing and measures the host's own uplink exit (the baseline probeEgressIP checks each
// tunnel against). Router-only: SO_BINDTODEVICE needs CAP_NET_RAW (the daemon runs as root on the
// router). Returns "" on any failure so the caller falls back to the endpoint's server IP.
//
// mark, when non-zero, is set as the socket's fwmark. Binding the device is not on its own enough
// to leave the box: sing-box's auto_redirect DNATs every local TCP connection into the engine
// unless the socket carries its bypass mark (see engineBypassMark), and the engine then dials the
// echo through an outbound of its own choosing. The bound socket follows the kernel datapath only
// once that redirect has been declined.
func probeExitIPViaIface(ctx context.Context, iface string, mark int) string {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: egressControl(iface, mark, false)}
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
