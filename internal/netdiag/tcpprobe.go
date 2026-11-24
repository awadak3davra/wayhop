package netdiag

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"
)

// ResolveProbeTarget turns a "host:port" probe target into the public "ip:port" to dial, refusing
// internal addresses exactly like ReachViaIface does: the probe runs as root and binds to tunnels, and
// a target that resolved to the LAN or to the router itself would make every exit an oracle for it.
// Resolve once per cycle and dial the result through every candidate, so all of them are measured
// against the same address.
func ResolveProbeTarget(ctx context.Context, target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", err
	}
	if n, perr := strconv.Atoi(port); perr != nil || n < 1 || n > 65535 {
		return "", errors.New("invalid port")
	}
	if !ValidTarget(host) {
		return "", errors.New("invalid host")
	}
	ip, err := resolvePublic(ctx, host)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip, port), nil
}

// TCPConnectViaIface measures one TCP handshake to addr ("ip:port", from ResolveProbeTarget) with the
// socket bound to iface (SO_BINDTODEVICE). A handshake is the cheapest question that an exit which
// passes ICMP but drops the traffic actually routed into it answers honestly: the SYN takes the same
// path as a client's.
//
// ran is false when nothing was measured — an invalid interface name, or a platform that cannot bind
// a socket to a device, where dialling anyway would measure the WAN and call that the tunnel. An
// interface the kernel no longer has IS a measurement: that exit carries nothing.
func TCPConnectViaIface(ctx context.Context, iface, addr string, timeout time.Duration) (ms int, ok, ran bool) {
	return TCPConnectViaIfaceMark(ctx, iface, addr, timeout, 0)
}

// TCPConnectViaIfaceMark is TCPConnectViaIface with the socket's fwmark set (SO_MARK; 0 sets none).
//
// OpenWrt needs it. The proxy core's transparent redirect there (sing-box auto_redirect) is a nat
// OUTPUT chain that sends every TCP connection the router itself opens into the core, bound to a
// device or not; only a socket carrying the core's own mark is left alone (`meta mark 0x00002024
// return` is that chain's first rule, read off a reference OpenWrt router). Unmarked, a probe "through awg1" was
// answered by the core over whatever route it chose, the same for every candidate.
//
// A mark that cannot be set is "not measured" (ran=false), never a dead exit: the handshake would have
// measured the core.
func TCPConnectViaIfaceMark(ctx context.Context, iface, addr string, timeout time.Duration, mark int) (ms int, ok, ran bool) {
	if !ValidIface(iface) {
		return 0, false, false
	}
	control := bindToDevice(iface)
	if control == nil {
		return 0, false, false
	}
	if !ifaceExists(iface) {
		return 0, false, true
	}
	return dialProbe(ctx, &net.Dialer{Timeout: timeout, Control: withMark(control, mark)}, addr)
}

// TCPConnect is TCPConnectViaIface on the router's own path: a socket bound to no device, which the
// main table routes (the provider). It is the reference a list's elector asks before it calls every
// tunnel dead: a target that answers here but through no tunnel proves the tunnels are the problem.
func TCPConnect(ctx context.Context, addr string, timeout time.Duration) (ms int, ok, ran bool) {
	return TCPConnectMark(ctx, addr, timeout, 0)
}

// TCPConnectMark is TCPConnect with the socket's fwmark set (see TCPConnectViaIfaceMark): past the
// core's redirect, the router's own path is the main table again and not the core's routing.
func TCPConnectMark(ctx context.Context, addr string, timeout time.Duration, mark int) (ms int, ok, ran bool) {
	return dialProbe(ctx, &net.Dialer{Timeout: timeout, Control: withMark(nil, mark)}, addr)
}

// errProbeSetup marks a probe socket that could not be prepared: nothing was measured.
var errProbeSetup = errors.New("probe socket setup")

// withMark chains the fwmark onto a dialer control; mark 0 returns next unchanged.
func withMark(next func(network, address string, c syscall.RawConn) error, mark int) func(network, address string, c syscall.RawConn) error {
	if mark == 0 {
		return next
	}
	return func(network, address string, c syscall.RawConn) error {
		if next != nil {
			if err := next(network, address, c); err != nil {
				return err
			}
		}
		if err := setSocketMark(c, mark); err != nil {
			return fmt.Errorf("%w: fwmark: %v", errProbeSetup, err)
		}
		return nil
	}
}

// dialProbe times one handshake. A refused connection (RST) is an answer: the SYN crossed the path
// and the far host replied, which is all a path probe asks (review F2: an automatic target with
// nothing listening on its port made every tunnel look dead).
func dialProbe(ctx context.Context, d *net.Dialer, addr string) (ms int, ok, ran bool) {
	started := time.Now()
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, errProbeSetup) {
			return 0, false, false // cancelled from outside, or never sent: not a verdict about the exit
		}
		if !connRefused(err) {
			return 0, false, true
		}
	} else {
		_ = c.Close()
	}
	ms = int(time.Since(started).Milliseconds())
	if ms < 1 {
		ms = 1
	}
	return ms, true, true
}

// connRefused reports a handshake answered with RST. 10061 is Windows' WSAECONNREFUSED (the dev
// build); no Linux errno has that value.
func connRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	var en syscall.Errno
	return errors.As(err, &en) && uintptr(en) == 10061
}

// CanBindToDevice reports whether this platform can tie a socket to one interface. Where it cannot, an
// "exit" probe would measure the WAN, so callers measure nothing instead.
func CanBindToDevice() bool { return bindToDevice("lo") != nil }
