package netdiag

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestResolveProbeTargetRefusesInternalAndMalformed(t *testing.T) {
	for _, in := range []string{"127.0.0.1:80", "192.168.50.1:443", "169.254.169.254:80", "cp.cloudflare.com", "8.8.8.8:0", "8.8.8.8:http", "bad host:443"} {
		if got, err := ResolveProbeTarget(context.Background(), in); err == nil {
			t.Errorf("%q resolved to %q", in, got)
		}
	}
	if got, err := ResolveProbeTarget(context.Background(), "149.154.167.51:443"); err != nil || got != "149.154.167.51:443" {
		t.Errorf("public literal: %q %v", got, err)
	}
}

// An interface name the probe refuses is "not measured", never "dead".
func TestTCPConnectViaIfaceInvalidIfaceDidNotRun(t *testing.T) {
	if _, ok, ran := TCPConnectViaIface(context.Background(), "nwg1; reboot", "149.154.167.51:443", time.Second); ok || ran {
		t.Fatalf("ok=%v ran=%v", ok, ran)
	}
}

// Review F2: a refused handshake (RST) proves the path; only silence or an unreachable route is a
// failure. Measured on the router's own path to a loopback port nothing listens on.
func TestTCPConnectRefusedIsAnAnswer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	ms, ok, ran := TCPConnect(context.Background(), addr, 2*time.Second)
	if !ran || !ok || ms < 1 {
		t.Fatalf("refused port: ms=%d ok=%v ran=%v, want an answer", ms, ok, ran)
	}
}

// A probe that needs the proxy core's bypass mark (OpenWrt) and cannot set it measured nothing: an
// unmarked handshake there is answered by the core, so "dead" and "alive" would both be about the
// core. With the mark set (root on Linux) a refused port is the same answer as without one.
func TestMarkedProbeIsNeverADeadExitWhenTheMarkCannotBeSet(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	if _, ok, ran := TCPConnectMark(context.Background(), addr, 2*time.Second, 0x2024); ran && !ok {
		t.Fatalf("ok=%v ran=%v: a probe whose mark was refused must not count as a dead path", ok, ran)
	}
	if _, ok, ran := TCPConnectViaIfaceMark(context.Background(), "awg1; reboot", addr, time.Second, 0x2024); ok || ran {
		t.Fatalf("invalid interface: ok=%v ran=%v", ok, ran)
	}
}
