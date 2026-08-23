package netdiag

import (
	"context"
	"net"
	"testing"
)

// isInternalAddr is the SSRF predicate: a reachability probe must refuse loopback,
// private, link-local (incl. 169.254.169.254 metadata) and unspecified targets.
func TestIsInternalAddr(t *testing.T) {
	for _, s := range []string{
		"127.0.0.1", "10.0.0.1", "192.168.50.1", "172.16.0.1", "169.254.169.254", "::1", "0.0.0.0", "fe80::1",
		"100.64.0.1", "100.96.5.9", "100.127.255.254", // RFC6598 CGNAT 100.64.0.0/10
		"::ffff:100.64.0.1", // CGNAT in IPv4-mapped-IPv6 form
	} {
		if !isInternalAddr(net.ParseIP(s)) {
			t.Errorf("isInternalAddr(%s) = false, want true (internal)", s)
		}
	}
	for _, s := range []string{
		"1.1.1.1", "8.8.8.8", "9.9.9.9",
		"100.63.255.255", "100.128.0.0", // boundaries just outside 100.64.0.0/10 — public
	} {
		if isInternalAddr(net.ParseIP(s)) {
			t.Errorf("isInternalAddr(%s) = true, want false (public)", s)
		}
	}
}

// ReachViaIface must REFUSE internal targets before shelling to curl — the probe runs
// as root through the router's main table, so an unguarded WAN probe is an SSRF sink.
// IP-literal hosts resolve locally, so these assertions make no network call.
func TestReachViaIface_SSRF(t *testing.T) {
	ctx := context.Background()
	for _, target := range []string{
		"http://127.0.0.1:9090", "http://127.0.0.1:8088/api/apply",
		"http://10.0.0.1:8088", "https://192.168.50.1", "http://169.254.169.254/",
	} {
		if r := ReachViaIface(ctx, "", target, 5000); r.Reachable || r.Err == "" {
			t.Errorf("SSRF target %q: reachable=%v err=%q, want refused", target, r.Reachable, r.Err)
		}
	}
}

// ReachViaIface must reject a bad interface name and a bad target BEFORE shelling
// out to curl (argument-injection / robustness guard), mirroring ReachVia's guards.
func TestReachViaIface_Validation(t *testing.T) {
	ctx := context.Background()
	if r := ReachViaIface(ctx, "bad iface!", "https://example.com", 5000); r.Reachable || r.Err != "invalid interface" {
		t.Errorf("invalid iface: reachable=%v err=%q, want unreachable + 'invalid interface'", r.Reachable, r.Err)
	}
	// A leading '-' is the flag-injection case ValidIface specifically rejects.
	if r := ReachViaIface(ctx, "-evil", "https://example.com", 5000); r.Reachable || r.Err != "invalid interface" {
		t.Errorf("flag-injection iface: reachable=%v err=%q, want 'invalid interface'", r.Reachable, r.Err)
	}
	if r := ReachViaIface(ctx, "nwg1", "has spaces $$", 5000); r.Reachable || r.Err == "" {
		t.Errorf("invalid target: reachable=%v err=%q, want unreachable + a non-empty err", r.Reachable, r.Err)
	}
	// WAN (iface "") relabels Egress to "direct" before any probe — assert that on a
	// path that returns before curl runs (invalid target), so the unit test makes no
	// network call. The iface guard must NOT reject the empty WAN interface.
	if r := ReachViaIface(ctx, "", "has spaces $$", 5000); r.Egress != "direct" || r.Err == "" {
		t.Errorf("WAN egress: egress=%q err=%q, want direct + invalid-target err", r.Egress, r.Err)
	}
}
