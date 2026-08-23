package netdiag

import (
	"context"
	"testing"
)

// TestReachVia_RefusesInternalLiteral: an INTERNAL IP-literal target must be refused before the Clash
// delay probe runs — a `direct`-routed group member egresses from the router itself, so probing
// 127.0.0.1 / 169.254.169.254 / RFC1918 through it would be a blind internal reachability oracle.
func TestReachVia_RefusesInternalLiteral(t *testing.T) {
	for _, target := range []string{
		"http://127.0.0.1:9090",   // the Clash controller / daemon
		"http://169.254.169.254/", // cloud metadata
		"http://192.168.50.1",     // LAN
		"http://10.0.0.5:22",      // RFC1918
		"http://[::1]:80",         // v6 loopback
	} {
		d := &stubDelay{ms: 5}
		r := ReachVia(context.Background(), d, target, "grp", 7000)
		if r.Reachable || r.Err == "" {
			t.Errorf("%s: internal target must be refused, got %+v", target, r)
		}
		if d.calls != 0 {
			t.Errorf("%s: the delay probe must NOT run for an internal target (SSRF oracle)", target)
		}
	}
	// A public IP-literal still probes (Delay is called, no false refusal).
	d := &stubDelay{ms: 7}
	if r := ReachVia(context.Background(), d, "http://1.1.1.1/", "grp", 7000); !r.Reachable || d.calls != 1 {
		t.Errorf("public target must still probe: reachable=%v calls=%d err=%q", r.Reachable, d.calls, r.Err)
	}
}
