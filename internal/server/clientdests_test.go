package server

import (
	"testing"

	"velinx/internal/clash"
)

// TestUnambiguousHosts: an IP seen with one host maps to it; an IP seen with multiple hosts (shared
// CDN) is omitted (no source IP to attribute by); empty host/IP entries are skipped.
func TestUnambiguousHosts(t *testing.T) {
	conns := []clash.Conn{
		{Metadata: clash.ConnMeta{DestinationIP: "8.8.8.8", Host: "dns.google"}},
		{Metadata: clash.ConnMeta{DestinationIP: "8.8.8.8", Host: "dns.google"}}, // same → still unambiguous
		{Metadata: clash.ConnMeta{DestinationIP: "104.16.0.1", Host: "a.com"}},   // CDN IP...
		{Metadata: clash.ConnMeta{DestinationIP: "104.16.0.1", Host: "b.com"}},   // ...two hosts → ambiguous → omitted
		{Metadata: clash.ConnMeta{DestinationIP: "1.2.3.4", Host: ""}},           // no host → skipped
		{Metadata: clash.ConnMeta{DestinationIP: "", Host: "x.com"}},             // no IP → skipped
	}
	got := unambiguousHosts(conns)
	if got["8.8.8.8"] != "dns.google" {
		t.Errorf("8.8.8.8 → %q, want dns.google", got["8.8.8.8"])
	}
	if _, ok := got["104.16.0.1"]; ok {
		t.Errorf("a multi-host CDN IP must be omitted, got %q", got["104.16.0.1"])
	}
	if len(got) != 1 {
		t.Errorf("want exactly 1 mapping, got %d: %v", len(got), got)
	}
}

func TestIsPublicDest(t *testing.T) {
	pub := []string{"8.8.8.8", "1.1.1.1", "142.250.190.78", "2606:4700:4700::1111"}
	priv := []string{"192.168.1.1", "10.0.0.5", "172.16.0.1", "127.0.0.1", "::1", "169.254.1.1", "fe80::1", "fd00::1", "224.0.0.1", "not-an-ip", ""}
	for _, d := range pub {
		if !isPublicDest(d) {
			t.Errorf("%q should be public", d)
		}
	}
	for _, d := range priv {
		if isPublicDest(d) {
			t.Errorf("%q should NOT be public", d)
		}
	}
}

// TestAggregateClientDests: private dests are dropped, per-(client,dst) traffic is summed, the exit
// is resolved from the connmark, dests sort by traffic, and clients sort by total traffic.
func TestAggregateClientDests(t *testing.T) {
	markExit := func(m uint32) string {
		if m == 0 {
			return "direct"
		}
		return "tunnel"
	}
	conns := []Conn{
		{Src: "192.168.1.50", Dst: "8.8.8.8", Dport: 443, Mark: 0, UpBytes: 100, DownBytes: 900},
		{Src: "192.168.1.50", Dst: "8.8.8.8", Dport: 443, Mark: 0, UpBytes: 10, DownBytes: 90},    // same dst → summed
		{Src: "192.168.1.50", Dst: "1.1.1.1", Dport: 443, Mark: 5, UpBytes: 1, DownBytes: 1},      // smaller → sorts after
		{Src: "192.168.1.50", Dst: "192.168.1.1", Dport: 53, Mark: 0, UpBytes: 50, DownBytes: 50}, // private → dropped
		{Src: "192.168.1.60", Dst: "9.9.9.9", Dport: 443, Mark: 5, UpBytes: 5, DownBytes: 5},      // smaller client total
	}
	leases := map[string]string{"192.168.1.50": "tablet"}
	hostByIP := map[string]string{"8.8.8.8": "dns.google"} // unambiguous SNI label
	out := aggregateClientDests(conns, leases, markExit, hostByIP, 50)
	if len(out) != 2 {
		t.Fatalf("want 2 clients, got %d: %+v", len(out), out)
	}
	// Client .50 has more total traffic → first; named "tablet".
	a := out[0]
	if a.IP != "192.168.1.50" || a.Name != "tablet" {
		t.Fatalf("first client = %+v, want 192.168.1.50/tablet", a)
	}
	if len(a.Dests) != 2 {
		t.Fatalf(".50 dests = %d, want 2 (8.8.8.8 + 1.1.1.1; private dropped): %+v", len(a.Dests), a.Dests)
	}
	if a.Dests[0].Dst != "8.8.8.8" || a.Dests[0].UpBytes != 110 || a.Dests[0].DownBytes != 990 {
		t.Errorf("top dest = %+v, want 8.8.8.8 summed 110/990", a.Dests[0])
	}
	if a.Dests[0].Domain != "dns.google" {
		t.Errorf("top dest domain = %q, want dns.google (from hostByIP)", a.Dests[0].Domain)
	}
	if a.Dests[1].Domain != "" {
		t.Errorf("1.1.1.1 has no host label → domain should be empty, got %q", a.Dests[1].Domain)
	}
	if a.Dests[0].Exit != "direct" || a.Dests[1].Exit != "tunnel" {
		t.Errorf("exits not resolved: %+v", a.Dests)
	}
	if out[1].IP != "192.168.1.60" {
		t.Errorf("second client = %q, want 192.168.1.60", out[1].IP)
	}
}
