package server

import (
	"fmt"
	"strings"
	"testing"
)

// conntrackSummary must cap the returned rows to the maxRows HEAVIEST flows (bytes-descending)
// while the per-exit and per-client totals still account for EVERY flow, and it must join DHCP
// lease names. Also checks the bounded path never drops a heavy flow that arrives late.
func TestConntrackSummaryBounded(t *testing.T) {
	const n = 20
	markExit := func(m uint32) string {
		if m == 0 {
			return "wan"
		}
		return "tun"
	}
	leases := map[string]string{"192.168.1.10": "laptop"}

	var b strings.Builder
	var wantTotalBytes int64
	for i := 1; i <= n; i++ {
		up := int64(i * 100) // flow i is heavier than flow i-1, so the top-N are the highest i
		src := "192.168.1.10"
		if i%2 == 0 {
			src = "192.168.1.20"
		}
		mark := 0
		if i%3 == 0 {
			mark = 196608
		}
		// original tuple (up bytes) then reply tuple (0 down bytes)
		fmt.Fprintf(&b, "ipv4 2 tcp 6 100 ESTABLISHED src=%s dst=8.8.8.8 sport=%d dport=443 packets=1 bytes=%d "+
			"src=8.8.8.8 dst=%s sport=443 dport=%d packets=1 bytes=0 mark=%d zone=0 use=2\n",
			src, 40000+i, up, src, 40000+i, mark)
		wantTotalBytes += up
	}

	const maxRows = 5
	conns, total, exits, clients := conntrackSummary(b.String(), markExit, leases, maxRows)

	if total != n {
		t.Fatalf("total = %d, want %d (pre-cap count)", total, n)
	}
	if len(conns) != maxRows {
		t.Fatalf("conns len = %d, want %d (capped)", len(conns), maxRows)
	}
	// The five heaviest flows are i=20..16 → 2000,1900,1800,1700,1600, descending.
	wantTop := []int64{2000, 1900, 1800, 1700, 1600}
	for i, c := range conns {
		if got := c.UpBytes + c.DownBytes; got != wantTop[i] {
			t.Errorf("conns[%d] bytes = %d, want %d", i, got, wantTop[i])
		}
	}

	// Per-exit totals must reflect ALL flows, not just the retained top-N.
	var exitSum int64
	for _, v := range exits {
		exitSum += v
	}
	if exitSum != wantTotalBytes {
		t.Errorf("exit totals sum = %d, want %d (all flows)", exitSum, wantTotalBytes)
	}
	if _, ok := exits["wan"]; !ok {
		t.Error("expected a wan exit bucket")
	}

	// Per-client aggregates reflect ALL flows, bytes-descending, with the lease name joined.
	if len(clients) != 2 {
		t.Fatalf("clients = %d, want 2", len(clients))
	}
	var cliSum int64
	for _, c := range clients {
		cliSum += c.UpBytes + c.DownBytes
	}
	if cliSum != wantTotalBytes {
		t.Errorf("client totals sum = %d, want %d (all flows)", cliSum, wantTotalBytes)
	}
	if clients[0].UpBytes+clients[0].DownBytes < clients[1].UpBytes+clients[1].DownBytes {
		t.Error("clients not sorted bytes-descending")
	}
	named := false
	for _, c := range clients {
		if c.IP == "192.168.1.10" && c.Name == "laptop" {
			named = true
		}
	}
	if !named {
		t.Error("DHCP lease name 'laptop' was not joined onto its client")
	}
}

// Under maxRows, every flow is returned, still bytes-descending; empty input yields a non-nil
// empty slice (marshals to [] not null).
func TestConntrackSummaryUnderCapAndEmpty(t *testing.T) {
	markExit := func(uint32) string { return "wan" }
	sample := "ipv4 2 tcp 6 100 ESTABLISHED src=192.168.1.5 dst=1.1.1.1 sport=5 dport=443 packets=1 bytes=500 src=1.1.1.1 dst=192.168.1.5 sport=443 dport=5 packets=1 bytes=100 mark=0 zone=0 use=2\n" +
		"ipv4 2 udp 17 30 src=192.168.1.6 dst=2.2.2.2 sport=6 dport=53 packets=1 bytes=50 src=2.2.2.2 dst=192.168.1.6 sport=53 dport=6 packets=1 bytes=900 mark=0 zone=0 use=2\n"
	conns, total, _, clients := conntrackSummary(sample, markExit, nil, 80)
	if total != 2 || len(conns) != 2 {
		t.Fatalf("total=%d conns=%d, want 2/2", total, len(conns))
	}
	// udp flow has 950 total > tcp's 600, so it must sort first.
	if conns[0].UpBytes+conns[0].DownBytes != 950 {
		t.Errorf("conns[0] total = %d, want 950 (heaviest first)", conns[0].UpBytes+conns[0].DownBytes)
	}
	if len(clients) != 2 {
		t.Errorf("clients = %d, want 2", len(clients))
	}

	empty, total0, _, cl0 := conntrackSummary("", markExit, nil, 80)
	if total0 != 0 {
		t.Errorf("empty total = %d, want 0", total0)
	}
	if empty == nil {
		t.Error("conns must be a non-nil empty slice (marshals to [] not null)")
	}
	if cl0 == nil {
		t.Error("clients must be a non-nil empty slice")
	}
}
