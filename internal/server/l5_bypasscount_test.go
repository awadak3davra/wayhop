package server

import (
	"strings"
	"testing"
)

// TestDoHBypassCountsDevicesNotPairs (L5): the row counts DEVICES, and it was counting rows.
//
// detectDoHClients emits one line per (client, resolver) pair — the evidence — and the summary
// printed len() of that as a client count. Measured on a live Keenetic: one address talking
// to both Google and AdGuard produced "2 client(s) may be bypassing the router's DNS (DoH/DoT)" with
// the same IPv6 address printed twice in the detail directly underneath. The number decides how many
// gadgets the operator goes and reconfigures, so it has to be a number of gadgets.
func TestDoHBypassCountsDevicesNotPairs(t *testing.T) {
	// One phone, two resolvers: Cloudflare and Google, both on the curated :443 list.
	conns := []Conn{
		{Src: "192.168.1.50", Dst: "1.1.1.1", Dport: 443},
		{Src: "192.168.1.50", Dst: "8.8.8.8", Dport: 443},
	}
	pairs, clients := detectDoHClients(conns, nil, nil)
	if len(pairs) != 2 {
		t.Fatalf("both resolvers stay in the evidence: %v", pairs)
	}
	if clients != 1 {
		t.Errorf("one device using two resolvers is one client, got %d (%v)", clients, pairs)
	}

	// Two devices, one resolver each: the count follows the devices, not the pairs.
	two := []Conn{
		{Src: "192.168.1.50", Dst: "1.1.1.1", Dport: 443},
		{Src: "192.168.1.51", Dst: "1.1.1.1", Dport: 443},
	}
	if _, n := detectDoHClients(two, nil, nil); n != 2 {
		t.Errorf("two devices are two clients, got %d", n)
	}

	// And the sentence must not read "1 client(s)" next to a single address.
	if got := countWordClients(1); got != "1 client" {
		t.Errorf("singular must be singular, got %q", got)
	}
	if got := countWordClients(3); !strings.Contains(got, "3 clients") {
		t.Errorf("plural must be plural, got %q", got)
	}
}
