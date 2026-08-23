package server

import (
	"strings"
	"testing"
)

// TestDetectDoHClients_DoTPortCountsWithoutTheList pins the one signal here that does not depend on a
// hand-written list being complete.
//
// Port 853 is IANA-assigned to DNS-over-TLS: a connection to it IS encrypted DNS, whoever the peer
// is. The detector nevertheless required BOTH the port AND a hit in the 21-entry resolver map, so a
// client using any resolver outside that map — NextDNS, ControlD, Mullvad, dns.sb, a self-hosted one —
// was dropped by the map check and the row reported "no client seen using a public DoH/DoT resolver".
//
// :443 genuinely needs the list, because DoH is indistinguishable from ordinary HTTPS by port alone.
// That asymmetry is the point: the check should use the scope-free signal where one exists.
func TestDetectDoHClients_DoTPortCountsWithoutTheList(t *testing.T) {
	conns := []Conn{
		// A DoT connection to a resolver nobody listed. Encrypted DNS by protocol, not by reputation.
		{Src: "192.168.1.60", Dst: "45.90.28.0", Dport: 853},
		// HTTPS to an unlisted host must STAY ignored: on :443 there is nothing to distinguish a DoH
		// request from any other web request, and flagging every HTTPS peer would make the row useless.
		{Src: "192.168.1.61", Dst: "93.184.216.34", Dport: 443},
	}
	got, _ := detectDoHClients(conns, map[string]string{"192.168.1.60": "laptop"}, nil)

	joined := strings.Join(got, " | ")
	if len(got) != 1 {
		t.Fatalf("want exactly the DoT client, got %d: %v", len(got), got)
	}
	if !strings.Contains(joined, "192.168.1.60") || !strings.Contains(joined, "laptop") {
		t.Errorf("the DoT client is not named: %v", got)
	}
	if !strings.Contains(joined, "45.90.28.0") {
		t.Errorf("an unknown resolver must be identified by its address, since there is no provider "+
			"name to give: %v", got)
	}
	if strings.Contains(joined, "192.168.1.61") {
		t.Errorf("plain HTTPS to an unlisted host was flagged as DNS: %v", got)
	}
}

// TestDnsBypassCheck_PassStatesItsScope: a negative result here means "nothing matched what this
// check can see", and the sentence has to say so. The row is the operator's evidence that domain
// routing applies to every client; read as unqualified it says the opposite of the truth for anyone
// running a DoH endpoint outside the curated list — stock Firefox, whose default DoH host resolves to
// Cloudflare anycast addresses (measured: 172.64.41.4, 162.159.61.4) that are NOT the 1.1.1.1 entries
// in the map.
func TestDnsBypassCheck_PassStatesItsScope(t *testing.T) {
	summary := dnsBypassPassSummary()
	if summary == "" {
		t.Fatal("no pass summary to inspect")
	}
	// It must name what was actually established, not merely assert a clean result.
	for _, want := range []string{"DoT", "known"} {
		if !strings.Contains(summary, want) {
			t.Errorf("the pass summary %q does not mention %q — a reader cannot tell what it covered", summary, want)
		}
	}
	if !strings.Contains(strings.ToLower(summary), "cannot") && !strings.Contains(strings.ToLower(summary), "can't") {
		t.Errorf("the pass summary %q does not say what it cannot see; a scope-free reading of it is "+
			"false for any resolver outside the curated list", summary)
	}
}
