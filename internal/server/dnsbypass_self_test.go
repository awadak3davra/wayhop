package server

import (
	"strings"
	"testing"
)

// TestDetectDoHClients_TheRouterIsNotOneOfItsClients pins the difference between "a device on the LAN
// resolves names itself" and "this router resolves names the way it was configured to".
//
// Found on a live AX3000T. WayHop's own secure default is DoH to 1.1.1.1, and it rides the
// tunnel, so `/proc/net/nf_conntrack` carried `src=10.0.0.30 dst=1.1.1.1 dport=443` — where 10.0.0.30
// is the address the router holds on its own awg0 device, created by the panel at Apply. The detector
// took any flow to a listed resolver, so the row titled "LAN clients use the router's DNS" reported
// the ROUTER as a client bypassing itself, and its fix text advised disabling DoH on that device or
// blocking the resolver in Routing — which would break the router's own encrypted DNS.
func TestDetectDoHClients_TheRouterIsNotOneOfItsClients(t *testing.T) {
	conns := []Conn{
		// The router's own resolver, egressing over its tunnel address.
		{Src: "10.0.0.30", Dst: "1.1.1.1", Dport: 443},
		// A real LAN client doing the thing this check exists to find.
		{Src: "192.168.2.50", Dst: "8.8.8.8", Dport: 443},
	}
	mine := map[string]bool{"10.0.0.30": true, "192.168.2.1": true}

	got, _ := detectDoHClients(conns, map[string]string{"192.168.2.50": "tablet"}, mine)

	joined := strings.Join(got, " | ")
	if strings.Contains(joined, "10.0.0.30") {
		t.Errorf("the router's own DoH was reported as a client bypassing the router: %v", got)
	}
	if len(got) != 1 || !strings.Contains(joined, "192.168.2.50") {
		t.Fatalf("the real client was lost along with the false positive — want exactly the tablet, got %v", got)
	}
	if !strings.Contains(joined, "tablet") {
		t.Errorf("the client is not named by its lease: %v", got)
	}
}

// And the guard must not become a blanket excuse: with no address set at all — which is what a failed
// read of the interfaces produces — the check behaves as it did before, noisier rather than quieter.
func TestDetectDoHClients_NoAddressSetKeepsThePreFixBehaviour(t *testing.T) {
	conns := []Conn{{Src: "10.0.0.30", Dst: "1.1.1.1", Dport: 443}}
	if got, _ := detectDoHClients(conns, nil, nil); len(got) != 1 {
		t.Fatalf("with no router addresses known the flow must still be reported, got %v", got)
	}
}
