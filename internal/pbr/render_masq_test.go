package pbr

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestRenderNft_MasqInterfaceEgress: a plan with an EgressInterface egress (a tunnel iface)
// must emit a forwarded-LAN MASQUERADE on that egress dev so forwarded LAN traffic does not
// keep its private source out the tunnel (the black-hole this fix prevents). The masquerade
// must match on oifname (not fwmark) and appear exactly once per unique iface even when the
// same iface backs multiple routing lists / zones.
func TestRenderNft_MasqInterfaceEgress(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "ru-awg0", Engine: model.EngineExternal, Server: "203.0.113.7",
			Enabled: true, Params: map[string]any{"interface": "awg0"},
		}},
		// Two distinct routing lists both routed to the SAME external endpoint → the awg0 iface
		// appears in two zones, but must yield exactly ONE masquerade line (dedupe by ifname).
		RoutingLists: []model.RoutingList{
			{ID: "alpha", Manual: []string{"198.51.100.0/24"}, Outbound: "ru-awg0", Enabled: true},
			{ID: "beta", Manual: []string{"203.0.113.128/25"}, Outbound: "ru-awg0", Enabled: true},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	nft := plan.RenderNft()

	mustContain(t, nft, "chain wr_nat {")
	mustContain(t, nft, "type nat hook postrouting priority srcnat; policy accept;")
	mustContain(t, nft, `oifname "awg0" masquerade`)

	if n := strings.Count(nft, `oifname "awg0" masquerade`); n != 1 {
		t.Errorf(`masquerade for awg0 emitted %d times (want exactly 1 — dedupe by iface)\n---\n%s`, n, nft)
	}
	// Must NOT key the SNAT off the fwmark — by POSTROUTING the packet is already on the tunnel
	// dev; matching on the mark would be wrong/fragile. The match is the egress oifname.
	if strings.Contains(nft, "fwmark") && strings.Contains(nft, "masquerade") {
		// (fwmark appears only in ip-rule output, never in RenderNft) — guard anyway.
		if i := strings.Index(nft, "masquerade"); i >= 0 && strings.Contains(nft[:i], "wr_nat") {
			line := nft[strings.LastIndex(nft[:i], "\n")+1 : i]
			if strings.Contains(line, "fwmark") || strings.Contains(line, "meta mark") {
				t.Errorf("masquerade must match on oifname, not the fwmark:\n%s", nft)
			}
		}
	}
}

// TestRenderNft_MasqDedupAcrossMembers: when several distinct tunnel ifaces are egresses
// (e.g. a failover group with multiple kernel members + another list), each unique iface gets
// its own masquerade line and none is duplicated.
func TestRenderNft_MasqDedupAcrossMembers(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "ep-a", Engine: model.EngineExternal, Server: "203.0.113.1", Enabled: true, Params: map[string]any{"interface": "awg0"}},
			{ID: "ep-b", Engine: model.EngineExternal, Server: "203.0.113.2", Enabled: true, Params: map[string]any{"interface": "awg1"}},
		},
		RoutingLists: []model.RoutingList{
			{ID: "to-a", Manual: []string{"198.51.100.0/24"}, Outbound: "ep-a", Enabled: true},
			{ID: "to-a-2", Manual: []string{"198.51.101.0/24"}, Outbound: "ep-a", Enabled: true},
			{ID: "to-b", Manual: []string{"192.0.2.0/24"}, Outbound: "ep-b", Enabled: true},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	nft := plan.RenderNft()

	for _, ifc := range []string{"awg0", "awg1"} {
		if n := strings.Count(nft, `oifname "`+ifc+`" masquerade`); n != 1 {
			t.Errorf(`iface %s masquerade emitted %d times (want 1)\n---\n%s`, ifc, n, nft)
		}
	}
}

// TestRenderNft_MasqNoInterfaceEgress: a WAN-only / no-interface-egress plan must emit NO
// masquerade and NO wr_nat chain — the byte-identical no-op guarantee that protects every
// existing render golden/snapshot test for WAN-only / block-only plans.
func TestRenderNft_MasqNoInterfaceEgress(t *testing.T) {
	// A list routed to WAN (direct) → only the WAN egress exists, no EgressInterface.
	p := &model.Profile{
		RoutingLists: []model.RoutingList{
			{ID: "direct-list", Manual: []string{"198.51.100.0/24"}, Outbound: model.OutboundDirect, Enabled: true},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	nft := plan.RenderNft()

	if strings.Contains(nft, "wr_nat") {
		t.Errorf("WAN-only plan must NOT emit a wr_nat chain:\n%s", nft)
	}
	if strings.Contains(nft, "masquerade") {
		t.Errorf("WAN-only plan must NOT emit any masquerade:\n%s", nft)
	}
	if ifs := plan.masqIfaces(); len(ifs) != 0 {
		t.Errorf("masqIfaces() = %v, want empty for a WAN-only plan", ifs)
	}
}

// TestRenderNft_MasqBlockOnlyNoOp: a block-only (blackhole) plan likewise emits no nat.
func TestRenderNft_MasqBlockOnlyNoOp(t *testing.T) {
	p := &model.Profile{
		RoutingLists: []model.RoutingList{
			{ID: "block-list", Manual: []string{"198.51.100.0/24"}, Outbound: model.OutboundBlock, Enabled: true},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	nft := plan.RenderNft()
	if strings.Contains(nft, "wr_nat") || strings.Contains(nft, "masquerade") {
		t.Errorf("block-only plan must emit no nat chain / masquerade:\n%s", nft)
	}
}

// TestRenderNft_MasqV4Only: an interface egress carrying a v6 zone must still emit the v4
// masquerade for the iface but NO v6 masquerade (fail-closed v6 posture; no v6 LAN on
// target). The masquerade is v4-qualified (meta nfproto ipv4) in the inet nat chain, so the
// guarantee here is the MASQUERADE statement stays v4-only even alongside a v6 routing rule.
func TestRenderNft_MasqV4Only(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "ep-v6", Engine: model.EngineExternal, Server: "203.0.113.9",
			Enabled: true, Params: map[string]any{"interface": "awg0"},
		}},
		RoutingLists: []model.RoutingList{
			{ID: "v6-list", Manual: []string{"2001:db8::/32"}, Outbound: "ep-v6", Enabled: true},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	nft := plan.RenderNft()

	// The masquerade must be v4-qualified (meta nfproto ipv4) — mirroring render_ipset.go's
	// posture of never NATing forwarded v6. A v6 ROUTING rule (`ip6 daddr @set meta mark`) is
	// legitimate and expected here; only the MASQUERADE statement must stay v4-only.
	mustContain(t, nft, `meta nfproto ipv4 oifname "awg0" masquerade`)
	for _, line := range strings.Split(nft, "\n") {
		if !strings.Contains(line, "masquerade") {
			continue
		}
		if strings.Contains(line, "ip6") || strings.Contains(line, "nfproto ipv6") {
			t.Errorf("masquerade line carries a v6 qualifier (must be v4-only): %q", line)
		}
		if !strings.Contains(line, "nfproto ipv4") {
			t.Errorf("masquerade line must be v4-qualified (meta nfproto ipv4): %q", line)
		}
	}
}
