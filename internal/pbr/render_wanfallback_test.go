package pbr

import (
	"strings"
	"testing"
)

// render_wanfallback_test.go covers the WAN-fallback MASQUERADE companion to the tunnel-iface
// masquerade in RenderNft's wr_nat chain (see render.go). The follow-up flagged in
// docs/NATIVE_P2_DESIGN.md: if a no-kill-switch / failover policy ever routes WR-marked
// forwarded traffic OUT the WAN uplink dev (an EgressWAN egress carrying a concrete Iface),
// those forwarded LAN flows must be SNAT'd to the WAN source or the upstream has no route back
// — the same black-hole the tunnel masquerade prevents, mirroring render_ipset.go's WAN-fallback
// SNAT. Compile never populates EgressWAN.Iface today, so these tests build the Plan directly
// (the trigger is a future failover wiring); the no-op guarantee for current plans is verified
// by render_masq_test.go's WAN-only / block-only cases.

// wanFallbackPlan is the minimal compiled-shape Plan whose WAN egress carries a concrete uplink
// iface (the no-kill-switch fallback). Synthetic data only (RFC5737 / documentation ifnames).
func wanFallbackPlan(wanIface string, tunIfaces ...string) *Plan {
	pl := &Plan{
		Table:    "wayhop_pbr",
		Mask:     0x00ff0000,
		Egresses: []Egress{{Tag: "direct", Kind: EgressWAN, Iface: wanIface, Mark: 0x00010000, Table: 254}},
	}
	pl.MasqIfaces = append([]string(nil), tunIfaces...)
	return pl
}

// TestRenderNft_WanFallbackMasq: a plan whose EgressWAN carries a WAN uplink iface emits the
// wr_nat chain with a v4 MASQUERADE for that WAN dev, oifname-matched (not fwmark-matched).
func TestRenderNft_WanFallbackMasq(t *testing.T) {
	plan := wanFallbackPlan("eth0")
	nft := plan.RenderNft()

	mustContain(t, nft, "chain wr_nat {")
	mustContain(t, nft, "type nat hook postrouting priority srcnat; policy accept;")
	mustContain(t, nft, `meta nfproto ipv4 oifname "eth0" masquerade`)

	if n := strings.Count(nft, `oifname "eth0" masquerade`); n != 1 {
		t.Errorf(`WAN masquerade for eth0 emitted %d times (want exactly 1)\n---\n%s`, n, nft)
	}
	// Must match on the egress oifname, never the fwmark (by POSTROUTING the packet is already on
	// the WAN dev). Mirror render_masq_test.go's guard.
	for _, line := range strings.Split(nft, "\n") {
		if !strings.Contains(line, "masquerade") {
			continue
		}
		if strings.Contains(line, "fwmark") || strings.Contains(line, "meta mark") {
			t.Errorf("WAN masquerade must match on oifname, not the fwmark: %q", line)
		}
		if !strings.Contains(line, "nfproto ipv4") {
			t.Errorf("WAN masquerade must be v4-qualified (meta nfproto ipv4): %q", line)
		}
		if strings.Contains(line, "ip6") || strings.Contains(line, "nfproto ipv6") {
			t.Errorf("WAN masquerade must stay v4-only (no v6 qualifier): %q", line)
		}
	}
}

// TestRenderNft_WanFallbackWithTunnel: a plan that has BOTH a tunnel-iface egress and a WAN
// fallback iface emits a masquerade for each, with no duplicate and no cross-contamination.
func TestRenderNft_WanFallbackWithTunnel(t *testing.T) {
	plan := wanFallbackPlan("eth0", "awg0")
	nft := plan.RenderNft()

	for _, ifc := range []string{"awg0", "eth0"} {
		if n := strings.Count(nft, `oifname "`+ifc+`" masquerade`); n != 1 {
			t.Errorf(`iface %s masquerade emitted %d times (want 1)\n---\n%s`, ifc, n, nft)
		}
	}
}

// TestRenderNft_WanFallbackDedupWithTunnel: if the WAN uplink iface is ALSO (somehow) a tunnel
// masq iface, the WAN-fallback path must NOT add a second identical masquerade line — the
// tunnel line already covers it. Exactly one masquerade for that iface.
func TestRenderNft_WanFallbackDedupWithTunnel(t *testing.T) {
	plan := wanFallbackPlan("eth0", "eth0")
	nft := plan.RenderNft()

	if n := strings.Count(nft, `oifname "eth0" masquerade`); n != 1 {
		t.Errorf(`eth0 masquerade emitted %d times (want exactly 1 — WAN line must dedupe against the tunnel line)\n---\n%s`, n, nft)
	}
}

// TestRenderNft_WanFallbackMultiDedup: two EgressWAN egresses naming the same WAN iface yield a
// single masquerade line (de-dupe across WAN egresses).
func TestRenderNft_WanFallbackMultiDedup(t *testing.T) {
	plan := &Plan{
		Table: "wayhop_pbr",
		Mask:  0x00ff0000,
		Egresses: []Egress{
			{Tag: "direct", Kind: EgressWAN, Iface: "eth0", Mark: 0x00010000, Table: 254},
			{Tag: "fallback", Kind: EgressWAN, Iface: "eth0", Mark: 0x00020000, Table: 254},
		},
	}
	nft := plan.RenderNft()
	if n := strings.Count(nft, `oifname "eth0" masquerade`); n != 1 {
		t.Errorf(`eth0 WAN masquerade emitted %d times (want exactly 1 — dedupe across WAN egresses)\n---\n%s`, n, nft)
	}
}

// TestRenderNft_TunnelOnlyNoWanLine: a tunnel-only plan (no WAN egress iface) emits ONLY the
// tunnel masquerade and NO extra WAN-iface line — the WAN-fallback path is inert.
func TestRenderNft_TunnelOnlyNoWanLine(t *testing.T) {
	plan := &Plan{
		Table:      "wayhop_pbr",
		Mask:       0x00ff0000,
		Egresses:   []Egress{{Tag: "direct", Kind: EgressWAN, Mark: 0x00010000, Table: 254}}, // WAN egress, NO Iface
		MasqIfaces: []string{"awg0"},
	}
	nft := plan.RenderNft()

	mustContain(t, nft, `oifname "awg0" masquerade`)
	if n := strings.Count(nft, "masquerade"); n != 1 {
		t.Errorf("tunnel-only plan must emit exactly one masquerade (the tunnel), got %d:\n%s", n, nft)
	}
	if got := plan.masqWanIfaces(plan.masqIfaces()); len(got) != 0 {
		t.Errorf("masqWanIfaces = %v, want empty for a WAN egress with no Iface", got)
	}
}

// TestRenderNft_NoEgressNoNat: a plan with no interface egress and no WAN-fallback iface emits
// NO wr_nat chain at all — the byte-identical no-op that protects the render goldens.
func TestRenderNft_NoEgressNoNat(t *testing.T) {
	plan := &Plan{
		Table:    "wayhop_pbr",
		Mask:     0x00ff0000,
		Egresses: []Egress{{Tag: "direct", Kind: EgressWAN, Mark: 0x00010000, Table: 254}},
	}
	nft := plan.RenderNft()

	if strings.Contains(nft, "wr_nat") {
		t.Errorf("no-egress plan must NOT emit a wr_nat chain:\n%s", nft)
	}
	if strings.Contains(nft, "masquerade") {
		t.Errorf("no-egress plan must NOT emit any masquerade:\n%s", nft)
	}
}
