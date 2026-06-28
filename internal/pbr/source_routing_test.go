package pbr

import (
	"strings"
	"testing"

	"wakeroute/internal/model"
)

// TestCompileSourceIPZone pins the Phase-C compiler activation: a source_ip_cidr + dest rule on
// the OpenWrt nft plane builds a SOURCE-SCOPED zone (dest in V4, source in SrcV4, SrcScoped set —
// the mark applies only to the matching source, never an over-route); a disabled rule builds no
// zone (honored on both planes); and a plain dest rule stays unscoped.
func TestCompileSourceIPZone(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20", Enabled: true, Params: map[string]any{"interface": "awg1"}},
		},
		Rules: []model.Rule{
			{ID: "kept", IPCIDR: []string{"1.2.3.0/24"}, Outbound: "ru-awg1"},
			{ID: "off", IPCIDR: []string{"5.6.7.0/24"}, Outbound: "ru-awg1", Disabled: true},
			{ID: "srcdest", IPCIDR: []string{"8.8.8.0/24"}, SourceIPCIDR: []string{"192.168.1.50/32"}, Outbound: "ru-awg1"},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	byName := map[string]Zone{}
	for _, z := range plan.Zones {
		byName[z.Name] = z
	}
	if _, ok := byName["rule_off"]; ok {
		t.Error("disabled rule must not produce a kernel zone")
	}
	kept, ok := byName["rule_kept"]
	if !ok {
		t.Fatal("expected a zone for the plain dest rule")
	}
	if kept.SrcScoped || len(kept.SrcV4) > 0 {
		t.Errorf("plain dest rule must be unscoped, got %+v", kept)
	}
	sd, ok := byName["rule_srcdest"]
	if !ok {
		t.Fatalf("expected a source-scoped zone for the source_ip+dest rule; zones=%+v", plan.Zones)
	}
	if !sd.SrcScoped {
		t.Errorf("source_ip+dest zone must be SrcScoped, got %+v", sd)
	}
	if len(sd.SrcV4) != 1 || !strings.Contains(sd.SrcV4[0], "192.168.1.50") {
		t.Errorf("source-scoped zone SrcV4 should hold the source CIDR, got %v", sd.SrcV4)
	}
	if len(sd.V4) != 1 || !strings.Contains(sd.V4[0], "8.8.8.0") {
		t.Errorf("source-scoped zone V4 should hold the dest CIDR, got %v", sd.V4)
	}
}

// TestCompileSourceMatchersBuildZone confirms the Phase-C activation of source mac/iface/port: a
// rule carrying any of them (+ a dest, nft plane) builds a SOURCE-SCOPED zone that threads the
// matchers through to the renderer (no source_ip_cidr → SrcV4 stays empty).
func TestCompileSourceMatchersBuildZone(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20", Enabled: true, Params: map[string]any{"interface": "awg1"}},
		},
		Rules: []model.Rule{
			{ID: "dev", IPCIDR: []string{"8.8.8.0/24"}, SourceIface: []string{"br-guest"}, SourceMAC: []string{"aa:bb:cc:dd:ee:ff"}, SourcePort: []int{443}, Outbound: "ru-awg1"},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(plan.Zones) != 1 {
		t.Fatalf("want 1 zone, got %d: %+v", len(plan.Zones), plan.Zones)
	}
	z := plan.Zones[0]
	if !z.SrcScoped {
		t.Errorf("mac/iface/port rule must build a SrcScoped zone, got %+v", z)
	}
	if len(z.SrcIface) != 1 || z.SrcIface[0] != "br-guest" {
		t.Errorf("SrcIface not threaded: %v", z.SrcIface)
	}
	if len(z.SrcMAC) != 1 || z.SrcMAC[0] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("SrcMAC not threaded: %v", z.SrcMAC)
	}
	if len(z.SrcPort) != 1 || z.SrcPort[0] != 443 {
		t.Errorf("SrcPort not threaded: %v", z.SrcPort)
	}
	if len(z.SrcV4) != 0 {
		t.Errorf("no source_ip_cidr → SrcV4 should be empty, got %v", z.SrcV4)
	}
}

// TestCompileSourceOnlyZone confirms a source-only rule (a source matcher, NO destination) builds
// a destination-less source-scoped zone on the nft plane (it routes every dest from the source).
func TestCompileSourceOnlyZone(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20", Enabled: true, Params: map[string]any{"interface": "awg1"}},
		},
		Rules: []model.Rule{
			{ID: "devall", SourceIPCIDR: []string{"192.168.1.50/32"}, Outbound: "ru-awg1"},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(plan.Zones) != 1 {
		t.Fatalf("want 1 zone, got %d: %+v", len(plan.Zones), plan.Zones)
	}
	z := plan.Zones[0]
	if !z.SrcScoped {
		t.Errorf("source-only rule must build a SrcScoped zone, got %+v", z)
	}
	if len(z.V4) != 0 || len(z.V6) != 0 {
		t.Errorf("source-only zone must have no dest CIDRs, got V4=%v V6=%v", z.V4, z.V6)
	}
	if len(z.SrcV4) != 1 || !strings.Contains(z.SrcV4[0], "192.168.1.50") {
		t.Errorf("source-only zone SrcV4 should hold the source CIDR, got %v", z.SrcV4)
	}
}

// TestRenderNftSourceOnly pins the source-only nft rendering: a destination-less source-scoped
// zone emits a `ip saddr @<name>_s4 <mark>` line (NO ip daddr) followed by a re-asserted anti-loop
// bypass so a tunnel-peer-destined packet from the matched source still goes WAN. The bypass mark
// line therefore appears TWICE — the initial one + the re-assert after the source-only line.
func TestRenderNftSourceOnly(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20", Enabled: true, Params: map[string]any{"interface": "awg1"}},
		},
		Rules: []model.Rule{
			{ID: "devall", SourceIPCIDR: []string{"192.168.1.50/32"}, Outbound: "ru-awg1"},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	nft := plan.RenderNft()
	if !strings.Contains(nft, "ip saddr @rule_devall_s4 meta mark set") {
		t.Errorf("missing source-only saddr line:\n%s", nft)
	}
	if strings.Contains(nft, "ip saddr @rule_devall_s4 ip daddr") || strings.Contains(nft, "@rule_devall_4") {
		t.Errorf("source-only zone must carry no dest set:\n%s", nft)
	}
	if n := strings.Count(nft, "ip daddr @bypass4 meta mark set"); n != 2 {
		t.Errorf("want the bypass4 mark line twice (initial + re-assert), got %d:\n%s", n, nft)
	}
	// The re-assert (last bypass line) must come AFTER the source-only line so it wins for peers.
	if strings.LastIndex(nft, "ip daddr @bypass4 meta mark set") < strings.Index(nft, "ip saddr @rule_devall_s4") {
		t.Errorf("bypass re-assert must follow the source-only line:\n%s", nft)
	}
}

// TestCompileSourceKeeneticPlaneBuildsZone confirms source matching is now kernel-routed on the
// Keenetic ipset plane too (CollectDomainZones), not just the nft plane: a source rule builds a
// SrcScoped zone (RenderIptablesScript emits the source ipset + match). Both a source+dest and a
// source-only rule build a zone.
func TestCompileSourceKeeneticPlaneBuildsZone(t *testing.T) {
	ep := model.Endpoint{ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20", Enabled: true, Params: map[string]any{"interface": "awg1"}}
	cases := []struct {
		name string
		rule model.Rule
	}{
		{"dest", model.Rule{ID: "r", IPCIDR: []string{"8.8.8.0/24"}, SourceIPCIDR: []string{"192.168.1.50/32"}, Outbound: "ru-awg1"}},
		{"source-only", model.Rule{ID: "r", SourceIPCIDR: []string{"192.168.1.50/32"}, Outbound: "ru-awg1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &model.Profile{Endpoints: []model.Endpoint{ep}, Rules: []model.Rule{tc.rule}}
			plan, _, err := Compile(p, Options{CollectDomainZones: true})
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if len(plan.Zones) != 1 || !plan.Zones[0].SrcScoped {
				t.Fatalf("%s: want 1 SrcScoped zone on the Keenetic plane, got %+v", tc.name, plan.Zones)
			}
		})
	}
}

// TestRenderNftSourceCrossFamilyGuard locks the cross-family guard: a zone whose source IP is in
// only ONE family must not emit a dest line in the OTHER family (its source can't constrain that
// traffic → would over-route). Injects a v6 dest + a v4-only source onto a compiled zone.
func TestRenderNftSourceCrossFamilyGuard(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20", Enabled: true, Params: map[string]any{"interface": "awg1"}},
		},
		Rules: []model.Rule{{ID: "kept", IPCIDR: []string{"1.2.3.0/24"}, Outbound: "ru-awg1"}},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	z := &plan.Zones[0]
	z.V6 = []string{"2001:db8::/48"}      // a v6 dest...
	z.SrcV4 = []string{"192.168.1.50/32"} // ...but the source IP is v4-only
	z.SrcScoped = true
	nft := plan.RenderNft()
	if !strings.Contains(nft, "ip saddr @rule_kept_s4 ip daddr @rule_kept_4") {
		t.Errorf("v4 line should carry the v4 source:\n%s", nft)
	}
	if strings.Contains(nft, "ip6 daddr @rule_kept_6 ") {
		t.Errorf("cross-family: the v6 dest line must be dropped (no v6 source to constrain it):\n%s", nft)
	}
}

// TestRenderNftSourceScoped pins the OpenWrt nft source rendering: a source-scoped zone emits a
// per-family saddr set and prepends the source matches (iface/mac/port family-agnostic + the
// per-family `ip saddr @<name>_s4`) to its wr_mark line, in a stable order, so the mark is set
// ONLY for traffic from the matching source (the dest set still bounds it). Injects the source
// fields onto a compiled zone to exercise the renderer in isolation.
func TestRenderNftSourceScoped(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20", Enabled: true, Params: map[string]any{"interface": "awg1"}},
		},
		Rules: []model.Rule{
			{ID: "kept", IPCIDR: []string{"1.2.3.0/24"}, Outbound: "ru-awg1"},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(plan.Zones) != 1 {
		t.Fatalf("want 1 zone, got %d", len(plan.Zones))
	}
	plan.Zones[0].SrcV4 = []string{"192.168.1.50/32"}
	plan.Zones[0].SrcIface = []string{"br-guest"}
	plan.Zones[0].SrcMAC = []string{"aa:bb:cc:dd:ee:ff"}
	plan.Zones[0].SrcPort = []int{443}
	plan.Zones[0].SrcScoped = true
	nft := plan.RenderNft()
	if !strings.Contains(nft, "set rule_kept_s4 {") || !strings.Contains(nft, "192.168.1.50") {
		t.Errorf("missing source set declaration:\n%s", nft)
	}
	// The wr_mark line carries iface/mac/port prefixes + the saddr + the dest, in order.
	wantLine := `iifname { "br-guest" } ether saddr { aa:bb:cc:dd:ee:ff } meta l4proto { tcp, udp } th sport { 443 } ip saddr @rule_kept_s4 ip daddr @rule_kept_4`
	if !strings.Contains(nft, wantLine) {
		t.Errorf("missing/wrong source-prefixed wr_mark line; want substring:\n%s\ngot:\n%s", wantLine, nft)
	}
	// Without any source field the line must stay dest-only — guard against prefixing every zone.
	plan.Zones[0].SrcV4, plan.Zones[0].SrcIface, plan.Zones[0].SrcMAC, plan.Zones[0].SrcPort = nil, nil, nil, nil
	if nft2 := plan.RenderNft(); strings.Contains(nft2, "ip saddr @rule_kept_s4") || strings.Contains(nft2, "iifname") || strings.Contains(nft2, "set rule_kept_s4") {
		t.Errorf("non-source zone must not emit any source match:\n%s", nft2)
	}
}
