package pbr

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestRenderNft_NftCheck runs the rendered ruleset through a REAL `nft -c` (check-only,
// no apply) when nft is on PATH (Linux CI / on-device). This is the only guard that
// catches an invalid-but-structurally-plausible ruleset — e.g. a chain named after a
// reserved keyword — which the mock-runner unit tests cannot see. Covers v4+v6 zones,
// the bypass sets, and the marking chain.
func TestRenderNft_NftCheck(t *testing.T) {
	nftBin, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not in PATH — skipping real nft syntax check (runs in CI / on-device)")
	}
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20",
			Enabled: true, Params: map[string]any{"interface": "awg1"},
		}},
		RoutingLists: []model.RoutingList{
			// Deliberately include OVERLAPPING entries (the /24 is inside the /16, the v6
			// /64 inside the /32): without collapsePrefixes these would make `nft -f` reject
			// the whole interval set. This is the end-to-end guard for that fix.
			{ID: "vowifi", Manual: []string{"198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "2001:db8:0:e::/64"}, Outbound: "ru-awg1", Enabled: true},
			{ID: "blk", Manual: []string{"10.10.0.0/16"}, Outbound: model.OutboundBlock, Enabled: true},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	f := filepath.Join(t.TempDir(), "ruleset.nft")
	if err := os.WriteFile(f, []byte(plan.RenderNft()), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(nftBin, "-c", "-f", f).CombinedOutput(); err != nil {
		// `nft -c` still initializes a netlink cache against the kernel even in
		// check-only mode; an unprivileged CI container (no CAP_NET_ADMIN / restricted
		// netns) can't do that and fails BEFORE parsing the ruleset. That's an
		// environment limitation, not a ruleset bug — skip rather than fail. A genuine
		// invalid ruleset produces a "syntax error"/parse message instead.
		if s := string(out); strings.Contains(s, "Operation not permitted") ||
			strings.Contains(s, "cache initialization failed") {
			t.Skipf("nft -c can't initialize in this environment (unprivileged?) — skipping syntax check: %s", strings.TrimSpace(s))
		}
		t.Fatalf("nft -c rejected the rendered ruleset: %v\n%s\n--- ruleset ---\n%s", err, out, plan.RenderNft())
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func egressByTag(pl *Plan, tag string) *Egress {
	for i := range pl.Egresses {
		if pl.Egresses[i].Tag == tag {
			return &pl.Egresses[i]
		}
	}
	return nil
}

// The motivating case: route a mobile carrier's ePDG subnet out the RU kernel tunnel (awg1).
func TestCompile_VoWiFi(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20",
			Enabled: true, Params: map[string]any{"interface": "awg1"},
		}},
		RoutingLists: []model.RoutingList{{
			ID: "carrier-carveout", Manual: []string{"198.51.100.0/24"}, Outbound: "ru-awg1", Enabled: true,
		}},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(plan.Zones) != 1 {
		t.Fatalf("want 1 zone, got %d", len(plan.Zones))
	}
	z := plan.Zones[0]
	if z.EgressTag != "ru-awg1" || !contains(z.V4, "198.51.100.0/24") {
		t.Errorf("zone = %+v", z)
	}
	eg := egressByTag(plan, "ru-awg1")
	if eg == nil || eg.Kind != EgressInterface || eg.Iface != "awg1" {
		t.Fatalf("ru-awg1 egress = %+v", eg)
	}
	if eg.Mark != 0x00020000 || eg.Table != 151 {
		t.Errorf("ru-awg1 mark/table = %s/%d, want 0x00020000/151", hexMark(eg.Mark), eg.Table)
	}
	if z.Mark != eg.Mark {
		t.Errorf("zone mark %s != egress mark %s", hexMark(z.Mark), hexMark(eg.Mark))
	}
	// Anti-loop bypass must include the tunnel peer's own server IP.
	if !contains(plan.BypassV4, "198.51.100.20/32") {
		t.Errorf("bypass missing peer IP: %v", plan.BypassV4)
	}
	// WAN egress always present (bypass routes through main).
	if w := egressByTag(plan, model.OutboundDirect); w == nil || w.Kind != EgressWAN || w.Table != 254 {
		t.Errorf("wan egress = %+v", w)
	}
}

func TestCompile_DirectAndBlock(t *testing.T) {
	p := &model.Profile{
		Rules: []model.Rule{
			{ID: "r-direct", IPCIDR: []string{"9.9.9.9/32"}, Outbound: model.OutboundDirect},
			{ID: "r-block", IPCIDR: []string{"10.10.0.0/16"}, Outbound: model.OutboundBlock},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if b := egressByTag(plan, model.OutboundBlock); b == nil || b.Kind != EgressBlackhole {
		t.Fatalf("block egress = %+v", b)
	}
	if len(plan.Zones) != 2 {
		t.Errorf("want 2 zones, got %d", len(plan.Zones))
	}
}

// A default (catch-all) rule's matcher fields are meaningless to sing-box, so a stale
// IPCIDR on it must NOT become a kernel zone — that would TUN-exclude the CIDR and
// silently shadow an earlier proxy rule for the same IP.
func TestCompile_DefaultRuleNoZone(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "ru", Engine: model.EngineExternal, Server: "1.2.3.4",
			Enabled: true, Params: map[string]any{"interface": "awg1"},
		}},
		Rules: []model.Rule{
			{ID: "viaproxy", IPCIDR: []string{"8.8.8.8/32"}, Outbound: "ru"},
			{ID: "def", Default: true, IPCIDR: []string{"8.8.8.8/32"}, Outbound: model.OutboundDirect},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(plan.Zones) != 1 {
		t.Fatalf("want 1 zone (the default rule's IPCIDR must NOT create one), got %d: %+v", len(plan.Zones), plan.Zones)
	}
	if plan.Zones[0].EgressTag != "ru" {
		t.Errorf("zone egress = %q, want ru (the kernel rule, not the default)", plan.Zones[0].EgressTag)
	}
}

func TestCompile_Warnings(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "nl-reality", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "1.2.3.4", Enabled: true,
		}},
		Rules: []model.Rule{
			{ID: "r-dom", Domain: []string{"example.com"}, Outbound: model.OutboundDirect},
			{ID: "r-proxy", IPCIDR: []string{"5.6.7.8/32"}, Outbound: "nl-reality"},
		},
	}
	plan, warns, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	// Proxy-engine target is NOT kernel-routed → no zone, but a warning.
	if len(plan.Zones) != 0 {
		t.Errorf("want 0 zones (proxy target not kernel-routed), got %d", len(plan.Zones))
	}
	var gotDom, gotProxy bool
	for _, w := range warns {
		if w.Scope == "r-dom" && strings.Contains(w.Msg, "domain") {
			gotDom = true
		}
		if w.Scope == "r-proxy" && strings.Contains(w.Msg, "proxy") {
			gotProxy = true
		}
	}
	if !gotDom || !gotProxy {
		t.Errorf("missing warnings: dom=%v proxy=%v (%+v)", gotDom, gotProxy, warns)
	}
}

func TestClassifyCIDRs(t *testing.T) {
	v4, v6, bad := classifyCIDRs([]string{
		"198.51.100.0/24", // aggregate
		"198.51.100.77",   // bare IP → /32, CONTAINED in the /16 → collapsed away
		"198.51.100.0/24", // exact dup → dropped
		"8.8.8.8",         // bare IP → /32, disjoint → kept (normalization still works)
		"2001:db8::/32",   // v6 aggregate
		"2001:db8:0:e::1", // v6 /128 CONTAINED in the /32 → collapsed away
		"2606:4700::1111", // disjoint v6 /128 → kept
		"example.com", "", // bad / empty
	})
	// Bare IP normalized to /32 and kept when disjoint; the aggregate stays while the
	// contained /32 and the exact dup are collapsed away (overlap-free for the nft set).
	if !contains(v4, "8.8.8.8/32") {
		t.Errorf("bare IP not normalized/kept: %v", v4)
	}
	if !contains(v4, "198.51.100.0/24") || contains(v4, "198.51.100.77/32") || len(v4) != 2 {
		t.Errorf("v4 collapse wrong: %v (want exactly [198.51.100.0/24, 8.8.8.8/32])", v4)
	}
	if !contains(v6, "2001:db8::/32") || contains(v6, "2001:db8:0:e::1/128") || len(v6) != 2 {
		t.Errorf("v6 collapse wrong: %v", v6)
	}
	if !contains(bad, "example.com") || len(bad) != 1 {
		t.Errorf("bad = %v", bad)
	}
	assertNoOverlap(t, v4)
	assertNoOverlap(t, v6)
}

// TestCompile_ZoneCollapsed: a RoutingList carrying overlapping CIDRs (e.g. a copy-pasted
// ASN dump with the aggregate /17 AND its more-specific /18 + /24 — the real VK case from
// the 2026-06-21 ru-heavy work) compiles to a single covering prefix, so the nft `flags
// interval` set (no auto-merge) loads instead of rejecting the whole ruleset at Apply.
func TestCompile_ZoneCollapsed(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20",
			Enabled: true, Params: map[string]any{"interface": "awg1"},
		}},
		RoutingLists: []model.RoutingList{{
			ID: "ru", Manual: []string{"95.213.0.0/17", "95.213.0.0/18", "95.213.44.0/24"},
			Outbound: "ru-awg1", Enabled: true,
		}},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var z *Zone
	for i := range plan.Zones {
		if plan.Zones[i].Name == "list_ru" {
			z = &plan.Zones[i]
		}
	}
	if z == nil {
		t.Fatal("zone list_ru missing")
	}
	if len(z.V4) != 1 || z.V4[0] != "95.213.0.0/17" {
		t.Errorf("zone V4 not collapsed to the covering /17: %v", z.V4)
	}
	assertNoOverlap(t, z.V4)
}

// TestCompile_ZoneNameCollision: two routing-list ids that differ only by characters
// nftName() squashes to '_' ("ru-services" vs "ru_services") must NOT produce the same nft
// set name — model.Validate allows them (distinct exact ids), but a duplicate `set` in the
// rendered ruleset makes `nft -f` reject the whole load → Apply fails. Both lists must keep
// kernel-routing (functionality preserved, not dropped).
func TestCompile_ZoneNameCollision(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "ru-awg1", Engine: model.EngineExternal, Server: "1.2.3.4",
			Enabled: true, Params: map[string]any{"interface": "awg1"},
		}},
		RoutingLists: []model.RoutingList{
			{ID: "ru-services", Manual: []string{"1.1.1.0/24"}, Outbound: "ru-awg1", Enabled: true},
			{ID: "ru_services", Manual: []string{"2.2.2.0/24"}, Outbound: "ru-awg1", Enabled: true},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if len(plan.Zones) != 2 {
		t.Fatalf("want 2 zones, got %d: %+v", len(plan.Zones), plan.Zones)
	}
	if plan.Zones[0].Name == plan.Zones[1].Name {
		t.Errorf("zone names collide: %q == %q (nft would declare the set twice)", plan.Zones[0].Name, plan.Zones[1].Name)
	}
	var all []string
	for _, z := range plan.Zones {
		all = append(all, z.V4...)
	}
	if !contains(all, "1.1.1.0/24") || !contains(all, "2.2.2.0/24") {
		t.Errorf("a colliding list's CIDRs were dropped (functionality lost): %v", all)
	}
	// The rendered ruleset must declare each set exactly once.
	nft := plan.RenderNft()
	for _, z := range plan.Zones {
		if n := strings.Count(nft, "set "+z.Name+"_4 {"); n != 1 {
			t.Errorf("set %s_4 declared %d times (want 1):\n%s", z.Name, n, nft)
		}
	}
}

// assertNoOverlap fails if any prefix in the list contains another — the invariant the nft
// `flags interval` sets require (overlapping elements make `nft -f` reject the ruleset).
func assertNoOverlap(t *testing.T, cidrs []string) {
	t.Helper()
	var ps []netip.Prefix
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("parse %s: %v", c, err)
		}
		ps = append(ps, p)
	}
	for i := range ps {
		for j := range ps {
			if i != j && ps[i].Bits() <= ps[j].Bits() && ps[i].Contains(ps[j].Addr()) {
				t.Errorf("overlap: %s contains %s — interval set would reject", ps[i], ps[j])
			}
		}
	}
}

// TestCompile_CIDRCache: a routing list's kernel zone is Manual ∪ CIDRCache (the last-good
// auto-refresh fetch), so a list with ONLY a CIDRCache (empty Manual) still yields a zone.
func TestCompile_CIDRCache(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20",
			Enabled: true, Params: map[string]any{"interface": "awg1"},
		}},
		RoutingLists: []model.RoutingList{
			{ID: "manual-plus-cache", Manual: []string{"1.1.1.0/24"}, CIDRCache: []string{"2.2.2.0/24"}, Outbound: "ru-awg1", Enabled: true},
			{ID: "cache-only", CIDRSource: "asn:13238", CIDRCache: []string{"3.3.3.0/24"}, Outbound: "ru-awg1", Enabled: true},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	got := map[string][]string{}
	for _, z := range plan.Zones {
		got[z.Name] = z.V4
	}
	if z := got["list_manual_plus_cache"]; !contains(z, "1.1.1.0/24") || !contains(z, "2.2.2.0/24") {
		t.Errorf("manual+cache zone = %v, want union of Manual and CIDRCache", z)
	}
	if z := got["list_cache_only"]; !contains(z, "3.3.3.0/24") {
		t.Errorf("cache-only list (empty Manual) must still produce a zone: %v (all=%v)", z, got)
	}
}

// offloadProfile is a minimal VoWiFi carve-out fixture for the Phase-1b flow-offload tests.
func offloadProfile() *model.Profile {
	return &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20",
			Enabled: true, Params: map[string]any{"interface": "awg1"},
		}},
		RoutingLists: []model.RoutingList{{
			ID: "carrier-carveout", Manual: []string{"198.51.100.0/24"}, Outbound: "ru-awg1", Enabled: true,
		}},
	}
}

// TestRenderNft_OffloadSoftware: Offload="sw" + devices renders a flowtable (no `flags
// offload`) and a forward chain that EXCLUDES carve-out marks before offloading general
// tcp/udp — the Phase-1b datapath. The mark-gate `return` must precede the `flow add`.
func TestRenderNft_OffloadSoftware(t *testing.T) {
	plan, _, err := Compile(offloadProfile(), Options{Offload: "sw", OffloadDevices: []string{"br-lan", "eth1"}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if plan.Flowtable == nil || plan.Flowtable.HW {
		t.Fatalf("Flowtable = %+v, want non-nil sw (HW=false)", plan.Flowtable)
	}
	nft := plan.RenderNft()
	for _, want := range []string{
		"flowtable ft {", "hook ingress priority filter - 1;", "devices = { br-lan, eth1 };",
		"chain wr_offload {", "type filter hook forward priority filter - 1; policy accept;",
		"meta mark & 0x00ff0000 != 0x0 return", "meta l4proto { tcp, udp } flow add @ft",
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("RenderNft missing %q\n---\n%s", want, nft)
		}
	}
	if strings.Contains(nft, "flags offload") {
		t.Errorf("software mode must NOT emit `flags offload`:\n%s", nft)
	}
	// The carve-out exclusion MUST come before the flow-add, or marked flows get offloaded
	// and lose their PBR route (the bug this whole design avoids).
	ret := strings.Index(nft, "meta mark & 0x00ff0000 != 0x0 return")
	add := strings.Index(nft, "flow add @ft")
	if ret < 0 || add < 0 || ret > add {
		t.Errorf("mark-gate `return` (%d) must precede `flow add` (%d)", ret, add)
	}
}

// TestRenderNft_OffloadHardware: "hw" adds `flags offload` (PPE) to the flowtable.
func TestRenderNft_OffloadHardware(t *testing.T) {
	plan, _, err := Compile(offloadProfile(), Options{Offload: "hw", OffloadDevices: []string{"br-lan", "eth1"}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if plan.Flowtable == nil || !plan.Flowtable.HW {
		t.Fatalf("Flowtable = %+v, want HW=true", plan.Flowtable)
	}
	if !strings.Contains(plan.RenderNft(), "flags offload;") {
		t.Errorf("hardware mode must emit `flags offload`:\n%s", plan.RenderNft())
	}
}

// TestRenderNft_OffloadOffDefault: default (no Offload) renders NO flowtable / wr_offload —
// byte-for-byte the pre-Phase-1b output, so landing this code changes nothing until a
// caller opts in. Also: offload requested with no devices is a no-op + a warning.
func TestRenderNft_OffloadOffDefault(t *testing.T) {
	plan, _, _ := Compile(offloadProfile(), Options{})
	if plan.Flowtable != nil {
		t.Errorf("default must have no flowtable, got %+v", plan.Flowtable)
	}
	nft := plan.RenderNft()
	if strings.Contains(nft, "flowtable") || strings.Contains(nft, "wr_offload") {
		t.Errorf("default RenderNft must not mention offload:\n%s", nft)
	}

	// requested but no devices → skipped + warned (never a broken half-flowtable).
	plan2, warns, _ := Compile(offloadProfile(), Options{Offload: "sw"})
	if plan2.Flowtable != nil {
		t.Errorf("offload with no devices must be skipped, got %+v", plan2.Flowtable)
	}
	var warned bool
	for _, w := range warns {
		if w.Scope == "offload" && strings.Contains(w.Msg, "no devices") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("missing 'no devices' warning: %+v", warns)
	}
}

func TestRender(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20",
			Enabled: true, Params: map[string]any{"interface": "awg1"},
		}},
		RoutingLists: []model.RoutingList{{
			ID: "carrier-carveout", Manual: []string{"198.51.100.0/24"}, Outbound: "ru-awg1", Enabled: true,
		}},
	}
	plan, _, _ := Compile(p, Options{})

	nft := plan.RenderNft()
	for _, want := range []string{
		"table inet wayhop_pbr {", "delete table inet wayhop_pbr", "list_carrier_carveout_4", "198.51.100.0/24",
		"bypass4", "198.51.100.20/32", "meta mark set meta mark & 0xff00ffff | 0x00020000",
		"type filter hook prerouting priority mangle", "chain wr_mark {",
		"ct mark set meta mark", // connmark-save → conntrack shows the egress (Dashboard attribution)
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("RenderNft missing %q\n---\n%s", want, nft)
		}
	}
	// The chain must NOT be named "mark" — that is an nft reserved keyword and the whole
	// ruleset fails to parse ("unexpected mark"). Regression for the on-device nft load.
	if strings.Contains(nft, "chain mark {") {
		t.Errorf("chain is named 'mark' (nft reserved keyword) — ruleset will not load:\n%s", nft)
	}

	ip := plan.RenderIP(Options{})
	if !contains(ip, "ip rule add fwmark 0x00020000/0x00ff0000 table 151 priority 150") {
		t.Errorf("RenderIP rules = %v", ip)
	}
	if !contains(ip, "ip route replace default dev awg1 table 151") {
		t.Errorf("RenderIP routes = %v", ip)
	}

	down := plan.RenderTeardown(Options{})
	if !contains(down, "nft delete table inet wayhop_pbr") {
		t.Errorf("RenderTeardown = %v", down)
	}
}
