package pbr

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"wakeroute/internal/model"
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
			{ID: "vowifi", Manual: []string{"198.51.100.0/24", "2001:db8::/32"}, Outbound: "ru-awg1", Enabled: true},
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
		"198.51.100.77", "198.51.100.0/24", "2001:db8::/32", "2001:db8:0:e::1", "example.com", "",
	})
	if !contains(v4, "198.51.100.77/32") || !contains(v4, "198.51.100.0/24") || len(v4) != 2 {
		t.Errorf("v4 = %v", v4)
	}
	if len(v6) != 2 {
		t.Errorf("v6 = %v", v6)
	}
	if !contains(bad, "example.com") || len(bad) != 1 {
		t.Errorf("bad = %v", bad)
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
		"table inet wakeroute_pbr {", "delete table inet wakeroute_pbr", "list_carrier_carveout_4", "198.51.100.0/24",
		"bypass4", "198.51.100.20/32", "meta mark set meta mark & 0xff00ffff | 0x00020000",
		"type filter hook prerouting priority mangle", "chain wr_mark {",
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
	if !contains(down, "nft delete table inet wakeroute_pbr") {
		t.Errorf("RenderTeardown = %v", down)
	}
}
