package generator

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"velinx/internal/model"
	"velinx/internal/pbr"
)

// hybridProfile is the canonical hybrid-split fixture: a kernel AmneziaWG endpoint
// referenced ONLY by pure-IP rules/lists (so pbr handles it → its outbound is
// omitted), a kernel External endpoint referenced by a DOMAIN rule (pbr can't
// kernel-route a domain → its outbound stays), a proxy VLESS endpoint, and a native
// (proxy-plane) WireGuard endpoint.
func hybridProfile() *model.Profile {
	wgKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	return &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "k-awg", Name: "AWG", Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
				Server: "awg.example.com", Port: 51820, Enabled: true,
				Params: map[string]any{"private_key": wgKey, "peer_public_key": wgKey}},
			{ID: "k-ext", Name: "EXT", Engine: model.EngineExternal, Enabled: true,
				Params: map[string]any{"interface": "awg1"}},
			// IP-literal server so generator.endpointBypass emits the proxy anti-loop
			// /32→direct rule we assert is preserved in hybrid mode.
			{ID: "p-vless", Name: "vless", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
				Server: "9.9.9.9", Port: 443, Enabled: true,
				Params: map[string]any{"uuid": "11111111-1111-1111-1111-111111111111"}},
			{ID: "p-wg", Name: "WG", Engine: model.EngineSingBox, Protocol: model.ProtoWireGuard,
				Server: "wg.example.com", Port: 51820, Enabled: true,
				Params: map[string]any{"private_key": wgKey, "peer_public_key": wgKey, "local_address": []string{"10.0.0.2/32"}}},
		},
		Rules: []model.Rule{
			{ID: "r-ip-awg", IPCIDR: []string{"10.0.0.0/8"}, Outbound: "k-awg"},         // pure IP → kernel → dropped (pbr)
			{ID: "r-dom-ext", DomainSuffix: []string{"example.com"}, Outbound: "k-ext"}, // domain → kernel → kept (sing-box)
			{ID: "r-ip-vless", IPCIDR: []string{"5.6.7.8/32"}, Outbound: "p-vless"},     // IP → proxy → kept
			{ID: "def", Default: true, Outbound: model.OutboundDirect},
		},
		RoutingLists: []model.RoutingList{
			{ID: "rl-ip-awg", Name: "L", Manual: []string{"192.168.50.0/24"}, Outbound: "k-awg", Enabled: true}, // pure IP → kernel → dropped
		},
	}
}

// hybridExclude folds the pbr Plan into the KernelExclude lists exactly as
// server.genOptions does, so the test exercises the real single-source-of-truth path.
func hybridExclude(t *testing.T, p *model.Profile) (v4, v6 []string) {
	t.Helper()
	plan, _, err := pbr.Compile(p, pbr.Options{})
	if err != nil {
		t.Fatalf("pbr.Compile: %v", err)
	}
	for _, z := range plan.Zones {
		v4 = append(v4, z.V4...)
		v6 = append(v6, z.V6...)
	}
	v4 = append(v4, plan.BypassV4...)
	v6 = append(v6, plan.BypassV6...)
	return v4, v6
}

func gen_outboundTags(res *Result) map[string]bool {
	tags := map[string]bool{}
	if obs, ok := res.Config["outbounds"].([]map[string]any); ok {
		for _, ob := range obs {
			if tag, _ := ob["tag"].(string); tag != "" {
				tags[tag] = true
			}
		}
	}
	if eps, ok := res.Config["endpoints"].([]map[string]any); ok {
		for _, ep := range eps {
			if tag, _ := ep["tag"].(string); tag != "" {
				tags[tag] = true
			}
		}
	}
	return tags
}

func gen_routeRules(res *Result) []map[string]any {
	route, _ := res.Config["route"].(map[string]any)
	rules, _ := route["rules"].([]map[string]any)
	return rules
}

// TestHybridMode is the core of Pass 3: in hybrid mode the kernel plane (pbr) owns
// WG/AmneziaWG/WAN + pure-IP carve-outs, sing-box keeps only the proxy plane.
func TestHybridMode(t *testing.T) {
	p := hybridProfile()
	ex4, ex6 := hybridExclude(t, p)
	res := gen_must(t, p, Options{MixedPort: 7890, TunEnabled: true, Hybrid: true, KernelExcludeV4: ex4, KernelExcludeV6: ex6})

	// (a) TUN excludes exactly the pbr CIDR union (zones + bypass).
	tun := gen_tunInbound(res)
	if tun == nil {
		t.Fatal("hybrid keeps the TUN, but no tun inbound was emitted")
	}
	gotEx, _ := tun["route_exclude_address"].([]string)
	wantEx := append(append([]string{}, ex4...), ex6...)
	if !reflect.DeepEqual(gotEx, wantEx) {
		t.Fatalf("route_exclude_address = %v, want %v", gotEx, wantEx)
	}
	if !gen_sliceHas(gotEx, "10.0.0.0/8") || !gen_sliceHas(gotEx, "192.168.50.0/24") {
		t.Errorf("route_exclude_address missing a kernel CIDR: %v", gotEx)
	}

	// (b) kernel outbound referenced ONLY by pure-IP rules is OMITTED; the one a
	// domain rule still references is KEPT (else that domain rule would dangle).
	tags := gen_outboundTags(res)
	if tags["k-awg"] {
		t.Errorf("k-awg outbound must be omitted in hybrid (pbr routes it): %v", tags)
	}
	if !tags["k-ext"] {
		t.Errorf("k-ext outbound must be KEPT (a domain rule references it): %v", tags)
	}
	// AmneziaWG keeps its Plugin so the daemon still brings the awg device up.
	var awgPlugin bool
	for _, pl := range res.Plugins {
		if pl.Endpoint.ID == "k-awg" {
			awgPlugin = true
		}
	}
	if !awgPlugin {
		t.Error("k-awg Plugin must be kept even when its outbound is omitted (pbr routes THROUGH the awg device)")
	}

	// (c) proxy plane is intact.
	if !tags["p-vless"] {
		t.Errorf("proxy vless outbound missing: %v", tags)
	}
	if !tags["p-wg"] {
		t.Errorf("native (proxy-plane) WireGuard endpoint missing: %v", tags)
	}

	// (d)+(e)+(f) rules: the pure-IP kernel rule and list are gone; the domain
	// kernel rule and the proxy IP rule survive; no rule references the omitted tag.
	rules := gen_routeRules(res)
	for _, r := range rules {
		if ob, _ := r["outbound"].(string); ob == "k-awg" {
			t.Errorf("a route rule still references the omitted k-awg outbound (dangling): %v", r)
		}
		if ips, _ := r["ip_cidr"].([]string); gen_sliceHas(ips, "10.0.0.0/8") {
			t.Errorf("the pure-IP kernel rule (10.0.0.0/8 → k-awg) must be dropped (pbr handles it): %v", r)
		}
		if ips, _ := r["ip_cidr"].([]string); gen_sliceHas(ips, "192.168.50.0/24") {
			t.Errorf("the pure-IP kernel list (192.168.50.0/24 → k-awg) must be dropped: %v", r)
		}
	}
	if !gen_ruleTargets(rules, "k-ext") {
		t.Error("the domain→k-ext rule must be kept in sing-box (pbr can't kernel-route a domain)")
	}
	if !gen_ruleTargets(rules, "p-vless") {
		t.Error("the IP→p-vless proxy rule must be kept")
	}

	// (g) final stays direct.
	if route, _ := res.Config["route"].(map[string]any); route["final"] != model.OutboundDirect {
		t.Errorf("route.final = %v, want direct", route["final"])
	}

	// (h) the sniff rule and the proxy endpoint-bypass /32 rule still lead the route.
	if len(rules) == 0 || rules[0]["action"] != "sniff" {
		t.Fatalf("hybrid TUN: rules[0] must be sniff, got %v", rules)
	}
	if !gen_hasBypassRule(rules) {
		t.Error("the proxy endpoint-bypass (/32 → direct) rule must be kept in hybrid (anti-loop for proxy dials)")
	}
}

// TestFastMode (RoutingMode="fast") is hybrid WITHOUT the capture-all TUN: general LAN
// traffic stays on the kernel fast-path (the live Steam-throughput fix: 143→~595 Mbps),
// so the generated config MUST NOT emit a tun inbound even though Hybrid=true — while the
// kernel partition (pbr drops pure-IP kernel rules/outbounds) still applies. Guards
// against a regression that re-couples Hybrid to the TUN (which would re-introduce the
// userspace capture and cap throughput again).
func TestFastMode(t *testing.T) {
	p := hybridProfile()
	// fast mode: server.genOptionsWithPlan sets Hybrid=true, TunEnabled=false, and no
	// KernelExclude (there is no TUN to exclude CIDRs from).
	res := gen_must(t, p, Options{MixedPort: 7890, TunEnabled: false, Hybrid: true})

	// (a) THE point of fast: NO tun inbound — general bypasses sing-box.
	if tun := gen_tunInbound(res); tun != nil {
		t.Fatalf("fast mode must NOT emit a tun inbound (general must take the kernel fast-path), got: %v", tun)
	}
	if ins, _ := res.Config["inbounds"].([]map[string]any); len(ins) != 1 || ins[0]["type"] != "mixed" {
		t.Fatalf("fast mode inbounds = %v, want exactly [mixed-in]", res.Config["inbounds"])
	}

	// (b) the hybrid kernel partition STILL applies: pure-IP kernel outbound omitted,
	// the domain-referenced kernel outbound kept.
	tags := gen_outboundTags(res)
	if tags["k-awg"] {
		t.Errorf("k-awg outbound must still be omitted in fast (pbr routes it): %v", tags)
	}
	if !tags["k-ext"] {
		t.Errorf("k-ext outbound (domain-referenced) must be kept in fast: %v", tags)
	}

	// (c) no TUN ⟹ no sniff rule (sniff is TUN-only) and the pure-IP kernel rule is
	// still dropped (pbr handles it).
	rules := gen_routeRules(res)
	for _, r := range rules {
		if r["action"] == "sniff" {
			t.Errorf("fast mode must NOT emit a sniff rule (no TUN to sniff): %v", rules)
		}
		if ips, _ := r["ip_cidr"].([]string); gen_sliceHas(ips, "10.0.0.0/8") {
			t.Errorf("pure-IP kernel rule (10.0.0.0/8 → k-awg) must be dropped in fast: %v", r)
		}
	}

	// (d) final stays direct.
	if route, _ := res.Config["route"].(map[string]any); route["final"] != model.OutboundDirect {
		t.Errorf("route.final = %v, want direct", route["final"])
	}
}

// TestHybridDefaultUnchanged: with Hybrid:false (the default tun/mixed path), output
// is the pre-Pass-3 shape — kernel outbounds present, no route_exclude, pure-IP kernel
// rules present. Proves the hybrid branch is fully gated and changes nothing otherwise.
func TestHybridDefaultUnchanged(t *testing.T) {
	p := hybridProfile()
	res := gen_must(t, p, Options{MixedPort: 7890, TunEnabled: true}) // Hybrid defaults false

	tags := gen_outboundTags(res)
	if !tags["k-awg"] || !tags["k-ext"] {
		t.Errorf("non-hybrid must emit both kernel outbounds: %v", tags)
	}
	if tun := gen_tunInbound(res); tun != nil {
		if _, has := tun["route_exclude_address"]; has {
			t.Error("non-hybrid TUN must NOT carry route_exclude_address")
		}
	}
	// The pure-IP kernel rule must still be present (sing-box routes it normally).
	if !gen_ruleTargets(gen_routeRules(res), "k-awg") {
		t.Error("non-hybrid must keep the IP→k-awg rule in sing-box")
	}
}

// TestHybridPredicates covers the partition predicates independently of full Generate.
func TestHybridPredicates(t *testing.T) {
	p := hybridProfile()
	p.Groups = []model.Group{
		{ID: "g-kernel", Name: "GK", Type: model.GroupURLTest, Members: []string{"k-ext", "p-vless"}},
		{ID: "g-proxy", Name: "GP", Type: model.GroupSelector, Members: []string{"p-vless", "p-wg"}},
	}

	for _, tc := range []struct {
		tag  string
		want bool
	}{
		{model.OutboundDirect, false}, {model.OutboundBlock, false}, {"", false},
		{"k-awg", true}, {"k-ext", true}, {"p-vless", false}, {"p-wg", false},
		{"g-kernel", true}, {"g-proxy", false}, {"nonexistent", false},
	} {
		if got := kernelEgress(p, tc.tag); got != tc.want {
			t.Errorf("kernelEgress(%q) = %v, want %v", tc.tag, got, tc.want)
		}
	}

	for _, tc := range []struct {
		name string
		r    model.Rule
		want bool
	}{
		{"ip-only", model.Rule{IPCIDR: []string{"1.2.3.4/32"}}, true},
		{"ip+domain", model.Rule{IPCIDR: []string{"1.2.3.4/32"}, Domain: []string{"a.com"}}, false},
		{"ip+suffix", model.Rule{IPCIDR: []string{"1.2.3.4/32"}, DomainSuffix: []string{"a.com"}}, false},
		{"ip+geosite", model.Rule{IPCIDR: []string{"1.2.3.4/32"}, GeoSite: []string{"google"}}, false},
		{"ip+geoip", model.Rule{IPCIDR: []string{"1.2.3.4/32"}, GeoIP: []string{"cn"}}, false},
		{"ip+port", model.Rule{IPCIDR: []string{"1.2.3.4/32"}, Port: []int{443}}, false},
		{"domain-only", model.Rule{Domain: []string{"a.com"}}, false},
		{"port-only", model.Rule{Port: []int{443}}, false},
	} {
		if got := ipOnlyKernelRule(&tc.r); got != tc.want {
			t.Errorf("ipOnlyKernelRule(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// gen_assertNoDangling fails if any outbound tag referenced by a route rule, by
// route.final, or by a group's member list is missing from the emitted outbounds/
// endpoints. A dangling reference fails `sing-box check` and takes ALL routing down on
// apply (one shared singbox.json), so this is the central brick-prevention invariant.
func gen_assertNoDangling(t *testing.T, res *Result) {
	t.Helper()
	tags := gen_outboundTags(res)
	tags[model.OutboundDirect] = true // builtin, always present
	if route, _ := res.Config["route"].(map[string]any); route != nil {
		if f, _ := route["final"].(string); f != "" && !tags[f] {
			t.Errorf("route.final %q has no matching outbound (dangling)", f)
		}
	}
	for _, r := range gen_routeRules(res) {
		ob, _ := r["outbound"].(string)
		if ob == "" || ob == model.OutboundDirect {
			continue
		}
		if !tags[ob] {
			t.Errorf("route rule references outbound %q with no matching outbound (dangling): %v", ob, r)
		}
	}
	if obs, ok := res.Config["outbounds"].([]map[string]any); ok {
		for _, ob := range obs {
			mem, _ := ob["outbounds"].([]string)
			for _, m := range mem {
				if !tags[m] {
					t.Errorf("group %v member %q has no matching outbound (dangling)", ob["tag"], m)
				}
			}
		}
	}
}

// TestHybridNoDanglingRefs is the brick-prevention guard: a mixed kernel+proxy group
// reached only by a pure-IP rule (pbr handles it) drops cleanly — group + rule both
// vanish with no dangling reference.
func TestHybridNoDanglingRefs(t *testing.T) {
	p := hybridProfile()
	p.Groups = []model.Group{{ID: "g-mixed", Name: "GM", Type: model.GroupURLTest, Members: []string{"k-ext", "p-vless"}}}
	p.Rules = append(p.Rules, model.Rule{ID: "r-grp", IPCIDR: []string{"8.8.8.0/24"}, Outbound: "g-mixed"})

	ex4, ex6 := hybridExclude(t, p)
	res := gen_must(t, p, Options{MixedPort: 7890, TunEnabled: true, Hybrid: true, KernelExcludeV4: ex4, KernelExcludeV6: ex6})

	gen_assertNoDangling(t, res)
	if gen_outboundTags(res)["g-mixed"] {
		t.Error("a kernel group reached only by a pure-IP rule must be dropped from sing-box in hybrid")
	}
}

// TestHybridKernelGroupReferenced is the regression for the group-reference brick: a
// kernel-bearing group reached by a rule/list/default that pbr CANNOT kernel-route
// (domain matcher, a domain/remote list, or the catch-all default) must be KEPT in
// sing-box together with its members — dropping it would dangle the surviving reference.
func TestHybridKernelGroupReferenced(t *testing.T) {
	mk := func(build func(*model.Profile)) *model.Profile {
		p := hybridProfile()
		p.Groups = []model.Group{{ID: "g-k", Name: "GK", Type: model.GroupURLTest, Members: []string{"k-awg", "p-vless"}}}
		build(p)
		return p
	}
	for _, tc := range []struct {
		name  string
		build func(*model.Profile)
	}{
		{"domain-rule", func(p *model.Profile) {
			p.Rules = append(p.Rules, model.Rule{ID: "rg", DomainSuffix: []string{"grp.example.com"}, Outbound: "g-k"})
		}},
		{"default-rule", func(p *model.Profile) {
			for i := range p.Rules {
				if p.Rules[i].Default {
					p.Rules[i].Outbound = "g-k" // catch-all → kernel group becomes route.final
				}
			}
		}},
		{"domain-list", func(p *model.Profile) {
			p.RoutingLists = append(p.RoutingLists, model.RoutingList{ID: "rlg", Name: "LG", Manual: []string{"listgrp.example.com"}, Outbound: "g-k", Enabled: true})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := mk(tc.build)
			ex4, ex6 := hybridExclude(t, p)
			res := gen_must(t, p, Options{MixedPort: 7890, TunEnabled: true, Hybrid: true, KernelExcludeV4: ex4, KernelExcludeV6: ex6})
			gen_assertNoDangling(t, res)
			tags := gen_outboundTags(res)
			if !tags["g-k"] {
				t.Errorf("kernel group g-k must be KEPT when a non-IP reference points at it: %v", tags)
			}
			if !tags["k-awg"] {
				t.Errorf("a kept kernel group's member k-awg must be emitted (else the group member dangles): %v", tags)
			}
		})
	}
}

// TestHybridNestedGroup is the regression for nested groups: an inner kernel group
// reached only through a (non-kernel-classified) outer group must be KEPT, because
// reachability follows membership transitively — so the outer group's member reference
// never dangles.
func TestHybridNestedGroup(t *testing.T) {
	p := hybridProfile()
	p.Groups = []model.Group{
		{ID: "g-inner", Name: "GI", Type: model.GroupSelector, Members: []string{"k-awg"}},
		{ID: "g-outer", Name: "GO", Type: model.GroupSelector, Members: []string{"g-inner", "p-vless"}},
	}
	p.Rules = append(p.Rules, model.Rule{ID: "rgo", DomainSuffix: []string{"outer.example.com"}, Outbound: "g-outer"})
	ex4, ex6 := hybridExclude(t, p)
	res := gen_must(t, p, Options{MixedPort: 7890, TunEnabled: true, Hybrid: true, KernelExcludeV4: ex4, KernelExcludeV6: ex6})
	gen_assertNoDangling(t, res)
	tags := gen_outboundTags(res)
	for _, want := range []string{"g-outer", "g-inner", "k-awg"} {
		if !tags[want] {
			t.Errorf("nested-group reachability: %q must be kept, tags=%v", want, tags)
		}
	}
}

// TestHybridSingBoxCheck validates the hybrid output with the REAL core when
// WR_SINGBOX is set (CI). It's the only reliable guard against the dangling-reference
// brick mode; the profile includes a mixed kernel+proxy group to confirm it drops
// cleanly rather than leaving a dangling member tag.
func TestHybridSingBoxCheck(t *testing.T) {
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — set it to a sing-box binary for a real hybrid `check`")
	}
	p := hybridProfile()
	p.Groups = []model.Group{{ID: "g-mixed", Name: "GM", Type: model.GroupURLTest, Members: []string{"k-ext", "p-vless"}}}
	p.Rules = append(p.Rules, model.Rule{ID: "r-grp", IPCIDR: []string{"8.8.8.0/24"}, Outbound: "g-mixed"})
	ex4, ex6 := hybridExclude(t, p)
	res := gen_must(t, p, Options{MixedPort: 7890, TunEnabled: true, Hybrid: true,
		KernelExcludeV4: ex4, KernelExcludeV6: ex6, CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	data, err := json.MarshalIndent(res.Config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "hybrid.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", f).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check rejected the hybrid config: %v\n%s", err, strings.TrimSpace(string(out)))
	}
}

func gen_sliceHas(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func gen_ruleTargets(rules []map[string]any, tag string) bool {
	for _, r := range rules {
		if ob, _ := r["outbound"].(string); ob == tag {
			return true
		}
		// logical (and) rules nest the matcher; check sub-rules' outbound is on the parent.
	}
	return false
}

func gen_hasBypassRule(rules []map[string]any) bool {
	for _, r := range rules {
		if ob, _ := r["outbound"].(string); ob == model.OutboundDirect {
			if _, hasIP := r["ip_cidr"]; hasIP {
				if act, _ := r["action"].(string); act == "route" {
					return true
				}
			}
		}
	}
	return false
}
