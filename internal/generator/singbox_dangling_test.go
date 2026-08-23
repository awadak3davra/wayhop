package generator

import (
	"encoding/json"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// gen_ruleSetTags collects every rule_set tag actually emitted into route.rule_set — the universe a
// DNS rule's rule_set reference must resolve against.
func gen_ruleSetTags(res *Result) map[string]bool {
	tags := map[string]bool{}
	route, _ := res.Config["route"].(map[string]any)
	sets, _ := route["rule_set"].([]map[string]any)
	for _, s := range sets {
		if t, _ := s["tag"].(string); t != "" {
			tags[t] = true
		}
	}
	return tags
}

// assertNoDanglingDNS enforces the invariant both dangling-reference bugs violate: every rule_set a
// DNS rule references is present in route.rule_set, and every DNS server detour is an emitted
// outbound/endpoint (or a builtin). A dangling reference makes `sing-box check` FATAL and rejects the
// whole shared config on apply.
func assertNoDanglingDNS(t *testing.T, res *Result) {
	t.Helper()
	d, _ := res.Config["dns"].(map[string]any)
	if d == nil {
		return
	}
	sets := gen_ruleSetTags(res)
	outs := gen_outboundTags(res)
	outs[model.OutboundDirect] = true
	rules, _ := d["rules"].([]map[string]any)
	for _, r := range rules {
		rs, _ := r["rule_set"].([]string)
		for _, tag := range rs {
			if !sets[tag] {
				t.Errorf("DNS rule references rule_set %q not emitted in route.rule_set %v", tag, sets)
			}
		}
	}
	servers, _ := d["servers"].([]map[string]any)
	for _, s := range servers {
		if dv, _ := s["detour"].(string); dv != "" && !outs[dv] {
			t.Errorf("DNS server %v detour %q is not an emitted outbound %v", s["tag"], dv, outs)
		}
	}
}

// TestDNSListTags_OnlyScopeMacOnly_NoDangling: a ScopeMode="only" routing list scoped to a MAC-only
// device group has no sing-box source expression, so routingFrom emits NO rule_set for it. A DNS rule
// referencing that list must not emit the tag either (dnsListTags must mirror the scope skip), or the
// rule_set dangles and sing-box check FATALs, taking all routing down on apply.
func TestDNSListTags_OnlyScopeMacOnly_NoDangling(t *testing.T) {
	p := &model.Profile{
		Endpoints:    []model.Endpoint{{ID: "nl", Engine: model.EngineExternal, Params: map[string]any{"interface": "awg0"}, Enabled: true}},
		DeviceGroups: []model.DeviceGroup{{ID: "g", Name: "phones", Members: []model.DeviceMember{{MAC: "aa:bb:cc:dd:ee:ff"}}}},
		RoutingLists: []model.RoutingList{
			{ID: "maconly", Name: "L", Manual: []string{"youtube.com"}, Outbound: model.OutboundDirect, Enabled: true, ScopeMode: "only", ScopeGroups: []string{"g"}},
		},
		DNS: &model.DNSSettings{
			Enabled: true,
			Servers: []model.DNSServer{{Tag: "local", Type: "local", Enabled: true}},
			Rules:   []model.DNSRule{{ID: "r", RuleSets: []string{"maconly"}, Server: "local"}},
		},
	}
	res, err := Generate(p, Options{MixedPort: 1080})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	assertNoDanglingDNS(t, res)
	// The MAC-only list's tag must appear NOWHERE in the DNS block (routingFrom emitted no set for it).
	d, _ := res.Config["dns"].(map[string]any)
	if blob, _ := json.Marshal(d); strings.Contains(string(blob), "maconly") {
		t.Errorf("MAC-only \"only\" list leaked a dangling rule_set into the DNS block:\n%s", blob)
	}
}

// TestHybridReachable_DNSDetourKeepsKernelOutbound: in hybrid mode a kernel endpoint referenced ONLY
// by pure-IP rules/lists (pbr routes it) is normally omitted from sing-box — but if a DNS server's
// detour targets it, omitting it dangles the emitted detour. hybridReachable must seed roots from DNS
// detours so the endpoint is KEPT and the detour resolves.
func TestHybridReachable_DNSDetourKeepsKernelOutbound(t *testing.T) {
	p := hybridProfile()
	p.DNS = &model.DNSSettings{
		Enabled: true,
		Servers: []model.DNSServer{
			{Tag: "via-awg", Type: "https", Server: "1.1.1.1", Detour: "k-awg", Enabled: true},
			{Tag: "local", Type: "local", Enabled: true},
		},
		Final: "via-awg",
	}
	ex4, ex6 := hybridExclude(t, p)
	res := gen_must(t, p, Options{MixedPort: 7890, TunEnabled: true, Hybrid: true, KernelExcludeV4: ex4, KernelExcludeV6: ex6})

	if !gen_outboundTags(res)["k-awg"] {
		t.Errorf("k-awg must be KEPT in hybrid when a DNS detour targets it (else the detour dangles): %v", gen_outboundTags(res))
	}
	assertNoDanglingDNS(t, res)
}
