package pbr

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// ndmPolicyMarks are the marks a live Keenetic reported for its two access policies.
var ndmPolicyMarks = map[string]uint32{"Policy0": 0x0ffffaaa, "Policy1": 0x0ffffaab}

// ndmPolicyProfile routes one list into the router's Policy1 and another into a WayHop tunnel, so the
// two kinds of zone are compiled and rendered side by side.
func ndmPolicyProfile() *model.Profile {
	return &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "awg", Name: "awg", Enabled: true, Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
			Server: "203.0.113.9", Params: map[string]any{"local_address": []string{"10.8.0.2/32", "fd00::2/128"}},
		}},
		RoutingLists: []model.RoutingList{
			{ID: "via-policy", Name: "via-policy", Enabled: true, Outbound: "ndm-policy:Policy1", Manual: []string{"198.51.100.0/24"}},
			{ID: "via-tunnel", Name: "via-tunnel", Enabled: true, Outbound: "awg", Manual: []string{"192.0.2.0/24"}},
		},
	}
}

func policyAndTunnelZones(t *testing.T, plan *Plan) (*Zone, *Zone) {
	t.Helper()
	var policyZone, tunnelZone *Zone
	for i := range plan.Zones {
		switch plan.Zones[i].Name {
		case "list_via_policy":
			policyZone = &plan.Zones[i]
		case "list_via_tunnel":
			tunnelZone = &plan.Zones[i]
		}
	}
	if policyZone == nil || tunnelZone == nil {
		t.Fatalf("zones = %+v", plan.Zones)
	}
	return policyZone, tunnelZone
}

// A policy list is marked with a WayHop slot after the last egress - set, saved and restored like any
// egress mark - and the slot is rewritten into the policy's whole mark after the save, for NDM's rule.
// NDM routes it: no table, no ip rule but the fail-closed backstop, and WayHop's own egresses keep
// their marks.
func TestCompileGivesAPolicyListASlotRewrittenAfterTheSave(t *testing.T) {
	plan, warns, err := Compile(ndmPolicyProfile(), Options{NDMPolicies: ndmPolicyMarks})
	if err != nil || len(warns) != 0 {
		t.Fatalf("compile: warns=%v err=%v", warns, err)
	}
	policyZone, tunnelZone := policyAndTunnelZones(t, plan)
	if policyZone.NDMPolicy != "Policy1" || policyZone.NDMMark != 0x0ffffaab ||
		policyZone.Mark != uint32(len(plan.Egresses)+1)*0x00010000 {
		t.Fatalf("policy zone = %+v (egresses %d)", *policyZone, len(plan.Egresses))
	}
	for _, e := range plan.Egresses {
		if e.Tag == "ndm-policy:Policy1" || e.Kind == EgressNDMPolicy || e.Mark == policyZone.Mark {
			t.Fatalf("the policy got a WayHop egress: %+v", e)
		}
	}
	alone := ndmPolicyProfile()
	alone.RoutingLists = alone.RoutingLists[1:]
	base, _, err := Compile(alone, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Egresses) != len(plan.Egresses) || base.Egresses[1] != plan.Egresses[1] ||
		tunnelZone.Mark != base.Zones[0].Mark {
		t.Fatalf("the policy list renumbered WayHop's egresses: %+v vs %+v", plan.Egresses, base.Egresses)
	}

	slot := hexMark(policyZone.Mark)
	script := plan.RenderIptablesScript(IpsetOptions{})
	restore := "-j CONNMARK --restore-mark --nfmask 0x00ff0000 --ctmask 0x00ff0000"
	zoneRule := "-m set --match-set wr_list_via_policy_4 dst -j MARK --set-xmark " + slot + "/0x00ff0000"
	save := "-j CONNMARK --save-mark --nfmask 0x00ff0000 --ctmask 0x00ff0000"
	translate := "-m mark --mark " + slot + "/0x00ff0000 -j MARK --set-xmark 0x0ffffaab/0xffffffff"
	at := map[string]int{}
	for _, want := range []string{restore, zoneRule, save, translate} {
		at[want] = strings.Index(script, want)
		if at[want] < 0 {
			t.Fatalf("script lacks %q:\n%s", want, script)
		}
	}
	if !(at[restore] < at[zoneRule] && at[zoneRule] < at[save] && at[save] < at[translate]) {
		t.Fatalf("want restore, zone, save, translate in that order:\n%s", script)
	}

	ip := plan.RenderIPScript(Options{})
	if !strings.Contains(ip, "ip rule add fwmark 0x0ffffaab blackhole priority 146") ||
		strings.Contains(ip, "table 0") || !strings.Contains(ip, "ip rule add fwmark 0x00020000/0x00ff0000 table 151") {
		t.Fatalf("ip script must route the tunnel and only backstop the policy:\n%s", ip)
	}
	teardown := plan.RenderTeardownScript(Options{}, IpsetOptions{})
	for _, want := range []string{"ipset destroy wr_list_via_policy_4", "ip rule del fwmark 0x0ffffaab blackhole priority 146"} {
		if !strings.Contains(teardown, want) {
			t.Fatalf("teardown lacks %q:\n%s", want, teardown)
		}
	}
	// The nft plane is OpenWrt's, where no access policy exists.
	if nft := plan.RenderNft(); strings.Contains(nft, "0x0ffffaab") {
		t.Fatalf("nft rendered the policy mark:\n%s", nft)
	}
}

// The review's finding, walked packet by packet through the rendered chain: a flow whose destination
// left the set (a dnsmasq member expiring) keeps its policy. The connmark holds the slot, the restore
// puts it back, and the rewrite after the save turns it into NDM's mark again. Saving the policy mark
// itself restored 0x00ff0000, which no rule matches - the WAN.
func TestPolicyFlowKeepsItsPolicyAfterLeavingTheSet(t *testing.T) {
	plan, _, err := Compile(ndmPolicyProfile(), Options{NDMPolicies: ndmPolicyMarks})
	if err != nil {
		t.Fatal(err)
	}
	policyZone, _ := policyAndTunnelZones(t, plan)
	const mask = 0x00ff0000
	chain := func(mark, ctmark uint32, inSet bool) (uint32, uint32) {
		mark = mark&^mask | ctmark&mask // restore
		if inSet {
			mark = mark&^mask | policyZone.Mark // zone rule
		}
		ctmark = ctmark&^mask | mark&mask // save
		for _, ps := range plan.NDMPolicySlots() {
			if mark&mask == ps.Slot {
				mark = ps.Mark // rewrite
			}
		}
		return mark, ctmark
	}
	// First packet, unmarked by NDM; then a later one after the member expired; then a device NDM put
	// in another policy (its MAC mark is already on the packet).
	m1, ct := chain(0, 0, true)
	m2, _ := chain(0, ct, false)
	m3, _ := chain(0x0ffffaaa, ct, false)
	for i, m := range []uint32{m1, m2, m3} {
		if m != 0x0ffffaab {
			t.Errorf("packet %d leaves with mark %#x, want the policy's 0x0ffffaab", i+1, m)
		}
	}
}

// A domain list is fed by dnsmasq at query time and matched by the same rule, so its slot is set in
// both families, and the rewrite follows the save in both.
func TestCompileMarksAPolicyDomainListInBothFamilies(t *testing.T) {
	p := &model.Profile{RoutingLists: []model.RoutingList{{
		ID: "dom", Name: "dom", Enabled: true, Outbound: "ndm-policy:Policy0", Manual: []string{"example.com"},
	}}}
	plan, warns, err := Compile(p, Options{CollectDomainZones: true, NDMPolicies: ndmPolicyMarks})
	if err != nil || len(warns) != 0 || len(plan.Zones) != 1 {
		t.Fatalf("compile: zones=%+v warns=%v err=%v", plan.Zones, warns, err)
	}
	slot := hexMark(plan.Zones[0].Mark)
	script := plan.RenderIptablesScript(IpsetOptions{})
	for _, fam := range []string{"4", "6"} {
		want := "-m set --match-set wr_list_dom_" + fam + " dst -j MARK --set-xmark " + slot + "/0x00ff0000"
		if !strings.Contains(script, want) {
			t.Fatalf("script lacks %q:\n%s", want, script)
		}
	}
	if n := strings.Count(script, "-m mark --mark "+slot+"/0x00ff0000 -j MARK --set-xmark 0x0ffffaaa/0xffffffff"); n != 2 {
		t.Fatalf("rewrite rules = %d, want one per family:\n%s", n, script)
	}
	if ip := plan.RenderIPScript(Options{}); !strings.Contains(ip, "ip -6 rule add fwmark 0x0ffffaaa blackhole priority 146") {
		t.Fatalf("no v6 backstop (some NDM policy marks have v4 rules only):\n%s", ip)
	}
	if conf := plan.DnsmasqIpsetConfig(IpsetOptions{}, 0); !strings.Contains(conf, "ipset=/example.com/wr_list_dom_4,wr_list_dom_6") {
		t.Fatalf("dnsmasq config = %q", conf)
	}
}

// A policy the router does not report is not guessed at: the list is left out of the plane, and the
// review hears why.
func TestCompileWarnsAboutAnUnknownPolicy(t *testing.T) {
	plan, warns, err := Compile(ndmPolicyProfile(), Options{NDMPolicies: map[string]uint32{"Policy0": 0x0ffffaaa}})
	if err != nil {
		t.Fatal(err)
	}
	for _, z := range plan.Zones {
		if z.NDMPolicy != "" {
			t.Fatalf("a zone was built for an unknown policy: %+v", z)
		}
	}
	if len(warns) != 1 || warns[0].Scope != "via-policy" || !strings.Contains(warns[0].Msg, "Policy1") {
		t.Fatalf("warnings = %+v", warns)
	}
}
