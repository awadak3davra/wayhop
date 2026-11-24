package server

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

func keeneticFastReviewProfile() *model.Profile {
	prof := fastReviewProfile()
	prof.RoutingLists = append(prof.RoutingLists, model.RoutingList{ID: "px", Name: "Proxy", Manual: []string{"proxied.example"}, Outbound: "vl", Enabled: true})
	return prof
}

func TestKeeneticFastFindings(t *testing.T) {
	prof := keeneticFastReviewProfile()
	plan, _, err := pbr.Compile(prof, pbr.Options{CollectDomainZones: true, ListEgresses: true})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{RoutingMode: "fast"}
	got := findingIDs(keeneticFastFindings(cfg, prof, plan, keeneticFastFacts{lanIfaces: []string{"br0"}}))
	names := got["fast_path.keenetic_names"]
	if names.Blocks != platform.BlocksNothing || !strings.Contains(names.Detail, "DNS enforcement is on") || !strings.Contains(names.Detail, "br0") ||
		!strings.Contains(names.Detail, "wd_") {
		t.Errorf("names finding: %+v", names)
	}
	if f, ok := got["fast_path.domain_widened.exact"]; !ok || f.Blocks != platform.BlocksNothing {
		t.Errorf("exact-name note: %+v", f)
	}
	nc := got["fast_path.keenetic_not_carried"]
	if !strings.Contains(nc.Detail, "remote lists (SRS)") || !strings.Contains(nc.Detail, "sent to a proxy (Proxy)") || strings.Contains(nc.Detail, "AI") {
		t.Errorf("not-carried note: %+v", nc)
	}
	if _, ok := got["fast_path.keenetic_resolver"]; ok {
		t.Error("a usable resolver was reported")
	}

	// Not Entware dnsmasq on :53: enforcement is refused; with enforcement off it is a note.
	bad := keeneticFastFacts{resolver: "sing-box owns LAN DNS, not Entware dnsmasq"}
	if f := findingIDs(keeneticFastFindings(cfg, prof, plan, bad))["fast_path.keenetic_resolver"]; f.Blocks != platform.BlocksApply ||
		!strings.Contains(f.Detail, "sing-box") {
		t.Errorf("resolver block: %+v", f)
	}
	off := false
	cfg.FastDNSEnforce = &off
	got = findingIDs(keeneticFastFindings(cfg, prof, plan, bad))
	if f := got["fast_path.keenetic_resolver"]; f.Blocks != platform.BlocksNothing {
		t.Errorf("resolver note with enforcement off: %+v", f)
	}
	if !strings.Contains(got["fast_path.keenetic_names"].Detail, "enforcement is off") {
		t.Errorf("enforcement off not said: %+v", got["fast_path.keenetic_names"])
	}
}

// HUNT-K #3: a list sent to an access policy is not in Review's plan (it compiles without the captured
// policies), but its names still need the resolver: the gate applies, and it is not called a proxy list.
func TestKeeneticFastFindingsNDMPolicyNames(t *testing.T) {
	prof := &model.Profile{RoutingLists: []model.RoutingList{
		{ID: "pol", Name: "Policy", Manual: []string{"policy.example", "192.0.2.0/24"}, Outbound: model.NDMPolicyPrefix + "Policy0", Enabled: true},
	}}
	plan := &pbr.Plan{}
	if !profileHasDomainNames(prof) {
		t.Fatal("the profile's names were not seen")
	}
	ipOnly := &model.Profile{RoutingLists: []model.RoutingList{{ID: "ip", Manual: []string{"192.0.2.0/24", "2001:db8::1"}, Outbound: "x", Enabled: true}}}
	if profileHasDomainNames(ipOnly) {
		t.Fatal("addresses counted as names")
	}
	facts := keeneticFastFacts{resolver: "nothing listens on :53", profileNames: true}
	got := findingIDs(keeneticFastFindings(config.Config{RoutingMode: "fast"}, prof, plan, facts))
	if f := got["fast_path.keenetic_resolver"]; f.Blocks != platform.BlocksApply {
		t.Errorf("resolver gate skipped for policy names: %+v", got)
	}
	if _, ok := got["fast_path.keenetic_not_carried"]; ok {
		t.Errorf("an access-policy list was called not carried: %+v", got["fast_path.keenetic_not_carried"])
	}
}

// Diagnostics: the wd_ sets' members, enforcement, the last fresh reset and the warm-up.
func TestKeeneticFastCheck(t *testing.T) {
	s, _ := useKeeneticFastFakes(t)
	plan := &pbr.Plan{Mask: 0x00ff0000, Zones: []pbr.Zone{{Name: "list_a", Domains: []string{"a.example"}, Mark: 0x20000}}}
	oldRead := keeneticSetMembers
	t.Cleanup(func() { keeneticSetMembers = oldRead })
	keeneticSetMembers = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(_ context.Context, set string) ([]netip.Prefix, error) {
			if set == "wd_list_a_4" {
				return []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("192.0.2.2/32")}, nil
			}
			return nil, nil
		}
	}
	k := executionKernelArtifactV1{Plan: plan, Ipset: &executionKernelIpsetArtifactV1{DynamicDomainSets: true, FastDNSEnforce: true}}
	s.fastDNS.keenetic.freshLast, s.fastDNS.keenetic.warm = 3, "asked for 1 names"
	row := s.keeneticFastCheckOf(context.Background(), healthRow{ID: "fast_dns"}, &k)
	if row.Status != "pass" || !strings.Contains(row.Summary, "2 wd_ sets, 2 addresses") || !strings.Contains(row.Summary, "enforcement on") ||
		!strings.Contains(row.Summary, "reset 3") || !strings.Contains(row.Detail, "warm-up asked for 1 names") {
		t.Fatalf("row = %+v", row)
	}
	s.fastDNS.backedOut, s.fastDNS.err = true, "stalled"
	if row := s.keeneticFastCheckOf(context.Background(), healthRow{}, &k); row.Status != "fail" || row.Detail != "stalled" {
		t.Fatalf("backed-out row = %+v", row)
	}
	if row := s.keeneticFastCheckOf(context.Background(), healthRow{}, nil); row.Status != "na" {
		t.Fatalf("no plane row = %+v", row)
	}
}

// HUNT-K #11: the prerequisite proves the main configuration reads the policy file.
func TestKeeneticPolicyIncluded(t *testing.T) {
	for conf, ok := range map[string]bool{
		"conf-dir=/opt/etc/dnsmasq.d,*.conf":              true, // a KeeneticOS router
		"conf-dir=/opt/etc/dnsmasq.d/":                    true,
		"conf-dir=/opt/etc/dnsmasq.d,.bak":                true,
		"conf-file=/opt/etc/dnsmasq.d/wayhop-policy.conf": true,
		"conf-dir=/opt/etc/dnsmasq.d,*.cfg":               false,
		"conf-dir=/opt/etc/dnsmasq.d,.conf":               false,
		"#conf-dir=/opt/etc/dnsmasq.d":                    false,
		"conf-dir=/etc/dnsmasq.d":                         false,
		"":                                                false,
	} {
		if got := keeneticPolicyIncluded("no-resolv\n"+conf+"\n") == ""; got != ok {
			t.Errorf("%q: included=%v, want %v", conf, got, ok)
		}
	}
}
