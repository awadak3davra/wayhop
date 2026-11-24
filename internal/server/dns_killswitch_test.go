package server

import (
	"net/netip"
	"slices"
	"testing"

	"wayhop/internal/failover"
	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// Kill switch audit / DNS: a kill-switched list whose lookups would go out by the provider is
// refused, encrypted resolver or not, whether a DNS rule sends it there or it falls through to the
// default server (CIDR lists through a tunnel group, default dns_secure direct).
func killSwitchDNSReview(t *testing.T, mut func(*model.Profile)) []Finding {
	t.Helper()
	p := dnsPathProfile(t, "direct")
	p.RoutingLists[0].Outbound = "auto"
	p.Groups[0].KillSwitch = true
	if mut != nil {
		mut(&p)
	}
	s := opshandlers_server(t)
	if err := s.store.Replace(p); err != nil {
		t.Fatalf("seed: %v", err)
	}
	pf := s.preflight(platform.Capabilities{
		Platform: "openwrt", Accel: platform.Accel{Kind: "nft-flowtable"}, SingboxPresent: true,
	}, platform.OffloadState{})
	return foldFindings(evaluatePlanFindings(platform.CapabilitySet{}, pf), nil)
}

func TestDNSKillSwitchRefusesDirectLookups(t *testing.T) {
	cases := map[string]func(*model.Profile){
		"rule to an encrypted direct server": nil,
		"no rule, default server direct":     func(p *model.Profile) { p.DNS.Rules = nil },
		"plaintext direct":                   func(p *model.Profile) { p.DNS.Servers[0].Type = "udp" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			review := killSwitchDNSReview(t, mut)
			found := false
			for _, r := range review {
				if r.Code == "DNS_KILLSWITCH_LEAK" {
					found = true
					if r.Blocks != platform.BlocksApply || r.AckRequired {
						t.Fatalf("must be a hard refusal: %+v", r)
					}
				}
			}
			if !found {
				t.Fatalf("no refusal: %+v", review)
			}
		})
	}
}

// The fix the remedy names clears it: the list's lookups ride the same group.
func TestDNSKillSwitchRuleThroughGroupPasses(t *testing.T) {
	review := killSwitchDNSReview(t, func(p *model.Profile) { p.DNS.Servers[0].Detour = "auto" })
	for _, r := range review {
		if r.Code == "DNS_KILLSWITCH_LEAK" || r.Code == "DNS_EXIT_MISMATCH_ENCRYPTED" {
			t.Fatalf("coherent DNS refused: %+v", r)
		}
	}
	// Without the kill switch the encrypted direct lookup stays an acknowledgeable report.
	review = killSwitchDNSReview(t, func(p *model.Profile) { p.Groups[0].KillSwitch = false })
	for _, r := range review {
		if r.Code == "DNS_KILLSWITCH_LEAK" {
			t.Fatalf("refused without a kill switch: %+v", r)
		}
	}
}

// A DNS detour that is the list's own group but has `direct` among its members falls back to the
// provider when the tunnels are down (sing-box picks the member): refused under a kill switch, the
// rule and the default-server path alike.
func TestDNSKillSwitchRefusesDirectFallback(t *testing.T) {
	for name, mut := range map[string]func(*model.Profile){
		"rule through a group with direct": func(p *model.Profile) {
			p.DNS.Servers[0].Detour = "auto"
			p.Groups[0].Members = append(p.Groups[0].Members, model.OutboundDirect)
		},
		"default server through a group with direct": func(p *model.Profile) {
			p.DNS.Rules = nil
			p.DNS.Servers[0].Detour = "auto"
			p.Groups[0].Members = append(p.Groups[0].Members, model.OutboundDirect)
		},
	} {
		t.Run(name, func(t *testing.T) {
			found := false
			for _, r := range killSwitchDNSReview(t, mut) {
				found = found || (r.Code == "DNS_KILLSWITCH_LEAK" && r.Blocks == platform.BlocksApply)
			}
			if !found {
				t.Fatal("a detour falling back to direct passed under the kill switch")
			}
		})
	}
}

// Kill switch audit / DNS: the router's own lookups on a list's behalf. A kill-switched list is never
// measured against host-name targets, which the router would resolve by its own (possibly direct)
// resolver: Instagram's built-in targets are names, so it falls back to an address-free default.
func TestKillSwitchListProbesNoListNames(t *testing.T) {
	profile := killSwitchFastest()
	profile.RoutingLists[0].Name = "Instagram"
	profile.RoutingLists[0].ID = "tg" // keep the plan's egress
	s, plan := fastestServer(t, profile, &fakeTables{})
	units := fastestUnitsFrom(plan, &profile, kernelIfaceByEndpoint(&profile, s.appliedKernelDevices()),
		autoFastestTargets, nil, 1)
	for _, tg := range units[0].Targets {
		if tg == "instagram.com:443" || tg == "facebook.com:443" {
			t.Fatalf("a list name is resolved by the router for a kill-switched list: %v", units[0].Targets)
		}
	}
}

// When a kill-switched list's targets answer through none of its tunnels, the router's
// own (unbound, main-table, WAN) reference probe must not dial the list's destinations: it asks
// neutral reference targets that no kill-switched list holds. A list without a kill switch keeps its
// own targets as the reference.
func TestKillSwitchListReferenceNeverDialsTheList(t *testing.T) {
	profile := killSwitchFastest()
	s, plan := fastestServer(t, profile, &fakeTables{})
	units := fastestUnitsFrom(plan, &profile, kernelIfaceByEndpoint(&profile, s.appliedKernelDevices()),
		autoFastestTargets, nil, 1)
	if len(units) != 1 {
		t.Fatalf("units %+v", units)
	}
	u := units[0]
	// Every candidate measured, nobody answered: the cycle asks for a reference.
	probes := map[failover.ProbeKey]failover.ProbeResult{}
	for _, c := range u.Candidates {
		for _, tg := range u.Targets {
			probes[failover.ProbeKey{Iface: u.Iface[c], Target: tg}] = failover.ProbeResult{Ran: true}
		}
	}
	refs := referenceKeys([]failover.TableUnit{u}, map[string]bool{u.List.List: true}, probes)
	if len(refs) == 0 {
		t.Fatal("no reference asked")
	}
	var covered []netip.Prefix
	for _, z := range plan.Zones {
		for _, c := range z.V4 {
			if p, err := netip.ParsePrefix(c); err == nil {
				covered = append(covered, p)
			}
		}
	}
	for _, k := range refs {
		if k.Iface != failover.ReferenceIface {
			t.Fatalf("reference key on a link: %+v", k)
		}
		if slices.Contains(u.Targets, k.Target) {
			t.Fatalf("the kill-switched list's own target %s dialled by the router's own path", k.Target)
		}
		ap, err := netip.ParseAddrPort(k.Target)
		if err != nil {
			t.Fatalf("reference %q is not an address", k.Target)
		}
		for _, p := range covered {
			if p.Contains(ap.Addr()) {
				t.Fatalf("reference %s is inside a list (%s)", k.Target, p)
			}
		}
	}
	// The evidence is read from the same reference targets.
	for _, k := range refs {
		probes[k] = failover.ProbeResult{Ran: true, Successes: 1}
	}
	if !failover.ReferenceAnswered(u, probes) {
		t.Fatal("the neutral reference's answer is not read as evidence")
	}
	// Without a kill switch the list's own targets are the reference, as before.
	plain := fastestProfile()
	s2, plan2 := fastestServer(t, plain, &fakeTables{})
	units2 := fastestUnitsFrom(plan2, &plain, kernelIfaceByEndpoint(&plain, s2.appliedKernelDevices()), autoFastestTargets, nil, 1)
	if len(units2) == 1 && units2[0].List.RefTargets != nil {
		t.Fatalf("a list without a kill switch got neutral references: %v", units2[0].List.RefTargets)
	}
}
