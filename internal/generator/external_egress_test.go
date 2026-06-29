package generator

import (
	"testing"

	"velinx/internal/model"
)

// NATIVE P2 STEP 5 — generator confirmation tests (no production code change).
//
// These lock the "sing-box is NOT in the path" contract for an EngineExternal egress
// used as a PURE-IP routing-list target in hybrid mode (docs/NATIVE_P2_DESIGN.md (c)).
// EngineExternal already represents "egress = an existing OS-owned native interface" and
// is wired through validate.go, pbr.kernelIface, and generator/singbox.go. In hybrid
// mode the generator must:
//   (a) OMIT the sing-box `direct`+bind_interface outbound for the external endpoint when
//       it is kernel-routed (only pure-IP lists reference it → pbr handles those verbatim),
//   (b) route_exclude_address the routed CIDRs from the TUN so LAN traffic falls through
//       to the kernel where pbr's fwmark rules steer it out the external iface,
//   (c) bypass the endpoint's own endpoint_ip to direct (anti-loop: routing the iface's
//       peer IP through the iface recurses), and
//   (d) emit NO Plugin record (netifd/NDM owns the iface; the daemon must not ip-link it).
//
// The complement (an EngineExternal KEPT because a domain rule references it) is covered
// by hybrid_test.go's `k-ext`. This file pins the pure-IP-egress / fully-omitted case so a
// future change can't silently put sing-box back in the native-egress path.

// extEgressProfile: a single EngineExternal endpoint bound to interface awg0 with a
// declared endpoint_ip, used ONLY as the egress of a pure-IP routing list (and a pure-IP
// rule). Synthetic data throughout. In hybrid mode this is the "fully kernel-routed,
// sing-box not in path" shape.
func extEgressProfile() *model.Profile {
	return &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "ext-awg0", Name: "native-awg0", Engine: model.EngineExternal, Enabled: true,
				Params: map[string]any{"interface": "awg0", "endpoint_ip": "203.0.113.7"}},
		},
		Rules: []model.Rule{
			// Pure-IP rule → external kernel egress: pbr routes it verbatim, so the
			// generator drops it (and never references the external outbound from it).
			{ID: "r-ip-ext", IPCIDR: []string{"198.51.100.0/24"}, Outbound: "ext-awg0"},
			{ID: "def", Default: true, Outbound: model.OutboundDirect},
		},
		RoutingLists: []model.RoutingList{
			// Pure-IP manual list (no remote Source, no domains) → external kernel egress:
			// dropped from sing-box in hybrid; pbr kernel-routes the same CIDRs.
			{ID: "rl-ip-ext", Name: "L", Manual: []string{"192.0.2.128/25"}, Outbound: "ext-awg0", Enabled: true},
		},
	}
}

// TestExternalEgressHybridFullyKernelRouted locks all four contract points for an
// EngineExternal endpoint used purely as an IP-list egress in hybrid mode.
func TestExternalEgressHybridFullyKernelRouted(t *testing.T) {
	p := extEgressProfile()
	ex4, ex6 := hybridExclude(t, p)
	res := gen_must(t, p, Options{MixedPort: 7890, TunEnabled: true, Hybrid: true,
		KernelExcludeV4: ex4, KernelExcludeV6: ex6})

	// (a) NO sing-box outbound for the external endpoint — it is kernel-routed, so the
	// `direct`+bind_interface outbound would be dead weight; the generator drops it.
	tags := gen_outboundTags(res)
	if tags["ext-awg0"] {
		t.Errorf("hybrid: the external endpoint's sing-box outbound must be OMITTED when it is "+
			"kernel-routed by pbr (sing-box must not be in the native-egress path): tags=%v", tags)
	}
	// Defensive: no outbound anywhere binds to the external iface (catches a future
	// regression that re-emits the bind_interface outbound under a different tag).
	for _, ob := range gen_allOutbounds(res) {
		if bi, _ := ob["bind_interface"].(string); bi == "awg0" {
			t.Errorf("hybrid: no sing-box outbound may bind the external iface awg0 (kernel owns it): %v", ob)
		}
	}

	// (b) the routed CIDRs are route_exclude'd from the TUN so they fall through to the
	// kernel where pbr's fwmark rules steer them out awg0.
	tun := gen_tunInbound(res)
	if tun == nil {
		t.Fatal("hybrid keeps the TUN inbound, but none was emitted")
	}
	gotEx, _ := tun["route_exclude_address"].([]string)
	for _, want := range []string{"198.51.100.0/24", "192.0.2.128/25"} {
		if !gen_sliceHas(gotEx, want) {
			t.Errorf("route_exclude_address must contain the external-egress CIDR %q (so it falls "+
				"through to the kernel pbr fwmark path): got %v", want, gotEx)
		}
	}

	// (c) the endpoint_ip is bypassed to direct as a leading rule (anti-loop — routing the
	// external iface's own peer IP through that iface recurses). It must also be in the
	// pbr-derived bypass set fed into route_exclude.
	rules := gen_routeRules(res)
	if !extEgressBypassesIP(rules, "203.0.113.7/32") {
		t.Errorf("the external endpoint_ip 203.0.113.7 must be bypassed to direct (anti-loop): rules=%v", rules)
	}
	// Anti-loop is enforced by two independent mechanisms verified above: the sing-box direct
	// route rule (for traffic that enters the TUN) and endpointBypass → the kernel pbr bypass
	// (for kernel-steered traffic). The endpoint_ip need NOT also appear in route_exclude_address
	// (that set carries the routed CIDRs + plan.Bypass zones, a separate concern from the
	// per-endpoint server bypass) — so we do not assert it there.
	bp := endpointBypass(p)
	if !gen_sliceHas(bp, "203.0.113.7/32") {
		t.Errorf("endpointBypass must include the external endpoint_ip /32: %v", bp)
	}

	// (d) NO Plugin record for the external endpoint — netifd/NDM owns the iface, so the
	// daemon must never bring it up/down (unlike AmneziaWG, which keeps its Plugin).
	if len(res.Plugins) != 0 {
		t.Errorf("an external endpoint must emit NO Plugin record (OS owns the iface): %+v", res.Plugins)
	}

	// The pure-IP rule/list that pbr handles must NOT survive into sing-box (no dangling
	// reference to the now-omitted external outbound, and no double-routing).
	for _, r := range rules {
		if ob, _ := r["outbound"].(string); ob == "ext-awg0" {
			t.Errorf("a route rule still references the omitted external outbound (dangling): %v", r)
		}
		if ips, _ := r["ip_cidr"].([]string); gen_sliceHas(ips, "198.51.100.0/24") {
			t.Errorf("the pure-IP rule to the external egress must be dropped (pbr handles it): %v", r)
		}
		if ips, _ := r["ip_cidr"].([]string); gen_sliceHas(ips, "192.0.2.128/25") {
			t.Errorf("the pure-IP list to the external egress must be dropped (pbr handles it): %v", r)
		}
	}
	// Brick-prevention: nothing the config emits may reference a missing outbound.
	gen_assertNoDangling(t, res)
}

// TestExternalEgressNonHybridKeepsOutbound proves the omission is hybrid-gated: with
// Hybrid:false the external endpoint keeps its `direct`+bind_interface outbound (sing-box
// routes through it normally), and the pure-IP list rule survives. Guards the additive
// nature of the hybrid branch — confirming Step 5 doesn't claim a contract that also
// holds (and would mask a regression) in the default path.
func TestExternalEgressNonHybridKeepsOutbound(t *testing.T) {
	p := extEgressProfile()
	res := gen_must(t, p, Options{MixedPort: 7890, TunEnabled: true}) // Hybrid defaults false

	ob := gen_outboundsByTagLocal(res)["ext-awg0"]
	if ob == nil || ob["type"] != "direct" || ob["bind_interface"] != "awg0" {
		t.Fatalf("non-hybrid: external endpoint must keep its direct+bind_interface(awg0) outbound: %v", ob)
	}
	if tun := gen_tunInbound(res); tun != nil {
		if _, has := tun["route_exclude_address"]; has {
			t.Error("non-hybrid TUN must NOT carry route_exclude_address")
		}
	}
	// Still no Plugin even outside hybrid — the OS owns the iface regardless of mode.
	if len(res.Plugins) != 0 {
		t.Errorf("external endpoint must emit no Plugin in any mode: %+v", res.Plugins)
	}
}

// extEgressBypassesIP reports whether a leading direct-route rule bypasses the given
// /32|/128 CIDR (the anti-loop endpoint bypass the generator prepends).
func extEgressBypassesIP(rules []map[string]any, cidr string) bool {
	for _, r := range rules {
		if ob, _ := r["outbound"].(string); ob != model.OutboundDirect {
			continue
		}
		if act, _ := r["action"].(string); act != "route" {
			continue
		}
		if ips, _ := r["ip_cidr"].([]string); gen_sliceHas(ips, cidr) {
			return true
		}
	}
	return false
}

// gen_allOutbounds returns every emitted outbound map (not endpoints), for binding checks.
func gen_allOutbounds(res *Result) []map[string]any {
	obs, _ := res.Config["outbounds"].([]map[string]any)
	return obs
}

// gen_outboundsByTagLocal indexes emitted outbounds by tag (a local, non-fatal variant of
// generator_outboundsByTag so this file has no cross-test coupling on its signature).
func gen_outboundsByTagLocal(res *Result) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, ob := range gen_allOutbounds(res) {
		if tag, _ := ob["tag"].(string); tag != "" {
			out[tag] = ob
		}
	}
	return out
}
