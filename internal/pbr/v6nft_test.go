package pbr

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestRenderIP_V6Datapath: when a plan has v6 zones (AWG carrying IPv6 CIDRs), RenderIP
// must emit a symmetric ip -6 datapath (ip -6 rule + route + ULA/link-local exclusions)
// so marked v6 packets route THROUGH the tunnel instead of falling through to the main
// v6 table (the censorship-leak gap the Keenetic RenderIPScript fix already closed).
// A v4-only plan must emit NO ip -6 commands at all.
func TestRenderIP_V6Datapath(t *testing.T) {
	// Plan with a v6 zone (AWG endpoint carrying IPv6 CIDRs).
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "nl-awg0", Engine: model.EngineAmneziaWG, Server: "203.0.113.5",
			Enabled: true, Params: map[string]any{},
		}},
		RoutingLists: []model.RoutingList{{
			ID: "v6-list", Manual: []string{"2001:db8::/32"}, Outbound: "nl-awg0", Enabled: true,
		}},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !plan.hasV6() {
		t.Fatal("hasV6() = false for a plan with a v6 zone — test setup wrong")
	}
	cmds := plan.RenderIP(Options{})
	join := strings.Join(cmds, "\n")

	// Must emit ip -6 fwmark rule and route for the AWG egress.
	mustHave := []string{
		"ip -6 rule add fwmark",
		"ip -6 route replace default dev",
		// v6 LAN/ULA exclusions must precede (lower prio number → higher precedence)
		"ip -6 rule add to fc00::/7 lookup main",
		"ip -6 rule add to fe80::/10 lookup main",
	}
	for _, w := range mustHave {
		if !strings.Contains(join, w) {
			t.Errorf("v6 datapath: missing %q\n---\n%s", w, join)
		}
	}

	// Teardown must symmetrically remove the ip -6 rules.
	down := strings.Join(plan.ipTeardown(Options{}), "\n")
	for _, w := range []string{
		"ip -6 rule del fwmark",
		"ip -6 route flush",
		"ip -6 rule del to fc00::/7",
		"ip -6 rule del to fe80::/10",
	} {
		if !strings.Contains(down, w) {
			t.Errorf("v6 teardown: missing %q\n---\n%s", w, down)
		}
	}
}

// TestRenderIP_V4OnlyPlanNoIPv6: a plan whose zones are all v4 must emit zero ip -6
// commands so a v4-only router's ip6tables/ip6 state is never touched.
func TestRenderIP_V4OnlyPlanNoIPv6(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "ru-awg0", Engine: model.EngineAmneziaWG, Server: "203.0.113.1",
			Enabled: true, Params: map[string]any{},
		}},
		RoutingLists: []model.RoutingList{{
			ID: "v4-only", Manual: []string{"198.51.100.0/24"}, Outbound: "ru-awg0", Enabled: true,
		}},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if plan.hasV6() {
		t.Fatal("hasV6() = true for a v4-only plan — test setup wrong")
	}
	join := strings.Join(plan.RenderIP(Options{}), "\n")
	if strings.Contains(join, "ip -6") {
		t.Errorf("v4-only plan emitted ip -6 commands:\n%s", join)
	}
	down := strings.Join(plan.ipTeardown(Options{}), "\n")
	if strings.Contains(down, "ip -6") {
		t.Errorf("v4-only teardown emitted ip -6 commands:\n%s", down)
	}
}

// TestRenderIP_ExternalV4OnlyPosture: an EngineExternal endpoint's zones are filtered to
// v4-only by Compile (the fail-closed posture). Even though the routing list carries
// a v6 CIDR, the plan must have NO v6 zones and emit no ip -6 commands.
func TestRenderIP_ExternalV4OnlyPosture(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "ext-awg0", Engine: model.EngineExternal, Server: "203.0.113.9",
			Enabled: true, Params: map[string]any{"interface": "awg0"},
		}},
		RoutingLists: []model.RoutingList{{
			// Mix of v4 and v6: Compile must strip v6 for EngineExternal.
			ID: "mixed", Manual: []string{"198.51.100.0/24", "2001:db8::/32"}, Outbound: "ext-awg0", Enabled: true,
		}},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if plan.hasV6() {
		t.Errorf("EngineExternal plan must be v4-only (v4-only posture): hasV6() = true")
	}
	join := strings.Join(plan.RenderIP(Options{}), "\n")
	if strings.Contains(join, "ip -6") {
		t.Errorf("EngineExternal plan emitted ip -6 commands (must be v4-only):\n%s", join)
	}
}
