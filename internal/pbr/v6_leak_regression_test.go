package pbr

import (
	"strings"
	"testing"

	"velinx/internal/model"
)

// TestRenderIP_V6SourceScopedDatapath is the regression for the hasV6()/hasV6Zone() asymmetry
// (the OpenWrt nft plane leaked v6 where the Keenetic ipset plane did not). The wr_mark chain
// sets the tunnel fwmark on v6 packets for (a) a family-agnostic source-only zone — its match is
// `iifname/ether/th sport` with NO family qualifier — and (b) a v6-source zone (`ip6 saddr`). If
// RenderIP then emits no `ip -6 rule fwmark`, that marked v6 packet falls through to the main v6
// table and egresses WAN unencrypted. Both sub-cases were RED before hasV6() reused hasV6Zone().
func TestRenderIP_V6SourceScopedDatapath(t *testing.T) {
	// Compile a single plain v4 dest zone, then mutate it into the source shape under test —
	// mirrors TestRenderNftSourceScoped, exercising the renderer + hasV6() deterministically.
	mk := func(t *testing.T) *Plan {
		t.Helper()
		p := &model.Profile{
			Endpoints: []model.Endpoint{{ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20", Enabled: true, Params: map[string]any{"interface": "awg1"}}},
			Rules:     []model.Rule{{ID: "kept", IPCIDR: []string{"1.2.3.0/24"}, Outbound: "ru-awg1"}},
		}
		plan, _, err := Compile(p, Options{})
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		if len(plan.Zones) != 1 {
			t.Fatalf("want 1 zone, got %d", len(plan.Zones))
		}
		return plan
	}

	t.Run("family-agnostic source-only (iface)", func(t *testing.T) {
		plan := mk(t)
		z := &plan.Zones[0]
		z.V4, z.V6, z.SrcV4, z.SrcV6 = nil, nil, nil, nil // source-only: no dest
		z.SrcIface = []string{"br-guest"}                 // iface-only → family-agnostic match
		z.SrcScoped = true

		// Sanity: the wr_mark line for this zone really is family-agnostic (marks v6 too).
		nft := plan.RenderNft()
		if !strings.Contains(nft, `iifname { "br-guest" } meta mark set`) {
			t.Fatalf("setup: expected a family-agnostic source-only mark line:\n%s", nft)
		}
		if !plan.hasV6() {
			t.Fatal("hasV6()=false: wr_mark marks v6 (no family qualifier) but RenderIP emits no ip -6 rule → v6 leaks to WAN")
		}
		join := strings.Join(plan.RenderIP(Options{}), "\n")
		if !strings.Contains(join, "ip -6 rule add fwmark") {
			t.Errorf("missing ip -6 fwmark rule for a v6-marking source-only zone:\n%s", join)
		}
		if down := strings.Join(plan.ipTeardown(Options{}), "\n"); !strings.Contains(down, "ip -6 rule del fwmark") {
			t.Errorf("teardown must symmetrically remove the ip -6 fwmark rule:\n%s", down)
		}
	})

	t.Run("v6 source CIDR", func(t *testing.T) {
		plan := mk(t)
		z := &plan.Zones[0]
		z.V4, z.V6, z.SrcV4 = nil, nil, nil
		z.SrcV6 = []string{"2001:db8::1/128"}
		z.SrcScoped = true

		nft := plan.RenderNft()
		if !strings.Contains(nft, "ip6 saddr @rule_kept_s6 meta mark set") {
			t.Fatalf("setup: expected a v6-source mark line:\n%s", nft)
		}
		if !plan.hasV6() {
			t.Fatal("hasV6()=false for a v6-source zone — wr_mark emits an `ip6 saddr` mark but RenderIP emits no ip -6 rule → leak")
		}
		if join := strings.Join(plan.RenderIP(Options{}), "\n"); !strings.Contains(join, "ip -6 rule add fwmark") {
			t.Errorf("missing ip -6 fwmark rule for a v6-source zone:\n%s", join)
		}
	})
}

// TestRenderIP_V6BlackholeIsReplace pins BUG-2: the v6 blackhole egress route must use `ip -6
// route replace` (idempotent) like every sibling line, not `add` (which errors
// "RTNETLINK answers: File exists" on a re-assert that skips the preceding flush).
func TestRenderIP_V6BlackholeIsReplace(t *testing.T) {
	p := &model.Profile{
		RoutingLists: []model.RoutingList{{
			ID: "blocklist", Manual: []string{"2001:db8::/32"}, Outbound: model.OutboundBlock, Enabled: true,
		}},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if !plan.hasV6() {
		t.Fatal("setup: expected a v6 plan")
	}
	join := strings.Join(plan.RenderIP(Options{}), "\n")
	if strings.Contains(join, "ip -6 route add blackhole") {
		t.Errorf("v6 blackhole must use `replace`, not `add`:\n%s", join)
	}
	if !strings.Contains(join, "ip -6 route replace blackhole default table") {
		t.Errorf("missing idempotent v6 blackhole route:\n%s", join)
	}
}
