package pbr

import (
	"testing"

	"velinx/internal/model"
)

// TestCompile_AWGV6Posture (L3(B)): a v6 dest CIDR routed to an AmneziaWG egress is stripped from
// the fwmark plane ONLY when the tunnel positively declares a v4-only local_address (else it would
// blackhole inside a v4-only tunnel). A dual-stack AWG keeps v6; an AWG whose address is unknown
// keeps v6 too (fail-open — no existing config regresses). EngineExternal's always-v4-only posture
// is already covered by TestCompile_VoWiFi et al.
func TestCompile_AWGV6Posture(t *testing.T) {
	mk := func(localAddr []string) *model.Profile {
		ep := model.Endpoint{
			ID: "awg-nl", Engine: model.EngineAmneziaWG, Server: "1.2.3.4", Port: 51820,
			Enabled: true, Params: map[string]any{},
		}
		if localAddr != nil {
			ep.Params["local_address"] = localAddr
		}
		return &model.Profile{
			Endpoints: []model.Endpoint{ep},
			RoutingLists: []model.RoutingList{{
				ID: "l6", Manual: []string{"8.8.8.0/24", "2001:db8::/32"}, Outbound: "awg-nl", Enabled: true,
			}},
		}
	}
	zoneV6 := func(p *model.Profile) []string {
		plan, _, err := Compile(p, Options{})
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		for _, z := range plan.Zones {
			if z.EgressTag == "awg-nl" {
				return z.V6
			}
		}
		t.Fatalf("no zone for awg-nl in %+v", plan.Zones)
		return nil
	}

	// v4-only AWG (local_address has no v6) → v6 stripped from the kernel zone.
	if v6 := zoneV6(mk([]string{"10.0.0.2/24"})); len(v6) != 0 {
		t.Errorf("v4-only AWG must strip v6 from the fwmark plane, got %v", v6)
	}
	// dual-stack AWG (local_address includes a v6) → v6 kept.
	if v6 := zoneV6(mk([]string{"10.0.0.2/24", "fd00::2/64"})); !contains(v6, "2001:db8::/32") {
		t.Errorf("dual-stack AWG must keep v6, got %v", v6)
	}
	// unknown local_address → keep v6 (fail-open, no regression).
	if v6 := zoneV6(mk(nil)); !contains(v6, "2001:db8::/32") {
		t.Errorf("AWG with unknown local_address must keep v6 (fail-open), got %v", v6)
	}

	// The []any shape (a JSON store round-trip) must classify identically to []string.
	pAny := mk(nil)
	pAny.Endpoints[0].Params["local_address"] = []any{"10.0.0.2/24"} // v4-only via []any
	if v6 := zoneV6(pAny); len(v6) != 0 {
		t.Errorf("v4-only AWG via []any must strip v6, got %v", v6)
	}
}
