package pbr

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestCompile_CanonicalizesNonColonMAC: net.ParseMAC (used by model.Validate) accepts a MAC in
// dash form ("aa-bb-cc-dd-ee-ff") and dotted form ("0123.4567.89ab") as well as colon form, and
// validation only CHECKS — it never rewrites. But BOTH routing planes render the stored string
// verbatim into a colon-only grammar: nft `ether saddr { <mac> }` (render.go) and iptables
// `-m mac --mac-source <mac>` (render_ipset.go). A non-colon MAC therefore produces an INVALID
// ruleset — the entire `nft -f -` transaction is rejected and the whole kernel PBR plane fails to
// apply (device-wide, not just that one zone). Compile must canonicalize every source MAC to the
// lowercase colon form so a validly-entered dash/dotted MAC still routes.
func TestCompile_CanonicalizesNonColonMAC(t *testing.T) {
	mkPlan := func(mac string) *Plan {
		p := &model.Profile{
			Endpoints:    []model.Endpoint{{ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20", Enabled: true, Params: map[string]any{"interface": "awg1"}}},
			DeviceGroups: []model.DeviceGroup{{ID: "kids", Name: "Kids", Members: []model.DeviceMember{{MAC: mac}}}},
			RoutingLists: []model.RoutingList{{ID: "yt", Name: "YT", Manual: []string{"8.8.8.0/24"}, Outbound: "ru-awg1", Enabled: true, ScopeMode: "only", ScopeGroups: []string{"kids"}}},
		}
		plan, _, err := Compile(p, Options{})
		if err != nil {
			t.Fatalf("Compile(%q): %v", mac, err)
		}
		return plan
	}

	const wantColon = "aa:bb:cc:dd:ee:ff"
	for _, mac := range []string{"aa-bb-cc-dd-ee-ff", "AA:BB:CC:DD:EE:FF", "aabb.ccdd.eeff"} {
		plan := mkPlan(mac)
		var z *Zone
		for i := range plan.Zones {
			if strings.HasSuffix(plan.Zones[i].Name, "_dm") {
				z = &plan.Zones[i]
				break
			}
		}
		if z == nil {
			t.Fatalf("%q: no MAC-scoped zone in %+v", mac, plan.Zones)
		}
		if len(z.SrcMAC) != 1 || z.SrcMAC[0] != wantColon {
			t.Errorf("%q: zone SrcMAC = %v, want [%s] (canonical colon form)", mac, z.SrcMAC, wantColon)
		}
		// End-to-end: the rendered nft must carry the colon form and NEVER the raw non-colon input
		// (which nft rejects, failing the whole `nft -f -` load).
		nft := plan.RenderNft()
		if !strings.Contains(nft, wantColon) {
			t.Errorf("%q: rendered nft lacks canonical %s:\n%s", mac, wantColon, nft)
		}
		if mac != wantColon && strings.Contains(nft, mac) {
			t.Errorf("%q: rendered nft leaked the non-canonical input verbatim (nft-invalid):\n%s", mac, nft)
		}
	}
}
