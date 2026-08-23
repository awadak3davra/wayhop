package pbr

import (
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/util"
)

// TestCompile_AWGMasquerade guards the AmneziaWG-egress blackhole fix: a kernel-routed
// EngineAmneziaWG endpoint must get a forwarded-LAN MASQUERADE on its wr-* iface, exactly
// like an EngineExternal tunnel — otherwise forwarded LAN packets leave with their RFC1918
// source, the peer has no return route, and every LAN client on that zone is black-holed.
func TestCompile_AWGMasquerade(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "nl-awg", Engine: model.EngineAmneziaWG, Server: "1.2.3.4", Port: 51820,
			Enabled: true, Params: map[string]any{"private_key": "k", "peer_public_key": "P"},
		}},
		RoutingLists: []model.RoutingList{
			{ID: "ru", Manual: []string{"5.6.7.0/24"}, Outbound: "nl-awg", Enabled: true},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	iface := util.AWGIface("nl-awg")
	if !contains(plan.MasqIfaces, iface) {
		t.Fatalf("MasqIfaces = %v, want the AWG iface %q (else forwarded LAN blackholes)", plan.MasqIfaces, iface)
	}
	nft := plan.RenderNft()
	if !strings.Contains(nft, iface) || !strings.Contains(nft, "masquerade") {
		t.Errorf("rendered nft has no masquerade for %q:\n%s", iface, nft)
	}
}
