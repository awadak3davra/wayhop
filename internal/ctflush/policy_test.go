package ctflush

import (
	"net/netip"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// A flow routed by a KeeneticOS access policy holds the policy's slot in its connmark. When the plane
// goes (routing off, a rollback to nothing) it is as stale as a tunnel flow: its NAT binding points at
// the tunnel while the main table now sends it out of the WAN. Unowned, it was kept, and stayed dead
// until the app gave up (QA-062).
func TestPolicySlotFlowIsStaleWhenThePlaneGoes(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "awg", Name: "awg", Enabled: true, Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
			Server: "203.0.113.9", Params: map[string]any{"local_address": []string{"10.8.0.2/32"}},
		}},
		RoutingLists: []model.RoutingList{
			{ID: "via-policy", Name: "via-policy", Enabled: true, Outbound: "ndm-policy:Policy1", Manual: []string{"198.51.100.0/24"}},
			{ID: "via-tunnel", Name: "via-tunnel", Enabled: true, Outbound: "awg", Manual: []string{"192.0.2.0/24"}},
		},
	}
	old, _, err := pbr.Compile(p, pbr.Options{NDMPolicies: map[string]uint32{"Policy1": 0x0ffffaab}})
	if err != nil {
		t.Fatal(err)
	}
	var slot, tun uint32
	for _, z := range old.Zones {
		if z.NDMPolicy != "" {
			slot = z.Mark
		} else {
			tun = z.Mark
		}
	}
	src := netip.MustParseAddr("192.168.77.50")
	pol := Entry{Family: 2, Src: src, Dst: netip.MustParseAddr("198.51.100.7"), Mark: slot}
	eg := Entry{Family: 2, Src: src, Dst: netip.MustParseAddr("192.0.2.7"), Mark: tun}
	for _, plane := range []Plane{PlaneNft, PlaneIpset} {
		d := newDecider(old, nil, Options{Plane: plane})
		if !d.stale(eg) {
			t.Fatalf("plane %d: test setup - the tunnel flow should be stale", plane)
		}
		if !d.stale(pol) {
			t.Errorf("plane %d: the policy flow was left on the dead path after the plane went", plane)
		}
	}
}
