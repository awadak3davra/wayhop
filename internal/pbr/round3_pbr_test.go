package pbr

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestCompile_BlockZoneWinsOverlappingTunnel (bug #11): both render planes emit one non-terminating
// mark per zone, so for OVERLAPPING destination CIDRs the LAST-emitted zone wins. A block/blackhole
// zone must therefore be ordered AFTER an overlapping tunnel zone — else (with the old alphabetical
// sort) an earlier-named block set is silently overwritten by the tunnel mark and blocked traffic
// leaks out the tunnel. The block list here is named to sort BEFORE the tunnel list alphabetically, so
// only the block-last ordering can keep it winning.
func TestCompile_BlockZoneWinsOverlappingTunnel(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "tunnel-a", Engine: model.EngineExternal, Server: "198.51.100.20",
			Enabled: true, Params: map[string]any{"interface": "awg1"},
		}},
		RoutingLists: []model.RoutingList{
			{ID: "aaa-block", Manual: []string{"1.2.3.0/24"}, Outbound: model.OutboundBlock, Enabled: true}, // list_aaa… sorts first
			{ID: "zzz-vpn", Manual: []string{"1.2.3.0/24"}, Outbound: "tunnel-a", Enabled: true},            // overlaps the SAME CIDR
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	blockIdx, tunnelIdx := -1, -1
	for i, z := range plan.Zones {
		switch z.EgressTag {
		case model.OutboundBlock:
			blockIdx = i
		case "tunnel-a":
			tunnelIdx = i
		}
	}
	if blockIdx < 0 || tunnelIdx < 0 {
		t.Fatalf("expected both a block and a tunnel zone, got %+v", plan.Zones)
	}
	if blockIdx < tunnelIdx {
		t.Errorf("block zone (idx %d) must be emitted AFTER the overlapping tunnel zone (idx %d) so its mark wins — else the block leaks out the tunnel", blockIdx, tunnelIdx)
	}
}

// TestRenderNft_ConnmarkSaveMasked (bug #17): the nft connmark save must be MASKED to Plan.Mask (the
// iptables --ctmask equivalent), preserving any non-owned connmark bits a coexisting subsystem (mwan3)
// keeps there — never a bare `ct mark set meta mark` full 32-bit clobber.
func TestRenderNft_ConnmarkSaveMasked(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "tunnel-a", Engine: model.EngineExternal, Server: "198.51.100.20",
			Enabled: true, Params: map[string]any{"interface": "awg1"},
		}},
		RoutingLists: []model.RoutingList{
			{ID: "mts", Manual: []string{"198.51.100.0/24"}, Outbound: "tunnel-a", Enabled: true},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	nft := plan.RenderNft()
	if strings.Contains(nft, "ct mark set meta mark\n") {
		t.Errorf("connmark save is an unmasked full copy (clobbers non-owned mwan3 bits):\n%s", nft)
	}
	if !strings.Contains(nft, "ct mark set ct mark & 0xff00ffff |") {
		t.Errorf("connmark save must be masked (ct mark set ct mark & ~M | <const>):\n%s", nft)
	}
}
