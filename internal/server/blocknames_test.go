package server

import (
	"testing"

	"wayhop/internal/model"
)

// A block list made of names cannot stop a connection the kernel already routed: in hybrid the
// kernel takes its lists' address ranges before the core sees them. A service listed to
// block, with every address in another list's range, leaves by the tunnel; the review must not say
// "No action needed". It names the block list; with no kernel ranges it says nothing.
func TestReviewNamesABlockListTheKernelCanBypass(t *testing.T) {
	s := dnsSeed(t)
	prof := model.Profile{
		Endpoints: []model.Endpoint{{ID: "awg", Name: "awg", Enabled: true, Engine: model.EngineExternal,
			Params: map[string]any{"interface": "awg1"}}},
		RoutingLists: []model.RoutingList{
			{ID: "block-max", Name: "MAX", Enabled: true, Outbound: model.OutboundBlock, Manual: []string{"max.example.net"}},
			{ID: "ip-ranges", Name: "Ranges", Enabled: true, Outbound: "awg", Manual: []string{"198.51.100.0/24"}},
		},
	}
	has := func(mode string, p model.Profile) bool {
		for _, f := range s.kernelPlaneFindings(modeCfg(mode), &p, nil) {
			if f.ID == "kernel_plane.block_names_shadowed" && f.Item == "MAX" {
				return true
			}
		}
		return false
	}
	if !has("hybrid", prof) {
		t.Fatal("hybrid: the block-by-name list the kernel can bypass was not named")
	}
	if has("tun", prof) {
		t.Error("tun: the core sees every connection there, so the block holds")
	}
	noRanges := prof
	noRanges.RoutingLists = noRanges.RoutingLists[:1]
	if has("hybrid", noRanges) {
		t.Error("hybrid with no kernel address ranges: nothing can bypass the block")
	}
}
