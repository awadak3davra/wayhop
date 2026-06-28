package health

import (
	"testing"

	"wakeroute/internal/model"
	"wakeroute/internal/util"
)

// TestTargetsResolveKernelIface: an AmneziaWG endpoint must get its kernel iface so it is probed via
// ReachableViaIface (a direct ping out the tunnel) rather than a Clash delay test — in fast mode an
// AWG endpoint is NOT a sing-box outbound, so the Clash probe can't see it and would report Unknown
// even when the tunnel is healthy. EngineExternal keeps its params["interface"]; a proxy endpoint has
// no iface (Clash-probed).
func TestTargetsResolveKernelIface(t *testing.T) {
	p := model.Profile{Endpoints: []model.Endpoint{
		{ID: "awg-nl", Name: "NL", Engine: model.EngineAmneziaWG, Enabled: true, Params: map[string]any{"private_key": "k"}},
		{ID: "ext", Name: "EXT", Engine: model.EngineExternal, Enabled: true, Params: map[string]any{"interface": "wg-adopted"}},
		{ID: "vless", Name: "V", Protocol: model.ProtoVLESS, Enabled: true, Params: map[string]any{"uuid": "u"}},
	}}
	byID := map[string]target{}
	for _, tg := range (&Monitor{}).targetsFrom(p) {
		byID[tg.id] = tg
	}

	wantAWG := util.AWGIface("awg-nl")
	if wantAWG == "" {
		t.Fatal("util.AWGIface returned empty for a valid id")
	}
	if got := byID["awg-nl"].iface; got != wantAWG {
		t.Errorf("AmneziaWG endpoint iface = %q, want %q (so it's probed via the iface, not Clash)", got, wantAWG)
	}
	if got := byID["ext"].iface; got != "wg-adopted" {
		t.Errorf("external endpoint iface = %q, want wg-adopted", got)
	}
	if got := byID["vless"].iface; got != "" {
		t.Errorf("proxy endpoint must have no iface (Clash-probed), got %q", got)
	}
}
