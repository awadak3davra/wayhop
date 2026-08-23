package health

import (
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/util"
)

// TestTargetsResolveKernelIface: an AmneziaWG endpoint must get its kernel iface so it is probed via
// ReachableViaIface (a direct ping out the tunnel) rather than a Clash delay test — in fast mode an
// AWG endpoint is NOT a sing-box outbound, so the Clash probe can't see it and would report Unknown
// even when the tunnel is healthy. EngineExternal keeps its params["interface"]; a proxy endpoint has
// no iface (Clash-probed).
func TestTargetsResolveKernelIface(t *testing.T) {
	p := model.Profile{Endpoints: []model.Endpoint{
		{ID: "awg-example", Name: "NL", Engine: model.EngineAmneziaWG, Enabled: true, Params: map[string]any{"private_key": "k"}},
		{ID: "ext", Name: "EXT", Engine: model.EngineExternal, Enabled: true, Params: map[string]any{"interface": "wg-adopted"}},
		{ID: "vless", Name: "V", Protocol: model.ProtoVLESS, Enabled: true, Params: map[string]any{"uuid": "u"}},
	}}
	byID := map[string]target{}
	for _, tg := range (&Monitor{}).targetsFrom(p) {
		byID[tg.id] = tg
	}

	wantAWG := util.AWGIface("awg-example")
	if wantAWG == "" {
		t.Fatal("util.AWGIface returned empty for a valid id")
	}
	if got := byID["awg-example"].iface; got != wantAWG {
		t.Errorf("AmneziaWG endpoint iface = %q, want %q (so it's probed via the iface, not Clash)", got, wantAWG)
	}
	if got := byID["ext"].iface; got != "wg-adopted" {
		t.Errorf("external endpoint iface = %q, want wg-adopted", got)
	}
	if got := byID["vless"].iface; got != "" {
		t.Errorf("proxy endpoint must have no iface (Clash-probed), got %q", got)
	}
}

func TestTargetsPreferAuthenticatedNativeInterfaceBindings(t *testing.T) {
	p := model.Profile{Endpoints: []model.Endpoint{
		{ID: "openwrt-wg", Engine: model.EngineSingBox, Protocol: model.ProtoWireGuard, Enabled: true},
		{ID: "keenetic-awg", Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG, Enabled: true},
		{ID: "proxy", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Enabled: true},
	}}
	m := &Monitor{}
	m.SetNativeInterfaceResolver(func() (map[string]string, bool) {
		return map[string]string{
			"openwrt-wg":   "wr_12345678",
			"keenetic-awg": "Wireguard12",
		}, true
	})
	byID := map[string]target{}
	for _, tg := range m.targetsFrom(p) {
		byID[tg.id] = tg
	}
	if got := byID["openwrt-wg"].iface; got != "wr_12345678" {
		t.Errorf("OpenWrt native WG iface = %q, want authenticated wr_* identity", got)
	}
	if got := byID["keenetic-awg"].iface; got != "Wireguard12" {
		t.Errorf("Keenetic native AWG iface = %q, want authenticated NDM identity", got)
	}
	if got := byID["proxy"].iface; got != "" {
		t.Errorf("OpenWrt compatibility endpoint invented iface %q", got)
	}
}

func TestTargetsTreatAuthenticatedEmptyBindingsAsAuthoritative(t *testing.T) {
	p := model.Profile{Endpoints: []model.Endpoint{{
		ID: "old-awg", Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG, Enabled: true,
	}}}
	m := &Monitor{}
	m.SetNativeInterfaceResolver(func() (map[string]string, bool) { return map[string]string{}, true })
	targets := m.targetsFrom(p)
	if len(targets) != 1 || targets[0].iface != "" {
		t.Fatalf("authoritative empty bindings fell back to guessed interface: %#v", targets)
	}
}
