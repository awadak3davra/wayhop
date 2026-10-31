package generator

import (
	"testing"

	"wayhop/internal/model"
)

// A ByeDPI connection becomes a SOCKS outbound to its local listener, with a plugin record for the
// daemon to start, and a routing list can use it like any other exit.
func TestByeDPIEndpointGenerates(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{ID: "bye", Name: "ByeDPI", Engine: model.EngineByeDPI, Enabled: true}},
		Rules:     []model.Rule{{ID: "d", Default: true, Outbound: model.OutboundDirect}},
		RoutingLists: []model.RoutingList{
			{ID: "yt", Name: "YouTube", Manual: []string{"youtube.com"}, Outbound: "bye", Enabled: true},
		},
	}
	res, err := Generate(p, Options{MixedPort: 7890, ProbePort: 17890})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(res.Plugins) != 1 || res.Plugins[0].Endpoint.ID != "bye" || res.Plugins[0].SOCKSPort != basePluginPort {
		t.Fatalf("plugins = %+v", res.Plugins)
	}
	var socks map[string]any
	for _, o := range res.Config["outbounds"].([]map[string]any) {
		if o["tag"] == "bye" {
			socks = o
		}
	}
	if socks == nil || socks["type"] != "socks" || socks["server"] != "127.0.0.1" || socks["server_port"] != basePluginPort {
		t.Errorf("outbound = %v", socks)
	}
	routed := false
	for _, r := range res.Config["route"].(map[string]any)["rules"].([]map[string]any) {
		if r["outbound"] == "bye" && r["inbound"] == nil {
			routed = true
		}
	}
	if !routed {
		t.Error("the list is not routed to the ByeDPI exit")
	}
}

// With a TUN, ciadpi's uid is excluded from it, so its own connections cannot loop back; without a
// ByeDPI connection, or without a TUN, nothing changes.
func TestByeDPIExcludedFromTUN(t *testing.T) {
	tunOf := func(p *model.Profile, tun bool) map[string]any {
		res, err := Generate(p, Options{MixedPort: 7890, TunEnabled: tun})
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		for _, in := range res.Config["inbounds"].([]map[string]any) {
			if in["type"] == "tun" {
				return in
			}
		}
		return nil
	}
	bye := &model.Profile{
		Endpoints: []model.Endpoint{{ID: "bye", Name: "ByeDPI", Engine: model.EngineByeDPI, Enabled: true}},
		Rules:     []model.Rule{{ID: "d", Default: true, Outbound: model.OutboundDirect}},
	}
	in := tunOf(bye, true)
	if uids, _ := in["exclude_uid"].([]int); len(uids) != 1 || uids[0] != model.ByeDPIUID {
		t.Errorf("tun exclude_uid = %v, want [%d]", in["exclude_uid"], model.ByeDPIUID)
	}
	bye.Endpoints[0].Enabled = false
	if _, ok := tunOf(bye, true)["exclude_uid"]; ok {
		t.Error("a disabled ByeDPI connection must not change the TUN")
	}
	bye.Endpoints[0].Enabled = true
	if tunOf(bye, false) != nil {
		t.Error("no TUN in mixed mode")
	}
}
