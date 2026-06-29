package generator

import (
	"testing"

	"velinx/internal/model"
)

// TestExternalInterfaceOutbound: an EngineExternal endpoint becomes a direct
// outbound bound to its interface, and creates NO plugin (Velinx must not try
// to bring up or tear down a UCI/netifd-managed interface).
func TestExternalInterfaceOutbound(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "ru-awg1", Name: "RU", Engine: model.EngineExternal, Enabled: true,
			Params: map[string]any{"interface": "awg1"},
		}},
	}
	res, err := Generate(p, Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(res.Plugins) != 0 {
		t.Fatalf("external endpoint must create no plugin, got %+v", res.Plugins)
	}
	ob := generator_outboundsByTag(t, res)["ru-awg1"]
	if ob == nil || ob["type"] != "direct" || ob["bind_interface"] != "awg1" {
		t.Fatalf("external outbound = %v, want direct bound to awg1", ob)
	}
}

// TestEndpointBypass: a tunnel's own endpoint IP (managed Server, or an external
// endpoint's endpoint_ip) is bypassed to direct as the FIRST rule — never routed
// through a tunnel (recursion). Hostname servers do not contribute.
func TestEndpointBypass(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "vless1", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "1.2.3.4", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u"}},
			{ID: "ru-awg1", Engine: model.EngineExternal, Enabled: true, Params: map[string]any{"interface": "awg1", "endpoint_ip": "198.51.100.20"}},
			{ID: "host1", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "vpn.example.com", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u"}},
		},
	}
	res, err := Generate(p, Options{MixedPort: 7890})
	if err != nil {
		t.Fatal(err)
	}
	rules, _ := res.Config["route"].(map[string]any)["rules"].([]map[string]any)
	if len(rules) == 0 || rules[0]["outbound"] != "direct" {
		t.Fatalf("rules[0] is not the direct bypass: %v", rules)
	}
	got := map[string]bool{}
	for _, c := range rules[0]["ip_cidr"].([]string) {
		got[c] = true
	}
	if !got["1.2.3.4/32"] || !got["198.51.100.20/32"] {
		t.Fatalf("bypass missing endpoint IPs: %v", rules[0]["ip_cidr"])
	}
	if got["vpn.example.com/32"] {
		t.Error("hostname server must not be bypassed")
	}
}
