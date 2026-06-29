package generator

import (
	"testing"

	"velinx/internal/model"
)

func gen_tunInbound(res *Result) map[string]any {
	ins, _ := res.Config["inbounds"].([]map[string]any)
	for _, in := range ins {
		if in["type"] == "tun" {
			return in
		}
	}
	return nil
}

func gen_must(t *testing.T, p *model.Profile, o Options) *Result {
	t.Helper()
	res, err := Generate(p, o)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return res
}

// TestTunGatewayMode: TunEnabled emits a complete tun inbound (address + auto_route
// + auto_redirect); the default mixed-only mode emits none. This is the gateway
// flag that the cutover flips (config.Gateway → Options.TunEnabled).
func TestTunGatewayMode(t *testing.T) {
	p := &model.Profile{}
	if in := gen_tunInbound(gen_must(t, p, Options{MixedPort: 7890})); in != nil {
		t.Fatalf("tun inbound present without TunEnabled: %v", in)
	}
	in := gen_tunInbound(gen_must(t, p, Options{MixedPort: 7890, TunEnabled: true}))
	if in == nil {
		t.Fatal("TunEnabled but no tun inbound")
	}
	if in["auto_route"] != true || in["auto_redirect"] != true {
		t.Fatalf("tun inbound missing auto_route/auto_redirect: %v", in)
	}
	if addr, _ := in["address"].([]string); len(addr) == 0 {
		t.Fatalf("tun inbound missing address: %v", in)
	}

	// Gateway mode must sniff (first route rule) so domain rule_sets match raw TUN
	// traffic; mixed mode (domain comes from the proxy CONNECT) must NOT add it.
	tunRes := gen_must(t, p, Options{MixedPort: 7890, TunEnabled: true})
	rules, _ := tunRes.Config["route"].(map[string]any)["rules"].([]map[string]any)
	if len(rules) == 0 || rules[0]["action"] != "sniff" {
		t.Fatalf("TUN mode: rules[0] must be sniff, got %v", rules)
	}
	mixedRes := gen_must(t, p, Options{MixedPort: 7890})
	if mr, _ := mixedRes.Config["route"].(map[string]any)["rules"].([]map[string]any); len(mr) > 0 && mr[0]["action"] == "sniff" {
		t.Error("mixed mode must not add a sniff rule")
	}
}

// TestTunGatewayMTUAddr: the TUN mtu/address are config-driven (Config.GatewayMTU/
// GatewayAddr → Options) rather than hardcoded — defaults when unset, the override
// when set (so a constrained tunnel exit can lower the MTU, e.g. 1280).
func TestTunGatewayMTUAddr(t *testing.T) {
	p := &model.Profile{}
	def := gen_tunInbound(gen_must(t, p, Options{MixedPort: 7890, TunEnabled: true}))
	if def["mtu"] != 1500 {
		t.Errorf("default tun mtu = %v, want 1500", def["mtu"])
	}
	if a, _ := def["address"].([]string); len(a) != 1 || a[0] != "172.19.0.1/30" {
		t.Errorf("default tun address = %v, want [172.19.0.1/30]", def["address"])
	}

	over := gen_tunInbound(gen_must(t, p, Options{MixedPort: 7890, TunEnabled: true, TunMTU: 1280, TunAddr: "10.255.0.1/30"}))
	if over["mtu"] != 1280 {
		t.Errorf("override tun mtu = %v, want 1280", over["mtu"])
	}
	if a, _ := over["address"].([]string); len(a) != 1 || a[0] != "10.255.0.1/30" {
		t.Errorf("override tun address = %v, want [10.255.0.1/30]", over["address"])
	}
}
