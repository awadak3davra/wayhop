package server

import (
	"testing"

	"velinx/internal/config"
	"velinx/internal/model"
)

// TestServerDatapathNativeOnly exercises the SERVER gate that decides whether the apply path skips
// (and stops) the sing-box core: s.datapathNativeOnly resolves the effective routing mode via
// s.routingMode(c) and delegates to the pure predicate. Skipping the core is the only change that
// can black-hole traffic, so this gate must be conservative — true ONLY in fast mode with an
// all-kernel-native profile. The pure predicate has its own unit tests; this locks the mode
// resolution + delegation the apply path relies on.
func TestServerDatapathNativeOnly(t *testing.T) {
	s, _ := sharehandlers_server(t)

	awg := model.Endpoint{
		ID: "awg", Engine: model.EngineAmneziaWG, Server: "1.2.3.4", Port: 51820, Enabled: true,
		Params: map[string]any{"private_key": "k", "peer_public_key": "k", "local_address": []string{"10.0.0.2/32"}},
	}
	nativeProfile := model.Profile{
		Endpoints: []model.Endpoint{awg},
		Rules: []model.Rule{
			{ID: "r", IPCIDR: []string{"1.2.3.0/24"}, Outbound: "awg"},
			{ID: "def", Default: true, Outbound: model.OutboundDirect},
		},
	}
	proxyProfile := model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "v", Name: "V", Protocol: model.ProtoVLESS, Server: "1.2.3.4", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u"}},
		},
		Rules: []model.Rule{{ID: "def", Default: true, Outbound: model.OutboundDirect}},
	}

	cases := []struct {
		name string
		mode string
		gw   bool
		prof model.Profile
		want bool
	}{
		{"fast + all-native -> skip sing-box", "fast", false, nativeProfile, true},
		{"hybrid + all-native -> keep (not fast)", "hybrid", false, nativeProfile, false},
		{"auto/empty + all-native -> keep (resolves to mixed)", "", false, nativeProfile, false},
		{"fast + a proxy endpoint -> keep (needs the core)", "fast", false, proxyProfile, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := config.Config{RoutingMode: c.mode, Gateway: c.gw}
			p := c.prof
			if got := s.datapathNativeOnly(cfg, &p); got != c.want {
				t.Errorf("datapathNativeOnly(mode=%q) = %v, want %v", c.mode, got, c.want)
			}
		})
	}
}
