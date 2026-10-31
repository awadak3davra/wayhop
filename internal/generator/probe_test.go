package generator

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"wayhop/internal/model"
)

func probeProfile() *model.Profile {
	nl := generator_singBoxEndpoint("nl", model.ProtoVLESS, map[string]any{"uuid": "11111111-2222-3333-4444-555555555555"})
	de := generator_singBoxEndpoint("de", model.ProtoTrojan, map[string]any{"password": "pw"})
	return &model.Profile{
		Endpoints: []model.Endpoint{nl, de},
		Groups:    []model.Group{{ID: "auto", Name: "Auto", Type: model.GroupURLTest, Members: []string{"nl", "de"}}},
		Rules:     []model.Rule{{ID: "d", Default: true, Outbound: "auto"}},
		RoutingLists: []model.RoutingList{
			{ID: "ru", Name: "Direct", Manual: []string{"example.ru"}, Outbound: model.OutboundDirect, Enabled: true},
		},
	}
}

// One probe user per exit (direct, endpoints and groups), each routed to its exit by
// rules that come before everything else.
func TestProbeInbound(t *testing.T) {
	res, err := Generate(probeProfile(), Options{MixedPort: 7890, ProbePort: 17890, ClashSecret: "s3cret", TunEnabled: true})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var probe map[string]any
	for _, in := range res.Config["inbounds"].([]map[string]any) {
		if in["tag"] == ProbeInboundTag {
			probe = in
		}
	}
	if probe == nil || probe["listen"] != "127.0.0.1" || probe["listen_port"] != 17890 || probe["type"] != "mixed" {
		t.Fatalf("probe inbound = %v", probe)
	}
	users := map[string]string{}
	for _, u := range probe["users"].([]map[string]any) {
		users[u["username"].(string)] = u["password"].(string)
	}
	for _, tag := range []string{model.OutboundDirect, "nl", "de", "auto"} {
		if users[ProbeUser(tag)] != ProbePassword("s3cret") {
			t.Errorf("no probe user for exit %s: %v", tag, users)
		}
	}
	rules := res.Config["route"].(map[string]any)["rules"].([]map[string]any)
	for i := 0; i < len(users); i++ {
		r := rules[i]
		in, _ := r["inbound"].([]string)
		au, _ := r["auth_user"].([]string)
		if len(in) != 1 || in[0] != ProbeInboundTag || len(au) != 1 || au[0] != ProbeUser(r["outbound"].(string)) || r["action"] != "route" {
			t.Errorf("rule %d is not a probe rule ahead of the rest: %v", i, r)
		}
	}
	if ProbePassword("s3cret") == ProbePassword("other") || len(ProbePassword("")) != 32 {
		t.Error("the password must follow the secret and have a fixed length")
	}

	// No port, no probe: the config is what it was before the probe existed.
	plain, _ := Generate(probeProfile(), Options{MixedPort: 7890, ClashSecret: "s3cret", TunEnabled: true})
	for _, in := range plain.Config["inbounds"].([]map[string]any) {
		if in["tag"] == ProbeInboundTag {
			t.Error("a probe inbound without a probe port")
		}
	}
	for _, r := range plain.Config["route"].(map[string]any)["rules"].([]map[string]any) {
		if _, ok := r["auth_user"]; ok {
			t.Errorf("a probe rule without a probe port: %v", r)
		}
	}
}

// The probe inbound and its rules pass the real core's check, on whatever WR_SINGBOX is.
func TestProbeInboundSingBoxCheck(t *testing.T) {
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — set it to a sing-box binary for a real `check`")
	}
	ver := singboxVersionOf(t, bin)
	// No TUN: its auto_redirect fails `check` off Linux, and the probe rules do not depend on it.
	res, err := Generate(probeProfile(), Options{MixedPort: 7890, ProbePort: 17890, ClashSecret: "s3cret", CoreVersion: ver})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	data, _ := json.MarshalIndent(res.Config, "", "  ")
	f := filepath.Join(t.TempDir(), "probe.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", f).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check rejected the probe inbound: %v\n%s", err, out)
	}
}
