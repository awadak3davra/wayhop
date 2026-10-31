package generator

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/model"
)

func hy2ExtrasProfile() *model.Profile {
	ep := func(id string, params map[string]any) model.Endpoint {
		params["password"] = "pw"
		return model.Endpoint{ID: id, Name: id, Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
			Server: "192.0.2.4", Port: 8443, TLS: &model.TLS{Enabled: true, Type: "tls", SNI: "hy.example.com"}, Params: params}
	}
	return &model.Profile{
		Endpoints: []model.Endpoint{
			ep("hy-gecko", map[string]any{"obfs": "gecko", "obfs_password": "obfspw", "obfs_min_packet_size": 600,
				"obfs_max_packet_size": 1100, "hop_ports": "20000-30000", "hop_interval": "20s", "hop_interval_max": "60s",
				"bbr_profile": "aggressive", "disable_chrome_parrot": true}),
			ep("hy-plain", map[string]any{"hop_ports": "40000-41000", "hop_interval": "30s", "hop_interval_max": "90s",
				"disable_chrome_parrot": true}),
		},
		Rules: []model.Rule{{ID: "a", DomainSuffix: []string{"a.example.com"}, Outbound: "hy-plain"},
			{ID: "def", Default: true, Outbound: "hy-gecko"}},
	}
}

func hy2Outbounds(cfg map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, ob := range cfg["outbounds"].([]map[string]any) {
		if ob["type"] == "hysteria2" {
			out[ob["tag"].(string)] = ob
		}
	}
	return out
}

// TestHysteria2ExtrasSingBoxCheck: gecko obfuscation, hop-interval randomisation, the BBR profile
// and Chrome-parrot opt-out reach a 1.14+ core; an older core gets the fields it has (hop_interval),
// and a gecko connection there renders without gecko - the shared config still loads - while the
// review names it (GeckoNeedsNewerCore).
func TestHysteria2ExtrasSingBoxCheck(t *testing.T) {
	p := hy2ExtrasProfile()
	res13, err := Generate(p, Options{MixedPort: 7890, CoreVersion: "1.13.21"})
	if err != nil {
		t.Fatalf("gecko on 1.13 must not fail the whole config: %v", err)
	}
	if ob := hy2Outbounds(res13.Config)["hy-gecko"]; ob["obfs"] != nil || ob["disable_chrome_parrot"] != nil {
		t.Errorf("1.13 gecko outbound must carry neither gecko nor 1.14 fields: %v", ob)
	}
	if !GeckoNeedsNewerCore(&p.Endpoints[0], "1.13.21") || GeckoNeedsNewerCore(&p.Endpoints[0], "1.14.4") ||
		GeckoNeedsNewerCore(&p.Endpoints[0], "") || GeckoNeedsNewerCore(&p.Endpoints[1], "1.13.21") {
		t.Error("GeckoNeedsNewerCore must flag only gecko on a known pre-1.14 core")
	}
	old := hy2ExtrasProfile()
	old.Endpoints = old.Endpoints[1:]
	old.Rules = []model.Rule{{ID: "def", Default: true, Outbound: "hy-plain"}}
	res, err := Generate(old, Options{MixedPort: 7890, CoreVersion: "1.13.21"})
	if err != nil {
		t.Fatalf("plain hy2 on 1.13: %v", err)
	}
	if ob := hy2Outbounds(res.Config)["hy-plain"]; ob["hop_interval"] != "30s" || ob["hop_interval_max"] != nil || ob["disable_chrome_parrot"] != nil {
		t.Errorf("1.13 outbound carries only what 1.13 knows: %v", ob)
	}
	res, err = Generate(p, Options{MixedPort: 7890, CoreVersion: "1.14.4", CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if err != nil {
		t.Fatalf("generate for 1.14.4: %v", err)
	}
	g := hy2Outbounds(res.Config)["hy-gecko"]
	obfs, _ := g["obfs"].(map[string]any)
	if obfs["type"] != "gecko" || obfs["min_packet_size"] != 600 || g["hop_interval_max"] != "60s" ||
		g["bbr_profile"] != "aggressive" || g["disable_chrome_parrot"] != true {
		t.Errorf("1.14 gecko outbound = %v", g)
	}

	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		return
	}
	ver := singboxVersionOf(t, bin)
	res, err = Generate(p, Options{MixedPort: 7890, CoreVersion: ver, CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if coreMinor(ver) < 14 && err == nil {
		if ob := hy2Outbounds(res.Config)["hy-gecko"]; ob["obfs"] != nil {
			t.Fatalf("sing-box %s has no gecko obfuscation, but the generator rendered it", strings.SplitN(ver, "\n", 2)[0])
		}
	}
	if err != nil {
		t.Fatalf("generate for %s: %v", strings.SplitN(ver, "\n", 2)[0], err)
	}
	data, _ := json.MarshalIndent(res.Config, "", "  ")
	f := filepath.Join(t.TempDir(), "hy2.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", f).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check rejected the Hysteria2 config: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "deprecated") {
		t.Fatalf("sing-box warned about a deprecated field:\n%s", out)
	}
}
