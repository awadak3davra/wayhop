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

func snellTestProfile() *model.Profile {
	ep := func(id string, params map[string]any) model.Endpoint {
		return model.Endpoint{ID: id, Name: id, Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoSnell,
			Server: "192.0.2.1", Port: 8443, Params: params}
	}
	return &model.Profile{
		Endpoints: []model.Endpoint{
			ep("snell4", map[string]any{"version": 4, "psk": "abcdefghijkl", "obfs_mode": "http", "obfs_host": "bing.com", "network": "tcp", "reuse": true}),
			// a JSON round-trip leaves numbers as float64
			ep("snell6", map[string]any{"version": float64(6), "psk": "abcdefghijkl", "mode": "unshaped"}),
		},
		Rules: []model.Rule{
			{ID: "a", DomainSuffix: []string{"a.example.com"}, Outbound: "snell6"},
			{ID: "def", Default: true, Outbound: "snell4"},
		},
	}
}

// TestSnellSingBoxCheck renders Snell v4 and v6. The structure is always asserted; with WR_SINGBOX
// set, a 1.14+ core must pass `sing-box check` without a deprecation warning and an older one must be
// refused by the generator by name.
func TestSnellSingBoxCheck(t *testing.T) {
	p := snellTestProfile()
	if _, err := Generate(p, Options{MixedPort: 7890, CoreVersion: "1.13.21"}); err == nil ||
		!strings.Contains(err.Error(), "Snell needs sing-box 1.14") {
		t.Fatalf("a 1.13 core: err = %v, want the 1.14 refusal", err)
	}
	res, err := Generate(p, Options{MixedPort: 7890, CoreVersion: "1.14.4", CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if err != nil {
		t.Fatalf("generate for 1.14.4: %v", err)
	}
	obs := map[string]map[string]any{}
	for _, ob := range res.Config["outbounds"].([]map[string]any) {
		if ob["type"] == "snell" {
			obs[ob["tag"].(string)] = ob
		}
	}
	if v4 := obs["snell4"]; v4 == nil || v4["version"] != 4 || v4["obfs_mode"] != "http" || v4["obfs_host"] != "bing.com" ||
		v4["network"] != "tcp" || v4["reuse"] != true || v4["mode"] != nil {
		t.Errorf("snell v4 = %v", obs["snell4"])
	}
	if v6 := obs["snell6"]; v6 == nil || v6["version"] != 6 || v6["mode"] != "unshaped" || v6["obfs_mode"] != nil {
		t.Errorf("snell v6 = %v", obs["snell6"])
	}
	p.Endpoints[0].Params["version"] = 3
	if _, err := Generate(p, Options{MixedPort: 7890, CoreVersion: "1.14.4"}); err == nil || !strings.Contains(err.Error(), "v4 and v6") {
		t.Fatalf("Snell v3: err = %v, want the version refusal", err)
	}
	p.Endpoints[0].Params["version"] = 4

	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		return
	}
	ver := singboxVersionOf(t, bin)
	res, err = Generate(p, Options{MixedPort: 7890, CoreVersion: ver, CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if coreMinor(ver) < snellMinMinor {
		if err == nil {
			t.Fatalf("sing-box %s has no snell outbound, but the generator rendered one", strings.SplitN(ver, "\n", 2)[0])
		}
		return
	}
	if err != nil {
		t.Fatalf("generate for %s: %v", strings.SplitN(ver, "\n", 2)[0], err)
	}
	data, _ := json.MarshalIndent(res.Config, "", "  ")
	f := filepath.Join(t.TempDir(), "snell.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", f).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check rejected the Snell config: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "deprecated") {
		t.Fatalf("sing-box warned about a deprecated field:\n%s", out)
	}
}
