package generator

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
)

func hy2RealmProfile() *model.Profile {
	return &model.Profile{
		Endpoints: []model.Endpoint{
			// A server and a hop range left over from before the realm: neither may reach the core,
			// which refuses a realm beside server, server_port or server_ports.
			{ID: "hy-realm", Name: "hy-realm", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
				Server: "192.0.2.4", Port: 8443, TLS: &model.TLS{Enabled: true, Type: "tls", SNI: "hy.example.com", Insecure: true},
				Params: map[string]any{"password": "pw", "realm": "realm://tok@rendezvous.example.com:8443/my-cabin-1f3a8c2e9b",
					"realm_stun": "192.0.2.7:3478", "obfs": "salamander", "obfs_password": "obfspw",
					"hop_ports": "20000-30000", "hop_interval": "20s"}},
			{ID: "hy-realm-http", Name: "hy-realm-http", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
				TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "hy.example.com"},
				Params: map[string]any{"password": "pw", "realm": "realm+http://rendezvous.example.com/lab-realm-0001"}},
		},
		Rules: []model.Rule{{ID: "a", DomainSuffix: []string{"a.example.com"}, Outbound: "hy-realm-http"},
			{ID: "def", Default: true, Outbound: "hy-realm"}},
	}
}

// TestHysteria2RealmSingBoxCheck: a server reached through a Hysteria realm renders as sing-box's
// realm object on a 1.14+ core, with no server fields and Hysteria's default STUN servers when none
// are named. An older (or unknown) core has no realm: the outbound is rendered without a server, so
// the shared config still loads, and the review names it (RealmNeedsNewerCore). With WR_SINGBOX the
// form for that core goes through the real check, whichever it is.
func TestHysteria2RealmSingBoxCheck(t *testing.T) {
	p := hy2RealmProfile()
	res, err := Generate(p, Options{MixedPort: 7890, CoreVersion: "1.14.4", CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if err != nil {
		t.Fatalf("generate for 1.14.4: %v", err)
	}
	obs := hy2Outbounds(res.Config)
	r := obs["hy-realm"]
	want := map[string]any{"server_url": "https://rendezvous.example.com:8443", "token": "tok",
		"realm_id": "my-cabin-1f3a8c2e9b", "stun_servers": []string{"192.0.2.7:3478"}}
	if !reflect.DeepEqual(r["realm"], want) {
		t.Errorf("1.14 realm = %v, want %v", r["realm"], want)
	}
	for _, k := range []string{"server", "server_port", "server_ports", "hop_interval"} {
		if _, ok := r[k]; ok {
			t.Errorf("1.14 realm outbound carries %s: %v", k, r)
		}
	}
	if obfs, _ := r["obfs"].(map[string]any); obfs["type"] != "salamander" {
		t.Errorf("the realm outbound lost its obfuscation: %v", r)
	}
	if tl, _ := r["tls"].(map[string]any); tl["server_name"] != "hy.example.com" {
		t.Errorf("the realm outbound lost its TLS server name: %v", r)
	}
	h, _ := obs["hy-realm-http"]["realm"].(map[string]any)
	if h["server_url"] != "http://rendezvous.example.com" || h["token"] != nil ||
		!reflect.DeepEqual(h["stun_servers"], hy2RealmDefaultSTUN) {
		t.Errorf("realm+http without STUN = %v", h)
	}

	for _, ver := range []string{"1.13.21", ""} {
		res13, err := Generate(hy2RealmProfile(), Options{MixedPort: 7890, CoreVersion: ver})
		if err != nil {
			t.Fatalf("a realm on core %q must not fail the whole config: %v", ver, err)
		}
		for tag, ob := range hy2Outbounds(res13.Config) {
			for _, k := range []string{"realm", "server", "server_port", "server_ports"} {
				if _, ok := ob[k]; ok {
					t.Errorf("core %q: %s carries %s: %v", ver, tag, k, ob)
				}
			}
		}
	}
	plain := model.Endpoint{Protocol: model.ProtoHysteria2, Server: "192.0.2.4", Port: 443, Params: map[string]any{"password": "pw"}}
	if !RealmNeedsNewerCore(&p.Endpoints[0], "1.13.21") || RealmNeedsNewerCore(&p.Endpoints[0], "1.14.4") ||
		RealmNeedsNewerCore(&p.Endpoints[0], "") || RealmNeedsNewerCore(&plain, "1.13.21") {
		t.Error("RealmNeedsNewerCore must flag only a realm on a known pre-1.14 core")
	}

	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		return
	}
	ver := singboxVersionOf(t, bin)
	res, err = Generate(hy2RealmProfile(), Options{MixedPort: 7890, CoreVersion: ver, CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if err != nil {
		t.Fatalf("generate for %s: %v", strings.SplitN(ver, "\n", 2)[0], err)
	}
	if _, ok := hy2Outbounds(res.Config)["hy-realm"]["realm"]; ok != (coreMinor(ver) >= 14) {
		t.Fatalf("sing-box %s: realm rendered = %v", strings.SplitN(ver, "\n", 2)[0], ok)
	}
	data, _ := json.MarshalIndent(res.Config, "", "  ")
	f := filepath.Join(t.TempDir(), "hy2-realm.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", f).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check rejected the Hysteria2 realm config: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "deprecated") {
		t.Fatalf("sing-box warned about a deprecated field:\n%s", out)
	}
}
