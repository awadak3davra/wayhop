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

func openconnectTestProfile() *model.Profile {
	ep := func(id, server string, port int, params map[string]any) model.Endpoint {
		return model.Endpoint{ID: id, Name: id, Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoOpenConnect,
			Server: server, Port: port, Params: params}
	}
	return &model.Profile{
		Endpoints: []model.Endpoint{
			ep("oc-ocserv", "vpn.example.com", 443, map[string]any{"username": "u", "password": "p", "auth_group": "staff",
				"server_cert": "pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}),
			ep("oc-gp", "192.0.2.9", 8443, map[string]any{"flavor": "gp", "username": "u", "password": "p",
				"totp_secret": "JBSWY3DPEHPK3PXP", "no_udp": true}),
		},
		Rules: []model.Rule{
			{ID: "a", DomainSuffix: []string{"a.example.com"}, Outbound: "oc-gp"},
			{ID: "def", Default: true, Outbound: "oc-ocserv"},
		},
	}
}

// TestOpenConnectSingBoxCheck renders AnyConnect/ocserv (certificate pin, auth group) and
// GlobalProtect (non-default port, TOTP, TLS-only). The structure is always asserted; with
// WR_SINGBOX set, a 1.14+ core must pass `sing-box check` without a deprecation warning and an
// older one must be refused by the generator by name.
func TestOpenConnectSingBoxCheck(t *testing.T) {
	p := openconnectTestProfile()
	if _, err := Generate(p, Options{MixedPort: 7890, CoreVersion: "1.13.21"}); err == nil ||
		!strings.Contains(err.Error(), "OpenConnect needs sing-box 1.14") {
		t.Fatalf("a 1.13 core: err = %v, want the 1.14 refusal", err)
	}
	res, err := Generate(p, Options{MixedPort: 7890, CoreVersion: "1.14.4", CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if err != nil {
		t.Fatalf("generate for 1.14.4: %v", err)
	}
	eps := map[string]map[string]any{}
	for _, ep := range res.Config["endpoints"].([]map[string]any) {
		if ep["type"] == "openconnect" {
			eps[ep["tag"].(string)] = ep
		}
	}
	oc, gp := eps["oc-ocserv"], eps["oc-gp"]
	if oc == nil || oc["server"] != "https://vpn.example.com" || oc["flavor"] != nil || oc["auth_group"] != "staff" ||
		oc["tls"].(map[string]any)["peer_fingerprint"] == nil {
		t.Errorf("ocserv endpoint = %v", oc)
	}
	if gp == nil || gp["server"] != "https://192.0.2.9:8443" || gp["flavor"] != "gp" || gp["no_udp"] != true ||
		gp["token"].(map[string]any)["mode"] != "totp" {
		t.Errorf("GlobalProtect endpoint = %v", gp)
	}
	p.Endpoints[1].Params["flavor"] = "sstp"
	if _, err := Generate(p, Options{MixedPort: 7890, CoreVersion: "1.14.4"}); err == nil || !strings.Contains(err.Error(), "flavor") {
		t.Fatalf("an unknown flavor: err = %v, want the flavor refusal", err)
	}
	p.Endpoints[1].Params["flavor"] = "gp"

	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		return
	}
	ver := singboxVersionOf(t, bin)
	res, err = Generate(p, Options{MixedPort: 7890, CoreVersion: ver, CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if coreMinor(ver) < openconnectMinMinor {
		if err == nil {
			t.Fatalf("sing-box %s has no openconnect endpoint, but the generator rendered one", strings.SplitN(ver, "\n", 2)[0])
		}
		return
	}
	if err != nil {
		t.Fatalf("generate for %s: %v", strings.SplitN(ver, "\n", 2)[0], err)
	}
	data, _ := json.MarshalIndent(res.Config, "", "  ")
	f := filepath.Join(t.TempDir(), "openconnect.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", f).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check rejected the OpenConnect config: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "deprecated") {
		t.Fatalf("sing-box warned about a deprecated field:\n%s", out)
	}
}
