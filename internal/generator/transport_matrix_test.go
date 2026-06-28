package generator

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"wakeroute/internal/importer"
	"wakeroute/internal/model"
)

// TestGeneratorTransportMatrix imports a spread of real-world share-links that vary the
// TRANSPORT (ws / grpc / httpupgrade / tcp) and TLS (tls / reality) dimensions the single
// all-protocols config does not exercise, generates ONE combined config, and — when
// WR_SINGBOX is set (CI singbox-check job) — validates the whole thing with a real sing-box
// on both pinned versions. Guards the import→generate transport/TLS matrix against
// regressions (a transport mis-emitted, or the flow gate breaking). The pbk is base64url of
// 32 zero bytes (a structurally valid x25519 reality key).
func TestGeneratorTransportMatrix(t *testing.T) {
	const pbk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const uuid = "11111111-2222-3333-4444-555555555555"
	cases := map[string]string{
		"vless-ws-tls":           "vless://" + uuid + "@203.0.113.10:443?encryption=none&security=tls&sni=ex.com&type=ws&path=%2Fws&host=ex.com&fp=chrome#t",
		"vless-grpc-tls":         "vless://" + uuid + "@203.0.113.10:443?encryption=none&security=tls&sni=ex.com&type=grpc&serviceName=gsvc&fp=chrome#t",
		"vless-httpupgrade-tls":  "vless://" + uuid + "@203.0.113.10:443?encryption=none&security=tls&sni=ex.com&type=httpupgrade&path=%2Fhu&host=ex.com#t",
		"vless-reality-tcp-flow": "vless://" + uuid + "@203.0.113.10:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=" + pbk + "&sid=ab12&type=tcp&flow=xtls-rprx-vision#t",
		"vless-reality-grpc":     "vless://" + uuid + "@203.0.113.10:443?encryption=none&security=reality&sni=www.microsoft.com&fp=firefox&pbk=" + pbk + "&sid=ab12&type=grpc&serviceName=gsvc&flow=xtls-rprx-vision#t",
		"trojan-grpc-tls":        "trojan://pw@203.0.113.10:443?security=tls&sni=ex.com&type=grpc&serviceName=gsvc#t",
		"trojan-ws-tls":          "trojan://pw@203.0.113.10:443?security=tls&sni=ex.com&type=ws&path=%2Fws&host=ex.com#t",
		"hy2-obfs":               "hysteria2://pw@203.0.113.10:443?obfs=salamander&obfs-password=op&sni=ex.com&insecure=1#t",
		"tuic-bbr":               "tuic://" + uuid + ":pw@203.0.113.10:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=ex.com&allow_insecure=1#t",
	}
	prof := &model.Profile{Rules: []model.Rule{{ID: "def", Default: true, Outbound: model.OutboundDirect}}}
	for name, link := range cases {
		ep, err := importer.Parse(link)
		if err != nil {
			t.Fatalf("%s: import: %v", name, err)
		}
		ep.ID, ep.Name, ep.Enabled = name, name, true
		prof.Endpoints = append(prof.Endpoints, *ep)
	}

	res, err := Generate(prof, Options{MixedPort: 7890, CacheFile: filepath.Join(t.TempDir(), "c.db")})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// flow (xtls-rprx-vision) must be KEPT on the tcp+reality endpoint and DROPPED on the grpc
	// one — vision runs only over a raw TLS-over-tcp stream (the singbox.go flow gate).
	flowByTag := map[string]any{}
	obs, _ := res.Config["outbounds"].([]map[string]any)
	for _, ob := range obs {
		if tag, _ := ob["tag"].(string); tag != "" {
			flowByTag[tag] = ob["flow"]
		}
	}
	if flowByTag["vless-reality-tcp-flow"] != "xtls-rprx-vision" {
		t.Errorf("flow should be kept on tcp+reality, got %v", flowByTag["vless-reality-tcp-flow"])
	}
	if f := flowByTag["vless-reality-grpc"]; f != nil && f != "" {
		t.Errorf("flow must be dropped on a grpc transport (vision is tcp-only), got %v", f)
	}

	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — ran import+generate only (set it for a real sing-box check)")
	}
	data, err := json.MarshalIndent(res.Config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "matrix.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", f).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check rejected the transport-matrix config: %v\n%s", err, strings.TrimSpace(string(out)))
	}
}
