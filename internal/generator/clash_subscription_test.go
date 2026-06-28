package generator

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"wakeroute/internal/importer"
	"wakeroute/internal/model"
)

// TestClashSubscriptionGenerate exercises the clash-YAML import path (ParseClash, a custom
// flat-map parser with clash-specific field names + nested ws/grpc/reality opts) end-to-end:
// a diverse clash subscription → endpoints → one combined config → (WR_SINGBOX) a real
// sing-box check on both pinned versions. This is the path my share-link transport-matrix
// test does NOT cover (clash uses different field names than share-links). Keys are computed
// so they are structurally valid (std-base64 for WG/SS-2022, base64url for the reality pbk).
func TestClashSubscriptionGenerate(t *testing.T) {
	const uuid = "11111111-2222-3333-4444-555555555555"
	pbk := base64.RawURLEncoding.EncodeToString(make([]byte, 32)) // reality x25519
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))    // WG + SS-2022 32-byte key

	yaml := fmt.Sprintf(`proxies:
  - name: vless-reality-tcp
    type: vless
    server: 203.0.113.10
    port: 443
    uuid: %[1]s
    network: tcp
    tls: true
    servername: www.microsoft.com
    client-fingerprint: chrome
    flow: xtls-rprx-vision
    reality-opts:
      public-key: %[2]s
      short-id: ab12
  - name: vless-ws
    type: vless
    server: 203.0.113.10
    port: 443
    uuid: %[1]s
    network: ws
    tls: true
    servername: ex.com
    ws-opts:
      path: /ws
      headers:
        Host: ex.com
  - name: vless-grpc
    type: vless
    server: 203.0.113.10
    port: 443
    uuid: %[1]s
    network: grpc
    tls: true
    servername: ex.com
    grpc-opts:
      grpc-service-name: gsvc
  - name: vmess-ws
    type: vmess
    server: 203.0.113.10
    port: 443
    uuid: %[1]s
    alterId: 0
    cipher: auto
    network: ws
    tls: true
    servername: ex.com
    ws-opts:
      path: /vm
  - name: trojan-grpc
    type: trojan
    server: 203.0.113.10
    port: 443
    password: pw
    network: grpc
    sni: ex.com
    grpc-opts:
      grpc-service-name: tsvc
  - name: ss-2022
    type: ss
    server: 203.0.113.10
    port: 8388
    cipher: 2022-blake3-aes-256-gcm
    password: %[3]s
  - name: hy2
    type: hysteria2
    server: 203.0.113.10
    port: 443
    password: pw
    sni: ex.com
    skip-cert-verify: true
    obfs: salamander
    obfs-password: op
  - name: tuic
    type: tuic
    server: 203.0.113.10
    port: 443
    uuid: %[1]s
    password: pw
    congestion-controller: bbr
    udp-relay-mode: native
    alpn: [h3]
    sni: ex.com
    skip-cert-verify: true
  - name: wg
    type: wireguard
    server: 203.0.113.10
    port: 51820
    private-key: %[4]s
    public-key: %[4]s
    ip: 10.0.0.2/32
`, uuid, pbk, key, key)

	eps, errs := importer.ParseClash(yaml)
	for _, e := range errs {
		t.Logf("clash parse warning: %s", e)
	}
	if len(eps) == 0 {
		t.Fatal("ParseClash returned no endpoints")
	}
	t.Logf("parsed %d/9 proxies", len(eps))
	prof := &model.Profile{Rules: []model.Rule{{ID: "def", Default: true, Outbound: model.OutboundDirect}}}
	for i := range eps {
		eps[i].Enabled = true
		prof.Endpoints = append(prof.Endpoints, eps[i])
	}

	res, err := Generate(prof, Options{MixedPort: 7890, CacheFile: filepath.Join(t.TempDir(), "c.db")})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — ran clash-import+generate only")
	}
	data, err := json.MarshalIndent(res.Config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "clashsub.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", f).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check rejected the clash-subscription config: %v\n%s", err, strings.TrimSpace(string(out)))
	}
}
