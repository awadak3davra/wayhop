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

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// TestWireGuardConfGenerate sweeps diverse plain-WireGuard wg-quick `.conf` imports (the one
// import format not covered by the share-link / clash matrices) through the real
// importer→generator path and — when WR_SINGBOX is set — validates the combined config with a
// real sing-box on both pinned versions. A plain WG .conf (no AmneziaWG Jc/Jmin/… params) maps
// to a native sing-box wireguard endpoint (EngineSingBox → endpointFor), so it is sing-box-
// checkable. Edge cases: dual-stack address/allowed-ips, PSK+MTU+keepalive+DNS, a bracketed
// IPv6 endpoint, and a multi-[Peer] mesh. Keys are computed std-base64 (valid 32-byte WG keys).
func TestWireGuardConfGenerate(t *testing.T) {
	k1 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	b2 := make([]byte, 32)
	for i := range b2 {
		b2[i] = 0x11
	}
	k2 := base64.StdEncoding.EncodeToString(b2)

	confs := map[string]string{
		"wg-basic":         fmt.Sprintf("[Interface]\nPrivateKey = %[1]s\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = %[2]s\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n", k1, k2),
		"wg-dualstack":     fmt.Sprintf("[Interface]\nPrivateKey = %[1]s\nAddress = 10.0.0.2/32, fd00::2/128\n\n[Peer]\nPublicKey = %[2]s\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n", k1, k2),
		"wg-psk-mtu-ka":    fmt.Sprintf("[Interface]\nPrivateKey = %[1]s\nAddress = 10.0.0.2/32\nMTU = 1280\nDNS = 1.1.1.1\n\n[Peer]\nPublicKey = %[2]s\nPresharedKey = %[1]s\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n", k1, k2),
		"wg-ipv6-endpoint": fmt.Sprintf("[Interface]\nPrivateKey = %[1]s\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = %[2]s\nEndpoint = [2001:db8::1]:51820\nAllowedIPs = 0.0.0.0/0\n", k1, k2),
		"wg-multipeer":     fmt.Sprintf("[Interface]\nPrivateKey = %[1]s\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = %[2]s\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 10.0.0.0/24\n\n[Peer]\nPublicKey = %[1]s\nEndpoint = 5.6.7.8:51820\nAllowedIPs = 0.0.0.0/0\n", k1, k2),
	}

	prof := &model.Profile{Rules: []model.Rule{{ID: "def", Default: true, Outbound: model.OutboundDirect}}}
	for name, conf := range confs {
		ep, err := importer.Parse(conf)
		if err != nil {
			t.Fatalf("%s: import: %v", name, err)
		}
		if ep.Protocol != model.ProtoWireGuard || ep.Engine != model.EngineSingBox {
			t.Errorf("%s: expected native WireGuard (sing-box), got proto=%v engine=%v", name, ep.Protocol, ep.Engine)
		}
		ep.ID, ep.Name, ep.Enabled = name, name, true
		prof.Endpoints = append(prof.Endpoints, *ep)
	}

	res, err := Generate(prof, Options{MixedPort: 7890, CacheFile: filepath.Join(t.TempDir(), "c.db")})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — ran WG-.conf import+generate only")
	}
	data, err := json.MarshalIndent(res.Config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "wgconf.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", f).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check rejected the WG-.conf config: %v\n%s", err, strings.TrimSpace(string(out)))
	}
}
