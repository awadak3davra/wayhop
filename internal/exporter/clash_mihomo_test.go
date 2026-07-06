package exporter

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// TestClashExportMihomo validates the clash SUBSCRIPTION export against the REAL mihomo
// (clash-meta) client via `mihomo -t` — the export analog of the generator's sing-box check.
// Until now the clash export was only round-trip tested (export → re-import into WayHop),
// which proves WayHop can re-read its own output but NOT that a mihomo client accepts it.
// The clash subscription — including the failover proxy-groups (url-test / fallback / select,
// with a nested group reference) — is a primary user-facing path, so a field mihomo rejects
// would break every subscribed client. Runs the real check only when WR_MIHOMO points at a
// mihomo binary; otherwise asserts the export is structurally complete.
func TestClashExportMihomo(t *testing.T) {
	const uuid = "11111111-2222-3333-4444-555555555555"
	const pbk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	links := map[string]string{
		"vless-ws-tls":           "vless://" + uuid + "@203.0.113.10:443?encryption=none&security=tls&sni=ex.com&type=ws&path=%2Fws&host=ex.com&fp=chrome#t",
		"vless-reality-tcp-flow": "vless://" + uuid + "@203.0.113.10:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=" + pbk + "&sid=ab12&type=tcp&flow=xtls-rprx-vision#t",
		"trojan-grpc-tls":        "trojan://pw@203.0.113.10:443?security=tls&sni=ex.com&type=grpc&serviceName=gsvc#t",
		"trojan-ws-tls":          "trojan://pw@203.0.113.10:443?security=tls&sni=ex.com&type=ws&path=%2Fws&host=ex.com#t",
		"hy2-obfs":               "hysteria2://pw@203.0.113.10:443?obfs=salamander&obfs-password=op&sni=ex.com&insecure=1#t",
		"tuic-bbr":               "tuic://" + uuid + ":pw@203.0.113.10:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=ex.com&allow_insecure=1#t",
	}
	var eps []model.Endpoint
	for name, link := range links {
		ep, err := importer.Parse(link)
		if err != nil {
			t.Fatalf("%s: import: %v", name, err)
		}
		ep.ID, ep.Name, ep.Enabled = name, name, true
		eps = append(eps, *ep)
	}
	groups := []model.Group{
		{ID: "g-auto", Name: "Auto", Type: model.GroupURLTest, Members: []string{"vless-ws-tls", "trojan-grpc-tls"}},
		{ID: "g-fb", Name: "Fallback", Type: model.GroupFallback, Members: []string{"hy2-obfs", "tuic-bbr"}},
		{ID: "g-pick", Name: "Pick", Type: model.GroupSelector, Members: []string{"vless-ws-tls", "g-auto"}}, // nested group ref
	}

	yaml, warns := ClashConfigWithGroups(eps, groups)
	for _, w := range warns {
		t.Logf("clash export warning: %s", w)
	}
	for _, must := range []string{"proxies:", "proxy-groups:", "rules:"} {
		if !strings.Contains(yaml, must) {
			t.Fatalf("clash export missing %q section:\n%s", must, yaml)
		}
	}

	bin := os.Getenv("WR_MIHOMO")
	if bin == "" {
		t.Skip("WR_MIHOMO not set — exported + structurally checked only (set it to a mihomo binary for a real -t check)")
	}
	dir := t.TempDir()
	f := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(f, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "-t", "-f", f, "-d", dir).CombinedOutput(); err != nil {
		t.Fatalf("mihomo rejected the exported clash config: %v\n%s", err, strings.TrimSpace(string(out)))
	}
}
