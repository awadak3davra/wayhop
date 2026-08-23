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

// TestYamlScalar_QuotesYAMLRetypedTokens: a YAML resolver (yaml.v3, which mihomo uses)
// re-types bare "007" as int 7, "+7" as 7, "0x1A" as 26, "0o17"/"0b101" as radix ints,
// a >int64 digit run as a float, and ".inf"/".NaN" as float specials. Left bare, a
// password/name of that shape reaches a strict clash client as a DIFFERENT string
// ("007" -> "7" — silent auth failure). yamlScalar must quote every such token; only a
// canonical base-10 integer (round-trips to identical text) may stay bare.
func TestYamlScalar_QuotesYAMLRetypedTokens(t *testing.T) {
	mustQuote := []string{"007", "+7", "0x1A", "0o17", "0b101", "1_000", ".inf", ".Inf", ".NaN", "-.inf", "99999999999999999999"}
	for _, s := range mustQuote {
		if got := yamlScalar(s); got == s {
			t.Errorf("yamlScalar(%q) left bare — a YAML resolver re-types it (want quoted)", s)
		}
	}
	// Canonical ints and ordinary strings stay bare (no noise regression).
	bare := []string{"42", "0", "password123", "50 Mbps", "aes-256-gcm", "1.2.3.4"}
	for _, s := range bare {
		if got := yamlScalar(s); got != s {
			t.Errorf("yamlScalar(%q) = %q, want bare", s, got)
		}
	}
}

// TestClashExport_LeadingZeroPasswordQuoted: end-to-end guard for the retyping fix — a
// trojan endpoint whose password is "007" must render with the password QUOTED in the
// clash YAML and survive a round-trip through our own importer unchanged.
func TestClashExport_LeadingZeroPasswordQuoted(t *testing.T) {
	e := model.Endpoint{
		ID: "t1", Name: "t1", Enabled: true,
		Engine: model.EngineSingBox, Protocol: model.ProtoTrojan,
		Server: "1.2.3.4", Port: 443,
		Params: map[string]any{"password": "007"},
		TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "ex.com"},
	}
	yaml, _ := ClashConfig([]model.Endpoint{e})
	if !strings.Contains(yaml, `password: "007"`) {
		t.Fatalf("password 007 not quoted in clash export:\n%s", yaml)
	}
	eps, err := importer.ParseClash(yaml)
	if err != nil {
		t.Fatalf("re-import: %v", err)
	}
	if len(eps) != 1 {
		t.Fatalf("re-import: got %d endpoints, want 1", len(eps))
	}
	if pw, _ := eps[0].Params["password"].(string); pw != "007" {
		t.Errorf("round-trip password = %q, want \"007\"", pw)
	}
}
