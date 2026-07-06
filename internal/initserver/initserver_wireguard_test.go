package initserver

import (
	"encoding/base64"
	"strings"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// A representative plain-WireGuard client .conf in the exact shape scriptWireGuard
// emits (with PUBLIC_IP / keys filled in by the shell). It carries NONE of
// AmneziaWG's obfuscation params, so it imports as a plain WireGuard endpoint.
const wgSampleConf = `[Interface]
PrivateKey = aW50ZXJmYWNlLXByaXZhdGUta2V5LTMyLWJ5dGVzPT0=
Address = 10.14.14.2/32
DNS = 1.1.1.1
[Peer]
PublicKey = c2VydmVyLXB1YmxpYy1rZXktMzItYnl0ZXMtcGFkZD0=
Endpoint = 203.0.113.9:51821
AllowedIPs = 0.0.0.0/0`

// TestWireGuardOptionRegistered confirms the plain-WireGuard Option is in the
// catalog with a non-empty script + detector + a distinct port, and that it is a
// separate id from AmneziaWG (not a rename/replacement).
func TestWireGuardOptionRegistered(t *testing.T) {
	if ProtoWireGuard != string(model.ProtoWireGuard) {
		t.Errorf("ProtoWireGuard=%q must match model.ProtoWireGuard=%q", ProtoWireGuard, model.ProtoWireGuard)
	}
	if !ValidOption(ProtoWireGuard) {
		t.Fatal("WireGuard: not a valid option")
	}
	o := optionByID(ProtoWireGuard)
	if o == nil {
		t.Fatal("WireGuard: optionByID returned nil")
	}
	if o.Name != "WireGuard" {
		t.Errorf("WireGuard: Name=%q, want %q", o.Name, "WireGuard")
	}
	if o.Script == "" {
		t.Error("WireGuard: empty Script")
	}
	if o.Detect == nil {
		t.Error("WireGuard: nil Detect")
	}
	if o.Summary == "" {
		t.Error("WireGuard: empty Summary")
	}
	if len(o.Details) == 0 {
		t.Error("WireGuard: empty Details")
	}
	if o.Transport != "udp" {
		t.Errorf("WireGuard: Transport=%q, want udp", o.Transport)
	}
	// AmneziaWG (:51820) and WireGuard (:51821) must be distinct so they coexist.
	if o.Port != 51821 {
		t.Errorf("WireGuard: Port=%d, want 51821", o.Port)
	}
	if awg := optionByID(ProtoAmneziaWG); awg != nil && awg.Port == o.Port {
		t.Errorf("WireGuard port %d collides with AmneziaWG port %d", o.Port, awg.Port)
	}
}

// TestWireGuardBuildScriptFragment confirms selecting WireGuard emits its fragment:
// the standard wireguard install (NOT amneziawg), the wg keygen, the server
// wg0.conf [Interface]+[Peer], wg-quick enable, the UDP port open, the marker, and
// the base64 client-config line. It also confirms the AmneziaWG fragment is absent
// for a WireGuard-only build (they are not the same script).
func TestWireGuardBuildScriptFragment(t *testing.T) {
	s := BuildScript([]string{ProtoWireGuard}, "203.0.113.9")
	for _, want := range []string{
		"#!/bin/sh",
		"# ---- WireGuard ----",
		"apt-get install -y wireguard wireguard-tools",
		"wg genkey",
		"wg pubkey",
		"ListenPort = 51821",
		"Address = 10.14.14.1/24",
		"AllowedIPs = 10.14.14.2/32",
		"wg-quick up wg0",
		"systemctl enable wg-quick@wg0",
		"iptables -I INPUT -p udp --dport 51821",
		"MASQUERADE",
		"WR_PROTO=wireguard",
		"WR_CLIENT_CONFIG_B64=",
		`PUBLIC_IP="203.0.113.9"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("WireGuard script missing %q", want)
		}
	}
	// A plain-WireGuard build must NOT pull in AmneziaWG (no awg tooling / PPA / its
	// obfuscation params), proving the two fragments are independent.
	for _, notWant := range []string{"# ---- AmneziaWG ----", "awg genkey", "add-apt-repository", "ppa:amnezia/ppa", "Jc = "} {
		if strings.Contains(s, notWant) {
			t.Errorf("WireGuard-only script unexpectedly contains %q", notWant)
		}
	}
}

// TestWireGuardPersistsKeys guards idempotence: the server + client keys are
// generated only when ABSENT (the `[ -f ... ] || wg genkey` guard) so a re-run
// reuses them and existing clients keep working — never rotating on re-provision.
func TestWireGuardPersistsKeys(t *testing.T) {
	s := BuildScript([]string{ProtoWireGuard}, "")
	for _, guard := range []string{
		"[ -f wg-server.key ] || wg genkey > wg-server.key",
		"[ -f wg-client.key ] || wg genkey > wg-client.key",
	} {
		if !strings.Contains(s, guard) {
			t.Errorf("WireGuard missing reuse-on-rerun key guard %q", guard)
		}
	}
}

// TestWireGuardMarkerPrecedesConfig re-asserts the ExtractTagged contract: the
// WR_PROTO=wireguard marker appears immediately before its WR_CLIENT_CONFIG_B64 line
// with no other WR_PROTO marker between them.
func TestWireGuardMarkerPrecedesConfig(t *testing.T) {
	s := BuildScript([]string{ProtoWireGuard}, "")
	const marker = "WR_PROTO=wireguard"
	iProto := strings.Index(s, marker)
	if iProto < 0 {
		t.Fatalf("missing marker %q", marker)
	}
	rest := s[iProto+len(marker):]
	iCfg := strings.Index(rest, "WR_CLIENT_CONFIG")
	if iCfg < 0 {
		t.Fatal("no WR_CLIENT_CONFIG follows the marker")
	}
	if strings.Contains(rest[:iCfg], "WR_PROTO=") {
		t.Error("a second WR_PROTO marker sits between the marker and its config")
	}
}

// TestWireGuardClientConfRoundTrips is the end-to-end contract: simulate the
// installer output (the shell base64-encodes the client .conf after the marker),
// feed it to ExtractTagged, and assert (a) the marker attributes it to wireguard,
// (b) the decoded payload is the exact .conf, and (c) the .conf imports to a plain
// model.ProtoWireGuard endpoint (NOT AmneziaWG) — proving the emitted config is a
// real, importable standard-WireGuard client.
func TestWireGuardClientConfRoundTrips(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte(wgSampleConf))
	out := "[wayhop-init] installing WireGuard...\n" +
		"WR_PROTO=wireguard\n" +
		"WR_CLIENT_CONFIG_B64=" + b64 + "\n" +
		"[wayhop-init] done\n"

	tagged := ExtractTagged(out)
	if len(tagged) != 1 {
		t.Fatalf("ExtractTagged returned %d configs, want 1", len(tagged))
	}
	if tagged[0].Proto != ProtoWireGuard {
		t.Errorf("tagged proto = %q, want %q", tagged[0].Proto, ProtoWireGuard)
	}
	if tagged[0].Config != wgSampleConf {
		t.Errorf("tagged config mangled\n got=%q\nwant=%q", tagged[0].Config, wgSampleConf)
	}

	ep, err := importer.Parse(tagged[0].Config)
	if err != nil {
		t.Fatalf("emitted .conf does not import: %v", err)
	}
	if ep.Protocol != model.ProtoWireGuard {
		t.Errorf("imported protocol = %q, want %q (a plain WG conf must NOT be read as AmneziaWG)", ep.Protocol, model.ProtoWireGuard)
	}
	if ep.Server != "203.0.113.9" || ep.Port != 51821 {
		t.Errorf("imported endpoint = %s:%d, want 203.0.113.9:51821", ep.Server, ep.Port)
	}
}

// TestWireGuardDetectFallback confirms the catalog detector recognises a plain-WG
// .conf (so a marker-less config still attributes), and — importantly — does NOT
// claim an AmneziaWG .conf (which carries the Jc/H1… obfuscation params).
func TestWireGuardDetectFallback(t *testing.T) {
	o := optionByID(ProtoWireGuard)
	if o == nil || o.Detect == nil {
		t.Fatal("WireGuard option/detector missing")
	}
	if !o.Detect(wgSampleConf) {
		t.Error("WireGuard detector should match a plain-WG .conf")
	}
	awgConf := wgSampleConf + "\nJc = 4\nH1 = 1234567"
	if o.Detect(awgConf) {
		t.Error("WireGuard detector must NOT claim an AmneziaWG .conf (has Jc/H1)")
	}
	if o.Detect("vless://uuid@host:443") {
		t.Error("WireGuard detector must NOT match a non-WG payload")
	}
}

// TestWireGuardCombinedWithAmneziaWG confirms a mixed AmneziaWG + WireGuard build
// emits BOTH fragments and BOTH markers on their distinct ports — proving the two
// WireGuard variants coexist rather than one overwriting the other.
func TestWireGuardCombinedWithAmneziaWG(t *testing.T) {
	s := BuildScript([]string{ProtoAmneziaWG, ProtoWireGuard}, "198.51.100.5")
	for _, want := range []string{
		"# ---- AmneziaWG ----",
		"# ---- WireGuard ----",
		"WR_PROTO=amneziawg",
		"WR_PROTO=wireguard",
		"ListenPort = 51820", // AmneziaWG
		"ListenPort = 51821", // WireGuard
		"awg genkey",
		"wg genkey",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("combined AmneziaWG+WireGuard build missing %q", want)
		}
	}
	// Both client configs round-trip: simulate the two base64 conf lines and confirm
	// ExtractTagged returns one tagged config per protocol, in order.
	awgConf := "[Interface]\nPrivateKey = k\nJc = 4\nH1 = 1234567\n[Peer]\nPublicKey = p\nEndpoint = 198.51.100.5:51820\nAllowedIPs = 0.0.0.0/0"
	out := "WR_PROTO=amneziawg\nWR_CLIENT_CONFIG_B64=" + base64.StdEncoding.EncodeToString([]byte(awgConf)) + "\n" +
		"WR_PROTO=wireguard\nWR_CLIENT_CONFIG_B64=" + base64.StdEncoding.EncodeToString([]byte(wgSampleConf)) + "\n"
	tagged := ExtractTagged(out)
	if len(tagged) != 2 {
		t.Fatalf("ExtractTagged returned %d, want 2", len(tagged))
	}
	if tagged[0].Proto != ProtoAmneziaWG {
		t.Errorf("tagged[0].Proto = %q, want %q", tagged[0].Proto, ProtoAmneziaWG)
	}
	if tagged[1].Proto != ProtoWireGuard {
		t.Errorf("tagged[1].Proto = %q, want %q", tagged[1].Proto, ProtoWireGuard)
	}
}
