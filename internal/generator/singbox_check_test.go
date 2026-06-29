package generator

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"velinx/internal/model"
)

// allProtocolProfile builds a profile with one endpoint per stable sing-box-native
// protocol the generator emits, plus a group, a route rule and a routing list,
// using minimally-VALID params (correct key lengths) so a real `sing-box check`
// accepts the result, not just structural generation.
//
// The protocol table is the SAFETY CONTRACT for the Init-Server provisioner: it
// MUST carry a representative endpoint for EVERY protocol the provisioner can hand
// a user, in the SAME SHAPE the provisioner's WR_CLIENT_CONFIG link decodes to (see
// internal/initserver/initserver.go scriptReality / scriptVMess / scriptTrojan /
// scriptShadowsocks / scriptHysteria2 / scriptTUIC / scriptWireGuard / scriptAmneziaWG).
// If any provisionable protocol produced a config a real sing-box rejects, the user
// would get a dead link; this test fails first. The 8 provisionable protocols are:
//
//	AmneziaWG, plain WireGuard, VLESS-Reality, VMess (ws+tls insecure),
//	Trojan (tls insecure), Shadowsocks (2022-blake3-aes-256-gcm), Hysteria2
//	(quic+tls insecure), TUIC (quic+tls insecure, cc=bbr).
//
// (SOCKS + HTTP are not provisioner-facing but are kept here so the generator's
// remaining outbound types stay covered by the real `check` too.)
//
// Native WireGuard IS included: the generator now emits it as a top-level
// `endpoints` entry (the 1.11+ schema) instead of the `wireguard` outbound that
// 1.11 deprecated and 1.13 removed. That endpoint form is accepted by BOTH the
// deployed 1.12.x and 1.13.x, so it is no longer version-sensitive and a real
// `check` validates it on every pinned sing-box the CI runs. AmneziaWG is a plugin
// engine: the generator emits it as a `direct` outbound bound to the awg interface
// (plus a Plugin record), which a real `check` accepts.
func allProtocolProfile() *model.Profile {
	ssKey128 := base64.StdEncoding.EncodeToString(make([]byte, 16)) // 2022-blake3-aes-128-gcm wants a 16-byte key
	ssKey256 := base64.StdEncoding.EncodeToString(make([]byte, 32)) // 2022-blake3-aes-256-gcm (the provisioner cipher) wants a 32-byte key
	wgKey := base64.StdEncoding.EncodeToString(make([]byte, 32))    // WireGuard keys are 32-byte base64
	uuid := "11111111-1111-1111-1111-111111111111"
	// A valid x25519 reality public key is the base64 of 32 bytes; the generator
	// drops a reality block whose public_key is malformed (validRealityPubKey), which
	// would silently downgrade the endpoint, so use a real-length key. short_id is
	// even-length hex (<=16 chars), matching `sing-box generate rand --hex 8`.
	realityPub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	realitySID := "0123456789abcdef"
	// Hysteria2 and TUIC run over QUIC+TLS and sing-box rejects them without a tls
	// block ("TLS required"); attach one. The provisioner's self-signed cert makes
	// the importer set insecure=1 + alpn h3, so mirror that exact shape.
	withQUICTLS := func(e model.Endpoint) model.Endpoint {
		e.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: "velinx.local", Insecure: true, ALPN: []string{"h3"}}
		return e
	}
	// VLESS-Reality endpoint mirrors scriptReality's link:
	// vless://uuid@host:443?security=reality&sni=...&fp=chrome&pbk=...&sid=...&flow=xtls-rprx-vision&type=tcp
	vlessReality := generator_singBoxEndpoint("p-vless", model.ProtoVLESS, map[string]any{"uuid": uuid, "flow": "xtls-rprx-vision"})
	vlessReality.TLS = &model.TLS{Enabled: true, Type: "reality", SNI: "www.microsoft.com", Fingerprint: "chrome", PublicKey: realityPub, ShortID: realitySID}
	// VMess endpoint mirrors scriptVMess's link: vmess over ws + self-signed TLS
	// (allowInsecure=1) on the /velinx path.
	vmess := generator_singBoxEndpoint("p-vmess", model.ProtoVMess, map[string]any{"uuid": uuid, "alter_id": 0, "security": "auto"})
	vmess.Transport = &model.Transport{Type: "ws", Path: "/velinx", Host: "velinx.local"}
	vmess.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: "velinx.local", Insecure: true, Fragment: true, RecordFragment: true}
	// Trojan endpoint mirrors scriptTrojan's link: trojan over TLS (self-signed,
	// insecure=1).
	trojan := generator_singBoxEndpoint("p-trojan", model.ProtoTrojan, map[string]any{"password": "pw"})
	trojan.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: "velinx.local", Insecure: true}
	// AnyTLS endpoint: password + TLS (self-signed, insecure=1), like Trojan (sing-box 1.12+).
	anytls := generator_singBoxEndpoint("p-anytls", model.ProtoAnyTLS, map[string]any{"password": "pw"})
	anytls.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: "velinx.local", Insecure: true}
	// AmneziaWG endpoint mirrors scriptAmneziaWG: a WG-shaped peer that the plugin
	// engine brings up; the generator emits a `direct` outbound bound to its iface.
	awg := generator_singBoxEndpoint("p-awg", model.ProtoAmneziaWG, map[string]any{
		"private_key": wgKey, "peer_public_key": wgKey, "local_address": []string{"10.0.0.2/32"},
	})
	awg.Engine = model.EngineAmneziaWG
	// An adopted native OS tunnel (EngineExternal, the /api/vpn/adopt output): the generator emits a
	// `direct` outbound bound to the interface (no Plugin). Covers that path in the real sing-box check.
	ext := generator_singBoxEndpoint("p-ext", model.ProtoWireGuard, map[string]any{"interface": "wg-native"})
	ext.Engine = model.EngineExternal
	eps := []model.Endpoint{
		vlessReality,
		vmess,
		trojan,
		anytls,
		generator_singBoxEndpoint("p-ss", model.ProtoShadowsocks, map[string]any{"method": "2022-blake3-aes-256-gcm", "password": ssKey256}),
		// Keep the 128-bit cipher covered too (the importer/generator support both).
		generator_singBoxEndpoint("p-ss128", model.ProtoShadowsocks, map[string]any{"method": "2022-blake3-aes-128-gcm", "password": ssKey128}),
		withQUICTLS(generator_singBoxEndpoint("p-hy2", model.ProtoHysteria2, map[string]any{"password": "pw", "obfs": "salamander", "obfs_password": "op"})),
		withQUICTLS(generator_singBoxEndpoint("p-tuic", model.ProtoTUIC, map[string]any{"uuid": uuid, "password": "pw", "congestion_control": "bbr", "udp_relay_mode": "native"})),
		generator_singBoxEndpoint("p-socks", model.ProtoSOCKS, map[string]any{}),
		generator_singBoxEndpoint("p-http", model.ProtoHTTP, map[string]any{}),
		// Native WireGuard → top-level `endpoints` entry. Real 32-byte keys so
		// sing-box's config build (which base64-decodes them) accepts the config.
		generator_singBoxEndpoint("p-wg", model.ProtoWireGuard, map[string]any{
			"private_key": wgKey, "peer_public_key": wgKey, "local_address": []string{"10.0.0.2/32"},
		}),
		awg,
		ext,
	}
	return &model.Profile{
		Endpoints: eps,
		Groups: []model.Group{
			// urltest carries the opt-in interrupt-on-switch flag (emits interrupt_exist_connections).
			{ID: "g", Name: "G", Type: model.GroupURLTest, Members: []string{"p-vless", "p-hy2"}, InterruptOnSwitch: true},
			// a selector group covers the selector outbound (and interrupt_exist_connections on it too).
			{ID: "sel", Name: "S", Type: model.GroupSelector, Members: []string{"p-trojan", "p-vmess"}, InterruptOnSwitch: true},
		},
		Rules: []model.Rule{
			{ID: "r1", DomainSuffix: []string{"example.com"}, Outbound: "g"},
			// a source-based rule covers the sing-box source_ip_cidr + source_port matchers.
			{ID: "src", SourceIPCIDR: []string{"192.168.50.0/24"}, SourcePort: []int{8080}, Outbound: "sel"},
			{ID: "def", Default: true, Outbound: model.OutboundDirect},
		},
		RoutingLists: []model.RoutingList{
			{ID: "rl", Name: "L", Manual: []string{"openai.com", "1.2.3.0/24"}, Outbound: "p-tuic", Enabled: true},
		},
	}
}

// TestAllProtocolsGenerate asserts every supported protocol generates its outbound
// (the per-protocol "each element" structural check, always run). When WR_SINGBOX
// points at a sing-box binary (CI sets this after downloading sing-box), it also
// validates the whole config with `sing-box check` — catching any protocol whose
// emitted JSON the real core would reject.
func TestAllProtocolsGenerate(t *testing.T) {
	p := allProtocolProfile()
	res, err := Generate(p, Options{MixedPort: 7890, CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if err != nil {
		t.Fatalf("generate all-protocols config: %v", err)
	}
	got := map[string]bool{}
	for _, ob := range res.Config["outbounds"].([]map[string]any) {
		if tp, _ := ob["type"].(string); tp != "" {
			got[tp] = true
		}
	}
	// Native WireGuard lives in the top-level `endpoints` array, not outbounds.
	if eps, ok := res.Config["endpoints"].([]map[string]any); ok {
		for _, ep := range eps {
			if tp, _ := ep["type"].(string); tp != "" {
				got[tp] = true
			}
		}
	}
	for _, want := range []string{"vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic", "socks", "http", "urltest", "direct", "wireguard"} {
		if !got[want] {
			t.Errorf("generated config is missing outbound/endpoint type %q", want)
		}
	}

	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — ran generation-only (set it to a sing-box binary for a real `check`)")
	}
	data, err := json.MarshalIndent(res.Config, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "all-protocols.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", f).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check rejected the all-protocols config: %v\n%s", err, strings.TrimSpace(string(out)))
	}
}
