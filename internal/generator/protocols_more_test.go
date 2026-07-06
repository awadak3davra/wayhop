package generator

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"wayhop/internal/model"
)

// wgTestPrivKey and wgTestPubKey are valid 32-byte WireGuard base64 keys used
// in unit tests. endpointFor validates that keys decode to exactly 32 bytes;
// the short placeholder keys ("k", "p", "priv==") used before the [64] fix
// no longer satisfy that check and have been replaced with these constants.
var (
	wgTestPrivKey = base64.StdEncoding.EncodeToString([]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}) // "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="
	wgTestPubKey = base64.StdEncoding.EncodeToString([]byte{
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
	}) // "ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A="
)

// generator_singBoxEndpoint builds a minimal valid sing-box endpoint of the
// given protocol. Caller fills Params/TLS/Transport as needed. Server, port and
// a non-empty id keep model.Validate happy.
func generator_singBoxEndpoint(id string, proto model.Protocol, params map[string]any) model.Endpoint {
	return model.Endpoint{
		ID:       id,
		Name:     id,
		Engine:   model.EngineSingBox,
		Protocol: proto,
		Server:   "example.com",
		Port:     443,
		Params:   params,
		Enabled:  true,
	}
}

// generator_genOne wraps a single endpoint into a profile, generates, asserts no
// error, round-trips the JSON, and returns the produced outbound for the id.
func generator_genOne(t *testing.T, e model.Endpoint) map[string]any {
	t.Helper()
	p := &model.Profile{Endpoints: []model.Endpoint{e}}
	res, err := Generate(p, Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate %s: %v", e.ID, err)
	}
	// Round-trip via a temp file to confirm the config is valid JSON.
	raw, err := json.Marshal(res.Config)
	if err != nil {
		t.Fatalf("marshal %s: %v", e.ID, err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	back, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read temp config: %v", err)
	}
	var rt map[string]any
	if err := json.Unmarshal(back, &rt); err != nil {
		t.Fatalf("invalid JSON for %s: %v", e.ID, err)
	}
	byTag := generator_outboundsByTag(t, res)
	ob, ok := byTag[e.ID]
	if !ok {
		t.Fatalf("no outbound produced for %q", e.ID)
	}
	return ob
}

// --- Per-protocol outbound shape -------------------------------------------

// TestOutboundVMess covers the vmess branch incl. alter_id (intp) and the
// security default ("auto") when no security param is given.
func TestOutboundVMess(t *testing.T) {
	e := generator_singBoxEndpoint("vmess-1", model.ProtoVMess, map[string]any{
		"uuid":     "v-uuid",
		"alter_id": 7,
		// security intentionally omitted -> the generator should default it to "auto".
	})
	ob := generator_genOne(t, e)

	if ob["type"] != "vmess" {
		t.Fatalf("type = %v, want vmess", ob["type"])
	}
	if ob["uuid"] != "v-uuid" {
		t.Fatalf("uuid = %v", ob["uuid"])
	}
	if ob["alter_id"] != 7 {
		t.Fatalf("alter_id = %v (%T), want int 7", ob["alter_id"], ob["alter_id"])
	}
	if ob["security"] != "auto" {
		t.Fatalf("security = %v, want default auto", ob["security"])
	}
	if ob["server"] != "example.com" || ob["server_port"] != 443 {
		t.Fatalf("server/port = %v:%v", ob["server"], ob["server_port"])
	}
}

// TestOutboundVMessFloatAlterID exercises intp's float64 case, which is how
// numbers arrive after a JSON round-trip into Params.
func TestOutboundVMessFloatAlterID(t *testing.T) {
	e := generator_singBoxEndpoint("vmess-2", model.ProtoVMess, map[string]any{
		"uuid":     "v2",
		"alter_id": float64(3), // JSON-decoded numbers are float64
		"security": "aes-128-gcm",
	})
	ob := generator_genOne(t, e)
	if ob["alter_id"] != 3 {
		t.Fatalf("alter_id from float64 = %v (%T), want int 3", ob["alter_id"], ob["alter_id"])
	}
	if ob["security"] != "aes-128-gcm" {
		t.Fatalf("security = %v, want aes-128-gcm", ob["security"])
	}
}

// TestOutboundVMessMissingAlterID confirms intp returns 0 when the key is
// absent (the no-key branch of intp).
func TestOutboundVMessMissingAlterID(t *testing.T) {
	e := generator_singBoxEndpoint("vmess-3", model.ProtoVMess, map[string]any{"uuid": "v3"})
	ob := generator_genOne(t, e)
	if ob["alter_id"] != 0 {
		t.Fatalf("alter_id = %v, want 0 when unset", ob["alter_id"])
	}
}

// TestOutboundTrojan covers the trojan branch.
func TestOutboundTrojan(t *testing.T) {
	e := generator_singBoxEndpoint("trojan-1", model.ProtoTrojan, map[string]any{"password": "tj-pass"})
	ob := generator_genOne(t, e)
	if ob["type"] != "trojan" {
		t.Fatalf("type = %v, want trojan", ob["type"])
	}
	if ob["password"] != "tj-pass" {
		t.Fatalf("password = %v", ob["password"])
	}
}

// TestOutboundShadowsocks covers the shadowsocks branch (method + password).
func TestOutboundShadowsocks(t *testing.T) {
	// A real 16-byte base64 PSK: 2022-blake3-aes-128-gcm requires that length, and
	// Validate (which Generate runs first) now enforces it.
	const psk = "MTIzNDU2Nzg5MDEyMzQ1Ng==" // base64("1234567890123456"), 16 bytes
	e := generator_singBoxEndpoint("ss-1", model.ProtoShadowsocks, map[string]any{
		"method":   "2022-blake3-aes-128-gcm",
		"password": psk,
	})
	ob := generator_genOne(t, e)
	if ob["type"] != "shadowsocks" {
		t.Fatalf("type = %v, want shadowsocks", ob["type"])
	}
	if ob["method"] != "2022-blake3-aes-128-gcm" {
		t.Fatalf("method = %v", ob["method"])
	}
	if ob["password"] != psk {
		t.Fatalf("password = %v", ob["password"])
	}
	if _, ok := ob["udp_over_tcp"]; ok {
		t.Fatalf("udp_over_tcp should be absent when unset: %v", ob["udp_over_tcp"])
	}
	// With the param set it emits as a bool.
	e2 := generator_singBoxEndpoint("ss-uot", model.ProtoShadowsocks, map[string]any{"method": "aes-256-gcm", "password": "p", "udp_over_tcp": true})
	if ob2 := generator_genOne(t, e2); ob2["udp_over_tcp"] != true {
		t.Fatalf("udp_over_tcp = %v, want true", ob2["udp_over_tcp"])
	}
}

// TestOutboundShadowsocksPlugin: sing-box natively supports obfs-local and
// v2ray-plugin, so a KNOWN plugin (+opts) is emitted; an UNKNOWN plugin name is
// dropped (it would fail the shared config load — degrade to plain SS instead).
func TestOutboundShadowsocksPlugin(t *testing.T) {
	known := generator_singBoxEndpoint("ss-pl", model.ProtoShadowsocks, map[string]any{
		"method": "aes-256-gcm", "password": "p",
		"plugin": "obfs-local", "plugin_opts": "obfs=http;obfs-host=www.bing.com",
	})
	ob := generator_genOne(t, known)
	if ob["plugin"] != "obfs-local" {
		t.Fatalf("plugin = %v, want obfs-local", ob["plugin"])
	}
	if ob["plugin_opts"] != "obfs=http;obfs-host=www.bing.com" {
		t.Fatalf("plugin_opts = %v", ob["plugin_opts"])
	}
	v2 := generator_singBoxEndpoint("ss-v2", model.ProtoShadowsocks, map[string]any{
		"method": "aes-256-gcm", "password": "p", "plugin": "v2ray-plugin",
	})
	if generator_genOne(t, v2)["plugin"] != "v2ray-plugin" {
		t.Fatalf("v2ray-plugin not emitted")
	}
	unknown := generator_singBoxEndpoint("ss-bad", model.ProtoShadowsocks, map[string]any{
		"method": "aes-256-gcm", "password": "p",
		"plugin": "kcptun", "plugin_opts": "x=y",
	})
	ob = generator_genOne(t, unknown)
	if _, ok := ob["plugin"]; ok {
		t.Fatalf("unknown plugin should be dropped, got %v", ob["plugin"])
	}
	if _, ok := ob["plugin_opts"]; ok {
		t.Fatalf("plugin_opts should be dropped with an unknown plugin")
	}
}

// TestOutboundTUIC covers the tuic branch incl. congestion_control set.
func TestOutboundTUIC(t *testing.T) {
	const tuicUUID = "11111111-2222-3333-4444-555555555555" // Validate enforces canonical uuids for tuic
	e := generator_singBoxEndpoint("tuic-1", model.ProtoTUIC, map[string]any{
		"uuid":               tuicUUID,
		"password":           "tuic-pass",
		"congestion_control": "bbr",
		"udp_relay_mode":     "quic",
	})
	ob := generator_genOne(t, e)
	if ob["type"] != "tuic" {
		t.Fatalf("type = %v, want tuic", ob["type"])
	}
	if ob["uuid"] != tuicUUID || ob["password"] != "tuic-pass" {
		t.Fatalf("uuid/password = %v/%v", ob["uuid"], ob["password"])
	}
	if ob["congestion_control"] != "bbr" {
		t.Fatalf("congestion_control = %v, want bbr", ob["congestion_control"])
	}
	// udp_relay_mode must reach the config (was silently dropped before).
	if ob["udp_relay_mode"] != "quic" {
		t.Fatalf("udp_relay_mode = %v, want quic", ob["udp_relay_mode"])
	}
}

// TestOutboundTUICUDPMutualExclusion: sing-box FATALs on a TUIC outbound carrying BOTH
// udp_over_stream and udp_relay_mode ("udp_over_stream is conflict with udp_relay_mode"),
// which bricks the whole shared singbox.json on apply. The generator must emit exactly one —
// udp_over_stream wins when set. (Real bug found via on-device `wayhop gen | sing-box check`.)
func TestOutboundTUICUDPMutualExclusion(t *testing.T) {
	const tuicUUID = "11111111-2222-3333-4444-555555555555"
	// Both set -> udp_over_stream wins, udp_relay_mode dropped (no conflict).
	ob := generator_genOne(t, generator_singBoxEndpoint("tuic-x", model.ProtoTUIC, map[string]any{
		"uuid": tuicUUID, "password": "p", "udp_over_stream": true, "udp_relay_mode": "quic",
	}))
	if ob["udp_over_stream"] != true {
		t.Fatalf("udp_over_stream = %v, want true", ob["udp_over_stream"])
	}
	if v, ok := ob["udp_relay_mode"]; ok {
		t.Fatalf("udp_relay_mode must be omitted when udp_over_stream is set (sing-box conflict), got %v", v)
	}
	// Only udp_relay_mode -> kept, no udp_over_stream key emitted.
	ob2 := generator_genOne(t, generator_singBoxEndpoint("tuic-y", model.ProtoTUIC, map[string]any{
		"uuid": tuicUUID, "password": "p", "udp_relay_mode": "native",
	}))
	if ob2["udp_relay_mode"] != "native" {
		t.Fatalf("udp_relay_mode = %v, want native", ob2["udp_relay_mode"])
	}
	if _, ok := ob2["udp_over_stream"]; ok {
		t.Fatalf("udp_over_stream must be absent when unset")
	}
}

// TestOutboundTUICDefaultsALPN: TUIC runs over QUIC/HTTP3 and REQUIRES a TLS ALPN.
// Without one the config passes sing-box check but every connection fails at runtime
// ("tls: no application protocol"), so the generator must default it to ["h3"]; an
// explicit ALPN is preserved.
func TestOutboundTUICDefaultsALPN(t *testing.T) {
	const tuicUUID = "11111111-2222-3333-4444-555555555555"
	mk := func(alpn []string) map[string]any {
		e := model.Endpoint{
			ID: "tuic-a", Engine: model.EngineSingBox, Protocol: model.ProtoTUIC,
			Server: "s", Port: 443, Enabled: true,
			Params: map[string]any{"uuid": tuicUUID, "password": "p"},
			TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "x", ALPN: alpn},
		}
		return generator_genOne(t, e)
	}
	tl := mk(nil)["tls"].(map[string]any)
	if got, _ := tl["alpn"].([]string); len(got) != 1 || got[0] != "h3" {
		t.Fatalf("tuic alpn = %v, want [h3] default", tl["alpn"])
	}
	tl2 := mk([]string{"h3", "h3-29"})["tls"].(map[string]any)
	if got, _ := tl2["alpn"].([]string); len(got) != 2 || got[0] != "h3" || got[1] != "h3-29" {
		t.Fatalf("explicit tuic alpn = %v, want preserved", tl2["alpn"])
	}
}

// TestOutboundTUICNoCongestion confirms the congestion_control key is omitted
// when not provided (the empty-string branch).
func TestOutboundTUICNoCongestion(t *testing.T) {
	e := generator_singBoxEndpoint("tuic-2", model.ProtoTUIC, map[string]any{
		"uuid":     "22222222-3333-4444-5555-666666666666",
		"password": "p2",
	})
	ob := generator_genOne(t, e)
	if _, present := ob["congestion_control"]; present {
		t.Fatalf("congestion_control should be absent, got %v", ob["congestion_control"])
	}
	if _, present := ob["udp_relay_mode"]; present {
		t.Fatalf("udp_relay_mode should be absent when unset, got %v", ob["udp_relay_mode"])
	}
}

// TestOutboundTUICExtraParams: heartbeat (a valid duration), zero_rtt_handshake
// and udp_over_stream are emitted; a malformed heartbeat is dropped (a bare
// number / garbage would fail sing-box config decode and brick the config).
func TestOutboundTUICExtraParams(t *testing.T) {
	uuid := "11111111-2222-3333-4444-555555555555"
	e := generator_singBoxEndpoint("tuic-x", model.ProtoTUIC, map[string]any{
		"uuid": uuid, "password": "p", "heartbeat": "10s",
		"zero_rtt_handshake": true, "udp_over_stream": true,
	})
	ob := generator_genOne(t, e)
	if ob["heartbeat"] != "10s" {
		t.Errorf("heartbeat = %v, want 10s", ob["heartbeat"])
	}
	if ob["zero_rtt_handshake"] != true || ob["udp_over_stream"] != true {
		t.Errorf("zero_rtt/udp_over_stream = %v/%v, want true/true", ob["zero_rtt_handshake"], ob["udp_over_stream"])
	}
	// Malformed heartbeat must be dropped, not emitted.
	for _, bad := range []string{"garbage", "10", "100ms-oops"} {
		eb := generator_singBoxEndpoint("tuic-hb", model.ProtoTUIC, map[string]any{"uuid": uuid, "password": "p", "heartbeat": bad})
		if obb := generator_genOne(t, eb); obb["heartbeat"] != nil {
			t.Errorf("malformed heartbeat %q must be dropped, got %v", bad, obb["heartbeat"])
		}
	}
}

// TestOutboundTUICHeartbeatNonPositive: time.ParseDuration ACCEPTS non-positive
// durations ("0s", "-5s", "-0s"), but sing-box rejects "heartbeat must be > 0" at
// config decode — which would brick the whole shared singbox.json on apply. The
// generator must drop a non-positive heartbeat (drop-don't-brick) while still
// emitting a valid positive one.
func TestOutboundTUICHeartbeatNonPositive(t *testing.T) {
	uuid := "11111111-2222-3333-4444-555555555555"
	// Non-positive durations parse but must NOT be emitted.
	for _, bad := range []string{"0s", "-5s", "-0s", "0", "-1h"} {
		eb := generator_singBoxEndpoint("tuic-hb0", model.ProtoTUIC, map[string]any{"uuid": uuid, "password": "p", "heartbeat": bad})
		if obb := generator_genOne(t, eb); obb["heartbeat"] != nil {
			t.Errorf("non-positive heartbeat %q must be dropped, got %v", bad, obb["heartbeat"])
		}
	}
	// A valid positive duration is still emitted.
	eg := generator_singBoxEndpoint("tuic-hbok", model.ProtoTUIC, map[string]any{"uuid": uuid, "password": "p", "heartbeat": "10s"})
	if ob := generator_genOne(t, eg); ob["heartbeat"] != "10s" {
		t.Errorf("positive heartbeat = %v, want 10s", ob["heartbeat"])
	}
}

// generator_wgEndpoint generates a profile holding the single native-WireGuard
// endpoint e, round-trips the config JSON, asserts WG is NOT emitted as an
// outbound, and returns the produced top-level endpoint map for e.ID (from
// res.Config["endpoints"]) plus the full Result.
func generator_wgEndpoint(t *testing.T, e model.Endpoint) (map[string]any, *Result) {
	t.Helper()
	p := &model.Profile{Endpoints: []model.Endpoint{e}}
	res, err := Generate(p, Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate %s: %v", e.ID, err)
	}
	if _, err := json.Marshal(res.Config); err != nil {
		t.Fatalf("marshal %s: %v", e.ID, err)
	}
	// Native WG must NOT appear as an outbound (the deprecated/removed schema).
	for _, ob := range res.Config["outbounds"].([]map[string]any) {
		if ob["tag"] == e.ID {
			t.Fatalf("WireGuard %q must not be an outbound; got %v", e.ID, ob)
		}
	}
	eps, ok := res.Config["endpoints"].([]map[string]any)
	if !ok {
		t.Fatalf("endpoints not []map[string]any: %T", res.Config["endpoints"])
	}
	for _, ep := range eps {
		if ep["tag"] == e.ID {
			return ep, res
		}
	}
	t.Fatalf("no endpoint produced for %q", e.ID)
	return nil, nil
}

// TestOutboundWireGuard covers native WireGuard, now emitted as a top-level
// sing-box `endpoints` entry (the 1.11+ schema that replaced the wireguard
// outbound removed in 1.13) — distinct from the AmneziaWG plugin path. The
// endpoint carries address + private_key; its single peer nests the server as
// address/port, the peer public key, an optional PSK, reserved bytes, and a
// full-tunnel allowed_ips.
func TestOutboundWireGuard(t *testing.T) {
	e := generator_singBoxEndpoint("wg-1", model.ProtoWireGuard, map[string]any{
		"private_key":     wgTestPrivKey,
		"peer_public_key": wgTestPubKey,
		"pre_shared_key":  "psk==",
		"local_address":   []string{"10.0.0.2/32"},
		"reserved":        []int{1, 2, 3},
	})
	ep, _ := generator_wgEndpoint(t, e)

	if ep["type"] != "wireguard" {
		t.Fatalf("type = %v, want wireguard", ep["type"])
	}
	if ep["private_key"] != wgTestPrivKey {
		t.Fatalf("private_key = %v", ep["private_key"])
	}
	// Interface address (was the outbound's local_address) — an array of CIDRs.
	addr, ok := ep["address"].([]string)
	if !ok || len(addr) != 1 || addr[0] != "10.0.0.2/32" {
		t.Fatalf("address = %v (%T)", ep["address"], ep["address"])
	}
	peers, ok := ep["peers"].([]map[string]any)
	if !ok || len(peers) != 1 {
		t.Fatalf("peers = %v (%T), want exactly 1", ep["peers"], ep["peers"])
	}
	pe := peers[0]
	if pe["address"] != "example.com" || pe["port"] != 443 {
		t.Fatalf("peer address:port = %v:%v, want example.com:443", pe["address"], pe["port"])
	}
	if pe["public_key"] != wgTestPubKey {
		t.Fatalf("peer public_key = %v", pe["public_key"])
	}
	if pe["pre_shared_key"] != "psk==" {
		t.Fatalf("peer pre_shared_key = %v", pe["pre_shared_key"])
	}
	aips, ok := pe["allowed_ips"].([]string)
	if !ok || len(aips) != 2 || aips[0] != "0.0.0.0/0" || aips[1] != "::/0" {
		t.Fatalf("allowed_ips = %v (%T), want full tunnel [0.0.0.0/0 ::/0]", pe["allowed_ips"], pe["allowed_ips"])
	}
	rsv, ok := pe["reserved"].([]int)
	if !ok || len(rsv) != 3 || rsv[0] != 1 || rsv[1] != 2 || rsv[2] != 3 {
		t.Fatalf("reserved = %v (%T), want [1 2 3] on the peer", pe["reserved"], pe["reserved"])
	}
	// The legacy outbound fields must NOT survive into the endpoint schema.
	for _, k := range []string{"server", "server_port", "peer_public_key", "local_address", "reserved"} {
		if _, present := ep[k]; present {
			t.Fatalf("endpoint must not carry legacy outbound field %q: %v", k, ep[k])
		}
	}
}

// TestOutboundWireGuardMinimal confirms the optional address/psk/reserved
// branches are skipped when absent, leaving a minimal endpoint + peer (the peer
// still carries the mandatory full-tunnel allowed_ips).
func TestOutboundWireGuardMinimal(t *testing.T) {
	e := generator_singBoxEndpoint("wg-2", model.ProtoWireGuard, map[string]any{
		"private_key":     wgTestPrivKey,
		"peer_public_key": wgTestPubKey,
	})
	ep, _ := generator_wgEndpoint(t, e)
	if _, ok := ep["address"]; ok {
		t.Fatalf("address should be absent when no local_address: %v", ep["address"])
	}
	pe := ep["peers"].([]map[string]any)[0]
	if _, ok := pe["pre_shared_key"]; ok {
		t.Fatalf("pre_shared_key should be absent: %v", pe["pre_shared_key"])
	}
	if _, ok := pe["reserved"]; ok {
		t.Fatalf("reserved should be absent: %v", pe["reserved"])
	}
	if pe["public_key"] != wgTestPubKey {
		t.Fatalf("peer public_key = %v, want wgTestPubKey", pe["public_key"])
	}
	if _, ok := pe["allowed_ips"].([]string); !ok {
		t.Fatalf("allowed_ips must always be present on the peer: %v", pe["allowed_ips"])
	}
	// No keepalive in params -> the peer must not carry one (don't invent a default).
	if _, ok := pe["persistent_keepalive_interval"]; ok {
		t.Fatalf("persistent_keepalive_interval present with no param: %v", pe["persistent_keepalive_interval"])
	}
}

// TestOutboundWireGuardKeepalive: an imported persistent_keepalive carries into
// the sing-box peer as persistent_keepalive_interval (seconds). float64 covers a
// JSON round-trip through the store.
func TestOutboundWireGuardKeepalive(t *testing.T) {
	e := generator_singBoxEndpoint("wg-ka", model.ProtoWireGuard, map[string]any{
		"private_key": wgTestPrivKey, "peer_public_key": wgTestPubKey,
		"persistent_keepalive": float64(25),
	})
	ep, _ := generator_wgEndpoint(t, e)
	pe := ep["peers"].([]map[string]any)[0]
	if pe["persistent_keepalive_interval"] != 25 {
		t.Fatalf("persistent_keepalive_interval = %v (%T), want 25 (int)", pe["persistent_keepalive_interval"], pe["persistent_keepalive_interval"])
	}
}

// TestOutboundWireGuardMTU: a plain-WG endpoint's MTU must be emitted on the sing-box
// endpoint — dropping it falls back to the kernel default and fragments/blackholes
// large packets (e.g. WARP needs 1280). float64 covers a JSON store round-trip.
func TestOutboundWireGuardMTU(t *testing.T) {
	e := generator_singBoxEndpoint("wg-mtu", model.ProtoWireGuard, map[string]any{
		"private_key": wgTestPrivKey, "peer_public_key": wgTestPubKey, "mtu": float64(1280),
	})
	ep, _ := generator_wgEndpoint(t, e)
	if ep["mtu"] != 1280 {
		t.Fatalf("endpoint mtu = %v (%T), want 1280 (int)", ep["mtu"], ep["mtu"])
	}
	e2 := generator_singBoxEndpoint("wg-nomtu", model.ProtoWireGuard, map[string]any{"private_key": wgTestPrivKey, "peer_public_key": wgTestPubKey})
	ep2, _ := generator_wgEndpoint(t, e2)
	if _, ok := ep2["mtu"]; ok {
		t.Fatalf("mtu should be omitted when unset, got %v", ep2["mtu"])
	}
}

// TestEndpointsTopLevelKey asserts native WireGuard lands in the top-level
// `endpoints` array (not `outbounds`) while other protocols stay in outbounds,
// and that a route default referencing the WG endpoint by tag is preserved —
// endpoint tags are referenceable exactly like outbound tags.
func TestEndpointsTopLevelKey(t *testing.T) {
	wg := generator_singBoxEndpoint("wg-ep", model.ProtoWireGuard, map[string]any{
		"private_key": wgTestPrivKey, "peer_public_key": wgTestPubKey, "local_address": []string{"10.0.0.2/32"},
	})
	vless := generator_singBoxEndpoint("vl", model.ProtoVLESS, map[string]any{"uuid": "u"})
	p := &model.Profile{
		Endpoints: []model.Endpoint{wg, vless},
		Rules:     []model.Rule{{ID: "def", Default: true, Outbound: wg.ID}},
	}
	res, err := Generate(p, Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	eps, ok := res.Config["endpoints"].([]map[string]any)
	if !ok || len(eps) != 1 || eps[0]["tag"] != wg.ID {
		t.Fatalf("endpoints = %v (%T), want one wireguard tag %q", res.Config["endpoints"], res.Config["endpoints"], wg.ID)
	}
	// vless stays an outbound; WG is NOT an outbound.
	byTag := generator_outboundsByTag(t, res)
	if _, ok := byTag[vless.ID]; !ok {
		t.Fatalf("vless outbound missing")
	}
	if _, ok := byTag[wg.ID]; ok {
		t.Fatalf("WireGuard must not be an outbound")
	}
	// The route default still references the WG endpoint tag (no rewrite needed).
	route := res.Config["route"].(map[string]any)
	if route["final"] != wg.ID {
		t.Fatalf("route.final = %v, want the WG endpoint tag %q", route["final"], wg.ID)
	}
}

// --- Bug [64]: WireGuard invalid base64 key guard ---------------------------

// TestWireGuardInvalidPrivKey asserts that endpointFor returns an error (and
// Generate propagates it) when the WireGuard private_key is not valid 32-byte
// base64. This prevents sing-box from receiving garbage that it would reject
// with a FATAL "decode private key" error at config check time, which would
// block the entire apply for all endpoints sharing the same singbox.json.
func TestWireGuardInvalidPrivKey(t *testing.T) {
	for _, bad := range []string{"", "notbase64!!!", "dG9vc2hvcnQ=", "priv=="} {
		e := generator_singBoxEndpoint("wg-badpriv", model.ProtoWireGuard, map[string]any{
			"private_key":     bad,
			"peer_public_key": wgTestPubKey,
		})
		p := &model.Profile{
			Endpoints: []model.Endpoint{e},
			Rules:     []model.Rule{{ID: "def", Default: true, Outbound: model.OutboundDirect}},
		}
		_, err := Generate(p, Options{MixedPort: 7890})
		if err == nil {
			t.Errorf("bad private_key %q: expected Generate to return error, got nil", bad)
		}
	}
}

// TestWireGuardInvalidPeerPubKey asserts that endpointFor returns an error when
// the peer_public_key is not valid 32-byte base64, even if private_key is good.
func TestWireGuardInvalidPeerPubKey(t *testing.T) {
	for _, bad := range []string{"", "notbase64!!!", "dG9vc2hvcnQ=", "peerpub=="} {
		e := generator_singBoxEndpoint("wg-badpub", model.ProtoWireGuard, map[string]any{
			"private_key":     wgTestPrivKey,
			"peer_public_key": bad,
		})
		p := &model.Profile{
			Endpoints: []model.Endpoint{e},
			Rules:     []model.Rule{{ID: "def", Default: true, Outbound: model.OutboundDirect}},
		}
		_, err := Generate(p, Options{MixedPort: 7890})
		if err == nil {
			t.Errorf("bad peer_public_key %q: expected Generate to return error, got nil", bad)
		}
	}
}

// TestWireGuardValidKeyVariants confirms that both padded (StdEncoding) and
// raw (no-pad, RawStdEncoding) 32-byte base64 WireGuard keys are accepted by
// endpointFor — the WG key spec does not mandate padding, and real-world .conf
// files and links use both forms.
func TestWireGuardValidKeyVariants(t *testing.T) {
	key32 := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	}
	padded := base64.StdEncoding.EncodeToString(key32) // padded "...A="
	raw := base64.RawStdEncoding.EncodeToString(key32) // no-pad "...A"
	for _, enc := range []string{padded, raw} {
		e := generator_singBoxEndpoint("wg-validenc", model.ProtoWireGuard, map[string]any{
			"private_key":     enc,
			"peer_public_key": enc,
		})
		p := &model.Profile{
			Endpoints: []model.Endpoint{e},
			Rules:     []model.Rule{{ID: "def", Default: true, Outbound: model.OutboundDirect}},
		}
		res, err := Generate(p, Options{MixedPort: 7890})
		if err != nil {
			t.Errorf("key encoding %q: Generate returned unexpected error: %v", enc, err)
			continue
		}
		eps, _ := res.Config["endpoints"].([]map[string]any)
		if len(eps) != 1 {
			t.Errorf("key encoding %q: want 1 endpoint, got %d", enc, len(eps))
		}
	}
}

// TestOutboundSOCKS covers the socks branch (version pinned to 5).
func TestOutboundSOCKS(t *testing.T) {
	e := generator_singBoxEndpoint("socks-1", model.ProtoSOCKS, nil)
	ob := generator_genOne(t, e)
	if ob["type"] != "socks" {
		t.Fatalf("type = %v, want socks", ob["type"])
	}
	if ob["version"] != "5" {
		t.Fatalf("version = %v, want 5", ob["version"])
	}
}

// TestOutboundHTTP covers the http branch.
func TestOutboundHTTP(t *testing.T) {
	e := generator_singBoxEndpoint("http-1", model.ProtoHTTP, nil)
	ob := generator_genOne(t, e)
	if ob["type"] != "http" {
		t.Fatalf("type = %v, want http", ob["type"])
	}
}

// TestOutboundProxyAuth: the UI collects a username/password for socks/http proxy
// endpoints; sing-box authenticates to the upstream proxy with them, so they must
// be emitted — dropping them makes an authenticated proxy reject the connection.
// A no-auth proxy must omit both keys.
func TestOutboundProxyAuth(t *testing.T) {
	for _, proto := range []model.Protocol{model.ProtoSOCKS, model.ProtoHTTP} {
		withAuth := generator_singBoxEndpoint("p-auth", proto, map[string]any{"username": "alice", "password": "s3cr3t"})
		ob := generator_genOne(t, withAuth)
		if ob["username"] != "alice" || ob["password"] != "s3cr3t" {
			t.Fatalf("%s auth dropped: username=%v password=%v", proto, ob["username"], ob["password"])
		}
		noAuth := generator_singBoxEndpoint("p-noauth", proto, nil)
		ob = generator_genOne(t, noAuth)
		if _, ok := ob["username"]; ok {
			t.Fatalf("%s no-auth should omit username, got %v", proto, ob["username"])
		}
		if _, ok := ob["password"]; ok {
			t.Fatalf("%s no-auth should omit password, got %v", proto, ob["password"])
		}
	}
}

// TestOutboundVLESSFlowDroppedWithTransport: xtls-rprx-vision works ONLY over a raw
// TLS stream — sing-box fails every connection at runtime with "vision: not a valid
// supported TLS connection" (even though check passes) when flow is paired with a
// transport (*v2raywebsocket.WebsocketConn) OR with no TLS (*net.TCPConn). So flow is
// dropped in both cases and kept only for the TLS-over-tcp (reality/vision) case.
func TestOutboundVLESSFlowDroppedWithTransport(t *testing.T) {
	reality := func() *model.TLS {
		return &model.TLS{Enabled: true, Type: "reality", SNI: "x", PublicKey: generatorTestPBK, ShortID: "ab"}
	}
	// flow + a transport (even with TLS) -> dropped.
	for _, tt := range []string{"ws", "grpc", "http", "httpupgrade"} {
		e := generator_singBoxEndpoint("vless-fl", model.ProtoVLESS, map[string]any{"uuid": "u", "flow": "xtls-rprx-vision"})
		e.Transport = &model.Transport{Type: tt, Path: "/p", ServiceName: "s"}
		e.TLS = reality()
		if _, ok := generator_genOne(t, e)["flow"]; ok {
			t.Fatalf("flow must be dropped with %s transport", tt)
		}
	}
	// flow + no TLS (raw tcp, no security) -> dropped (vision can't run over a bare TCP conn).
	noTLS := generator_singBoxEndpoint("vless-notls", model.ProtoVLESS, map[string]any{"uuid": "u", "flow": "xtls-rprx-vision"})
	if _, ok := generator_genOne(t, noTLS)["flow"]; ok {
		t.Fatal("flow must be dropped when there is no TLS layer")
	}
	// flow + TLS + no transport -> kept (the reality/vision case the live config uses).
	ok := generator_singBoxEndpoint("vless-rl", model.ProtoVLESS, map[string]any{"uuid": "u", "flow": "xtls-rprx-vision"})
	ok.TLS = reality()
	if generator_genOne(t, ok)["flow"] != "xtls-rprx-vision" {
		t.Fatal("flow must be kept for a TLS-over-tcp (no-transport) vless endpoint")
	}
}

// TestOutboundVLESSNoFlow exercises the vless branch where the optional flow is
// absent so the flow key must be omitted.
func TestOutboundVLESSNoFlow(t *testing.T) {
	e := generator_singBoxEndpoint("vless-noflow", model.ProtoVLESS, map[string]any{"uuid": "u"})
	ob := generator_genOne(t, e)
	if ob["type"] != "vless" {
		t.Fatalf("type = %v, want vless", ob["type"])
	}
	if _, ok := ob["flow"]; ok {
		t.Fatalf("flow should be absent: %v", ob["flow"])
	}
}

// TestOutboundHysteria2NoObfs confirms the obfs block is omitted when no obfs.
func TestOutboundHysteria2NoObfs(t *testing.T) {
	e := generator_singBoxEndpoint("hy2-plain", model.ProtoHysteria2, map[string]any{"password": "h2"})
	ob := generator_genOne(t, e)
	if ob["type"] != "hysteria2" || ob["password"] != "h2" {
		t.Fatalf("type/password = %v/%v", ob["type"], ob["password"])
	}
	if _, ok := ob["obfs"]; ok {
		t.Fatalf("obfs should be absent: %v", ob["obfs"])
	}
}

// TestOutboundHysteria2ObfsNoPassword: an obfs type without a password must NOT
// emit an obfs block — sing-box rejects "obfs without password", which fails the
// whole shared config load. Degrade to plain (valid) hysteria2 instead.
func TestOutboundHysteria2ObfsNoPassword(t *testing.T) {
	e := generator_singBoxEndpoint("hy2-obfs-nopw", model.ProtoHysteria2, map[string]any{
		"password": "h2", "obfs": "salamander", // no obfs_password
	})
	ob := generator_genOne(t, e)
	if _, ok := ob["obfs"]; ok {
		t.Fatalf("obfs must be omitted when its password is empty (sing-box would reject the whole config): %v", ob["obfs"])
	}
	// A complete obfs (type + password) still emits.
	e2 := generator_singBoxEndpoint("hy2-obfs-ok", model.ProtoHysteria2, map[string]any{
		"password": "h2", "obfs": "salamander", "obfs_password": "zz",
	})
	ob2 := generator_genOne(t, e2)
	obfs, ok := ob2["obfs"].(map[string]any)
	if !ok || obfs["type"] != "salamander" || obfs["password"] != "zz" {
		t.Fatalf("complete obfs must still emit: %v", ob2["obfs"])
	}
}

// TestOutboundRealityNoPublicKey: a reality TLS without a public_key must NOT
// emit a reality block (sing-box rejects "invalid public_key", failing the whole
// shared config). Degrade to plain TLS so the outbound stays valid; a complete
// reality (with public_key) still emits.
func TestOutboundRealityNoPublicKey(t *testing.T) {
	e := model.Endpoint{
		ID: "vless-reality-nopbk", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: "1.1.1.1", Port: 443, Enabled: true,
		Params: map[string]any{"uuid": "u"},
		TLS:    &model.TLS{Enabled: true, Type: "reality", SNI: "www.microsoft.com", ShortID: "ab12"}, // no PublicKey
	}
	ob := generator_genOne(t, e)
	tls, ok := ob["tls"].(map[string]any)
	if !ok || tls["enabled"] != true {
		t.Fatalf("tls block missing/disabled: %v", ob["tls"])
	}
	if _, ok := tls["reality"]; ok {
		t.Fatalf("reality block must be omitted without a public_key (sing-box would reject whole config): %v", tls["reality"])
	}
	if tls["server_name"] != "www.microsoft.com" {
		t.Fatalf("server_name should survive the degrade-to-plain-tls: %v", tls["server_name"])
	}
	// With a public_key, reality still emits.
	e2 := e
	tlsCopy := *e.TLS
	tlsCopy.PublicKey = generatorTestPBK
	e2.TLS = &tlsCopy
	e2.ID = "vless-reality-ok"
	ob2 := generator_genOne(t, e2)
	r, ok := ob2["tls"].(map[string]any)["reality"].(map[string]any)
	if !ok || r["public_key"] != generatorTestPBK {
		t.Fatalf("complete reality must still emit public_key: %v", ob2["tls"])
	}
}

// TestOutboundDropsUnknownEnums: an unknown value for an optional enum (vless
// flow, tuic congestion_control, hysteria2 obfs type, uTLS fingerprint) must be
// DROPPED, not emitted — sing-box hard-rejects unknown enums, which would fail
// the whole shared config. Valid values are kept.
func TestOutboundDropsUnknownEnums(t *testing.T) {
	// vless flow
	bad := generator_singBoxEndpoint("v-flow-bad", model.ProtoVLESS, map[string]any{"uuid": "u", "flow": "weird-flow"})
	if ob := generator_genOne(t, bad); ob["flow"] != nil {
		t.Errorf("unknown vless flow must be dropped, got %v", ob["flow"])
	}
	good := generator_singBoxEndpoint("v-flow-ok", model.ProtoVLESS, map[string]any{"uuid": "u", "flow": "xtls-rprx-vision"})
	good.TLS = &model.TLS{Enabled: true, Type: "reality", SNI: "x", PublicKey: generatorTestPBK, ShortID: "ab"} // flow needs a TLS layer
	if ob := generator_genOne(t, good); ob["flow"] != "xtls-rprx-vision" {
		t.Errorf("valid vless flow must be kept, got %v", ob["flow"])
	}
	// tuic congestion_control
	tbad := generator_singBoxEndpoint("t-cc-bad", model.ProtoTUIC, map[string]any{"uuid": "11111111-2222-3333-4444-555555555555", "congestion_control": "foobar"})
	if ob := generator_genOne(t, tbad); ob["congestion_control"] != nil {
		t.Errorf("unknown tuic cc must be dropped, got %v", ob["congestion_control"])
	}
	tgood := generator_singBoxEndpoint("t-cc-ok", model.ProtoTUIC, map[string]any{"uuid": "11111111-2222-3333-4444-555555555555", "congestion_control": "bbr"})
	if ob := generator_genOne(t, tgood); ob["congestion_control"] != "bbr" {
		t.Errorf("valid tuic cc must be kept, got %v", ob["congestion_control"])
	}
	// hysteria2 obfs type
	hbad := generator_singBoxEndpoint("h-obfs-bad", model.ProtoHysteria2, map[string]any{"password": "p", "obfs": "weirdtype", "obfs_password": "x"})
	if ob := generator_genOne(t, hbad); ob["obfs"] != nil {
		t.Errorf("unknown hy2 obfs type must be dropped, got %v", ob["obfs"])
	}
	hgood := generator_singBoxEndpoint("h-obfs-ok", model.ProtoHysteria2, map[string]any{"password": "p", "obfs": "salamander", "obfs_password": "x"})
	if ob := generator_genOne(t, hgood); ob["obfs"] == nil {
		t.Errorf("valid hy2 obfs must be kept")
	}
	// uTLS fingerprint (via TLS block)
	fpBad := model.Endpoint{ID: "fp-bad", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "1.1.1.1", Port: 443, Enabled: true,
		Params: map[string]any{"uuid": "u"}, TLS: &model.TLS{Enabled: true, Type: "tls", SNI: "x", Fingerprint: "totally-bogus"}}
	if ob := generator_genOne(t, fpBad); ob["tls"].(map[string]any)["utls"] != nil {
		t.Errorf("unknown utls fingerprint must be dropped, got %v", ob["tls"].(map[string]any)["utls"])
	}
	fpOk := fpBad
	tlsCopy := *fpBad.TLS
	tlsCopy.Fingerprint = "firefox"
	fpOk.TLS = &tlsCopy
	fpOk.ID = "fp-ok"
	if ob := generator_genOne(t, fpOk); ob["tls"].(map[string]any)["utls"] == nil {
		t.Errorf("valid utls fingerprint (firefox) must be kept")
	}
	// vmess security (scy): unknown -> fall back to "auto" (sing-box rejects an
	// unknown security type); a valid value is kept.
	vsBad := generator_singBoxEndpoint("vs-bad", model.ProtoVMess, map[string]any{"uuid": "u", "security": "bogus-scy"})
	if ob := generator_genOne(t, vsBad); ob["security"] != "auto" {
		t.Errorf("unknown vmess security must fall back to auto, got %v", ob["security"])
	}
	vsOk := generator_singBoxEndpoint("vs-ok", model.ProtoVMess, map[string]any{"uuid": "u", "security": "zero"})
	if ob := generator_genOne(t, vsOk); ob["security"] != "zero" {
		t.Errorf("valid vmess security must be kept, got %v", ob["security"])
	}
	// vless packet_encoding: xudp/packetaddr kept; an unknown value dropped (it
	// makes sing-box PANIC, so it must never be emitted).
	for _, pe := range []string{"xudp", "packetaddr"} {
		e := generator_singBoxEndpoint("pe-ok", model.ProtoVLESS, map[string]any{"uuid": "u", "packet_encoding": pe})
		if ob := generator_genOne(t, e); ob["packet_encoding"] != pe {
			t.Errorf("valid packet_encoding %q must be kept, got %v", pe, ob["packet_encoding"])
		}
	}
	peBad := generator_singBoxEndpoint("pe-bad", model.ProtoVLESS, map[string]any{"uuid": "u", "packet_encoding": "bogus-enc"})
	if ob := generator_genOne(t, peBad); ob["packet_encoding"] != nil {
		t.Errorf("unknown packet_encoding must be dropped, got %v", ob["packet_encoding"])
	}
}

// TestOutboundHysteria2PortHopping: an imported hop range (dash form) becomes
// sing-box server_ports (colon form); a comma list maps element-wise; malformed
// ranges are dropped (never emitted as a config sing-box would reject).
func TestOutboundHysteria2PortHopping(t *testing.T) {
	eq := func(got any, want []string) bool {
		g, ok := got.([]string)
		if !ok || len(g) != len(want) {
			return false
		}
		for i := range g {
			if g[i] != want[i] {
				return false
			}
		}
		return true
	}
	cases := []struct {
		name string
		hp   string
		want []string // nil => server_ports must be absent
	}{
		{"single-range", "20000-50000", []string{"20000:50000"}},
		{"list-single-becomes-range", "443,5000-6000", []string{"443:443", "5000:6000"}},
		{"bare-single-port", "8443", []string{"8443:8443"}},
		{"drops-garbage", "garbage,7000-8000", []string{"7000:8000"}},
		{"all-bad-absent", "abc,xyz", nil},
		{"out-of-range-dropped", "70000-80000,1000-2000", []string{"1000:2000"}},
		{"reversed-range-normalized", "50000-20000", []string{"20000:50000"}}, // start>end -> ascending
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := generator_singBoxEndpoint("hy2-hop", model.ProtoHysteria2, map[string]any{"password": "p", "hop_ports": c.hp})
			ob := generator_genOne(t, e)
			if c.want == nil {
				if _, ok := ob["server_ports"]; ok {
					t.Fatalf("server_ports should be absent for %q, got %v", c.hp, ob["server_ports"])
				}
				return
			}
			if !eq(ob["server_ports"], c.want) {
				t.Fatalf("server_ports = %v, want %v", ob["server_ports"], c.want)
			}
		})
	}
}

// TestOutboundRealityMalformedFields: a malformed reality public_key degrades to
// plain TLS (no reality block), and a malformed short_id is dropped — sing-box
// hard-rejects both ("invalid public_key" / "decode short_id"), which would brick
// the whole config.
func TestOutboundRealityMalformedFields(t *testing.T) {
	mk := func(pbk, sid string) map[string]any {
		e := model.Endpoint{
			ID: "r", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "1.1.1.1", Port: 443, Enabled: true,
			Params: map[string]any{"uuid": "u"},
			TLS:    &model.TLS{Enabled: true, Type: "reality", SNI: "x", PublicKey: pbk, ShortID: sid},
		}
		return generator_genOne(t, e)["tls"].(map[string]any)
	}
	// Malformed pbk -> no reality block (degraded to plain TLS).
	for _, bad := range []string{"not-a-real-key", "abc", "!!!", ""} {
		if _, ok := mk(bad, "ab12")["reality"]; ok {
			t.Errorf("malformed pbk %q must degrade to plain tls (no reality block)", bad)
		}
	}
	// Valid pbk + malformed short_id -> reality emitted but WITHOUT short_id.
	for _, badSid := range []string{"xyz", "abc", "0123456789abcdef01", "zz", ""} {
		r, ok := mk(generatorTestPBK, badSid)["reality"].(map[string]any)
		if !ok {
			t.Fatalf("valid pbk must emit reality (sid=%q)", badSid)
		}
		if _, has := r["short_id"]; has {
			t.Errorf("malformed/empty short_id %q must be dropped, got %v", badSid, r["short_id"])
		}
	}
	// Valid pbk + valid short_id -> both present.
	r := mk(generatorTestPBK, "ab12")["reality"].(map[string]any)
	if r["public_key"] != generatorTestPBK || r["short_id"] != "ab12" {
		t.Fatalf("valid reality fields must be kept: %v", r)
	}
}

// TestOutboundUnsupportedProtocol exercises the default error branch of
// outboundFor through Generate, which must wrap it with the endpoint id.
func TestOutboundUnsupportedProtocol(t *testing.T) {
	// A sing-box-engine endpoint whose protocol the generator does not handle.
	e := generator_singBoxEndpoint("weird-1", model.Protocol("smoke-signals"), nil)
	p := &model.Profile{Endpoints: []model.Endpoint{e}}
	res, err := Generate(p, Options{MixedPort: 7890})
	if err == nil {
		t.Fatalf("expected error for unsupported protocol, got %+v", res)
	}
	if res != nil {
		t.Fatalf("expected nil result on error, got %+v", res)
	}
}

// --- Transport variants -----------------------------------------------------

// TestTransportWS covers the ws transport branch with both path and host
// (host lands in headers.Host).
func TestTransportWS(t *testing.T) {
	e := generator_singBoxEndpoint("vless-ws", model.ProtoVLESS, map[string]any{"uuid": "u"})
	e.Transport = &model.Transport{Type: "ws", Path: "/wspath", Host: "cdn.example.com"}
	ob := generator_genOne(t, e)
	tr, ok := ob["transport"].(map[string]any)
	if !ok {
		t.Fatalf("transport missing/typed wrong: %T", ob["transport"])
	}
	if tr["type"] != "ws" {
		t.Fatalf("transport type = %v, want ws", tr["type"])
	}
	if tr["path"] != "/wspath" {
		t.Fatalf("ws path = %v", tr["path"])
	}
	headers, ok := tr["headers"].(map[string]any)
	if !ok {
		t.Fatalf("ws headers missing: %T", tr["headers"])
	}
	if headers["Host"] != "cdn.example.com" {
		t.Fatalf("ws Host header = %v", headers["Host"])
	}
}

// TestTransportWSEmpty confirms ws with neither path nor host omits both keys.
func TestTransportWSEmpty(t *testing.T) {
	e := generator_singBoxEndpoint("vless-ws2", model.ProtoVLESS, map[string]any{"uuid": "u"})
	e.Transport = &model.Transport{Type: "ws"}
	ob := generator_genOne(t, e)
	tr := ob["transport"].(map[string]any)
	if tr["type"] != "ws" {
		t.Fatalf("transport type = %v, want ws", tr["type"])
	}
	if _, ok := tr["path"]; ok {
		t.Fatalf("ws path should be absent: %v", tr["path"])
	}
	if _, ok := tr["headers"]; ok {
		t.Fatalf("ws headers should be absent: %v", tr["headers"])
	}
}

// TestTransportWSEarlyData: a v2rayN/Xray ws path carries early-data as
// "/path?ed=N". sing-box needs that split into a bare path + max_early_data +
// early_data_header_name, or the literal "?ed=N" is sent as the request path and
// the server 404s the upgrade. Verified live: the unsplit form gets a 404, the
// split form connects.
func TestTransportWSEarlyData(t *testing.T) {
	e := generator_singBoxEndpoint("vless-ed", model.ProtoVLESS, map[string]any{"uuid": "u"})
	e.Transport = &model.Transport{Type: "ws", Path: "/vl?ed=2048"}
	tr := generator_genOne(t, e)["transport"].(map[string]any)
	if tr["path"] != "/vl" {
		t.Fatalf("ws path = %v, want /vl (the ?ed= must be stripped)", tr["path"])
	}
	if tr["max_early_data"] != 2048 {
		t.Fatalf("max_early_data = %v, want 2048", tr["max_early_data"])
	}
	if tr["early_data_header_name"] != "Sec-WebSocket-Protocol" {
		t.Fatalf("early_data_header_name = %v, want Sec-WebSocket-Protocol", tr["early_data_header_name"])
	}
}

// TestTransportWSNonEdQueryUntouched: a "?" in the path with no valid ed must be
// left verbatim — we only rewrite the path when a real early-data hint is found.
func TestTransportWSNonEdQueryUntouched(t *testing.T) {
	for _, p := range []string{"/p?foo=bar", "/p?ed=0", "/p?ed=notanint"} {
		e := generator_singBoxEndpoint("vless-q", model.ProtoVLESS, map[string]any{"uuid": "u"})
		e.Transport = &model.Transport{Type: "ws", Path: p}
		tr := generator_genOne(t, e)["transport"].(map[string]any)
		if tr["path"] != p {
			t.Fatalf("path %q rewritten to %v, want unchanged", p, tr["path"])
		}
		if _, ok := tr["max_early_data"]; ok {
			t.Fatalf("path %q should not set max_early_data", p)
		}
	}
}

// TestTransportGRPC covers the grpc transport branch with a service_name.
func TestTransportGRPC(t *testing.T) {
	e := generator_singBoxEndpoint("vless-grpc", model.ProtoVLESS, map[string]any{"uuid": "u"})
	e.Transport = &model.Transport{Type: "grpc", ServiceName: "MyService"}
	ob := generator_genOne(t, e)
	tr := ob["transport"].(map[string]any)
	if tr["type"] != "grpc" {
		t.Fatalf("transport type = %v, want grpc", tr["type"])
	}
	if tr["service_name"] != "MyService" {
		t.Fatalf("grpc service_name = %v", tr["service_name"])
	}
}

// TestTransportGRPCNoService confirms grpc omits service_name when empty.
func TestTransportGRPCNoService(t *testing.T) {
	e := generator_singBoxEndpoint("vless-grpc2", model.ProtoVLESS, map[string]any{"uuid": "u"})
	e.Transport = &model.Transport{Type: "grpc"}
	ob := generator_genOne(t, e)
	tr := ob["transport"].(map[string]any)
	if _, ok := tr["service_name"]; ok {
		t.Fatalf("grpc service_name should be absent: %v", tr["service_name"])
	}
}

// TestTransportGRPCIgnoresPath locks in that a grpc transport emits ONLY
// service_name and never a `path` field, even when the model also carries Path.
// The vmess importer sets BOTH Transport.ServiceName AND Transport.Path from a
// vmess-JSON grpc link's "path" (a vmess link has no separate serviceName key),
// so the generator's grpc branch MUST drop Path: sing-box rejects an unknown
// `path` field inside a grpc transport, and because every endpoint shares one
// singbox.json that decode failure would take ALL routing down on the next
// apply. Verified correct against `sing-box check` on the live OpenWrt router
// (cycle 68) — this guards against a future refactor reintroducing the brick.
func TestTransportGRPCIgnoresPath(t *testing.T) {
	e := generator_singBoxEndpoint("vmess-grpc", model.ProtoVMess, map[string]any{"uuid": "u"})
	e.Transport = &model.Transport{Type: "grpc", ServiceName: "GrpcSvc", Path: "GrpcSvc"}
	ob := generator_genOne(t, e)
	tr := ob["transport"].(map[string]any)
	if tr["service_name"] != "GrpcSvc" {
		t.Fatalf("grpc service_name = %v, want GrpcSvc", tr["service_name"])
	}
	if _, ok := tr["path"]; ok {
		t.Fatalf("grpc transport must NOT emit a path field (sing-box rejects it): %v", tr["path"])
	}
}

// TestTransportDroppedForNonV2RayProtocols guards the shared generator chokepoint:
// a v2ray-style transport (ws/grpc/http/httpupgrade) must be emitted ONLY on the
// VLESS/VMess/Trojan outbounds and DROPPED on every other protocol. sing-box
// FATALs on a `transport` field for hysteria2/tuic/shadowsocks/socks/http
// ("json: unknown field transport", verified on the live router, cycle 69), and
// because every endpoint shares one singbox.json that decode failure takes ALL
// routing down on the next apply. The importer and the UI manual form never
// attach a transport to those protocols, but a raw POST /api/endpoints accepts an
// arbitrary endpoint and model.Validate is protocol-agnostic — so without this
// guard a hand-crafted hysteria2+transport endpoint bricks Apply.
func TestTransportDroppedForNonV2RayProtocols(t *testing.T) {
	ws := &model.Transport{Type: "ws", Path: "/x", Host: "h.example"}
	for _, tc := range []struct {
		proto  model.Protocol
		params map[string]any
	}{
		{model.ProtoHysteria2, map[string]any{"password": "p"}},
		{model.ProtoTUIC, map[string]any{"uuid": "e3253e13-6ca8-4544-9b13-952bc4dfa148", "password": "p"}},
		{model.ProtoShadowsocks, map[string]any{"method": "aes-256-gcm", "password": "p"}},
		{model.ProtoSOCKS, nil},
		{model.ProtoHTTP, nil},
	} {
		e := generator_singBoxEndpoint("e-"+string(tc.proto), tc.proto, tc.params)
		e.Transport = ws
		ob := generator_genOne(t, e)
		if _, ok := ob["transport"]; ok {
			t.Errorf("%s: a stray transport must be dropped (sing-box rejects it → bricks the shared config), got %v", tc.proto, ob["transport"])
		}
	}
	// Control: VLESS still KEEPS its transport — the guard is protocol-scoped, not a blanket drop.
	e := generator_singBoxEndpoint("e-vless", model.ProtoVLESS, map[string]any{"uuid": "u"})
	e.Transport = ws
	ob := generator_genOne(t, e)
	if _, ok := ob["transport"]; !ok {
		t.Fatalf("vless must keep its ws transport (guard is protocol-scoped), got none")
	}
}

// TestTLSDroppedForNonTLSProtocols is the tls twin of the transport guard: a
// `tls` block must be emitted ONLY on outbounds that carry one in sing-box 1.12.x
// (VLESS/VMess/Trojan/Hysteria2/TUIC/HTTP) and DROPPED on shadowsocks/socks
// (no tls container → FATAL "unknown field tls" → bricks the shared singbox.json).
// Reachable via a raw POST /api/endpoints (model.Validate never inspects e.TLS).
func TestTLSDroppedForNonTLSProtocols(t *testing.T) {
	tls := &model.TLS{Enabled: true, Type: "tls", SNI: "s.example"}
	for _, tc := range []struct {
		proto  model.Protocol
		params map[string]any
	}{
		{model.ProtoShadowsocks, map[string]any{"method": "aes-256-gcm", "password": "p"}},
		{model.ProtoSOCKS, nil},
	} {
		e := generator_singBoxEndpoint("d-"+string(tc.proto), tc.proto, tc.params)
		e.TLS = tls
		ob := generator_genOne(t, e)
		if _, ok := ob["tls"]; ok {
			t.Errorf("%s: a stray tls must be dropped (sing-box rejects it → bricks the shared config), got %v", tc.proto, ob["tls"])
		}
	}
	for _, tc := range []struct {
		proto  model.Protocol
		params map[string]any
	}{
		{model.ProtoVLESS, map[string]any{"uuid": "11111111-2222-3333-4444-555555555555"}},
		{model.ProtoTrojan, map[string]any{"password": "p"}},
		{model.ProtoHysteria2, map[string]any{"password": "p"}},
		{model.ProtoTUIC, map[string]any{"uuid": "11111111-2222-3333-4444-555555555555", "password": "p"}},
		{model.ProtoHTTP, nil},
	} {
		e := generator_singBoxEndpoint("k-"+string(tc.proto), tc.proto, tc.params)
		e.TLS = tls
		ob := generator_genOne(t, e)
		if _, ok := ob["tls"]; !ok {
			t.Errorf("%s: must keep its tls block (tls-capable protocol), got none", tc.proto)
		}
	}
}

// TestOutboundTUICStripsNonH3ALPN: TUIC runs over QUIC so only the h3 ALPN family
// is valid. sing-box does NOT override tuic's alpn, so a non-h3 alpn passes
// `sing-box check` but fails every connection at runtime ("tls: no application
// protocol"). The generator must keep only h3-family entries and default to [h3].
func TestOutboundTUICStripsNonH3ALPN(t *testing.T) {
	alpnOf := func(in []string) []string {
		e := generator_singBoxEndpoint("tuic-alpn", model.ProtoTUIC, map[string]any{"uuid": "11111111-2222-3333-4444-555555555555", "password": "p"})
		e.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: "s", ALPN: in}
		ob := generator_genOne(t, e)
		tl := ob["tls"].(map[string]any)
		got, _ := tl["alpn"].([]string)
		return got
	}
	if a := alpnOf([]string{"h2", "http/1.1"}); len(a) != 1 || a[0] != "h3" {
		t.Fatalf("tuic non-h3 alpn must collapse to [h3], got %v", a)
	}
	if a := alpnOf([]string{"h3", "h3-29"}); len(a) != 2 || a[0] != "h3" || a[1] != "h3-29" {
		t.Fatalf("tuic h3-family alpn must be preserved, got %v", a)
	}
	if a := alpnOf([]string{"h2", "h3"}); len(a) != 1 || a[0] != "h3" {
		t.Fatalf("tuic mixed alpn must keep only h3, got %v", a)
	}
	if a := alpnOf(nil); len(a) != 1 || a[0] != "h3" {
		t.Fatalf("tuic absent alpn must default to [h3], got %v", a)
	}
}

// TestTransportHTTP covers the http transport branch where host becomes a
// []string and path is carried.
func TestTransportHTTP(t *testing.T) {
	e := generator_singBoxEndpoint("vmess-http", model.ProtoVMess, map[string]any{"uuid": "u"})
	e.Transport = &model.Transport{Type: "http", Path: "/h", Host: "h.example.com"}
	ob := generator_genOne(t, e)
	tr := ob["transport"].(map[string]any)
	if tr["type"] != "http" {
		t.Fatalf("transport type = %v, want http", tr["type"])
	}
	if tr["path"] != "/h" {
		t.Fatalf("http path = %v", tr["path"])
	}
	host, ok := tr["host"].([]string)
	if !ok || len(host) != 1 || host[0] != "h.example.com" {
		t.Fatalf("http host = %v (%T)", tr["host"], tr["host"])
	}
}

// TestTransportHTTPMultiHost: an h2/http domain-fronting link lists several hosts
// ("host=a,b,c"); sing-box round-robins over the host LIST, so they must become
// separate elements, not one comma-joined string (which sends a bogus Host header).
func TestTransportHTTPMultiHost(t *testing.T) {
	e := generator_singBoxEndpoint("vless-h2mh", model.ProtoVLESS, map[string]any{"uuid": "u"})
	e.Transport = &model.Transport{Type: "http", Path: "/h2", Host: "a.example.com, b.example.com ,c.example.com"}
	tr := generator_genOne(t, e)["transport"].(map[string]any)
	host, ok := tr["host"].([]string)
	if !ok {
		t.Fatalf("http host type = %T, want []string", tr["host"])
	}
	want := []string{"a.example.com", "b.example.com", "c.example.com"}
	if len(host) != len(want) {
		t.Fatalf("http host = %v, want %v (split + trimmed)", host, want)
	}
	for i := range want {
		if host[i] != want[i] {
			t.Fatalf("http host[%d] = %q, want %q", i, host[i], want[i])
		}
	}
}

// TestTransportHTTPUpgrade: httpupgrade's host is a single STRING, unlike the
// http/h2 transport's string-LIST. sing-box rejects an array here with
// "transport.host: cannot unmarshal array into Go value of type string", so an
// httpupgrade endpoint produced an invalid config and could not connect.
func TestTransportHTTPUpgrade(t *testing.T) {
	e := generator_singBoxEndpoint("vmess-hu", model.ProtoVMess, map[string]any{"uuid": "u"})
	e.Transport = &model.Transport{Type: "httpupgrade", Path: "/up", Host: "up.example.com"}
	ob := generator_genOne(t, e)
	tr := ob["transport"].(map[string]any)
	if tr["type"] != "httpupgrade" {
		t.Fatalf("transport type = %v, want httpupgrade", tr["type"])
	}
	if tr["path"] != "/up" {
		t.Fatalf("httpupgrade path = %v", tr["path"])
	}
	host, ok := tr["host"].(string)
	if !ok || host != "up.example.com" {
		t.Fatalf("httpupgrade host = %v (%T), want string %q", tr["host"], tr["host"], "up.example.com")
	}
}

// TestTransportHTTPUpgradeEarlyData: an httpupgrade share-link carries the same
// "/path?ed=N" early-data hint as ws, but sing-box's httpupgrade transport has no
// early-data fields (it REJECTS max_early_data) — so the hint must be STRIPPED, not
// translated. Left literal, the upgrade fails at runtime against a server matching
// the bare path (passes `sing-box check`, every connection dies with `unexpected
// EOF`). Verified on a live xray httpupgrade inbound: literal → no exit, stripped → exits.
func TestTransportHTTPUpgradeEarlyData(t *testing.T) {
	e := generator_singBoxEndpoint("vless-hu-ed", model.ProtoVLESS, map[string]any{"uuid": "u"})
	e.Transport = &model.Transport{Type: "httpupgrade", Path: "/hu?ed=2048", Host: "h.example.com"}
	tr := generator_genOne(t, e)["transport"].(map[string]any)
	if tr["path"] != "/hu" {
		t.Fatalf("httpupgrade path = %v, want /hu (the ?ed= must be stripped)", tr["path"])
	}
	// httpupgrade has no early-data fields — they must NOT be emitted (they'd fail check).
	if _, ok := tr["max_early_data"]; ok {
		t.Fatalf("httpupgrade must not set max_early_data (sing-box rejects it)")
	}
	if _, ok := tr["early_data_header_name"]; ok {
		t.Fatalf("httpupgrade must not set early_data_header_name")
	}
}

// TestTransportHTTPUpgradeNonEdQueryUntouched: a "?" with no valid ed is left
// verbatim — we only strip a real early-data hint (mirrors the ws rule).
func TestTransportHTTPUpgradeNonEdQueryUntouched(t *testing.T) {
	for _, p := range []string{"/p?foo=bar", "/p?ed=0", "/p?ed=notanint"} {
		e := generator_singBoxEndpoint("vless-hu-q", model.ProtoVLESS, map[string]any{"uuid": "u"})
		e.Transport = &model.Transport{Type: "httpupgrade", Path: p}
		tr := generator_genOne(t, e)["transport"].(map[string]any)
		if tr["path"] != p {
			t.Fatalf("httpupgrade path %q rewritten to %v, want unchanged", p, tr["path"])
		}
	}
}

// TestTransportHTTPEmpty confirms http with no path/host omits both keys.
func TestTransportHTTPEmpty(t *testing.T) {
	e := generator_singBoxEndpoint("vmess-http2", model.ProtoVMess, map[string]any{"uuid": "u"})
	e.Transport = &model.Transport{Type: "http"}
	ob := generator_genOne(t, e)
	tr := ob["transport"].(map[string]any)
	if _, ok := tr["path"]; ok {
		t.Fatalf("http path should be absent: %v", tr["path"])
	}
	if _, ok := tr["host"]; ok {
		t.Fatalf("http host should be absent: %v", tr["host"])
	}
}

// TestTransportUnknownType covers the transport with a type the switch does not
// special-case: only {"type": ...} is emitted.
func TestTransportUnknownType(t *testing.T) {
	e := generator_singBoxEndpoint("vless-quic", model.ProtoVLESS, map[string]any{"uuid": "u"})
	e.Transport = &model.Transport{Type: "quic", Path: "/ignored"}
	ob := generator_genOne(t, e)
	tr := ob["transport"].(map[string]any)
	if tr["type"] != "quic" {
		t.Fatalf("transport type = %v, want quic", tr["type"])
	}
	if _, ok := tr["path"]; ok {
		t.Fatalf("unknown transport must not carry path: %v", tr["path"])
	}
}

// TestTransportEmptyTypeOmitted confirms a Transport with an empty Type yields
// no transport block (transportJSON returns nil).
func TestTransportEmptyTypeOmitted(t *testing.T) {
	e := generator_singBoxEndpoint("vless-notr", model.ProtoVLESS, map[string]any{"uuid": "u"})
	e.Transport = &model.Transport{Type: ""}
	ob := generator_genOne(t, e)
	if _, ok := ob["transport"]; ok {
		t.Fatalf("empty-type transport should be omitted: %v", ob["transport"])
	}
}

// --- TLS variants -----------------------------------------------------------

// TestTLSPlainFull exercises the non-reality TLS path with sni, insecure, alpn
// and a uTLS fingerprint, and asserts no reality block appears.
func TestTLSPlainFull(t *testing.T) {
	e := generator_singBoxEndpoint("trojan-tls", model.ProtoTrojan, map[string]any{"password": "p"})
	e.TLS = &model.TLS{
		Enabled:     true,
		Type:        "tls",
		SNI:         "secure.example.com",
		Insecure:    true,
		ALPN:        []string{"h2", "http/1.1"},
		Fingerprint: "chrome",
	}
	ob := generator_genOne(t, e)
	tl, ok := ob["tls"].(map[string]any)
	if !ok {
		t.Fatalf("tls missing: %T", ob["tls"])
	}
	if tl["enabled"] != true {
		t.Fatalf("tls.enabled = %v", tl["enabled"])
	}
	if tl["server_name"] != "secure.example.com" {
		t.Fatalf("server_name = %v", tl["server_name"])
	}
	if tl["insecure"] != true {
		t.Fatalf("insecure = %v, want true", tl["insecure"])
	}
	alpn, ok := tl["alpn"].([]string)
	if !ok || len(alpn) != 2 || alpn[0] != "h2" || alpn[1] != "http/1.1" {
		t.Fatalf("alpn = %v (%T)", tl["alpn"], tl["alpn"])
	}
	utls, ok := tl["utls"].(map[string]any)
	if !ok {
		t.Fatalf("utls missing: %T", tl["utls"])
	}
	if utls["enabled"] != true || utls["fingerprint"] != "chrome" {
		t.Fatalf("utls = %v", utls)
	}
	if _, ok := tl["reality"]; ok {
		t.Fatalf("plain TLS must not carry a reality block: %v", tl["reality"])
	}
}

// TestTLSReality exercises the reality branch with public_key + short_id.
func TestTLSReality(t *testing.T) {
	e := generator_singBoxEndpoint("vless-rty", model.ProtoVLESS, map[string]any{"uuid": "u"})
	e.TLS = &model.TLS{
		Enabled:   true,
		Type:      "reality",
		SNI:       "www.apple.com",
		PublicKey: generatorTestPBK,
		ShortID:   "deadbeef",
	}
	ob := generator_genOne(t, e)
	tl := ob["tls"].(map[string]any)
	if tl["server_name"] != "www.apple.com" {
		t.Fatalf("server_name = %v", tl["server_name"])
	}
	r, ok := tl["reality"].(map[string]any)
	if !ok {
		t.Fatalf("reality block missing: %v", tl)
	}
	if r["enabled"] != true {
		t.Fatalf("reality.enabled = %v", r["enabled"])
	}
	if r["public_key"] != generatorTestPBK {
		t.Fatalf("reality public_key = %v", r["public_key"])
	}
	if r["short_id"] != "deadbeef" {
		t.Fatalf("reality short_id = %v", r["short_id"])
	}
}

// TestTLSRealityEmptyKeys: reality WITHOUT a public_key must NOT emit a reality
// block — sing-box rejects "invalid public_key" and that fails the whole shared
// config load. (This previously asserted the buggy reality:{enabled} shape, which
// sing-box actually rejects.) The TLS block degrades to plain tls and stays valid.
func TestTLSRealityEmptyKeys(t *testing.T) {
	e := generator_singBoxEndpoint("vless-rty2", model.ProtoVLESS, map[string]any{"uuid": "u"})
	e.TLS = &model.TLS{Enabled: true, Type: "reality"}
	ob := generator_genOne(t, e)
	tl := ob["tls"].(map[string]any)
	if tl["enabled"] != true {
		t.Fatalf("tls should stay enabled (plain tls): %v", tl)
	}
	if _, ok := tl["reality"]; ok {
		t.Fatalf("reality block must be omitted without a public_key (sing-box rejects it): %v", tl["reality"])
	}
}

// TestTLSDisabledOmitted confirms a TLS struct with Enabled=false yields no tls
// block (tlsJSON returns nil).
func TestTLSDisabledOmitted(t *testing.T) {
	e := generator_singBoxEndpoint("trojan-notls", model.ProtoTrojan, map[string]any{"password": "p"})
	e.TLS = &model.TLS{Enabled: false, SNI: "ignored.example.com"}
	ob := generator_genOne(t, e)
	if _, ok := ob["tls"]; ok {
		t.Fatalf("disabled TLS must be omitted: %v", ob["tls"])
	}
}

// TestTLSMinimalEnabled confirms an enabled TLS with no extra fields produces
// just {"enabled": true} (all optional branches skipped).
func TestTLSMinimalEnabled(t *testing.T) {
	e := generator_singBoxEndpoint("trojan-mintls", model.ProtoTrojan, map[string]any{"password": "p"})
	e.TLS = &model.TLS{Enabled: true}
	ob := generator_genOne(t, e)
	tl := ob["tls"].(map[string]any)
	if tl["enabled"] != true {
		t.Fatalf("enabled = %v", tl["enabled"])
	}
	for _, k := range []string{"server_name", "insecure", "alpn", "utls", "reality"} {
		if _, ok := tl[k]; ok {
			t.Fatalf("minimal TLS should not carry %q: %v", k, tl[k])
		}
	}
}

// TestTLSXrayRandomizedFingerprintAliases: Xray/v2rayN expose uTLS fingerprints
// "randomizedalpn" / "randomizednoalpn" that sing-box does NOT accept ("unknown
// uTLS fingerprint" — verified live on 1.12.17). Since one bad outbound fails the
// shared singbox.json, these must NOT reach the config verbatim (would brick all
// routing on apply). They are mapped to sing-box's "randomized" so the link keeps
// its anti-fingerprint intent instead of degrading to Go's default TLS hello.
func TestTLSXrayRandomizedFingerprintAliases(t *testing.T) {
	for _, alias := range []string{"randomizedalpn", "randomizednoalpn"} {
		e := generator_singBoxEndpoint("vless-fp", model.ProtoVLESS, map[string]any{"uuid": "u"})
		e.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: "x", Fingerprint: alias}
		tl := generator_genOne(t, e)["tls"].(map[string]any)
		utls, ok := tl["utls"].(map[string]any)
		if !ok {
			t.Fatalf("fp %q: utls block missing (must map to randomized, not drop)", alias)
		}
		if utls["fingerprint"] != "randomized" {
			t.Fatalf("fp %q mapped to %v, want randomized", alias, utls["fingerprint"])
		}
	}
}

// TestWSStripsH2ALPN: WebSocket/httpupgrade are HTTP/1.1 upgrades and can't run
// over an h2-negotiated TLS connection. A ws/httpupgrade endpoint carrying alpn=h2
// passes sing-box check but fails every connection at runtime (server picks h2, the
// upgrade never completes — verified live). The generator must strip h2 for these
// transports; grpc (which needs h2) keeps it.
func TestWSStripsH2ALPN(t *testing.T) {
	cases := []struct {
		transport string
		in        []string
		want      []string // nil => alpn key must be absent
	}{
		{"ws", []string{"h2"}, nil},
		{"ws", []string{"h2", "http/1.1"}, []string{"http/1.1"}},
		{"httpupgrade", []string{"h2", "http/1.1"}, []string{"http/1.1"}},
		{"ws", []string{"http/1.1"}, []string{"http/1.1"}},
		{"grpc", []string{"h2"}, []string{"h2"}}, // grpc needs h2 → untouched
	}
	for _, c := range cases {
		e := generator_singBoxEndpoint("vless-alpn", model.ProtoVLESS, map[string]any{"uuid": "u"})
		e.Transport = &model.Transport{Type: c.transport, Path: "/p"}
		if c.transport == "grpc" {
			e.Transport = &model.Transport{Type: "grpc", ServiceName: "s"}
		}
		e.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: "x", ALPN: c.in}
		tl := generator_genOne(t, e)["tls"].(map[string]any)
		got, has := tl["alpn"].([]string)
		if c.want == nil {
			if has {
				t.Fatalf("%s alpn=%v: want alpn absent, got %v", c.transport, c.in, got)
			}
			continue
		}
		if !has || len(got) != len(c.want) {
			t.Fatalf("%s alpn=%v: got %v, want %v", c.transport, c.in, tl["alpn"], c.want)
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Fatalf("%s alpn=%v: got %v, want %v", c.transport, c.in, got, c.want)
			}
		}
	}
}

// TestGRPCKeepsOnlyH2ALPN: the mirror of TestWSStripsH2ALPN. grpc and the http/h2
// transport REQUIRE an h2-negotiated TLS connection; a non-h2 alpn makes the server
// settle on http/1.1 and the gRPC stream never establishes (passes check, fails at
// runtime — verified live). The generator keeps only h2 (deletes alpn if none left,
// so sing-box defaults h2). ws/httpupgrade are the opposite case (kept untouched here).
func TestGRPCKeepsOnlyH2ALPN(t *testing.T) {
	cases := []struct {
		transport string
		in        []string
		want      []string // nil => alpn key must be absent
	}{
		{"grpc", []string{"http/1.1"}, nil},                  // non-h2 only → drop → auto-h2
		{"grpc", []string{"h2", "http/1.1"}, []string{"h2"}}, // keep only h2
		{"grpc", []string{"h2"}, []string{"h2"}},
		{"http", []string{"http/1.1"}, nil},
		{"http", []string{"h2", "http/1.1"}, []string{"h2"}},
		{"ws", []string{"http/1.1"}, []string{"http/1.1"}}, // ws keeps http/1.1 (opposite rule)
	}
	for _, c := range cases {
		e := generator_singBoxEndpoint("vless-galpn", model.ProtoVLESS, map[string]any{"uuid": "u"})
		if c.transport == "grpc" {
			e.Transport = &model.Transport{Type: "grpc", ServiceName: "s"}
		} else {
			e.Transport = &model.Transport{Type: c.transport, Path: "/p"}
		}
		e.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: "x", ALPN: c.in}
		tl := generator_genOne(t, e)["tls"].(map[string]any)
		got, has := tl["alpn"].([]string)
		if c.want == nil {
			if has {
				t.Fatalf("%s alpn=%v: want alpn absent, got %v", c.transport, c.in, got)
			}
			continue
		}
		if !has || len(got) != len(c.want) || got[0] != c.want[0] {
			t.Fatalf("%s alpn=%v: got %v, want %v", c.transport, c.in, tl["alpn"], c.want)
		}
	}
}

// TestStripsH3ALPNForNonQUIC completes the ALPN<->transport matrix (ws/httpupgrade
// keep http/1.1, grpc/http keep h2): h3 (HTTP/3) is valid ONLY over QUIC, so on a
// TCP-based TLS endpoint (vless/vmess/trojan over tcp/ws/grpc) an alpn of "h3" is
// invalid and an ALPN-enforcing server rejects the handshake at runtime while
// `sing-box check` passes. The generator strips h3 for non-QUIC protocols (dropping
// alpn if nothing remains) but KEEPS it for the QUIC-native tuic/hysteria2.
func TestStripsH3ALPNForNonQUIC(t *testing.T) {
	// vless over raw tcp: h3 alone -> dropped; h3+h2 -> h2 kept (h2 valid over tcp).
	for _, c := range []struct {
		in   []string
		want []string // nil => alpn absent
	}{
		{[]string{"h3"}, nil},
		{[]string{"h3", "h2"}, []string{"h2"}},
		{[]string{"h3", "http/1.1"}, []string{"http/1.1"}},
	} {
		e := generator_singBoxEndpoint("vless-h3", model.ProtoVLESS, map[string]any{"uuid": "u"})
		e.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: "x", ALPN: c.in}
		tl := generator_genOne(t, e)["tls"].(map[string]any)
		got, has := tl["alpn"].([]string)
		if c.want == nil {
			if has {
				t.Fatalf("vless-tcp alpn=%v: want alpn absent, got %v", c.in, got)
			}
			continue
		}
		if !has || len(got) != len(c.want) || got[0] != c.want[0] {
			t.Fatalf("vless-tcp alpn=%v: got %v, want %v", c.in, tl["alpn"], c.want)
		}
	}

	// vless over ws: ws strips h2 first, then h3 is stripped too -> http/1.1 remains.
	ews := generator_singBoxEndpoint("vless-ws-h3", model.ProtoVLESS, map[string]any{"uuid": "u"})
	ews.Transport = &model.Transport{Type: "ws", Path: "/p"}
	ews.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: "x", ALPN: []string{"h3", "h2", "http/1.1"}}
	wtl := generator_genOne(t, ews)["tls"].(map[string]any)
	if got, _ := wtl["alpn"].([]string); len(got) != 1 || got[0] != "http/1.1" {
		t.Fatalf("vless-ws alpn=[h3,h2,http/1.1]: got %v, want [http/1.1]", wtl["alpn"])
	}

	// QUIC-native protocols keep h3 (it is the correct ALPN there).
	etuic := generator_singBoxEndpoint("tuic-h3", model.ProtoTUIC, map[string]any{
		"uuid": "11111111-2222-3333-4444-555555555555", "password": "p",
	})
	etuic.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: "x", ALPN: []string{"h3"}}
	if got, _ := generator_genOne(t, etuic)["tls"].(map[string]any)["alpn"].([]string); len(got) != 1 || got[0] != "h3" {
		t.Fatalf("tuic alpn=[h3] must be kept (QUIC), got %v", got)
	}
	ehy2 := generator_singBoxEndpoint("hy2-h3", model.ProtoHysteria2, map[string]any{"password": "p"})
	ehy2.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: "x", ALPN: []string{"h3"}}
	if got, _ := generator_genOne(t, ehy2)["tls"].(map[string]any)["alpn"].([]string); len(got) != 1 || got[0] != "h3" {
		t.Fatalf("hysteria2 alpn=[h3] must be kept (QUIC), got %v", got)
	}
}

// TestTransportAndTLSTogether exercises both transport and TLS landing on one
// outbound (ws + reality), the common real-world VLESS-Reality-over-ws case.
func TestTransportAndTLSTogether(t *testing.T) {
	e := generator_singBoxEndpoint("vless-ws-rty", model.ProtoVLESS, map[string]any{
		"uuid": "u", "flow": "xtls-rprx-vision",
	})
	e.Transport = &model.Transport{Type: "ws", Path: "/ray", Host: "front.example.com"}
	e.TLS = &model.TLS{Enabled: true, Type: "reality", SNI: "front.example.com", PublicKey: generatorTestPBK, ShortID: "ff"}
	ob := generator_genOne(t, e)

	// flow (xtls-rprx-vision) cannot run over a transport, so it must be dropped here
	// even though reality + the ws transport are both kept (sing-box would otherwise
	// fail every connection at runtime). See TestOutboundVLESSFlowDroppedWithTransport.
	if _, ok := ob["flow"]; ok {
		t.Fatalf("flow must be dropped when a transport is set, got %v", ob["flow"])
	}
	tr, ok := ob["transport"].(map[string]any)
	if !ok || tr["type"] != "ws" {
		t.Fatalf("transport = %v", ob["transport"])
	}
	tl, ok := ob["tls"].(map[string]any)
	if !ok {
		t.Fatalf("tls missing: %T", ob["tls"])
	}
	if _, ok := tl["reality"].(map[string]any); !ok {
		t.Fatalf("reality missing: %v", tl)
	}
}

// --- str helper edge: non-string value -------------------------------------

// TestStrNonStringParam confirms str() returns "" (and the key is therefore
// omitted) when a param holds a non-string value.
func TestStrNonStringParam(t *testing.T) {
	e := generator_singBoxEndpoint("vless-badtype", model.ProtoVLESS, map[string]any{
		"uuid": 12345, // not a string
	})
	ob := generator_genOne(t, e)
	// uuid is always set (even to "") in the vless branch; str returns "".
	if ob["uuid"] != "" {
		t.Fatalf("uuid from non-string param = %v, want empty string", ob["uuid"])
	}
}

// --- route section: multiple rule match kinds -------------------------------

// TestRouteAllMatchKinds drives every addIf-backed match field plus port and a
// non-direct default, covering the route rule assembly branches.
func TestRouteAllMatchKinds(t *testing.T) {
	vless := generator_singBoxEndpoint("rt-vless", model.ProtoVLESS, map[string]any{"uuid": "u"})
	p := &model.Profile{
		Endpoints: []model.Endpoint{vless},
		Rules: []model.Rule{
			{
				ID:           "rich",
				DomainSuffix: []string{".cn"},
				Domain:       []string{"exact.example.com"},
				GeoSite:      []string{"geolocation-cn"},
				GeoIP:        []string{"cn"},
				IPCIDR:       []string{"10.0.0.0/8"},
				Port:         []int{80, 443},
				Outbound:     model.OutboundBlock,
			},
			{ID: "def", Default: true, Outbound: vless.ID},
		},
	}
	res, err := Generate(p, Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	route := res.Config["route"].(map[string]any)
	if route["final"] != vless.ID {
		t.Fatalf("route.final = %v, want %q", route["final"], vless.ID)
	}
	rules, ok := route["rules"].([]map[string]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %v", route["rules"])
	}
	r := rules[0]
	// A block-targeted rule is now a reject action (sing-box >=1.12), not an outbound.
	if r["action"] != "reject" {
		t.Fatalf("rule action = %v, want reject", r["action"])
	}
	if _, has := r["outbound"]; has {
		t.Fatalf("reject rule must not carry an outbound, got %v", r["outbound"])
	}
	// A rule with BOTH geosite AND geoip becomes a logical-AND rule: inline these were
	// different field types (AND'd), but two tags in one rule_set field are OR'd, so the
	// generator must AND them via sub-rules to preserve the original semantics. The
	// domain/ip/port matchers ride along as the first AND sub-rule.
	if r["type"] != "logical" || r["mode"] != "and" {
		t.Fatalf("rule must be a logical-and (geosite AND geoip): %v", r)
	}
	if _, has := r["geosite"]; has {
		t.Fatalf("rule must not carry inline geosite (bricks sing-box 1.12): %v", r["geosite"])
	}
	sub := r["rules"].([]map[string]any)
	if len(sub) != 3 {
		t.Fatalf("logical sub-rules = %d, want 3 (matchers + geosite + geoip)", len(sub))
	}
	matchers := sub[0] // domain/ip/port
	if len(matchers["domain_suffix"].([]string)) != 1 || len(matchers["domain"].([]string)) != 1 ||
		len(matchers["ip_cidr"].([]string)) != 1 || len(matchers["port"].([]int)) != 2 {
		t.Fatalf("matcher sub-rule wrong: %v", matchers)
	}
	if gs := sub[1]["rule_set"].([]string); len(gs) != 1 || gs[0] != "geosite-geolocation-cn" {
		t.Fatalf("geosite sub-rule = %v", sub[1])
	}
	if gi := sub[2]["rule_set"].([]string); len(gi) != 1 || gi[0] != "geoip-cn" {
		t.Fatalf("geoip sub-rule = %v", sub[2])
	}
	// The two synthesised rule-sets must be present as remote .srs entries.
	sets, _ := route["rule_set"].([]map[string]any)
	got := map[string]string{}
	for _, s := range sets {
		got[s["tag"].(string)] = s["url"].(string)
	}
	if u := got["geosite-geolocation-cn"]; u != geositeSRSBase+"geolocation-cn.srs" {
		t.Fatalf("geosite rule-set url = %q", u)
	}
	if u := got["geoip-cn"]; u != geoipSRSBase+"cn.srs" {
		t.Fatalf("geoip rule-set url = %q", u)
	}
}

// TestRouteNoDefaultFallsBackToDirect confirms that without a default rule the
// route final is "direct" while non-default rules still emit.
func TestRouteNoDefaultFallsBackToDirect(t *testing.T) {
	vless := generator_singBoxEndpoint("rt-vless2", model.ProtoVLESS, map[string]any{"uuid": "u"})
	p := &model.Profile{
		Endpoints: []model.Endpoint{vless},
		Rules: []model.Rule{
			{ID: "r1", Domain: []string{"a.example.com"}, Outbound: vless.ID},
		},
	}
	res, err := Generate(p, Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	route := res.Config["route"].(map[string]any)
	if route["final"] != model.OutboundDirect {
		t.Fatalf("route.final = %v, want direct (no default rule)", route["final"])
	}
	rules, ok := route["rules"].([]map[string]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %v", route["rules"])
	}
}

// --- selector default group type (groupOutbound default branch) -------------

// TestFallbackGroupIsUrltest confirms a GroupFallback group is realized as a
// urltest outbound (shares the urltest case), with default Health knobs when
// Test is nil.
func TestFallbackGroupIsUrltest(t *testing.T) {
	a := generator_singBoxEndpoint("fb-a", model.ProtoVLESS, map[string]any{"uuid": "a"})
	b := generator_singBoxEndpoint("fb-b", model.ProtoTrojan, map[string]any{"password": "b"})
	p := &model.Profile{
		Endpoints: []model.Endpoint{a, b},
		Groups: []model.Group{{
			ID: "fb", Name: "Fallback", Type: model.GroupFallback,
			Members: []string{a.ID, b.ID},
			// Test nil -> defaults apply.
		}},
	}
	res, err := Generate(p, Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	byTag := generator_outboundsByTag(t, res)
	fb := byTag["fb"]
	if fb == nil || fb["type"] != "urltest" {
		t.Fatalf("fallback group type = %v, want urltest", fb["type"])
	}
	if fb["url"] != defaultHealthURL {
		t.Fatalf("default url = %v, want %q", fb["url"], defaultHealthURL)
	}
	if fb["interval"] != "1m" {
		t.Fatalf("default interval = %v, want 1m", fb["interval"])
	}
	if fb["tolerance"] != 50 {
		t.Fatalf("default tolerance = %v, want 50", fb["tolerance"])
	}
}
