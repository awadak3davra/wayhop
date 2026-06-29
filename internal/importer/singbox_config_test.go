package importer

// Tests for sing-box config.json import (ParseSingbox / looksLikeSingbox) and the
// generator->import ROUND-TRIP. Internal test package so it can call the unexported
// looksLikeSingbox directly AND import the generator: generator's production code
// never imports importer, so importing generator from importer's test binary creates
// no cycle (the two packages' test binaries are independent).
//
// All servers / UUIDs / keys here are SYNTHETIC.

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"velinx/internal/generator"
	"velinx/internal/model"
)

// synthWGKey returns a valid 32-byte base64 WireGuard key derived from seed (so
// tests use distinct, structurally-valid keys without hardcoding a real one).
func synthWGKey(seed byte) string {
	var b [32]byte
	for i := range b {
		b[i] = seed + byte(i)
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

func TestLooksLikeSingbox(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"outbounds array", `{"outbounds":[{"type":"vless","tag":"a"}]}`, true},
		{"endpoints array", `{"endpoints":[{"type":"wireguard","tag":"w"}]}`, true},
		{"empty outbounds array", `{"outbounds":[]}`, true},
		{"full config", `{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}],"route":{}}`, true},
		{"clash yaml", "proxies:\n  - name: a\n    type: ss\n", false},
		{"vless link", "vless://uuid@host:443?security=tls#n", false},
		{"base64 blob", "dmxlc3M6Ly91dWlkQGhvc3Q6NDQz", false},
		{"non-singbox json", `{"a":1}`, false},
		{"outbounds not array", `{"outbounds":{"type":"vless"}}`, false},
		{"outbounds null", `{"outbounds":null}`, false},
		{"top-level array", `[{"type":"vless"}]`, false},
		{"invalid json", `{"outbounds":[`, false},
		{"empty", ``, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := looksLikeSingbox(c.in); got != c.want {
				t.Fatalf("looksLikeSingbox(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// TestSubscriptionDispatchSingbox verifies ParseSubscription routes a sing-box
// config to ParseSingbox (not the line/base64 path) and leaves the other formats
// to their own paths.
func TestSubscriptionDispatchSingbox(t *testing.T) {
	cfg := `{"outbounds":[{"type":"vless","tag":"v","server":"h","server_port":443,"uuid":"u"}]}`
	eps, errs := ParseSubscription(cfg)
	if len(errs) != 0 {
		t.Fatalf("dispatch errs: %v", errs)
	}
	if len(eps) != 1 || eps[0].Protocol != model.ProtoVLESS {
		t.Fatalf("dispatch did not route to ParseSingbox: %+v", eps)
	}
}

func TestParseSingbox_PerType(t *testing.T) {
	type check func(t *testing.T, e model.Endpoint)
	cases := []struct {
		name   string
		config string
		proto  model.Protocol
		verify check
	}{
		{
			name:   "vless reality",
			config: `{"outbounds":[{"type":"vless","tag":"v1","server":"1.2.3.4","server_port":443,"uuid":"uuid-1","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"ex.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"pk","short_id":"ab"}}}]}`,
			proto:  model.ProtoVLESS,
			verify: func(t *testing.T, e model.Endpoint) {
				if e.Params["uuid"] != "uuid-1" || e.Params["flow"] != "xtls-rprx-vision" {
					t.Fatalf("vless params: %+v", e.Params)
				}
				if e.TLS == nil || e.TLS.Type != "reality" || e.TLS.PublicKey != "pk" || e.TLS.ShortID != "ab" {
					t.Fatalf("vless tls: %+v", e.TLS)
				}
				if e.TLS.Fingerprint != "chrome" || e.TLS.SNI != "ex.com" {
					t.Fatalf("vless tls fp/sni: %+v", e.TLS)
				}
			},
		},
		{
			name:   "vless ws+tls",
			config: `{"outbounds":[{"type":"vless","tag":"v2","server":"h","server_port":443,"uuid":"u","transport":{"type":"ws","path":"/p","headers":{"Host":"cdn.example"}},"tls":{"enabled":true,"server_name":"cdn.example","alpn":["http/1.1"]}}]}`,
			proto:  model.ProtoVLESS,
			verify: func(t *testing.T, e model.Endpoint) {
				if e.Transport == nil || e.Transport.Type != "ws" || e.Transport.Path != "/p" || e.Transport.Host != "cdn.example" {
					t.Fatalf("vless transport: %+v", e.Transport)
				}
				if e.TLS == nil || len(e.TLS.ALPN) != 1 || e.TLS.ALPN[0] != "http/1.1" {
					t.Fatalf("vless alpn: %+v", e.TLS)
				}
			},
		},
		{
			name:   "vmess grpc",
			config: `{"outbounds":[{"type":"vmess","tag":"m1","server":"h","server_port":8443,"uuid":"u","alter_id":0,"security":"auto","transport":{"type":"grpc","service_name":"svc"}}]}`,
			proto:  model.ProtoVMess,
			verify: func(t *testing.T, e model.Endpoint) {
				if e.Params["uuid"] != "u" || e.Params["security"] != "auto" {
					t.Fatalf("vmess params: %+v", e.Params)
				}
				if e.Transport == nil || e.Transport.Type != "grpc" || e.Transport.ServiceName != "svc" {
					t.Fatalf("vmess transport: %+v", e.Transport)
				}
			},
		},
		{
			name:   "trojan",
			config: `{"outbounds":[{"type":"trojan","tag":"t1","server":"h","server_port":443,"password":"pw","tls":{"enabled":true,"server_name":"h","insecure":true}}]}`,
			proto:  model.ProtoTrojan,
			verify: func(t *testing.T, e model.Endpoint) {
				if e.Params["password"] != "pw" {
					t.Fatalf("trojan pw: %+v", e.Params)
				}
				if e.TLS == nil || !e.TLS.Insecure {
					t.Fatalf("trojan tls: %+v", e.TLS)
				}
			},
		},
		{
			name:   "shadowsocks",
			config: `{"outbounds":[{"type":"shadowsocks","tag":"s1","server":"h","server_port":8388,"method":"aes-256-gcm","password":"pw","udp_over_tcp":true,"plugin":"obfs-local","plugin_opts":"obfs=http"}]}`,
			proto:  model.ProtoShadowsocks,
			verify: func(t *testing.T, e model.Endpoint) {
				if e.Params["method"] != "aes-256-gcm" || e.Params["password"] != "pw" {
					t.Fatalf("ss params: %+v", e.Params)
				}
				if e.Params["udp_over_tcp"] != true {
					t.Fatalf("ss uot: %+v", e.Params)
				}
				if e.Params["plugin"] != "obfs-local" || e.Params["plugin_opts"] != "obfs=http" {
					t.Fatalf("ss plugin: %+v", e.Params)
				}
			},
		},
		{
			name:   "hysteria2",
			config: `{"outbounds":[{"type":"hysteria2","tag":"h1","server":"h","server_port":443,"password":"pw","obfs":{"type":"salamander","password":"op"},"server_ports":["20000:50000"],"tls":{"enabled":true,"server_name":"h","insecure":true,"alpn":["h3"]}}]}`,
			proto:  model.ProtoHysteria2,
			verify: func(t *testing.T, e model.Endpoint) {
				if e.Params["password"] != "pw" || e.Params["obfs"] != "salamander" || e.Params["obfs_password"] != "op" {
					t.Fatalf("hy2 params: %+v", e.Params)
				}
				if e.Params["hop_ports"] != "20000-50000" {
					t.Fatalf("hy2 hop_ports: %+v", e.Params["hop_ports"])
				}
				if e.TLS == nil || !e.TLS.Insecure {
					t.Fatalf("hy2 tls: %+v", e.TLS)
				}
			},
		},
		{
			name:   "tuic",
			config: `{"outbounds":[{"type":"tuic","tag":"u1","server":"h","server_port":443,"uuid":"12345678-1234-1234-1234-1234567890ab","password":"pw","congestion_control":"bbr","udp_relay_mode":"native","tls":{"enabled":true,"server_name":"h","alpn":["h3"]}}]}`,
			proto:  model.ProtoTUIC,
			verify: func(t *testing.T, e model.Endpoint) {
				if e.Params["uuid"] != "12345678-1234-1234-1234-1234567890ab" || e.Params["password"] != "pw" {
					t.Fatalf("tuic params: %+v", e.Params)
				}
				if e.Params["congestion_control"] != "bbr" || e.Params["udp_relay_mode"] != "native" {
					t.Fatalf("tuic cc/relay: %+v", e.Params)
				}
			},
		},
		{
			name:   "socks",
			config: `{"outbounds":[{"type":"socks","tag":"k1","server":"h","server_port":1080,"version":"5","username":"u","password":"p"}]}`,
			proto:  model.ProtoSOCKS,
			verify: func(t *testing.T, e model.Endpoint) {
				if e.Params["username"] != "u" || e.Params["password"] != "p" {
					t.Fatalf("socks params: %+v", e.Params)
				}
			},
		},
		{
			name:   "http",
			config: `{"outbounds":[{"type":"http","tag":"hp1","server":"h","server_port":8080,"username":"u","password":"p"}]}`,
			proto:  model.ProtoHTTP,
			verify: func(t *testing.T, e model.Endpoint) {
				if e.Params["username"] != "u" || e.Params["password"] != "p" {
					t.Fatalf("http params: %+v", e.Params)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			eps, errs := ParseSingbox(c.config)
			if len(errs) != 0 {
				t.Fatalf("unexpected errors: %v", errs)
			}
			if len(eps) != 1 {
				t.Fatalf("got %d endpoints, want 1", len(eps))
			}
			e := eps[0]
			if e.Protocol != c.proto {
				t.Fatalf("protocol = %q, want %q", e.Protocol, c.proto)
			}
			if e.Engine != model.EngineSingBox {
				t.Fatalf("engine = %q, want singbox", e.Engine)
			}
			if e.Server != "h" && e.Server != "1.2.3.4" && e.Server != "cdn.example" {
				// servers in fixtures are "h"/"1.2.3.4"; just assert non-empty
				if e.Server == "" {
					t.Fatalf("empty server")
				}
			}
			if !e.Enabled {
				t.Fatalf("endpoint not enabled")
			}
			if e.ID == "" {
				t.Fatalf("empty id")
			}
			c.verify(t, e)
		})
	}
}

func TestParseSingbox_WireGuardEndpoint(t *testing.T) {
	priv := synthWGKey(1)
	pub := synthWGKey(2)
	psk := synthWGKey(3)
	config := `{"endpoints":[{"type":"wireguard","tag":"wg1","private_key":"` + priv +
		`","address":["10.0.0.2/32"],"mtu":1280,"peers":[{"address":"5.6.7.8","port":51820,"public_key":"` + pub +
		`","pre_shared_key":"` + psk + `","reserved":[1,2,3],"persistent_keepalive_interval":25,"allowed_ips":["0.0.0.0/0","::/0"]}]}]}`
	eps, errs := ParseSingbox(config)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(eps) != 1 {
		t.Fatalf("got %d endpoints, want 1", len(eps))
	}
	e := eps[0]
	if e.Protocol != model.ProtoWireGuard || e.Engine != model.EngineSingBox {
		t.Fatalf("proto/engine: %q/%q", e.Protocol, e.Engine)
	}
	if e.Server != "5.6.7.8" || e.Port != 51820 {
		t.Fatalf("server/port: %s:%d", e.Server, e.Port)
	}
	if e.Params["private_key"] != priv || e.Params["peer_public_key"] != pub || e.Params["pre_shared_key"] != psk {
		t.Fatalf("wg keys: %+v", e.Params)
	}
	if e.MTU != 1280 || e.PersistentKeepalive != 25 {
		t.Fatalf("wg mtu/keepalive: %d/%d", e.MTU, e.PersistentKeepalive)
	}
	la, ok := e.Params["local_address"].([]string)
	if !ok || len(la) != 1 || la[0] != "10.0.0.2/32" {
		t.Fatalf("wg local_address: %+v", e.Params["local_address"])
	}
}

func TestParseSingbox_SkipsBuiltinsAndCollectsUnknown(t *testing.T) {
	config := `{"outbounds":[
		{"type":"direct","tag":"direct"},
		{"type":"block","tag":"block"},
		{"type":"dns","tag":"dns"},
		{"type":"selector","tag":"grp","outbounds":["a","b"]},
		{"type":"urltest","tag":"auto","outbounds":["a"]},
		{"type":"vless","tag":"v","server":"h","server_port":443,"uuid":"u"},
		{"type":"wireguard_legacy_outbound","tag":"x","server":"h","server_port":1}
	]}`
	eps, errs := ParseSingbox(config)
	if len(eps) != 1 || eps[0].Protocol != model.ProtoVLESS {
		t.Fatalf("expected only the vless endpoint, got %+v", eps)
	}
	if len(errs) != 1 || !strings.Contains(errs[0], "wireguard_legacy_outbound") {
		t.Fatalf("expected one unknown-type error, got %v", errs)
	}
}

// TestRoundTrip builds a profile with one endpoint per supported type, runs it
// through generator.Generate, marshals the config, re-imports via ParseSingbox, and
// asserts the core fields survive the round-trip.
func TestRoundTrip(t *testing.T) {
	priv := synthWGKey(10)
	pub := synthWGKey(20)
	p := &model.Profile{
		Endpoints: []model.Endpoint{
			{
				ID: "vless-ep", Name: "vless-ep", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
				Server: "v.example", Port: 443, Enabled: true,
				Params: map[string]any{"uuid": "uuid-vless", "flow": "xtls-rprx-vision"},
				TLS:    &model.TLS{Enabled: true, Type: "reality", SNI: "v.example", PublicKey: validRealityKey(), ShortID: "abcd", Fingerprint: "chrome"},
			},
			{
				ID: "vmess-ep", Name: "vmess-ep", Engine: model.EngineSingBox, Protocol: model.ProtoVMess,
				Server: "m.example", Port: 8443, Enabled: true,
				Params:    map[string]any{"uuid": "uuid-vmess", "alter_id": 0, "security": "auto"},
				Transport: &model.Transport{Type: "ws", Path: "/ws", Host: "m.example"},
				TLS:       &model.TLS{Enabled: true, Type: "tls", SNI: "m.example"},
			},
			{
				ID: "trojan-ep", Name: "trojan-ep", Engine: model.EngineSingBox, Protocol: model.ProtoTrojan,
				Server: "t.example", Port: 443, Enabled: true,
				Params: map[string]any{"password": "pw-trojan"},
				TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "t.example"},
			},
			{
				ID: "ss-ep", Name: "ss-ep", Engine: model.EngineSingBox, Protocol: model.ProtoShadowsocks,
				Server: "s.example", Port: 8388, Enabled: true,
				Params: map[string]any{"method": "aes-256-gcm", "password": "pw-ss"},
			},
			{
				ID: "hy2-ep", Name: "hy2-ep", Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
				Server: "hy.example", Port: 443, Enabled: true,
				Params: map[string]any{"password": "pw-hy2", "obfs": "salamander", "obfs_password": "op"},
				TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "hy.example", Insecure: true},
			},
			{
				ID: "tuic-ep", Name: "tuic-ep", Engine: model.EngineSingBox, Protocol: model.ProtoTUIC,
				Server: "tu.example", Port: 443, Enabled: true,
				Params: map[string]any{"uuid": "12345678-1234-1234-1234-1234567890ab", "password": "pw-tuic", "congestion_control": "bbr", "udp_relay_mode": "native"},
				TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "tu.example"},
			},
			{
				ID: "wg-ep", Name: "wg-ep", Engine: model.EngineSingBox, Protocol: model.ProtoWireGuard,
				Server: "wg.example", Port: 51820, Enabled: true, MTU: 1280, PersistentKeepalive: 25,
				Params: map[string]any{"private_key": priv, "peer_public_key": pub, "local_address": []string{"10.0.0.2/32"}},
			},
		},
	}

	res, err := generator.Generate(p, generator.Options{})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	raw, err := json.Marshal(res.Config)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	eps, errs := ParseSingbox(string(raw))
	if len(errs) != 0 {
		t.Fatalf("re-import errors: %v", errs)
	}

	got := map[model.Protocol]model.Endpoint{}
	for _, e := range eps {
		got[e.Protocol] = e
	}
	if len(got) != 7 {
		t.Fatalf("expected 7 endpoints by protocol, got %d: %+v", len(got), eps)
	}

	// vless
	v := got[model.ProtoVLESS]
	if v.Server != "v.example" || v.Port != 443 || v.Params["uuid"] != "uuid-vless" {
		t.Fatalf("vless core: %+v %+v", v, v.Params)
	}
	if v.Params["flow"] != "xtls-rprx-vision" {
		t.Fatalf("vless flow lost: %+v", v.Params)
	}
	if v.TLS == nil || v.TLS.Type != "reality" || v.TLS.SNI != "v.example" || v.TLS.ShortID != "abcd" {
		t.Fatalf("vless tls: %+v", v.TLS)
	}

	// vmess (ws + tls)
	m := got[model.ProtoVMess]
	if m.Server != "m.example" || m.Port != 8443 || m.Params["uuid"] != "uuid-vmess" {
		t.Fatalf("vmess core: %+v", m.Params)
	}
	if m.Transport == nil || m.Transport.Type != "ws" || m.Transport.Path != "/ws" || m.Transport.Host != "m.example" {
		t.Fatalf("vmess transport: %+v", m.Transport)
	}
	if m.TLS == nil || m.TLS.SNI != "m.example" {
		t.Fatalf("vmess tls: %+v", m.TLS)
	}

	// trojan
	tr := got[model.ProtoTrojan]
	if tr.Server != "t.example" || tr.Params["password"] != "pw-trojan" || tr.TLS == nil {
		t.Fatalf("trojan: %+v %+v", tr, tr.Params)
	}

	// shadowsocks
	ss := got[model.ProtoShadowsocks]
	if ss.Server != "s.example" || ss.Port != 8388 || ss.Params["method"] != "aes-256-gcm" || ss.Params["password"] != "pw-ss" {
		t.Fatalf("ss: %+v", ss.Params)
	}

	// hysteria2
	hy := got[model.ProtoHysteria2]
	if hy.Server != "hy.example" || hy.Params["password"] != "pw-hy2" || hy.Params["obfs"] != "salamander" || hy.Params["obfs_password"] != "op" {
		t.Fatalf("hy2: %+v", hy.Params)
	}
	if hy.TLS == nil || !hy.TLS.Insecure {
		t.Fatalf("hy2 insecure lost: %+v", hy.TLS)
	}

	// tuic
	tu := got[model.ProtoTUIC]
	if tu.Server != "tu.example" || tu.Params["uuid"] != "12345678-1234-1234-1234-1234567890ab" || tu.Params["password"] != "pw-tuic" {
		t.Fatalf("tuic: %+v", tu.Params)
	}
	if tu.Params["congestion_control"] != "bbr" || tu.Params["udp_relay_mode"] != "native" {
		t.Fatalf("tuic cc/relay: %+v", tu.Params)
	}

	// wireguard
	wg := got[model.ProtoWireGuard]
	if wg.Server != "wg.example" || wg.Port != 51820 {
		t.Fatalf("wg server/port: %s:%d", wg.Server, wg.Port)
	}
	if wg.Params["private_key"] != priv || wg.Params["peer_public_key"] != pub {
		t.Fatalf("wg keys: %+v", wg.Params)
	}
	if wg.MTU != 1280 || wg.PersistentKeepalive != 25 {
		t.Fatalf("wg mtu/keepalive: %d/%d", wg.MTU, wg.PersistentKeepalive)
	}

	// Re-generate the re-imported endpoints to prove the round-trip is accepted by
	// the generator (no errors), i.e. the result is a valid profile.
	p2 := &model.Profile{Endpoints: eps}
	if _, err := generator.Generate(p2, generator.Options{}); err != nil {
		t.Fatalf("re-generate of re-imported endpoints failed: %v", err)
	}
}

// validRealityKey returns a base64 x25519-shaped public key (32 bytes) so the
// generator's tlsJSON emits the reality block (it drops a malformed key).
func validRealityKey() string {
	var b [32]byte
	for i := range b {
		b[i] = byte(i + 7)
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

// TestSbIntRejectsOverflow: sbInt must reject a value beyond int32 range (returning 0)
// instead of overflowing the int(t) conversion to a junk value on a 32-bit router arch —
// mirroring asInt's guard. A real port/MTU/alter_id is tiny, so a huge number in a pasted
// sing-box config is bogus.
func TestSbIntRejectsOverflow(t *testing.T) {
	const overMaxInt32 = 3000000000 // > math.MaxInt32 (2147483647)
	cases := []struct {
		name string
		v    any
		want int
	}{
		{"valid float port", float64(443), 443},
		{"valid json.Number", json.Number("1500"), 1500},
		{"overflow float", float64(overMaxInt32), 0},
		{"overflow json.Number", json.Number("3000000000"), 0},
	}
	for _, c := range cases {
		if got := sbInt(map[string]any{"x": c.v}, "x"); got != c.want {
			t.Errorf("%s: sbInt=%d, want %d", c.name, got, c.want)
		}
	}
}
