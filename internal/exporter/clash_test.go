package exporter

import (
	"strings"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// TestClashConfigPerType checks each proxy type emits the right clash keys.
func TestClashConfigPerType(t *testing.T) {
	cases := []struct {
		name string
		ep   model.Endpoint
		want []string // substrings that must appear in the rendered YAML
	}{
		{
			name: "ss",
			ep: model.Endpoint{
				Name: "SS", Engine: model.EngineSingBox, Protocol: model.ProtoShadowsocks,
				Server: "9.9.9.9", Port: 8388, Enabled: true,
				Params: map[string]any{"method": "aes-256-gcm", "password": "sspw"},
			},
			want: []string{"type: ss", "cipher: aes-256-gcm", "password: sspw", "server: 9.9.9.9", "port: 8388"},
		},
		{
			name: "vmess-ws-tls",
			ep: model.Endpoint{
				Name: "VM", Engine: model.EngineSingBox, Protocol: model.ProtoVMess,
				Server: "1.1.1.1", Port: 443, Enabled: true,
				Params:    map[string]any{"uuid": "u-1", "alter_id": 0, "security": "auto"},
				Transport: &model.Transport{Type: "ws", Path: "/vm", Host: "cdn.example.com"},
				TLS:       &model.TLS{Enabled: true, Type: "tls", SNI: "cdn.example.com"},
			},
			want: []string{"type: vmess", "uuid: u-1", "cipher: auto", "network: ws", "ws-opts:", "path: /vm", "Host: cdn.example.com", "tls: true", "servername: cdn.example.com"},
		},
		{
			name: "trojan",
			ep: model.Endpoint{
				Name: "TJ", Engine: model.EngineSingBox, Protocol: model.ProtoTrojan,
				Server: "2.2.2.2", Port: 443, Enabled: true,
				Params: map[string]any{"password": "tjpw"},
				TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "sni.example.com"},
			},
			want: []string{"type: trojan", "password: tjpw", "sni: sni.example.com"},
		},
		{
			name: "anytls",
			ep: model.Endpoint{
				Name: "AT", Engine: model.EngineSingBox, Protocol: model.ProtoAnyTLS,
				Server: "2.2.2.3", Port: 8443, Enabled: true,
				Params: map[string]any{"password": "atpw"},
				TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "at.example.com", Insecure: true},
			},
			want: []string{"type: anytls", "password: atpw", "sni: at.example.com", "skip-cert-verify: true"},
		},
		{
			name: "vless-reality",
			ep: model.Endpoint{
				Name: "VL", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
				Server: "3.3.3.3", Port: 443, Enabled: true,
				Params: map[string]any{"uuid": "u-2", "flow": "xtls-rprx-vision"},
				TLS:    &model.TLS{Enabled: true, Type: "reality", SNI: "www.microsoft.com", Fingerprint: "chrome", PublicKey: "PUBKEYabc", ShortID: "ab12"},
			},
			want: []string{"type: vless", "uuid: u-2", "flow: xtls-rprx-vision", "tls: true", "servername: www.microsoft.com", "reality-opts:", "public-key: PUBKEYabc", "short-id: ab12"},
		},
		{
			name: "hysteria2",
			ep: model.Endpoint{
				Name: "HY", Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
				Server: "5.6.7.8", Port: 8443, Enabled: true,
				Params: map[string]any{"password": "hpass", "obfs": "salamander", "obfs_password": "ob", "hop_ports": "20000-30000"},
				TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "example.org"},
			},
			want: []string{"type: hysteria2", "password: hpass", "obfs: salamander", "obfs-password: ob", "ports: 20000-30000", "sni: example.org"},
		},
		{
			name: "tuic",
			ep: model.Endpoint{
				Name: "TU", Engine: model.EngineSingBox, Protocol: model.ProtoTUIC,
				Server: "4.4.4.4", Port: 443, Enabled: true,
				Params: map[string]any{"uuid": "u-3", "password": "tupw", "congestion_control": "bbr", "udp_relay_mode": "native"},
				TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "tuic.example.com"},
			},
			want: []string{"type: tuic", "uuid: u-3", "password: tupw", "congestion-controller: bbr", "udp-relay-mode: native"},
		},
		{
			name: "wireguard",
			ep: model.Endpoint{
				Name: "WG", Engine: model.EngineSingBox, Protocol: model.ProtoWireGuard,
				Server: "203.0.113.7", Port: 51820, Enabled: true, MTU: 1280,
				Params: map[string]any{
					"private_key": "PRIV=", "peer_public_key": "PUB=",
					"local_address": []string{"10.13.13.2/32"},
				},
			},
			want: []string{"type: wireguard", "private-key: PRIV=", "public-key: PUB=", "ip: 10.13.13.2/32", "mtu: 1280"},
		},
	}
	for _, c := range cases {
		yaml, skipped := ClashConfig([]model.Endpoint{c.ep})
		if len(skipped) != 0 {
			t.Fatalf("%s: unexpectedly skipped: %v\n%s", c.name, skipped, yaml)
		}
		for _, sub := range c.want {
			if !strings.Contains(yaml, sub) {
				t.Errorf("%s: missing %q in:\n%s", c.name, sub, yaml)
			}
		}
		// Every config has the group + ruleset scaffold.
		if !strings.Contains(yaml, "name: WayHop") || !strings.Contains(yaml, "MATCH,WayHop") {
			t.Errorf("%s: missing proxy-group/rules scaffold:\n%s", c.name, yaml)
		}
	}
}

// TestClashBoolsUnquoted guards every YAML boolean against being scalar-quoted.
// clash/mihomo types tls / skip-cert-verify / udp-over-tcp as Go bool, and its strict
// decoder rejects a quoted-string source ('expected type bool, got string') — which
// fails the ENTIRE config load, not just one proxy. The round-trip test can't catch
// this because the importer un-quotes before parsing, so we assert the emitted shape.
func TestClashBoolsUnquoted(t *testing.T) {
	eps := []model.Endpoint{
		{ // vmess + TLS(insecure) -> tls: true + skip-cert-verify: true
			Name: "VM", Engine: model.EngineSingBox, Protocol: model.ProtoVMess,
			Server: "1.1.1.1", Port: 443, Enabled: true,
			Params: map[string]any{"uuid": "u", "alter_id": 0, "security": "auto"},
			TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "x.example", Insecure: true},
		},
		{ // ss + udp-over-tcp -> udp-over-tcp: true
			Name: "SS", Engine: model.EngineSingBox, Protocol: model.ProtoShadowsocks,
			Server: "9.9.9.9", Port: 8388, Enabled: true,
			Params: map[string]any{"method": "aes-256-gcm", "password": "p", "udp_over_tcp": true},
		},
	}
	yaml, skipped := ClashConfig(eps)
	if len(skipped) != 0 {
		t.Fatalf("unexpectedly skipped: %v\n%s", skipped, yaml)
	}
	for _, want := range []string{"tls: true", "skip-cert-verify: true", "udp-over-tcp: true"} {
		if !strings.Contains(yaml, want) {
			t.Errorf("missing bare YAML bool %q in:\n%s", want, yaml)
		}
	}
	for _, bad := range []string{`tls: "true"`, `skip-cert-verify: "true"`, `udp-over-tcp: "true"`, `tls: "false"`} {
		if strings.Contains(yaml, bad) {
			t.Errorf("boolean was scalar-quoted (clash/mihomo's bool decoder rejects it): %q in:\n%s", bad, yaml)
		}
	}
}

// TestClashReservedIsFlowList guards against re-quoting WARP `reserved`: it must be
// emitted as a YAML flow sequence ([a,b,c]), NOT the scalar-quoted string "[a,b,c]".
// clash/mihomo type `reserved` as a list of ints and reject the string form, which
// silently breaks the WARP WireGuard proxy on the client. (The round-trip test misses
// this because the importer unquotes before parsing — so we assert the emitted shape.)
func TestClashReservedIsFlowList(t *testing.T) {
	ep := model.Endpoint{
		Name: "WARP", Engine: model.EngineSingBox, Protocol: model.ProtoWireGuard,
		Server: "162.159.192.1", Port: 2408, Enabled: true,
		Params: map[string]any{
			"private_key": "PRIV=", "peer_public_key": "PUB=",
			"local_address": []string{"172.16.0.2/32"},
			"reserved":      []int{12, 34, 56},
		},
	}
	yaml, skipped := ClashConfig([]model.Endpoint{ep})
	if len(skipped) != 0 {
		t.Fatalf("unexpectedly skipped: %v\n%s", skipped, yaml)
	}
	if !strings.Contains(yaml, "reserved: [12,34,56]") {
		t.Errorf("reserved not emitted as a flow list; want `reserved: [12,34,56]` in:\n%s", yaml)
	}
	if strings.Contains(yaml, `reserved: "[`) || strings.Contains(yaml, `reserved: '[`) {
		t.Errorf("reserved was scalar-quoted into a string (clash/mihomo reject it):\n%s", yaml)
	}
}

// TestClashH2OptsHostIsFlowList guards the h2 (HTTP/2) transport export: mihomo types
// h2-opts.host as []string, so it must be a real flow sequence `host: [a.com]`, not a
// scalar-quoted "[a.com]" string — the latter trips mihomo's strict decoder and fails the
// WHOLE config load (same class as TestClashReservedIsFlowList).
func TestClashH2OptsHostIsFlowList(t *testing.T) {
	ep := model.Endpoint{
		ID: "h", Name: "H2", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: "1.1.1.1", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u1"},
		TLS:       &model.TLS{Enabled: true, SNI: "cdn.example.com"},
		Transport: &model.Transport{Type: "http", Path: "/h2", Host: "cdn.example.com"},
	}
	yaml, skipped := ClashConfig([]model.Endpoint{ep})
	if len(skipped) != 0 {
		t.Fatalf("unexpectedly skipped: %v\n%s", skipped, yaml)
	}
	if !strings.Contains(yaml, "host: [cdn.example.com]") {
		t.Errorf("h2-opts host not a flow list; want `host: [cdn.example.com]` in:\n%s", yaml)
	}
	if strings.Contains(yaml, `host: "[`) || strings.Contains(yaml, `host: '[`) {
		t.Errorf("h2-opts host was scalar-quoted into a string (mihomo rejects it):\n%s", yaml)
	}
	if got, errs := importer.ParseClash(yaml); len(got) != 1 {
		t.Fatalf("round-trip of h2 config: got %d (errs %v)\n%s", len(got), errs, yaml)
	}
}

// TestClashOmittedNestedGroupNotReferenced guards the group renderer: a group whose members
// are all unexportable is omitted, and a parent that nested it must NOT keep a dangling
// reference to the omitted name — mihomo rejects a proxy-group referencing an undefined
// proxy/group, failing the entire config load.
func TestClashOmittedNestedGroupNotReferenced(t *testing.T) {
	eps := []model.Endpoint{
		{ID: "e1", Name: "NL", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "1.1.1.1", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u1"}},
	}
	groups := []model.Group{
		{ID: "g-empty", Name: "EmptyGrp", Members: []string{"does-not-exist"}},
		{ID: "g-top", Name: "TopGrp", Members: []string{"e1", "g-empty"}},
	}
	yaml, _ := ClashConfigWithGroups(eps, groups)
	if strings.Contains(yaml, "EmptyGrp") {
		t.Errorf("omitted all-unexportable group EmptyGrp must not appear (a dangling ref breaks mihomo):\n%s", yaml)
	}
	if !strings.Contains(yaml, "TopGrp") || !strings.Contains(yaml, "- NL") {
		t.Errorf("TopGrp should still render with its exportable member:\n%s", yaml)
	}
	if got, errs := importer.ParseClash(yaml); len(got) != 1 {
		t.Fatalf("round-trip: got %d (errs %v)\n%s", len(got), errs, yaml)
	}
}

// TestClashFailoverGroups checks that a WayHop failover group exports as a clash
// url-test proxy-group (so a clash client keeps the panel's auto-failover), the top-level
// selector references the group instead of the now-grouped endpoints, the health params
// carry over, and the YAML still parses back to the endpoints. With no groups the output
// is the flat pre-groups form.
func TestClashFailoverGroups(t *testing.T) {
	eps := []model.Endpoint{
		{ID: "e1", Name: "NL", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "1.1.1.1", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u1"}},
		{ID: "e2", Name: "DE", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "2.2.2.2", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u2"}},
	}
	groups := []model.Group{{
		ID: "g1", Name: "EU-failover", Type: model.GroupURLTest,
		Members: []string{"e1", "e2"}, Test: &model.Health{URL: "http://t.example/204", Interval: 120, Tolerance: 80},
	}}
	yaml, skipped := ClashConfigWithGroups(eps, groups)
	if len(skipped) != 0 {
		t.Fatalf("unexpectedly skipped: %v\n%s", skipped, yaml)
	}
	for _, want := range []string{"type: url-test", "EU-failover", "http://t.example/204", "interval: 120", "tolerance: 80"} {
		if !strings.Contains(yaml, want) {
			t.Errorf("group export missing %q in:\n%s", want, yaml)
		}
	}
	// The url-test group must list both members.
	if !strings.Contains(yaml, "- NL") || !strings.Contains(yaml, "- DE") {
		t.Errorf("group members missing:\n%s", yaml)
	}
	// Still valid clash: re-import yields both endpoints (ParseClash reads proxies).
	got, errs := importer.ParseClash(yaml)
	if len(got) != 2 {
		t.Fatalf("round-trip of grouped config: got %d endpoints (errs %v)\n%s", len(got), errs, yaml)
	}

	// Backward-compat: no groups -> no url-test group, endpoints listed flat in the selector.
	flat, _ := ClashConfig(eps)
	if strings.Contains(flat, "type: url-test") {
		t.Errorf("nil-groups output must not contain a url-test group:\n%s", flat)
	}
}

// TestClashRoundTrip renders endpoints to clash YAML, re-imports via
// importer.ParseClash, and checks the key fields survive the trip.
func TestClashRoundTrip(t *testing.T) {
	eps := []model.Endpoint{
		{
			Name: "SS node", Engine: model.EngineSingBox, Protocol: model.ProtoShadowsocks,
			Server: "9.9.9.9", Port: 8388, Enabled: true,
			Params: map[string]any{"method": "aes-256-gcm", "password": "sspw"},
		},
		{
			Name: "VMess WS TLS", Engine: model.EngineSingBox, Protocol: model.ProtoVMess,
			Server: "1.1.1.1", Port: 443, Enabled: true,
			Params:    map[string]any{"uuid": "11111111-1111-1111-1111-111111111111", "alter_id": 0, "security": "auto"},
			Transport: &model.Transport{Type: "ws", Path: "/vm", Host: "cdn.example.com"},
			TLS:       &model.TLS{Enabled: true, Type: "tls", SNI: "cdn.example.com", Insecure: true},
		},
		{
			Name: "Trojan", Engine: model.EngineSingBox, Protocol: model.ProtoTrojan,
			Server: "2.2.2.2", Port: 443, Enabled: true,
			Params: map[string]any{"password": "tjpw"},
			TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "sni.example.com"},
		},
		{
			Name: "VLESS Reality", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
			Server: "3.3.3.3", Port: 443, Enabled: true,
			Params: map[string]any{"uuid": "22222222-2222-2222-2222-222222222222", "flow": "xtls-rprx-vision"},
			TLS:    &model.TLS{Enabled: true, Type: "reality", SNI: "www.microsoft.com", Fingerprint: "chrome", PublicKey: "PUBKEYabc", ShortID: "ab12"},
		},
		{
			Name: "HY2", Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
			Server: "5.6.7.8", Port: 8443, Enabled: true,
			Params: map[string]any{"password": "hpass", "obfs": "salamander", "obfs_password": "ob"},
			TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "example.org", Insecure: true},
		},
		{
			Name: "TUIC", Engine: model.EngineSingBox, Protocol: model.ProtoTUIC,
			Server: "4.4.4.4", Port: 443, Enabled: true,
			Params: map[string]any{"uuid": "33333333-3333-3333-3333-333333333333", "password": "tupw", "congestion_control": "bbr", "udp_relay_mode": "native"},
			TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "tuic.example.com"},
		},
		{
			Name: "WG node", Engine: model.EngineSingBox, Protocol: model.ProtoWireGuard,
			Server: "203.0.113.7", Port: 51820, Enabled: true, MTU: 1420,
			Params: map[string]any{
				"private_key": "PRIVkey=", "peer_public_key": "PUBkey=",
				"local_address": []string{"10.13.13.2/32"},
			},
		},
	}

	yaml, skipped := ClashConfig(eps)
	if len(skipped) != 0 {
		t.Fatalf("unexpected skips: %v", skipped)
	}
	got, errs := importer.ParseClash(yaml)
	if len(errs) != 0 {
		t.Fatalf("re-import errors: %v\n%s", errs, yaml)
	}
	if len(got) != len(eps) {
		t.Fatalf("re-imported %d endpoints, want %d\n%s", len(got), len(eps), yaml)
	}

	for i, want := range eps {
		g := got[i]
		if g.Protocol != want.Protocol || g.Server != want.Server || g.Port != want.Port {
			t.Errorf("%s: core mismatch: proto=%s server=%s port=%d", want.Name, g.Protocol, g.Server, g.Port)
			continue
		}
		// Per-protocol key fields.
		switch want.Protocol {
		case model.ProtoShadowsocks:
			eqParam(t, want.Name, g, "method", "aes-256-gcm")
			eqParam(t, want.Name, g, "password", "sspw")
		case model.ProtoVMess:
			eqParam(t, want.Name, g, "uuid", str(want.Params, "uuid"))
			if g.Transport == nil || g.Transport.Type != "ws" || g.Transport.Path != "/vm" {
				t.Errorf("%s: ws transport lost: %+v", want.Name, g.Transport)
			}
			if g.Transport != nil && g.Transport.Host != "cdn.example.com" {
				t.Errorf("%s: ws host lost: %q", want.Name, g.Transport.Host)
			}
			if g.TLS == nil || !g.TLS.Insecure {
				t.Errorf("%s: insecure flag lost: %+v", want.Name, g.TLS)
			}
		case model.ProtoTrojan:
			eqParam(t, want.Name, g, "password", "tjpw")
			if g.TLS == nil || g.TLS.SNI != "sni.example.com" {
				t.Errorf("%s: trojan tls/sni lost: %+v", want.Name, g.TLS)
			}
		case model.ProtoVLESS:
			eqParam(t, want.Name, g, "uuid", str(want.Params, "uuid"))
			eqParam(t, want.Name, g, "flow", "xtls-rprx-vision")
			if g.TLS == nil || g.TLS.Type != "reality" || g.TLS.PublicKey != "PUBKEYabc" || g.TLS.ShortID != "ab12" {
				t.Errorf("%s: reality keys lost: %+v", want.Name, g.TLS)
			}
		case model.ProtoHysteria2:
			eqParam(t, want.Name, g, "password", "hpass")
			eqParam(t, want.Name, g, "obfs", "salamander")
			eqParam(t, want.Name, g, "obfs_password", "ob")
			if g.TLS == nil || g.TLS.SNI != "example.org" || !g.TLS.Insecure {
				t.Errorf("%s: hy2 tls lost: %+v", want.Name, g.TLS)
			}
		case model.ProtoTUIC:
			eqParam(t, want.Name, g, "uuid", str(want.Params, "uuid"))
			eqParam(t, want.Name, g, "password", "tupw")
			eqParam(t, want.Name, g, "congestion_control", "bbr")
			eqParam(t, want.Name, g, "udp_relay_mode", "native")
		case model.ProtoWireGuard:
			eqParam(t, want.Name, g, "private_key", "PRIVkey=")
			eqParam(t, want.Name, g, "peer_public_key", "PUBkey=")
			if mtu := intStr(g.Params, "mtu"); mtu != "1420" {
				t.Errorf("%s: wg mtu lost: %q", want.Name, mtu)
			}
			addrs := localAddrStrings(g.Params)
			if len(addrs) != 1 || addrs[0] != "10.13.13.2/32" {
				t.Errorf("%s: wg local_address lost: %v", want.Name, addrs)
			}
		}
	}
}

// TestClashSkipped: unsupported endpoints are skipped (collected in skipped),
// while supported ones still render.
func TestClashSkipped(t *testing.T) {
	eps := []model.Endpoint{
		{Name: "external", Engine: model.EngineExternal, Protocol: model.ProtoVLESS, Server: "x", Port: 1, Enabled: true},
		{Name: "olcrtc", Engine: model.EngineOlcRTC, Protocol: model.ProtoOlcRTC, Server: "y", Port: 2, Enabled: true},
		{Name: "awg", Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG, Server: "z", Port: 3, Enabled: true,
			Params: map[string]any{"private_key": "p", "peer_public_key": "q", "jc": 4, "h1": 1}},
		{Name: "good ss", Engine: model.EngineSingBox, Protocol: model.ProtoShadowsocks, Server: "9.9.9.9", Port: 8388, Enabled: true,
			Params: map[string]any{"method": "aes-256-gcm", "password": "pw"}},
	}
	yaml, skipped := ClashConfig(eps)
	wantSkip := map[string]bool{"external": true, "olcrtc": true, "awg": true}
	if len(skipped) != len(wantSkip) {
		t.Fatalf("skipped = %v, want %v", skipped, wantSkip)
	}
	for _, s := range skipped {
		if !wantSkip[s] {
			t.Errorf("unexpected skip %q", s)
		}
	}
	if !strings.Contains(yaml, "name: good ss") || !strings.Contains(yaml, "type: ss") {
		t.Errorf("good ss endpoint not rendered:\n%s", yaml)
	}
	// And it round-trips to exactly one proxy.
	got, errs := importer.ParseClash(yaml)
	if len(errs) != 0 {
		t.Fatalf("re-import errs: %v", errs)
	}
	if len(got) != 1 || got[0].Protocol != model.ProtoShadowsocks {
		t.Errorf("expected one ss proxy, got %+v", got)
	}
}

// TestClashDuplicateNames: two endpoints with the same name get unique clash
// proxy names (clash requires uniqueness).
func TestClashDuplicateNames(t *testing.T) {
	eps := []model.Endpoint{
		{Name: "dup", Engine: model.EngineSingBox, Protocol: model.ProtoShadowsocks, Server: "1.1.1.1", Port: 8388, Enabled: true,
			Params: map[string]any{"method": "aes-256-gcm", "password": "a"}},
		{Name: "dup", Engine: model.EngineSingBox, Protocol: model.ProtoShadowsocks, Server: "2.2.2.2", Port: 8388, Enabled: true,
			Params: map[string]any{"method": "aes-256-gcm", "password": "b"}},
	}
	yaml, _ := ClashConfig(eps)
	got, errs := importer.ParseClash(yaml)
	if len(errs) != 0 {
		t.Fatalf("errs: %v\n%s", errs, yaml)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 proxies, got %d\n%s", len(got), yaml)
	}
	if got[0].Name == got[1].Name {
		t.Errorf("duplicate proxy names not de-duplicated: both %q", got[0].Name)
	}
}

// TestClashQuotesSpecialNames: a name with spaces/unicode must be quoted so the
// YAML stays parseable and the name survives the round-trip.
func TestClashQuotesSpecialNames(t *testing.T) {
	eps := []model.Endpoint{
		{Name: "M+ Сервер #1", Engine: model.EngineSingBox, Protocol: model.ProtoShadowsocks,
			Server: "1.1.1.1", Port: 8388, Enabled: true,
			Params: map[string]any{"method": "aes-256-gcm", "password": "p@ss: word, ok"}},
	}
	yaml, _ := ClashConfig(eps)
	got, errs := importer.ParseClash(yaml)
	if len(errs) != 0 {
		t.Fatalf("errs: %v\n%s", errs, yaml)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 proxy, got %d\n%s", len(got), yaml)
	}
	if got[0].Name != "M+ Сервер #1" {
		t.Errorf("name not preserved: %q\n%s", got[0].Name, yaml)
	}
	if pw := str(got[0].Params, "password"); pw != "p@ss: word, ok" {
		t.Errorf("special password not preserved: %q\n%s", pw, yaml)
	}
}

// --- test helpers ---

func eqParam(t *testing.T, name string, e model.Endpoint, key, want string) {
	t.Helper()
	if got := str(e.Params, key); got != want {
		t.Errorf("%s: param %q = %q, want %q", name, key, got, want)
	}
}

func localAddrStrings(p map[string]any) []string {
	switch t := p["local_address"].(type) {
	case []string:
		return t
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
