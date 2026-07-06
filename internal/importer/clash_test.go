package importer

import (
	"reflect"
	"testing"

	"wayhop/internal/model"
)

// All servers / keys here are SYNTHETIC.

func TestLooksLikeClash(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"block proxies", "proxies:\n  - name: a\n    type: ss\n", true},
		{"proxies empty list", "proxies: []\n", true},
		{"proxies with comment", "port: 7890\nproxies:   # list\n  - {name: a}\n", true},
		{"vless share link", "vless://uuid@example.com:443?type=tcp#x", false},
		{"vmess share link", "vmess://eyJhZGQiOiJ4In0=", false},
		{"base64 blob", "dmxlc3M6Ly91dWlkQGV4YW1wbGUuY29tOjQ0Mw==", false},
		{"plain proxy line not key", "  proxies: indented", false},
		{"no proxies key", "rules:\n  - MATCH,DIRECT\n", false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := looksLikeClash(c.in); got != c.want {
				t.Fatalf("looksLikeClash(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// epByName finds a parsed endpoint by name.
func epByName(eps []model.Endpoint, name string) *model.Endpoint {
	for i := range eps {
		if eps[i].Name == name {
			return &eps[i]
		}
	}
	return nil
}

func TestParseClash_Shadowsocks_Block(t *testing.T) {
	cfg := `proxies:
  - name: ss-a
    type: ss
    server: ss.example.com
    port: 8388
    cipher: aes-256-gcm
    password: pw123
    udp: true
`
	eps, errs := ParseClash(cfg)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	e := epByName(eps, "ss-a")
	if e == nil {
		t.Fatal("ss-a not parsed")
	}
	if e.Engine != model.EngineSingBox || e.Protocol != model.ProtoShadowsocks {
		t.Fatalf("engine/proto = %v/%v", e.Engine, e.Protocol)
	}
	if e.Server != "ss.example.com" || e.Port != 8388 {
		t.Fatalf("server/port = %q/%d", e.Server, e.Port)
	}
	if e.Params["method"] != "aes-256-gcm" || e.Params["password"] != "pw123" {
		t.Fatalf("params = %#v", e.Params)
	}
	if !e.Enabled {
		t.Fatal("not enabled")
	}
}

func TestParseClash_Shadowsocks_Flow(t *testing.T) {
	cfg := `proxies:
  - {name: ss-flow, type: ss, server: 198.51.100.7, port: 8388, cipher: chacha20-ietf-poly1305, password: p}
`
	eps, errs := ParseClash(cfg)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	e := epByName(eps, "ss-flow")
	if e == nil {
		t.Fatal("ss-flow not parsed")
	}
	if e.Params["method"] != "chacha20-ietf-poly1305" || e.Server != "198.51.100.7" || e.Port != 8388 {
		t.Fatalf("got %#v server=%q port=%d", e.Params, e.Server, e.Port)
	}
}

func TestParseClash_VMess_WS_TLS(t *testing.T) {
	cfg := `proxies:
  - name: vm
    type: vmess
    server: vm.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    alterId: 0
    cipher: auto
    tls: true
    servername: front.example.com
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /ray
      headers:
        Host: cdn.example.com
`
	eps, errs := ParseClash(cfg)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	e := epByName(eps, "vm")
	if e == nil {
		t.Fatal("vm not parsed")
	}
	if e.Protocol != model.ProtoVMess {
		t.Fatalf("proto %v", e.Protocol)
	}
	if e.Params["uuid"] != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("uuid %v", e.Params["uuid"])
	}
	if e.Params["alter_id"] != 0 {
		t.Fatalf("alter_id %v", e.Params["alter_id"])
	}
	if e.Params["security"] != "auto" {
		t.Fatalf("security %v", e.Params["security"])
	}
	if e.Transport == nil || e.Transport.Type != "ws" || e.Transport.Path != "/ray" || e.Transport.Host != "cdn.example.com" {
		t.Fatalf("transport %#v", e.Transport)
	}
	if e.TLS == nil || !e.TLS.Enabled || e.TLS.SNI != "front.example.com" || !e.TLS.Insecure {
		t.Fatalf("tls %#v", e.TLS)
	}
}

func TestParseClash_VMess_NoTLS(t *testing.T) {
	cfg := `proxies:
  - {name: vm2, type: vmess, server: v.example.com, port: 80, uuid: u, alterId: 0}
`
	eps, _ := ParseClash(cfg)
	e := epByName(eps, "vm2")
	if e == nil {
		t.Fatal("vm2 not parsed")
	}
	if e.TLS != nil {
		t.Fatalf("expected no TLS, got %#v", e.TLS)
	}
}

func TestParseClash_Trojan_DefaultTLS(t *testing.T) {
	cfg := `proxies:
  - name: tr
    type: trojan
    server: tr.example.com
    port: 443
    password: secret
    sni: tr.example.com
    network: grpc
    grpc-opts:
      grpc-service-name: gun
`
	eps, errs := ParseClash(cfg)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	e := epByName(eps, "tr")
	if e == nil {
		t.Fatal("tr not parsed")
	}
	if e.Protocol != model.ProtoTrojan || e.Params["password"] != "secret" {
		t.Fatalf("got %v %#v", e.Protocol, e.Params)
	}
	if e.TLS == nil || !e.TLS.Enabled || e.TLS.SNI != "tr.example.com" {
		t.Fatalf("tls %#v (trojan defaults TLS on)", e.TLS)
	}
	if e.Transport == nil || e.Transport.Type != "grpc" || e.Transport.ServiceName != "gun" {
		t.Fatalf("transport %#v", e.Transport)
	}
}

func TestParseClash_VLESS_Reality(t *testing.T) {
	cfg := `proxies:
  - name: vl
    type: vless
    server: vl.example.com
    port: 443
    uuid: 22222222-2222-2222-2222-222222222222
    flow: xtls-rprx-vision
    network: tcp
    tls: true
    servername: www.example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: PBKEY_SYNTH
      short-id: ab12
`
	eps, errs := ParseClash(cfg)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	e := epByName(eps, "vl")
	if e == nil {
		t.Fatal("vl not parsed")
	}
	if e.Protocol != model.ProtoVLESS || e.Params["uuid"] != "22222222-2222-2222-2222-222222222222" {
		t.Fatalf("got %v %#v", e.Protocol, e.Params)
	}
	if e.Params["flow"] != "xtls-rprx-vision" {
		t.Fatalf("flow %v", e.Params["flow"])
	}
	if e.TLS == nil || e.TLS.Type != "reality" || e.TLS.PublicKey != "PBKEY_SYNTH" ||
		e.TLS.ShortID != "ab12" || e.TLS.SNI != "www.example.com" || e.TLS.Fingerprint != "chrome" {
		t.Fatalf("reality tls %#v", e.TLS)
	}
}

func TestParseClash_Hysteria2(t *testing.T) {
	cfg := `proxies:
  - name: hy
    type: hysteria2
    server: hy.example.com
    port: 8443
    password: hpw
    sni: hy.example.com
    skip-cert-verify: true
    obfs: salamander
    obfs-password: obfspw
    up: "100 Mbps"
    down: 200
`
	eps, errs := ParseClash(cfg)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	e := epByName(eps, "hy")
	if e == nil {
		t.Fatal("hy not parsed")
	}
	if e.Protocol != model.ProtoHysteria2 || e.Params["password"] != "hpw" {
		t.Fatalf("got %v %#v", e.Protocol, e.Params)
	}
	if e.Params["obfs"] != "salamander" || e.Params["obfs_password"] != "obfspw" {
		t.Fatalf("obfs %#v", e.Params)
	}
	if e.Params["up_mbps"] != 100 || e.Params["down_mbps"] != 200 {
		t.Fatalf("bw %#v", e.Params)
	}
	if e.TLS == nil || !e.TLS.Enabled || !e.TLS.Insecure || e.TLS.SNI != "hy.example.com" {
		t.Fatalf("tls %#v", e.TLS)
	}
}

func TestParseClash_TUIC(t *testing.T) {
	cfg := `proxies:
  - name: tu
    type: tuic
    server: tu.example.com
    port: 443
    uuid: 33333333-3333-3333-3333-333333333333
    password: tpw
    sni: tu.example.com
    congestion-controller: bbr
    udp-relay-mode: native
    alpn: [h3]
    skip-cert-verify: true
`
	eps, errs := ParseClash(cfg)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	e := epByName(eps, "tu")
	if e == nil {
		t.Fatal("tu not parsed")
	}
	if e.Protocol != model.ProtoTUIC || e.Params["uuid"] != "33333333-3333-3333-3333-333333333333" || e.Params["password"] != "tpw" {
		t.Fatalf("got %v %#v", e.Protocol, e.Params)
	}
	if e.Params["congestion_control"] != "bbr" || e.Params["udp_relay_mode"] != "native" {
		t.Fatalf("tuic params %#v", e.Params)
	}
	if e.TLS == nil || !e.TLS.Insecure || !reflect.DeepEqual(e.TLS.ALPN, []string{"h3"}) {
		t.Fatalf("tls %#v", e.TLS)
	}
}

func TestParseClash_WireGuard(t *testing.T) {
	cfg := `proxies:
  - name: wg
    type: wireguard
    server: wg.example.com
    port: 51820
    private-key: PRIVSYNTH=
    public-key: PUBSYNTH=
    pre-shared-key: PSKSYNTH=
    ip: 10.0.0.2/32
    ipv6: fd00::2/128
    mtu: 1280
    reserved: [1, 2, 3]
`
	eps, errs := ParseClash(cfg)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	e := epByName(eps, "wg")
	if e == nil {
		t.Fatal("wg not parsed")
	}
	if e.Protocol != model.ProtoWireGuard {
		t.Fatalf("proto %v", e.Protocol)
	}
	if e.Params["private_key"] != "PRIVSYNTH=" || e.Params["peer_public_key"] != "PUBSYNTH=" {
		t.Fatalf("keys %#v", e.Params)
	}
	if e.Params["pre_shared_key"] != "PSKSYNTH=" {
		t.Fatalf("psk %v", e.Params["pre_shared_key"])
	}
	la, ok := e.Params["local_address"].([]string)
	if !ok || !reflect.DeepEqual(la, []string{"10.0.0.2/32", "fd00::2/128"}) {
		t.Fatalf("local_address %#v", e.Params["local_address"])
	}
	if e.Params["mtu"] != 1280 {
		t.Fatalf("mtu %v", e.Params["mtu"])
	}
	if r, ok := e.Params["reserved"].([]int); !ok || !reflect.DeepEqual(r, []int{1, 2, 3}) {
		t.Fatalf("reserved %#v", e.Params["reserved"])
	}
}

func TestParseClash_MultiProxy(t *testing.T) {
	cfg := `proxies:
  - {name: a, type: ss, server: a.example.com, port: 8388, cipher: aes-256-gcm, password: p}
  - name: b
    type: trojan
    server: b.example.com
    port: 443
    password: q
  - {name: c, type: vmess, server: c.example.com, port: 443, uuid: u, alterId: 0}
proxy-groups:
  - name: g
`
	eps, errs := ParseClash(cfg)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	if len(eps) != 3 {
		t.Fatalf("want 3 endpoints, got %d: %+v", len(eps), eps)
	}
	for _, n := range []string{"a", "b", "c"} {
		if epByName(eps, n) == nil {
			t.Fatalf("missing %q", n)
		}
	}
}

func TestParseClash_MalformedEntrySkipped(t *testing.T) {
	cfg := `proxies:
  - {name: good, type: ss, server: g.example.com, port: 8388, cipher: aes-256-gcm, password: p}
  - {name: bad, type: ss, server: nohost.example.com}
  - {name: unknowntype, type: snell, server: s.example.com, port: 1}
`
	eps, errs := ParseClash(cfg)
	if len(eps) != 1 || epByName(eps, "good") == nil {
		t.Fatalf("expected only 'good', got %+v", eps)
	}
	if len(errs) != 2 {
		t.Fatalf("expected 2 errors (bad + unknowntype), got %v", errs)
	}
}

func TestParseClash_UniqueIDs(t *testing.T) {
	// Two identical-shape proxies must get distinct IDs.
	cfg := `proxies:
  - {name: x1, type: ss, server: dup.example.com, port: 8388, cipher: aes-256-gcm, password: p}
  - {name: x2, type: ss, server: dup.example.com, port: 8388, cipher: aes-256-gcm, password: p}
`
	eps, errs := ParseClash(cfg)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	if len(eps) != 2 {
		t.Fatalf("want 2, got %d", len(eps))
	}
	if eps[0].ID == eps[1].ID {
		t.Fatalf("IDs collided: %q", eps[0].ID)
	}
}

func TestParseClash_NoProxies(t *testing.T) {
	_, errs := ParseClash("proxies:\n")
	if len(errs) == 0 {
		t.Fatal("expected an error for an empty proxies list")
	}
}

// ParseSubscription must route a pasted clash YAML through ParseClash.
func TestParseSubscription_DispatchesClash(t *testing.T) {
	cfg := `proxies:
  - {name: viasub, type: ss, server: sub.example.com, port: 8388, cipher: aes-256-gcm, password: p}
`
	eps, errs := ParseSubscription(cfg)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	if epByName(eps, "viasub") == nil {
		t.Fatalf("clash not dispatched via ParseSubscription, got %+v", eps)
	}
}

// A normal (non-clash) subscription must still parse via the line-by-line path.
func TestParseSubscription_NonClashUnaffected(t *testing.T) {
	sub := "ss://YWVzLTI1Ni1nY206cEBleGFtcGxlLmNvbTo4Mzg4#node\n"
	eps, _ := ParseSubscription(sub)
	if len(eps) != 1 || eps[0].Protocol != model.ProtoShadowsocks {
		t.Fatalf("non-clash sub regressed: %+v", eps)
	}
}

// FIX 1: a block-style list field (alpn) inside a proxy must NOT be intercepted as
// a new proxy. Its `- h3`/`- h2` lines are more-indented than the proxy dash, so
// they fold into the alpn list; a field AFTER the list block must survive.
func TestParseClash_BlockAlpnList(t *testing.T) {
	cfg := "proxies:\n" +
		"  - name: tu\n" +
		"    type: tuic\n" +
		"    server: tu.example.com\n" +
		"    port: 443\n" +
		"    uuid: 33333333-3333-3333-3333-333333333333\n" +
		"    password: tpw\n" +
		"    alpn:\n" +
		"      - h3\n" +
		"      - h2\n" +
		"    congestion-controller: bbr\n" +
		"  - name: hy\n" +
		"    type: hysteria2\n" +
		"    server: hy.example.com\n" +
		"    port: 8443\n" +
		"    password: hpw\n" +
		"    alpn:\n" +
		"      - h3\n" +
		"      - h2\n" +
		"    obfs: salamander\n" +
		"    obfs-password: op\n"
	eps, errs := ParseClash(cfg)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors (block list mis-parsed?): %v", errs)
	}
	if len(eps) != 2 {
		t.Fatalf("want 2 endpoints, got %d: %+v", len(eps), eps)
	}
	tu := epByName(eps, "tu")
	if tu == nil {
		t.Fatal("tu not parsed")
	}
	if tu.TLS == nil || !reflect.DeepEqual(tu.TLS.ALPN, []string{"h3", "h2"}) {
		t.Fatalf("tuic alpn = %#v, want [h3 h2]", tu.TLS)
	}
	// The field AFTER the alpn block must survive (it was dropped before the fix).
	if tu.Params["congestion_control"] != "bbr" {
		t.Fatalf("field after alpn list dropped: %#v", tu.Params)
	}
	hy := epByName(eps, "hy")
	if hy == nil {
		t.Fatal("hy not parsed")
	}
	if hy.TLS == nil || !reflect.DeepEqual(hy.TLS.ALPN, []string{"h3", "h2"}) {
		t.Fatalf("hy alpn = %#v, want [h3 h2]", hy.TLS)
	}
	if hy.Params["obfs"] != "salamander" || hy.Params["obfs_password"] != "op" {
		t.Fatalf("fields after hy alpn block dropped: %#v", hy.Params)
	}
}

// FIX 2: trailing inline comments must be stripped from scalar values and dash-line
// flow mappings; a `#` with no leading space or inside quotes is preserved.
func TestParseClash_InlineComments(t *testing.T) {
	cfg := "proxies:\n" +
		"  - name: c1\n" +
		"    type: ss\n" +
		"    server: c1.example.com\n" +
		"    port: 8388 # the port\n" +
		"    cipher: aes-256-gcm\n" +
		"    password: pw#notacomment\n" +
		"  - {name: c2, type: ss, server: c2.example.com, port: 8388, cipher: aes-256-gcm, password: p}  # node name\n"
	eps, errs := ParseClash(cfg)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(eps) != 2 {
		t.Fatalf("want 2 endpoints, got %d: %+v", len(eps), eps)
	}
	c1 := epByName(eps, "c1")
	if c1 == nil {
		t.Fatal("c1 not parsed (port comment broke the port?)")
	}
	if c1.Port != 8388 {
		t.Fatalf("port = %d, want 8388 (inline comment not stripped)", c1.Port)
	}
	// A '#' with no preceding space must be preserved (it's part of the value).
	if c1.Params["password"] != "pw#notacomment" {
		t.Fatalf("password = %q, want pw#notacomment (no-space # wrongly stripped)", c1.Params["password"])
	}
	if epByName(eps, "c2") == nil {
		t.Fatalf("flow proxy with trailing comment not parsed: %+v", eps)
	}
}

// FIX 2b: a '#' inside a quoted scalar must not be treated as a comment.
func TestParseClash_HashInsideQuotes(t *testing.T) {
	cfg := "proxies:\n" +
		"  - {name: q, type: ss, server: q.example.com, port: 8388, cipher: aes-256-gcm, password: \"a # b\"}\n"
	eps, errs := ParseClash(cfg)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	e := epByName(eps, "q")
	if e == nil {
		t.Fatal("q not parsed")
	}
	if e.Params["password"] != "a # b" {
		t.Fatalf("password = %q, want 'a # b' (# inside quotes wrongly stripped)", e.Params["password"])
	}
}

// FIX 3: a UTF-8 BOM-prefixed clash doc must be detected + parsed.
func TestParseClash_BOM(t *testing.T) {
	cfg := "\uFEFFproxies:\n" +
		"  - {name: bom, type: ss, server: bom.example.com, port: 8388, cipher: aes-256-gcm, password: p}\n"
	if !looksLikeClash(cfg) {
		t.Fatal("looksLikeClash false for a BOM-prefixed clash doc")
	}
	eps, errs := ParseClash(cfg)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	if epByName(eps, "bom") == nil {
		t.Fatalf("BOM-prefixed clash not parsed: %+v", eps)
	}
	// And via the subscription entrypoint.
	eps2, _ := ParseSubscription(cfg)
	if epByName(eps2, "bom") == nil {
		t.Fatalf("BOM-prefixed clash not dispatched via ParseSubscription: %+v", eps2)
	}
}

// FIX 4: hysteria2 port-hopping `ports` must map to Params["hop_ports"].
func TestParseClash_Hysteria2_PortHopping(t *testing.T) {
	cfg := `proxies:
  - name: hyhop
    type: hysteria2
    server: hyhop.example.com
    port: 443
    password: p
    ports: "443-8443"
    sni: hyhop.example.com
`
	eps, errs := ParseClash(cfg)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	e := epByName(eps, "hyhop")
	if e == nil {
		t.Fatal("hyhop not parsed")
	}
	if e.Params["hop_ports"] != "443-8443" {
		t.Fatalf("hop_ports = %v, want 443-8443", e.Params["hop_ports"])
	}
}

// FIX 5: ss plugin/plugin-opts must map to Params["plugin"]/["plugin_opts"], with
// the clash `obfs` name normalized to the sing-box-native `obfs-local`.
func TestParseClash_Shadowsocks_Plugin(t *testing.T) {
	cfg := `proxies:
  - name: ssp
    type: ss
    server: ssp.example.com
    port: 8388
    cipher: aes-256-gcm
    password: p
    plugin: obfs
    plugin-opts:
      mode: tls
      host: bing.example.com
`
	eps, errs := ParseClash(cfg)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	e := epByName(eps, "ssp")
	if e == nil {
		t.Fatal("ssp not parsed")
	}
	if e.Params["plugin"] != "obfs-local" {
		t.Fatalf("plugin = %v, want obfs-local", e.Params["plugin"])
	}
	if e.Params["plugin_opts"] != "obfs=tls;obfs-host=bing.example.com" {
		t.Fatalf("plugin_opts = %v, want obfs=tls;obfs-host=bing.example.com", e.Params["plugin_opts"])
	}
}

// FIX 6: vmess h2-opts.host given as a YAML list must yield a bare host (no brackets).
func TestParseClash_VMess_H2HostList(t *testing.T) {
	cfg := `proxies:
  - name: vmh2
    type: vmess
    server: vmh2.example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    alterId: 0
    network: h2
    h2-opts:
      host: [a.example.com]
      path: /h2
`
	eps, errs := ParseClash(cfg)
	if len(errs) != 0 {
		t.Fatalf("errs: %v", errs)
	}
	e := epByName(eps, "vmh2")
	if e == nil {
		t.Fatal("vmh2 not parsed")
	}
	if e.Transport == nil || e.Transport.Type != "http" {
		t.Fatalf("transport = %#v, want http", e.Transport)
	}
	if e.Transport.Host != "a.example.com" {
		t.Fatalf("h2 host = %q, want a.example.com (list brackets not stripped)", e.Transport.Host)
	}
}
