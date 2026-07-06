package importer

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// This file exercises the edge and error paths of Parse() and
// ParseSubscription() against the ACTUAL current behavior of the importer.
// Every helper/type is prefixed importer_ to avoid clashes with other tests
// in this package.

// importer_b64std returns a padded std-base64 encoding of s.
func importer_b64std(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// importer_b64rawurl returns a raw (unpadded) url-base64 encoding of s.
func importer_b64rawurl(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// ---------------------------------------------------------------------------
// Parse(): empty / whitespace / scheme errors
// ---------------------------------------------------------------------------

func TestParse_EmptyAndWhitespace(t *testing.T) {
	for _, in := range []string{"", "   ", "\t\n ", "\r\n"} {
		e, err := Parse(in)
		if err == nil {
			t.Fatalf("Parse(%q): want error, got endpoint %+v", in, e)
		}
		if err.Error() != "empty link" {
			t.Fatalf("Parse(%q): want %q, got %q", in, "empty link", err.Error())
		}
	}
}

func TestParse_UnknownScheme(t *testing.T) {
	e, err := Parse("foo://bar:123")
	if err == nil {
		t.Fatalf("want error for unknown scheme, got %+v", e)
	}
	if !strings.Contains(err.Error(), "unsupported scheme") {
		t.Fatalf("want 'unsupported scheme' error, got %q", err.Error())
	}
}

// A bare token with no "://" parses to scheme "" and falls into the default
// (unsupported scheme) branch rather than panicking.
func TestParse_NoSchemeGarbage(t *testing.T) {
	e, err := Parse("garbage-not-a-link")
	if err == nil {
		t.Fatalf("want error for schemeless garbage, got %+v", e)
	}
	if !strings.Contains(err.Error(), "unsupported scheme") {
		t.Fatalf("want 'unsupported scheme' error, got %q", err.Error())
	}
}

// A scheme-only string ("vless://") with no userinfo/host must not panic.
func TestParse_SchemeOnlyDoesNotPanic(t *testing.T) {
	for _, in := range []string{"vless://", "trojan://", "tuic://", "wireguard://"} {
		// We only care that it returns (endpoint or error) without panicking.
		_, _ = Parse(in)
	}
}

// ---------------------------------------------------------------------------
// vmess: bad base64, non-JSON body, numeric vs string port
// ---------------------------------------------------------------------------

func TestParseVMess_BadBase64(t *testing.T) {
	// Contains characters not valid in any base64 alphabet tried by decodeB64.
	e, err := Parse("vmess://!!!notbase64$$$")
	if err == nil {
		t.Fatalf("want error for bad vmess base64, got %+v", e)
	}
	if !strings.Contains(err.Error(), "vmess: invalid base64 body") {
		t.Fatalf("want 'vmess: invalid base64 body', got %q", err.Error())
	}
}

func TestParseVMess_EmptyBody(t *testing.T) {
	// Empty body decodes to "" which is treated as invalid base64 body.
	e, err := Parse("vmess://")
	if err == nil {
		t.Fatalf("want error for empty vmess body, got %+v", e)
	}
	if !strings.Contains(err.Error(), "vmess: invalid base64 body") {
		t.Fatalf("want 'vmess: invalid base64 body', got %q", err.Error())
	}
}

func TestParseVMess_ValidBase64NotJSON(t *testing.T) {
	// "not json at all" is valid base64 (decodes fine) but not JSON.
	link := "vmess://" + importer_b64std("not json at all")
	e, err := Parse(link)
	if err == nil {
		t.Fatalf("want JSON parse error, got %+v", e)
	}
	if !strings.HasPrefix(err.Error(), "vmess:") {
		t.Fatalf("want error prefixed 'vmess:', got %q", err.Error())
	}
}

func TestParseVMess_NumericPort(t *testing.T) {
	// JSON numeric port -> decoded via float64 path in asInt.
	js := `{"v":"2","ps":"NUM","add":"vm.example.com","port":443,"id":"uuid-n","aid":0,"net":"tcp","scy":"auto"}`
	e, err := Parse("vmess://" + importer_b64std(js))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Protocol != model.ProtoVMess {
		t.Fatalf("proto = %s", e.Protocol)
	}
	if e.Server != "vm.example.com" || e.Port != 443 {
		t.Fatalf("server:port = %s:%d (want vm.example.com:443)", e.Server, e.Port)
	}
	if e.Params["uuid"] != "uuid-n" {
		t.Fatalf("uuid = %v", e.Params["uuid"])
	}
	// alter_id 0 must be an int (asInt), security default "auto".
	if e.Params["alter_id"] != 0 {
		t.Fatalf("alter_id = %v (%T)", e.Params["alter_id"], e.Params["alter_id"])
	}
	if e.Params["security"] != "auto" {
		t.Fatalf("security = %v", e.Params["security"])
	}
}

func TestParseVMess_CarriesTLSFingerprint(t *testing.T) {
	// A vmess+tls link with a uTLS fingerprint must preserve it (vless/trojan do).
	// Dropping it silently degrades the handshake to vanilla Go TLS — the opposite
	// of what picking fp=chrome was for.
	js := `{"v":"2","ps":"FP","add":"vm.example.com","port":"443","id":"u","net":"ws","path":"/p","tls":"tls","sni":"x.example.com","fp":"chrome","alpn":"h2,http/1.1"}`
	e, err := Parse("vmess://" + importer_b64std(js))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.TLS == nil || !e.TLS.Enabled {
		t.Fatalf("TLS not enabled: %+v", e.TLS)
	}
	if e.TLS.Fingerprint != "chrome" {
		t.Fatalf("fingerprint = %q, want chrome", e.TLS.Fingerprint)
	}
	if len(e.TLS.ALPN) != 2 || e.TLS.ALPN[0] != "h2" {
		t.Fatalf("alpn = %v, want [h2 http/1.1]", e.TLS.ALPN)
	}
}

// TestParseVMess_CarriesAllowInsecure: vmess was the only protocol whose importer
// dropped the skip-cert-verify flag, so a vmess+TLS endpoint with a self-signed
// cert silently failed certificate verification at runtime. allowInsecure (string
// "true" or bool true) must set TLS.Insecure, like vless/trojan/hy2/tuic.
func TestParseVMess_CarriesAllowInsecure(t *testing.T) {
	for _, js := range []string{
		`{"add":"vm.example.com","port":"443","id":"u","net":"ws","path":"/p","tls":"tls","allowInsecure":"true"}`,
		`{"add":"vm.example.com","port":"443","id":"u","net":"ws","path":"/p","tls":"tls","allowInsecure":true}`,
	} {
		e, err := Parse("vmess://" + importer_b64std(js))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if e.TLS == nil || !e.TLS.Insecure {
			t.Fatalf("allowInsecure not carried: %+v", e.TLS)
		}
	}
	// No allowInsecure → Insecure stays false (cert verification on).
	js := `{"add":"vm.example.com","port":"443","id":"u","net":"ws","tls":"tls"}`
	e, _ := Parse("vmess://" + importer_b64std(js))
	if e.TLS == nil || e.TLS.Insecure {
		t.Fatalf("default must be secure: %+v", e.TLS)
	}
}

// TestParseVMess_TLSTypeRobust: the vmess "tls" field is normally the string "tls",
// but some generators emit a JSON bool true or "1"/"true". A bare `== "tls"` check
// silently left TLS OFF for those → a vmess+TLS endpoint connected in plaintext to a
// TLS server and failed. Detection must be type-robust (like asInt for port/aid),
// while "" / "none" / "false" / "0" stay OFF so plaintext vmess is unaffected.
func TestParseVMess_TLSTypeRobust(t *testing.T) {
	on := []string{
		`{"add":"h","port":"443","id":"u","net":"ws","tls":"tls"}`, // standard
		`{"add":"h","port":"443","id":"u","net":"ws","tls":true}`,  // bool
		`{"add":"h","port":"443","id":"u","net":"ws","tls":"1"}`,   // numeric-string
		`{"add":"h","port":"443","id":"u","net":"ws","tls":"true"}`,
	}
	for _, js := range on {
		e, err := Parse("vmess://" + importer_b64std(js))
		if err != nil {
			t.Fatalf("parse %s: %v", js, err)
		}
		if e.TLS == nil || !e.TLS.Enabled {
			t.Fatalf("TLS must be ENABLED for %s, got %+v", js, e.TLS)
		}
	}
	off := []string{
		`{"add":"h","port":"443","id":"u","net":"ws"}`,          // no tls key
		`{"add":"h","port":"443","id":"u","net":"ws","tls":""}`, // empty
		`{"add":"h","port":"443","id":"u","net":"ws","tls":"none"}`,
		`{"add":"h","port":"443","id":"u","net":"ws","tls":"false"}`,
		`{"add":"h","port":"443","id":"u","net":"ws","tls":false}`, // bool false
	}
	for _, js := range off {
		e, err := Parse("vmess://" + importer_b64std(js))
		if err != nil {
			t.Fatalf("parse %s: %v", js, err)
		}
		if e.TLS != nil && e.TLS.Enabled {
			t.Fatalf("TLS must be OFF for %s, got enabled", js)
		}
	}
}

func TestParseVMess_StringPort(t *testing.T) {
	// JSON string port -> decoded via atoi path in asInt.
	js := `{"add":"h.example","port":"8080","id":"u","net":"tcp"}`
	e, err := Parse("vmess://" + importer_b64std(js))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Port != 8080 {
		t.Fatalf("port = %d (want 8080)", e.Port)
	}
	if e.Server != "h.example" {
		t.Fatalf("server = %q", e.Server)
	}
}

func TestParseVMess_MissingPortDefaults443(t *testing.T) {
	js := `{"add":"h.example","id":"u","net":"tcp"}`
	e, err := Parse("vmess://" + importer_b64std(js))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Port != 443 {
		t.Fatalf("port = %d (want default 443)", e.Port)
	}
	// security defaults to "auto" when scy is absent.
	if e.Params["security"] != "auto" {
		t.Fatalf("security = %v (want auto)", e.Params["security"])
	}
}

// ---------------------------------------------------------------------------
// shadowsocks: SIP002 vs legacy, bad base64, missing host/port
// ---------------------------------------------------------------------------

func TestParseSS_SIP002Form(t *testing.T) {
	// SIP002: ss://base64(method:password)@host:port#name
	userinfo := importer_b64rawurl("aes-256-gcm:supersecret")
	link := "ss://" + userinfo + "@9.9.9.9:8388#SS-SIP002"
	e, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Protocol != model.ProtoShadowsocks {
		t.Fatalf("proto = %s", e.Protocol)
	}
	if e.Params["method"] != "aes-256-gcm" || e.Params["password"] != "supersecret" {
		t.Fatalf("creds = %+v", e.Params)
	}
	if e.Server != "9.9.9.9" || e.Port != 8388 {
		t.Fatalf("server:port = %s:%d", e.Server, e.Port)
	}
	if e.Name != "SS-SIP002" {
		t.Fatalf("name = %q", e.Name)
	}
}

// TestInsecureFlagAliases pins down that the "skip TLS verification" flag is
// recognized regardless of which alias/spelling a client used. Before the fix
// each protocol accepted only one narrow form (vless/trojan: allowInsecure==1;
// tuic: allow_insecure==1; hy2: insecure 1/true) so a self-signed endpoint
// imported as e.g. allowInsecure=true or insecure=1 silently failed cert verify.
func TestInsecureFlagAliases(t *testing.T) {
	cases := []struct {
		name string
		link string
		want bool
	}{
		{"trojan-allowInsecure-true", "trojan://p@1.2.3.4:443?security=tls&sni=x&allowInsecure=true#a", true},
		{"trojan-allowInsecure-1", "trojan://p@1.2.3.4:443?security=tls&sni=x&allowInsecure=1#a", true},
		{"vless-insecure-1", "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=tls&type=tcp&sni=x&insecure=1#a", true},
		{"vless-allow_insecure-true", "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=tls&type=tcp&sni=x&allow_insecure=true#a", true},
		{"tuic-allow_insecure-true", "tuic://u:p@1.2.3.4:443?alpn=h3&allow_insecure=true#a", true},
		{"tuic-insecure-1", "tuic://u:p@1.2.3.4:443?alpn=h3&insecure=1#a", true},
		{"hy2-allowInsecure-1", "hysteria2://p@1.2.3.4:443?sni=x&allowInsecure=1#a", true},
		{"hy2-insecure-true", "hysteria2://p@1.2.3.4:443?sni=x&insecure=true#a", true},
		{"vless-no-flag", "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=tls&type=tcp&sni=x#a", false},
		{"vless-insecure-0", "vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=tls&type=tcp&sni=x&allowInsecure=0#a", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, err := Parse(c.link)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if e.TLS == nil {
				t.Fatalf("nil TLS for %q", c.link)
			}
			if e.TLS.Insecure != c.want {
				t.Fatalf("Insecure = %v, want %v (%s)", e.TLS.Insecure, c.want, c.link)
			}
		})
	}
}

func TestParseSS_SIP002PlaintextUserinfo(t *testing.T) {
	// Real-world SS-2022 links carry method:password as PLAINTEXT userinfo (the PSK
	// is already base64; clients do not double-wrap it). Importer must not blindly
	// base64-decode the userinfo — that yields an empty method and a broken outbound.
	link := "ss://2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==@9.9.9.9:8388#SS2022"
	e, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Protocol != model.ProtoShadowsocks {
		t.Fatalf("proto = %s", e.Protocol)
	}
	if e.Params["method"] != "2022-blake3-aes-128-gcm" || e.Params["password"] != "MTIzNDU2Nzg5MDEyMzQ1Ng==" {
		t.Fatalf("creds = %+v (want method=2022-blake3-aes-128-gcm, password=MTIz...)", e.Params)
	}
	if e.Server != "9.9.9.9" || e.Port != 8388 {
		t.Fatalf("server:port = %s:%d", e.Server, e.Port)
	}
	if e.Name != "SS2022" {
		t.Fatalf("name = %q", e.Name)
	}
}

// TestParseSS_2022PSKWithPlus: an SS-2022 PSK is base64 and routinely contains '+'.
// The userinfo must be PathUnescape'd (not QueryUnescape'd) so the '+' survives —
// else it becomes a space, corrupting the 32-byte key. Both raw '+' and %2B forms
// must yield the exact PSK.
func TestParseSS_2022PSKWithPlus(t *testing.T) {
	const psk = "DnPYPaIHbNE2mwBlyi+U+V7DKI3yV7whhutQtRp/5Ek=" // 32 bytes, two '+', one '/'
	for _, link := range []string{
		"ss://2022-blake3-aes-256-gcm:" + psk + "@9.9.9.9:8388#s",                                          // raw '+'
		"ss://2022-blake3-aes-256-gcm:DnPYPaIHbNE2mwBlyi%2BU%2BV7DKI3yV7whhutQtRp%2F5Ek%3D@9.9.9.9:8388#s", // %2B-encoded
	} {
		e, err := Parse(link)
		if err != nil {
			t.Fatalf("parse %q: %v", link, err)
		}
		if e.Params["method"] != "2022-blake3-aes-256-gcm" {
			t.Fatalf("method = %v", e.Params["method"])
		}
		if e.Params["password"] != psk {
			t.Fatalf("password = %q, want %q (the '+' must survive)", e.Params["password"], psk)
		}
	}
}

// TestParseTUICExtraParams: heartbeat / zero_rtt_handshake / udp_over_stream must
// be carried (they were dropped before).
func TestParseTUICExtraParams(t *testing.T) {
	e, err := Parse("tuic://11111111-2222-3333-4444-555555555555:pw@1.2.3.4:443?alpn=h3&sni=x&heartbeat=10s&zero_rtt_handshake=1&udp_over_stream=true#t")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Params["heartbeat"] != "10s" {
		t.Errorf("heartbeat = %v, want 10s", e.Params["heartbeat"])
	}
	if e.Params["zero_rtt_handshake"] != true {
		t.Errorf("zero_rtt_handshake = %v, want true", e.Params["zero_rtt_handshake"])
	}
	if e.Params["udp_over_stream"] != true {
		t.Errorf("udp_over_stream = %v, want true", e.Params["udp_over_stream"])
	}
	// Absent -> keys absent.
	e2, _ := Parse("tuic://11111111-2222-3333-4444-555555555555:pw@1.2.3.4:443?alpn=h3&sni=x#t")
	for _, k := range []string{"heartbeat", "zero_rtt_handshake", "udp_over_stream"} {
		if _, ok := e2.Params[k]; ok {
			t.Errorf("%s present when link had none", k)
		}
	}
}

// TestParseVLESSPacketEncoding: packetEncoding (xudp/packetaddr) must be carried
// so the generator can emit packet_encoding for UDP-over-VLESS.
func TestParseVLESSPacketEncoding(t *testing.T) {
	for _, key := range []string{"packetEncoding", "packet_encoding"} {
		e, err := Parse("vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=tls&type=tcp&sni=x&" + key + "=xudp#v")
		if err != nil {
			t.Fatalf("%s: parse: %v", key, err)
		}
		if e.Params["packet_encoding"] != "xudp" {
			t.Errorf("%s: packet_encoding = %v, want xudp", key, e.Params["packet_encoding"])
		}
	}
	e, _ := Parse("vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?security=tls&type=tcp&sni=x#v")
	if _, ok := e.Params["packet_encoding"]; ok {
		t.Errorf("packet_encoding present when link had none")
	}
}

// TestParseHysteria2PortHopping: the hop range (mport= or ports=) must be carried
// so the generator can emit server_ports — dropping it would leave the tunnel
// trying only the base port.
func TestParseHysteria2PortHopping(t *testing.T) {
	for _, key := range []string{"mport", "ports"} {
		e, err := Parse("hysteria2://pw@1.2.3.4:443?sni=x&" + key + "=20000-50000#hy")
		if err != nil {
			t.Fatalf("%s: parse: %v", key, err)
		}
		if e.Params["hop_ports"] != "20000-50000" {
			t.Errorf("%s: hop_ports = %v, want 20000-50000", key, e.Params["hop_ports"])
		}
	}
	// No hop param -> no hop_ports key.
	e, _ := Parse("hysteria2://pw@1.2.3.4:443?sni=x#hy")
	if _, ok := e.Params["hop_ports"]; ok {
		t.Errorf("hop_ports present when link had none: %v", e.Params["hop_ports"])
	}
}

// TestParseSS_Plugin: the SIP002 "plugin=name;opts" param is split into plugin +
// plugin_opts. sing-box implements obfs-local and v2ray-plugin natively, so a plugin
// SS link is connectable and the plugin must be carried, not dropped.
func TestParseSS_Plugin(t *testing.T) {
	link := "ss://" + importer_b64rawurl("aes-256-gcm:pw") +
		"@9.9.9.9:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dwww.bing.com#p"
	e, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Params["plugin"] != "obfs-local" {
		t.Fatalf("plugin = %v, want obfs-local", e.Params["plugin"])
	}
	if e.Params["plugin_opts"] != "obfs=http;obfs-host=www.bing.com" {
		t.Fatalf("plugin_opts = %v, want obfs=http;obfs-host=www.bing.com", e.Params["plugin_opts"])
	}
	// A bare plugin name with no opts must set plugin and omit plugin_opts.
	e2, _ := Parse("ss://" + importer_b64rawurl("aes-256-gcm:pw") + "@9.9.9.9:8388?plugin=v2ray-plugin#p2")
	if e2.Params["plugin"] != "v2ray-plugin" {
		t.Fatalf("plugin = %v, want v2ray-plugin", e2.Params["plugin"])
	}
	if _, ok := e2.Params["plugin_opts"]; ok {
		t.Fatalf("plugin_opts should be absent for a bare plugin name")
	}
	// RAW ';' (NOT %3B-encoded) is how real external SS-plugin links are written.
	// Go 1.17+ url.ParseQuery rejects a raw ';' and drops the pair, which silently
	// lost the plugin — the manual &-split must keep the ';' as the opts separator.
	e3, err := Parse("ss://" + importer_b64rawurl("aes-256-gcm:pw") +
		"@9.9.9.9:8388?plugin=v2ray-plugin;mode=websocket;path=/vpws;host=cdn.example.com#p3")
	if err != nil {
		t.Fatalf("raw-semicolon plugin link: %v", err)
	}
	if e3.Params["plugin"] != "v2ray-plugin" {
		t.Fatalf("raw ';' plugin = %v, want v2ray-plugin (dropped by url.ParseQuery before the fix)", e3.Params["plugin"])
	}
	if e3.Params["plugin_opts"] != "mode=websocket;path=/vpws;host=cdn.example.com" {
		t.Fatalf("raw ';' plugin_opts = %v", e3.Params["plugin_opts"])
	}
	// A raw ';' in the query must not collaterally drop udp-over-tcp either.
	e4, _ := Parse("ss://" + importer_b64rawurl("aes-256-gcm:pw") +
		"@9.9.9.9:8388?uot=1&plugin=obfs-local;obfs=http;obfs-host=x.com#p4")
	if e4.Params["udp_over_tcp"] != true {
		t.Fatalf("uot must survive a raw ';' query: %+v", e4.Params)
	}
	if e4.Params["plugin"] != "obfs-local" {
		t.Fatalf("raw ';' obfs-local plugin dropped: %v", e4.Params["plugin"])
	}
}

// TestParseSS_UDPOverTCP: UoT (udp-over-tcp / uot) is parsed from the query — UoT
// is built into sing-box.
func TestParseSS_UDPOverTCP(t *testing.T) {
	for _, key := range []string{"udp-over-tcp", "udp_over_tcp", "uot"} {
		link := "ss://" + importer_b64rawurl("aes-256-gcm:pw") + "@9.9.9.9:8388?" + key + "=1#u"
		e, err := Parse(link)
		if err != nil {
			t.Fatalf("%s: parse: %v", key, err)
		}
		if e.Params["udp_over_tcp"] != true {
			t.Errorf("%s: udp_over_tcp = %v, want true", key, e.Params["udp_over_tcp"])
		}
		if e.Server != "9.9.9.9" || e.Port != 8388 {
			t.Errorf("%s: server:port = %s:%d (query must not corrupt host parse)", key, e.Server, e.Port)
		}
	}
	// No UoT param -> key absent.
	e, _ := Parse("ss://" + importer_b64rawurl("aes-256-gcm:pw") + "@9.9.9.9:8388?plugin=obfs-local#u")
	if _, ok := e.Params["udp_over_tcp"]; ok {
		t.Errorf("udp_over_tcp present when link had none")
	}
}

func TestParseSS_LegacyForm(t *testing.T) {
	// Legacy: ss://base64(method:password@host:port)#name
	body := importer_b64rawurl("chacha20-ietf-poly1305:pass@10.0.0.1:8388")
	link := "ss://" + body + "#Legacy"
	e, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Server != "10.0.0.1" || e.Port != 8388 {
		t.Fatalf("server:port = %s:%d", e.Server, e.Port)
	}
	if e.Params["method"] != "chacha20-ietf-poly1305" || e.Params["password"] != "pass" {
		t.Fatalf("creds = %+v", e.Params)
	}
	if e.Name != "Legacy" {
		t.Fatalf("name = %q", e.Name)
	}
}

func TestParseSS_SIP002StripsPluginParams(t *testing.T) {
	// The "?plugin=..." query is stripped before host:port parsing.
	userinfo := importer_b64rawurl("aes-128-gcm:pw")
	link := "ss://" + userinfo + "@1.2.3.4:8388?plugin=obfs-local;obfs=http#withplugin"
	e, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Server != "1.2.3.4" || e.Port != 8388 {
		t.Fatalf("server:port = %s:%d", e.Server, e.Port)
	}
	if e.Name != "withplugin" {
		t.Fatalf("name = %q", e.Name)
	}
}

func TestParseSS_LegacyBadBase64(t *testing.T) {
	// No '@' in body and body is not decodable base64 -> credentials error.
	e, err := Parse("ss://!!!notbase64$$$")
	if err == nil {
		t.Fatalf("want error, got %+v", e)
	}
	if err.Error() != "ss: cannot parse credentials" {
		t.Fatalf("want 'ss: cannot parse credentials', got %q", err.Error())
	}
}

func TestParseSS_MissingHostPort(t *testing.T) {
	// SIP002 form with host empty and port 0 -> missing host/port error.
	userinfo := importer_b64rawurl("aes-256-gcm:pw")
	e, err := Parse("ss://" + userinfo + "@:0#x")
	if err == nil {
		t.Fatalf("want error, got %+v", e)
	}
	if err.Error() != "ss: missing host/port" {
		t.Fatalf("want 'ss: missing host/port', got %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// WireGuard URL form
// ---------------------------------------------------------------------------

func TestParseWireGuardURL_FullParams(t *testing.T) {
	link := "wireguard://privkey@1.2.3.4:51820?publickey=PUB&presharedkey=PSK&address=10.0.0.2/32,fd00::2/128"
	e, err := Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Protocol != model.ProtoWireGuard || e.Engine != model.EngineSingBox {
		t.Fatalf("proto/engine = %s/%s", e.Protocol, e.Engine)
	}
	if e.Server != "1.2.3.4" || e.Port != 51820 {
		t.Fatalf("server:port = %s:%d", e.Server, e.Port)
	}
	if e.Params["private_key"] != "privkey" {
		t.Fatalf("private_key = %v", e.Params["private_key"])
	}
	if e.Params["peer_public_key"] != "PUB" {
		t.Fatalf("peer_public_key = %v", e.Params["peer_public_key"])
	}
	if e.Params["pre_shared_key"] != "PSK" {
		t.Fatalf("pre_shared_key = %v", e.Params["pre_shared_key"])
	}
	addr, ok := e.Params["local_address"].([]string)
	if !ok || len(addr) != 2 || addr[0] != "10.0.0.2/32" || addr[1] != "fd00::2/128" {
		t.Fatalf("local_address = %#v", e.Params["local_address"])
	}
}

// TestParseWireGuardURL_PlusInKeys: a real wireguard:// link carries the base64
// peer key / PSK with un-percent-encoded '+' chars (the common form most base64
// keys contain a '+'). url.Query() decodes a raw '+' to a space, so without a fix
// the key is corrupted and the handshake fails. Both the raw-'+' and the properly
// %2B-encoded forms must yield the exact original key.
func TestParseWireGuardURL_PlusInKeys(t *testing.T) {
	const key = "DnPYPaIHbNE2mwBlyi+U+V7DKI3yV7whhutQtRp/5Ek=" // two '+', one '/'
	for _, raw := range []string{
		"wireguard://priv@1.2.3.4:51820?publickey=" + key + "&presharedkey=" + key,                                                                                        // raw '+'
		"wireguard://priv@1.2.3.4:51820?publickey=DnPYPaIHbNE2mwBlyi%2BU%2BV7DKI3yV7whhutQtRp%2F5Ek%3D&presharedkey=DnPYPaIHbNE2mwBlyi%2BU%2BV7DKI3yV7whhutQtRp%2F5Ek%3D", // %2B-encoded
	} {
		e, err := Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if e.Params["peer_public_key"] != key {
			t.Fatalf("peer_public_key = %q, want %q (the '+' must survive)", e.Params["peer_public_key"], key)
		}
		if e.Params["pre_shared_key"] != key {
			t.Fatalf("pre_shared_key = %q, want %q", e.Params["pre_shared_key"], key)
		}
	}
}

// TestParseWireGuardURL_Reserved: WARP's 3 client-id bytes (the WG "reserved"
// field) must be parsed from a wireguard:// link as a []int{a,b,c}; the WARP server
// rejects the handshake without them. A malformed value is dropped (not 3 bytes, or
// out of range), since sing-box requires a 3-element array.
// TestParseWireGuardURL_MTU: a wireguard:// link's mtu must be carried onto the
// endpoint (WARP links use mtu=1280); absent/zero leaves it unset.
func TestParseWireGuardURL_MTU(t *testing.T) {
	e, err := Parse("wireguard://priv@1.2.3.4:2408?publickey=PUB&mtu=1280")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Params["mtu"] != 1280 {
		t.Fatalf("mtu = %v, want 1280", e.Params["mtu"])
	}
	e2, _ := Parse("wireguard://priv@1.2.3.4:2408?publickey=PUB")
	if _, ok := e2.Params["mtu"]; ok {
		t.Fatalf("mtu present when link had none: %v", e2.Params["mtu"])
	}
}

func TestParseWireGuardURL_Reserved(t *testing.T) {
	for _, raw := range []string{
		"wireguard://priv@1.2.3.4:2408?publickey=PUB&reserved=1,2,3",
		"wireguard://priv@1.2.3.4:2408?publickey=PUB&reserved=%5B1,2,3%5D", // [1,2,3]
	} {
		e, err := Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		r, ok := e.Params["reserved"].([]int)
		if !ok || len(r) != 3 || r[0] != 1 || r[1] != 2 || r[2] != 3 {
			t.Fatalf("reserved = %#v, want []int{1,2,3}", e.Params["reserved"])
		}
	}
	for _, raw := range []string{
		"wireguard://priv@1.2.3.4:2408?publickey=PUB",                  // none
		"wireguard://priv@1.2.3.4:2408?publickey=PUB&reserved=1,2",     // not 3
		"wireguard://priv@1.2.3.4:2408?publickey=PUB&reserved=1,2,999", // out of range
		"wireguard://priv@1.2.3.4:2408?publickey=PUB&reserved=a,b,c",   // non-numeric
	} {
		e, _ := Parse(raw)
		if _, ok := e.Params["reserved"]; ok {
			t.Fatalf("%q: reserved should be absent/dropped, got %#v", raw, e.Params["reserved"])
		}
	}
}

func TestParseWireGuardURL_DefaultPortAndShortScheme(t *testing.T) {
	// wg:// short scheme with no port defaults to 51820, optional params absent.
	e, err := Parse("wg://privkey@5.6.7.8?publickey=PUB")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Protocol != model.ProtoWireGuard {
		t.Fatalf("proto = %s", e.Protocol)
	}
	if e.Port != 51820 {
		t.Fatalf("port = %d (want default 51820)", e.Port)
	}
	if _, ok := e.Params["pre_shared_key"]; ok {
		t.Fatalf("pre_shared_key should be absent, got %v", e.Params["pre_shared_key"])
	}
	if _, ok := e.Params["local_address"]; ok {
		t.Fatalf("local_address should be absent, got %v", e.Params["local_address"])
	}
}

// ---------------------------------------------------------------------------
// WireGuard / AmneziaWG .conf parsing
// ---------------------------------------------------------------------------

func TestParseConf_PlainWireGuardFromFile(t *testing.T) {
	// Read a .conf written to a temp dir, then feed its content to Parse.
	conf := strings.Join([]string{
		"[Interface]",
		"PrivateKey = key==",
		"Address = 10.0.0.2/32",
		"DNS = 1.1.1.1",
		"",
		"[Peer]",
		"PublicKey = pub==",
		"Endpoint = host.example:51820",
		"AllowedIPs = 0.0.0.0/0",
	}, "\n")

	dir := t.TempDir()
	path := filepath.Join(dir, "wg0.conf")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatalf("write conf: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read conf: %v", err)
	}

	e, err := Parse(string(b))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Protocol != model.ProtoWireGuard || e.Engine != model.EngineSingBox {
		t.Fatalf("proto/engine = %s/%s (want wireguard/singbox)", e.Protocol, e.Engine)
	}
	if e.Server != "host.example" || e.Port != 51820 {
		t.Fatalf("server:port = %s:%d", e.Server, e.Port)
	}
	if e.Params["private_key"] != "key==" || e.Params["peer_public_key"] != "pub==" {
		t.Fatalf("keys = %+v", e.Params)
	}
	if e.Name != "WireGuard host.example" {
		t.Fatalf("name = %q", e.Name)
	}
}

func TestParseConf_AmneziaWGDetectedByJunkKeys(t *testing.T) {
	// Presence of any awg junk key in [Interface] routes to amneziawg engine.
	conf := strings.Join([]string{
		"[Interface]",
		"PrivateKey = priv==",
		"Address = 10.8.0.2/32",
		"Jc = 4",
		"Jmin = 40",
		"Jmax = 70",
		"S1 = 0",
		"H1 = 1",
		"",
		"[Peer]",
		"PublicKey = peerpub==",
		"PresharedKey = psk==",
		"Endpoint = 203.0.113.10:51820",
		"AllowedIPs = 0.0.0.0/0",
	}, "\n")
	e, err := Parse(conf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Protocol != model.ProtoAmneziaWG || e.Engine != model.EngineAmneziaWG {
		t.Fatalf("proto/engine = %s/%s (want amneziawg/amneziawg)", e.Protocol, e.Engine)
	}
	// Jc/Jmin/Jmax are small -> ints; H1-H4 are kept as strings (can exceed 2^31,
	// which atoi overflows to 0 on a 32-bit build).
	if e.Params["jc"] != 4 || e.Params["jmin"] != 40 || e.Params["jmax"] != 70 || e.Params["h1"] != "1" {
		t.Fatalf("awg junk params = %+v", e.Params)
	}
	if e.Params["pre_shared_key"] != "psk==" {
		t.Fatalf("pre_shared_key = %v", e.Params["pre_shared_key"])
	}
	if e.Name != "AmneziaWG 203.0.113.10" {
		t.Fatalf("name = %q", e.Name)
	}
}

func TestParseConf_MissingEndpoint(t *testing.T) {
	conf := strings.Join([]string{
		"[Interface]",
		"PrivateKey = key==",
		"Address = 10.0.0.2/32",
		"",
		"[Peer]",
		"PublicKey = pub==",
		"AllowedIPs = 0.0.0.0/0",
	}, "\n")
	e, err := Parse(conf)
	if err == nil {
		t.Fatalf("want error for missing endpoint, got %+v", e)
	}
	if err.Error() != "conf: missing [Peer] Endpoint" {
		t.Fatalf("want 'conf: missing [Peer] Endpoint', got %q", err.Error())
	}
}

func TestParseConf_CommentsAndBlankLinesIgnored(t *testing.T) {
	// '#' and ';' comments and blank lines must be ignored; default port 51820.
	conf := strings.Join([]string{
		"# this is a comment",
		"; another comment",
		"[Interface]",
		"   ",
		"PrivateKey = k==",
		"",
		"[Peer]",
		"; peer comment",
		"PublicKey = p==",
		"Endpoint = h.example", // no port -> default 51820
	}, "\n")
	e, err := Parse(conf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Server != "h.example" || e.Port != 51820 {
		t.Fatalf("server:port = %s:%d (want h.example:51820)", e.Server, e.Port)
	}
}

// ---------------------------------------------------------------------------
// finalize() side effects: ID, Name, Enabled
// ---------------------------------------------------------------------------

func TestParse_FinalizeDefaults(t *testing.T) {
	// No fragment -> Name synthesized as "<PROTO upper> <server>"; ID slugged;
	// Enabled forced true.
	e, err := Parse("trojan://pw@host.example:443")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Name != "TROJAN host.example" {
		t.Fatalf("name = %q (want 'TROJAN host.example')", e.Name)
	}
	if e.ID != "trojan-host-example-443" {
		t.Fatalf("id = %q (want 'trojan-host-example-443')", e.ID)
	}
	if !e.Enabled {
		t.Fatal("Enabled should be forced true")
	}
}

// ---------------------------------------------------------------------------
// ParseSubscription(): mixed blank lines + comments + base64-wrapped blob
// ---------------------------------------------------------------------------

func TestParseSubscription_PlainMixed(t *testing.T) {
	// Leading/trailing blank lines, CRLF, '#' comments, and a junk line.
	sub := "\n\n  # header comment\r\n" +
		"vless://u@1.1.1.1:443?security=reality&pbk=K&sni=a.com#A\r\n" +
		"\r\n   \n" +
		"trojan://pw@2.2.2.2:443#B\n" +
		"#another comment\n" +
		"junkline-no-scheme\n"
	eps, errs := ParseSubscription(sub)
	if len(eps) != 2 {
		t.Fatalf("want 2 endpoints, got %d (errs=%v)", len(eps), errs)
	}
	if len(errs) != 1 {
		t.Fatalf("want exactly 1 error (junkline), got %d: %v", len(errs), errs)
	}
	if !strings.Contains(errs[0], "junkline-no-scheme") {
		t.Fatalf("error should reference the junk line, got %q", errs[0])
	}
	// Endpoint order is preserved.
	if eps[0].Protocol != model.ProtoVLESS || eps[1].Protocol != model.ProtoTrojan {
		t.Fatalf("order/protocols = %s,%s", eps[0].Protocol, eps[1].Protocol)
	}
}

func TestParseSubscription_Base64Wrapped(t *testing.T) {
	// A base64-wrapped blob (no "://" until decoded) containing links + a
	// comment + a blank line + a garbage line.
	inner := "ss://" + importer_b64rawurl("aes-256-gcm:secret") + "@4.4.4.4:8388#S\n" +
		"# a comment line\n" +
		"\n" +
		"hysteria2://pw@2.2.2.2:8443?sni=b.com#B\n" +
		"garbage-not-a-link\n"
	blob := importer_b64std(inner)

	eps, errs := ParseSubscription(blob)
	if len(eps) != 2 {
		t.Fatalf("want 2 endpoints from decoded blob, got %d (errs=%v)", len(eps), errs)
	}
	if len(errs) != 1 {
		t.Fatalf("want 1 error (the garbage line), got %d: %v", len(errs), errs)
	}
	if eps[0].Protocol != model.ProtoShadowsocks || eps[1].Protocol != model.ProtoHysteria2 {
		t.Fatalf("protocols = %s,%s", eps[0].Protocol, eps[1].Protocol)
	}
}

func TestParseSubscription_AllGarbage(t *testing.T) {
	// Every non-comment line is garbage -> no endpoints, all errors, no panic.
	sub := "garbage1\nfoo://x\n# comment\n\nbar-no-scheme\n"
	eps, errs := ParseSubscription(sub)
	if len(eps) != 0 {
		t.Fatalf("want 0 endpoints, got %d", len(eps))
	}
	if len(errs) != 3 {
		t.Fatalf("want 3 errors, got %d: %v", len(errs), errs)
	}
}

func TestParseSubscription_EmptyInput(t *testing.T) {
	eps, errs := ParseSubscription("")
	if len(eps) != 0 || len(errs) != 0 {
		t.Fatalf("empty input: want (0,0), got (%d,%d)", len(eps), len(errs))
	}
}

// TestParse_IPv6ServerBracketStripped: the non-URL parsers (Shadowsocks SIP002,
// WireGuard/AmneziaWG .conf) must return a BARE IPv6 host. A bracketed literal
// ("[2001:db8::1]") left in e.Server makes sing-box DNS-resolve it as a hostname
// (NXDOMAIN → every connection dies at runtime) and double-brackets on export.
func TestParse_IPv6ServerBracketStripped(t *testing.T) {
	ui := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:supersecret"))
	e, err := Parse("ss://" + ui + "@[2001:db8::1]:8388#v6")
	if err != nil {
		t.Fatalf("parse ss ipv6: %v", err)
	}
	if e.Server != "2001:db8::1" {
		t.Fatalf("SS IPv6 server must be bare, got %q", e.Server)
	}
	if e.Port != 8388 {
		t.Fatalf("SS IPv6 port = %d, want 8388", e.Port)
	}
	// A v4 host:port and a hostname:port must be unaffected by the bracket logic.
	if e4, _ := Parse("ss://" + ui + "@9.9.9.9:8388#v4"); e4 == nil || e4.Server != "9.9.9.9" || e4.Port != 8388 {
		t.Fatalf("SS v4 must still parse to 9.9.9.9:8388, got %+v", e4)
	}
}

// TestSplitHostPortBrackets exercises the helper directly across the forms its
// SS/.conf callers see, including the no-port and bare-host fallbacks.
func TestSplitHostPortBrackets(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort int
	}{
		{"[2001:db8::1]:443", "2001:db8::1", 443},
		{"[2001:db8::1]", "2001:db8::1", 0},
		{"1.2.3.4:51820", "1.2.3.4", 51820},
		{"vpn.example.com:8443", "vpn.example.com", 8443},
		{"1.2.3.4", "1.2.3.4", 0},
	}
	for _, c := range cases {
		h, p := splitHostPort(c.in)
		if h != c.wantHost || p != c.wantPort {
			t.Errorf("splitHostPort(%q) = (%q,%d), want (%q,%d)", c.in, h, p, c.wantHost, c.wantPort)
		}
	}
}
