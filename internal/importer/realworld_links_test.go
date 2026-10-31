package importer

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// Share links in the shapes today's clients emit (v2rayN / v2rayNG, NekoBox, Hiddify, the official
// Hysteria 2 URI scheme, sing-box and mihomo configs). Every key, password and host is SYNTHETIC:
// keys are fixed byte patterns, addresses are RFC 5737 / RFC 3849 or example.com.

const rwUUID = "a3482e88-686a-4a58-8126-99c9df64b7bf"

// rwKey is a synthetic 32-byte key in standard base64; pattern bytes 0xfb 0xff put '+' and '/'
// into it so the escaping paths are exercised.
func rwKey(b byte) string {
	return base64.StdEncoding.EncodeToString(append(bytes.Repeat([]byte{b}, 30), 0xfb, 0xff))
}

// rwPBK is a synthetic x25519 Reality public key as clients print it (raw url-safe base64).
var rwPBK = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))

func rwVMess(m map[string]any) string {
	b, _ := json.Marshal(m)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

type rwWant struct {
	proto     model.Protocol
	engine    model.Engine
	server    string
	port      int
	name      string
	params    map[string]any   // each listed key must equal; unlisted keys are not checked
	transport *model.Transport // nil = must have no transport
	tls       *model.TLS       // nil = must have no TLS; checked field by field (see below)
}

func TestRealWorldShareLinks(t *testing.T) {
	priv, pub, psk := rwKey(0x11), rwKey(0x22), rwKey(0x33)
	// plusKey starts with a '+' (first byte 0xf8): an unencoded leading '+' must survive query decoding.
	plusKey := base64.StdEncoding.EncodeToString(append([]byte{0xf8}, bytes.Repeat([]byte{0x01}, 31)...))
	ss256 := rwKey(0x44) // a 2022-blake3-aes-256-gcm PSK is 32 bytes
	ss128 := base64.StdEncoding.EncodeToString(append(bytes.Repeat([]byte{0x55}, 14), 0xfb, 0xff))
	ss128u := base64.StdEncoding.EncodeToString(append(bytes.Repeat([]byte{0x66}, 14), 0xfb, 0xff))
	qe := url.QueryEscape
	pe := url.PathEscape

	cases := []struct {
		name string
		link string
		want rwWant
	}{
		{"v2rayN vless reality vision", "vless://" + rwUUID + "@203.0.113.10:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=" + rwPBK + "&sid=6ba85179e30d4fc2&spx=%2F&type=tcp&headerType=none#RU%20Reality",
			rwWant{proto: model.ProtoVLESS, server: "203.0.113.10", port: 443, name: "RU Reality",
				params: map[string]any{"uuid": rwUUID, "flow": "xtls-rprx-vision"},
				tls:    &model.TLS{Enabled: true, Type: "reality", SNI: "www.example.com", Fingerprint: "chrome", PublicKey: rwPBK, ShortID: "6ba85179e30d4fc2"}}},
		{"xray raw is plain tcp", "vless://" + rwUUID + "@203.0.113.11:443?security=reality&sni=www.example.com&pbk=" + rwPBK + "&type=raw&flow=xtls-rprx-vision#raw",
			rwWant{proto: model.ProtoVLESS, server: "203.0.113.11", port: 443, name: "raw",
				tls: &model.TLS{Enabled: true, Type: "reality", SNI: "www.example.com", PublicKey: rwPBK}}},
		{"v2rayN vless ws tls early data", "vless://" + rwUUID + "@203.0.113.12:443?encryption=none&security=tls&sni=ws.example.com&fp=chrome&alpn=" + qe("h2,http/1.1") + "&type=ws&host=ws.example.com&path=" + qe("/vless?ed=2560") + "#ws",
			rwWant{proto: model.ProtoVLESS, server: "203.0.113.12", port: 443, name: "ws",
				transport: &model.Transport{Type: "ws", Path: "/vless?ed=2560", Host: "ws.example.com"},
				tls:       &model.TLS{Enabled: true, Type: "tls", SNI: "ws.example.com", Fingerprint: "chrome", ALPN: []string{"h2", "http/1.1"}}}},
		{"v2rayN vless grpc reality", "vless://" + rwUUID + "@203.0.113.13:443?encryption=none&security=reality&sni=www.example.com&fp=firefox&pbk=" + rwPBK + "&sid=ab&type=grpc&serviceName=grpc-svc&mode=gun&authority=#grpc",
			rwWant{proto: model.ProtoVLESS, server: "203.0.113.13", port: 443, name: "grpc",
				transport: &model.Transport{Type: "grpc", ServiceName: "grpc-svc"},
				tls:       &model.TLS{Enabled: true, Type: "reality", SNI: "www.example.com", Fingerprint: "firefox", PublicKey: rwPBK, ShortID: "ab"}}},
		{"v2rayN vless httpupgrade", "vless://" + rwUUID + "@203.0.113.14:80?encryption=none&security=none&type=httpupgrade&host=up.example.com&path=%2Fup#up",
			rwWant{proto: model.ProtoVLESS, server: "203.0.113.14", port: 80, name: "up",
				transport: &model.Transport{Type: "httpupgrade", Path: "/up", Host: "up.example.com"}}},
		{"transport type is case-insensitive", "vless://" + rwUUID + "@203.0.113.15:443?security=tls&sni=example.com&type=WS&path=%2Fws#case",
			rwWant{proto: model.ProtoVLESS, server: "203.0.113.15", port: 443, name: "case",
				transport: &model.Transport{Type: "ws", Path: "/ws"},
				tls:       &model.TLS{Enabled: true, Type: "tls", SNI: "example.com"}}},
		{"v2rayN vmess ws tls", rwVMess(map[string]any{"v": "2", "ps": "vm", "add": "203.0.113.20", "port": "443", "id": rwUUID, "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": "vm.example.com", "path": "/vm", "tls": "tls", "sni": "vm.example.com", "alpn": "", "fp": "chrome"}),
			rwWant{proto: model.ProtoVMess, server: "203.0.113.20", port: 443, name: "vm",
				params:    map[string]any{"uuid": rwUUID, "alter_id": 0, "security": "auto"},
				transport: &model.Transport{Type: "ws", Path: "/vm", Host: "vm.example.com"},
				tls:       &model.TLS{Enabled: true, Type: "tls", SNI: "vm.example.com", Fingerprint: "chrome"}}},
		{"v2rayN vmess grpc numeric port", rwVMess(map[string]any{"v": "2", "ps": "vg", "add": "203.0.113.21", "port": 8443, "id": rwUUID, "aid": 0, "net": "grpc", "type": "gun", "path": "vm-grpc", "tls": "tls", "sni": "g.example.com"}),
			rwWant{proto: model.ProtoVMess, server: "203.0.113.21", port: 8443, name: "vg",
				transport: &model.Transport{Type: "grpc", Path: "vm-grpc", ServiceName: "vm-grpc"},
				tls:       &model.TLS{Enabled: true, Type: "tls", SNI: "g.example.com"}}},
		{"v2rayN trojan tls", "trojan://" + pe("p@ss w0rd") + "@203.0.113.30:443?security=tls&sni=tj.example.com&fp=firefox&type=tcp&headerType=none#tj",
			rwWant{proto: model.ProtoTrojan, server: "203.0.113.30", port: 443, name: "tj",
				params: map[string]any{"password": "p@ss w0rd"},
				tls:    &model.TLS{Enabled: true, Type: "tls", SNI: "tj.example.com", Fingerprint: "firefox"}}},
		{"trojan grpc", "trojan://pw@203.0.113.31:443?security=tls&sni=tg.example.com&type=grpc&serviceName=tj-grpc#tg",
			rwWant{proto: model.ProtoTrojan, server: "203.0.113.31", port: 443, name: "tg",
				transport: &model.Transport{Type: "grpc", ServiceName: "tj-grpc"},
				tls:       &model.TLS{Enabled: true, Type: "tls", SNI: "tg.example.com"}}},
		{"ss 2022 plaintext userinfo", "ss://2022-blake3-aes-256-gcm:" + qe(ss256) + "@203.0.113.40:8388#ss22",
			rwWant{proto: model.ProtoShadowsocks, server: "203.0.113.40", port: 8388, name: "ss22",
				params: map[string]any{"method": "2022-blake3-aes-256-gcm", "password": ss256}}},
		{"ss 2022 multi-user (iPSK:uPSK)", "ss://2022-blake3-aes-128-gcm:" + qe(ss128) + "%3A" + qe(ss128u) + "@203.0.113.41:8388#eih",
			rwWant{proto: model.ProtoShadowsocks, server: "203.0.113.41", port: 8388, name: "eih",
				params: map[string]any{"method": "2022-blake3-aes-128-gcm", "password": ss128 + ":" + ss128u}}},
		{"ss SIP002 base64 + obfs-local", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw")) + "@203.0.113.42:8388/?plugin=" + qe("obfs-local;obfs=http;obfs-host=www.example.com") + "#obfs",
			rwWant{proto: model.ProtoShadowsocks, server: "203.0.113.42", port: 8388, name: "obfs",
				params: map[string]any{"method": "chacha20-ietf-poly1305", "password": "pw", "plugin": "obfs-local", "plugin_opts": "obfs=http;obfs-host=www.example.com"}}},
		{"ss v2ray-plugin websocket tls", "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@203.0.113.43:443?plugin=" + qe("v2ray-plugin;mode=websocket;tls;host=ss.example.com;path=/ss") + "#v2p",
			rwWant{proto: model.ProtoShadowsocks, server: "203.0.113.43", port: 443, name: "v2p",
				params: map[string]any{"method": "aes-256-gcm", "plugin": "v2ray-plugin", "plugin_opts": "mode=websocket;tls;host=ss.example.com;path=/ss"}}},
		{"hysteria2 official URI with multi-port authority", "hysteria2://letmein@203.0.113.50:443,20000-30000/?insecure=1&obfs=salamander&obfs-password=gawrgura&pinSHA256=" + pinAHex + "&sni=real.example.com#cool",
			rwWant{proto: model.ProtoHysteria2, server: "203.0.113.50", port: 443, name: "cool",
				params: map[string]any{"password": "letmein", "obfs": "salamander", "obfs_password": "gawrgura", "hop_ports": "443,20000-30000"},
				tls:    &model.TLS{Enabled: true, Type: "tls", SNI: "real.example.com", Insecure: true, PinCertSHA256: []string{pinAHex}}}},
		{"hy2 port range only", "hy2://pw@hy.example.com:20000-50000?sni=hy.example.com#range",
			rwWant{proto: model.ProtoHysteria2, server: "hy.example.com", port: 20000, name: "range",
				params: map[string]any{"hop_ports": "20000-50000"},
				tls:    &model.TLS{Enabled: true, Type: "tls", SNI: "hy.example.com"}}},
		{"hy2 bracketed IPv6 with port list", "hysteria2://pw@[2001:db8::50]:443,5000-6000/?sni=v6.example.com#v6",
			rwWant{proto: model.ProtoHysteria2, server: "2001:db8::50", port: 443, name: "v6",
				params: map[string]any{"hop_ports": "443,5000-6000"},
				tls:    &model.TLS{Enabled: true, Type: "tls", SNI: "v6.example.com"}}},
		{"v2rayN hysteria2 mport query", "hysteria2://pw@203.0.113.51:443?sni=hq.example.com&insecure=0&mport=1000-2000#mport",
			rwWant{proto: model.ProtoHysteria2, server: "203.0.113.51", port: 443, name: "mport",
				params: map[string]any{"hop_ports": "1000-2000"},
				tls:    &model.TLS{Enabled: true, Type: "tls", SNI: "hq.example.com"}}},
		{"hysteria2 userpass auth", "hysteria2://alice:s3cret@203.0.113.52:8443?sni=up.example.com#userpass",
			rwWant{proto: model.ProtoHysteria2, server: "203.0.113.52", port: 8443, name: "userpass",
				params: map[string]any{"password": "alice:s3cret"},
				tls:    &model.TLS{Enabled: true, Type: "tls", SNI: "up.example.com"}}},
		{"v2rayN tuic v5", "tuic://" + rwUUID + ":tpass@203.0.113.60:443?sni=tuic.example.com&alpn=h3&congestion_control=bbr&allow_insecure=1#tuic",
			rwWant{proto: model.ProtoTUIC, server: "203.0.113.60", port: 443, name: "tuic",
				params: map[string]any{"uuid": rwUUID, "password": "tpass", "congestion_control": "bbr"},
				tls:    &model.TLS{Enabled: true, Type: "tls", SNI: "tuic.example.com", Insecure: true, ALPN: []string{"h3"}}}},
		{"NekoBox tuic quic relay", "tuic://" + rwUUID + ":tpass@203.0.113.61:443?congestion_control=cubic&udp_relay_mode=quic&alpn=h3&sni=tn.example.com&allow_insecure=0#nb",
			rwWant{proto: model.ProtoTUIC, server: "203.0.113.61", port: 443, name: "nb",
				params: map[string]any{"congestion_control": "cubic", "udp_relay_mode": "quic"},
				tls:    &model.TLS{Enabled: true, Type: "tls", SNI: "tn.example.com", ALPN: []string{"h3"}}}},
		{"v2rayN anytls", "anytls://apw@203.0.113.70:443?sni=anytls.example.com&insecure=1#at",
			rwWant{proto: model.ProtoAnyTLS, server: "203.0.113.70", port: 443, name: "at",
				params: map[string]any{"password": "apw"},
				tls:    &model.TLS{Enabled: true, Type: "tls", SNI: "anytls.example.com", Insecure: true}}},
		{"v2rayN wireguard (WARP)", "wireguard://" + pe(priv) + "@203.0.113.80:2408?publickey=" + qe(pub) + "&reserved=1,2,3&address=" + qe("172.16.0.2/32,2001:db8::2/128") + "&mtu=1280#warp",
			rwWant{proto: model.ProtoWireGuard, engine: model.EngineSingBox, server: "203.0.113.80", port: 2408, name: "warp",
				params: map[string]any{"private_key": priv, "peer_public_key": pub, "reserved": []int{1, 2, 3},
					"local_address": []string{"172.16.0.2/32", "2001:db8::2/128"}, "mtu": 1280}}},
		{"Hiddify wg:// with parameter keys", "wg://203.0.113.81:51820?pk=" + qe(priv) + "&peer_pk=" + qe(pub) + "&psk=" + qe(psk) + "&local_address=10.8.0.2/32&mtu=1420#hid",
			rwWant{proto: model.ProtoWireGuard, engine: model.EngineSingBox, server: "203.0.113.81", port: 51820, name: "hid",
				params: map[string]any{"private_key": priv, "peer_public_key": pub, "pre_shared_key": psk,
					"local_address": []string{"10.8.0.2/32"}, "mtu": 1420}}},
		{"wireguard key with an unencoded '+'", "wireguard://" + pe(priv) + "@203.0.113.83:51820?public_key=" + plusKey + "&psk=" + pub + "&address=10.0.0.2/32#plus",
			rwWant{proto: model.ProtoWireGuard, engine: model.EngineSingBox, server: "203.0.113.83", port: 51820, name: "plus",
				params: map[string]any{"private_key": priv, "peer_public_key": plusKey, "pre_shared_key": pub}}},
		{"wg:// carrying AmneziaWG parameters", "wg://" + pe(priv) + "@203.0.113.82:51820?publickey=" + qe(pub) + "&address=10.9.0.2/32&jc=4&jmin=40&jmax=70&s1=0&s2=0&h1=1&h2=2&h3=3&h4=4#awg",
			rwWant{proto: model.ProtoAmneziaWG, engine: model.EngineAmneziaWG, server: "203.0.113.82", port: 51820, name: "awg",
				params: map[string]any{"private_key": priv, "peer_public_key": pub, "jc": 4, "jmin": 40, "jmax": 70, "h1": "1", "h4": "4"}}},
		{"AmneziaWG 2.0 .conf saved with a BOM", utf8BOM + "[Interface]\r\nPrivateKey = " + priv + "\r\nAddress = 10.7.0.2/32\r\nJc = 4\r\nJmin = 10\r\nJmax = 50\r\nS1 = 15\r\nS2 = 18\r\nS3 = 20\r\nS4 = 22\r\nH1 = 1000-2000\r\nH2 = 3000-4000\r\nH3 = 5000-6000\r\nH4 = 7000-8000\r\nI1 = <b 0x5f0a>\r\n\r\n[Peer]\r\nPublicKey = " + pub + "\r\nEndpoint = 203.0.113.90:51820\r\nAllowedIPs = 0.0.0.0/0\r\n",
			rwWant{proto: model.ProtoAmneziaWG, engine: model.EngineAmneziaWG, server: "203.0.113.90", port: 51820,
				params: map[string]any{"private_key": priv, "peer_public_key": pub, "s3": 20, "h1": "1000-2000", "i1": "<b 0x5f0a>"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := Parse(tc.link)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			checkRealWorld(t, e, tc.want)
		})
	}
}

func checkRealWorld(t *testing.T, e *model.Endpoint, w rwWant) {
	t.Helper()
	if e.Protocol != w.proto {
		t.Errorf("protocol = %q, want %q", e.Protocol, w.proto)
	}
	if w.engine != "" && e.Engine != w.engine {
		t.Errorf("engine = %q, want %q", e.Engine, w.engine)
	}
	if e.Server != w.server || e.Port != w.port {
		t.Errorf("server = %s:%d, want %s:%d", e.Server, e.Port, w.server, w.port)
	}
	if w.name != "" && e.Name != w.name {
		t.Errorf("name = %q, want %q", e.Name, w.name)
	}
	for k, v := range w.params {
		if got := e.Params[k]; !reflect.DeepEqual(got, v) {
			t.Errorf("params[%q] = %#v, want %#v", k, got, v)
		}
	}
	if !reflect.DeepEqual(e.Transport, w.transport) {
		t.Errorf("transport = %+v, want %+v", e.Transport, w.transport)
	}
	switch {
	case w.tls == nil && e.TLS != nil && e.TLS.Enabled:
		t.Errorf("tls = %+v, want none", e.TLS)
	case w.tls != nil && e.TLS == nil:
		t.Errorf("tls missing, want %+v", w.tls)
	case w.tls != nil:
		g := *e.TLS
		if g.Enabled != w.tls.Enabled || g.Type != w.tls.Type || g.SNI != w.tls.SNI || g.Insecure != w.tls.Insecure ||
			g.PublicKey != w.tls.PublicKey || g.ShortID != w.tls.ShortID ||
			(w.tls.Fingerprint != "" && g.Fingerprint != w.tls.Fingerprint) ||
			(w.tls.ALPN != nil && !reflect.DeepEqual(g.ALPN, w.tls.ALPN)) ||
			!reflect.DeepEqual(g.PinCertSHA256, w.tls.PinCertSHA256) {
			t.Errorf("tls = %+v, want %+v", g, *w.tls)
		}
	}
}

// TestRealWorldShareLinksRefused: shapes a sing-box core cannot dial. Each used to import "fine" as
// something else (raw TCP, plain VLESS) - an endpoint that passes `sing-box check` and fails every
// connection. They must fail the import, saying why, without echoing the credential.
func TestRealWorldShareLinksRefused(t *testing.T) {
	const secretish = "mlkem768x25519plus.native.0rtt.SYNTHETICKEYMATERIAL"
	for _, tc := range []struct {
		name, link, wantErr string
	}{
		{"vless xhttp", "vless://" + rwUUID + "@203.0.113.100:443?encryption=none&security=reality&sni=www.example.com&pbk=" + rwPBK + "&type=xhttp&path=%2Fx&mode=auto#x", "XHTTP"},
		{"vless splithttp (old XHTTP name)", "vless://" + rwUUID + "@203.0.113.101:443?security=tls&sni=example.com&type=splithttp&path=%2Fs#s", "XHTTP"},
		{"vless mkcp", "vless://" + rwUUID + "@203.0.113.102:443?type=kcp&headerType=none&seed=x#k", "mKCP"},
		{"trojan xhttp", "trojan://pw@203.0.113.103:443?security=tls&sni=example.com&type=xhttp#t", "XHTTP"},
		{"vmess xhttp", rwVMess(map[string]any{"v": "2", "add": "203.0.113.104", "port": "443", "id": rwUUID, "net": "xhttp", "path": "/x", "tls": "tls"}), "XHTTP"},
		{"vmess kcp", rwVMess(map[string]any{"v": "2", "add": "203.0.113.105", "port": "443", "id": rwUUID, "net": "kcp", "type": "wechat-video"}), "mKCP"},
		{"vless Xray encryption", "vless://" + rwUUID + "@203.0.113.106:443?encryption=" + secretish + "&security=tls&sni=example.com&type=tcp#e", "VLESS encryption"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := Parse(tc.link)
			if err == nil {
				t.Fatalf("Parse accepted it: %+v", e)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), rwUUID) || strings.Contains(err.Error(), "SYNTHETICKEYMATERIAL") {
				t.Errorf("error echoes a credential: %q", err)
			}
		})
	}
}

// TestSplitAuthorityPortList pins the rewrite that lifts a Hysteria 2 multi-port list out of the
// authority, and the shapes it must leave alone.
func TestSplitAuthorityPortList(t *testing.T) {
	for _, tc := range []struct{ in, out, ports string }{
		{"hysteria2://a@h.example.com:443,5000-6000/?sni=x#n", "hysteria2://a@h.example.com:443/?sni=x#n", "443,5000-6000"},
		{"hy2://a@h.example.com:20000-30000", "hy2://a@h.example.com:20000", "20000-30000"},
		{"hy2://a@[2001:db8::1]:443,7000?x=1", "hy2://a@[2001:db8::1]:443?x=1", "443,7000"},
		{"hy2://a@h.example.com:443/?mport=1-2", "hy2://a@h.example.com:443/?mport=1-2", ""},   // single port
		{"hy2://a@h.example.com/?x=1", "hy2://a@h.example.com/?x=1", ""},                       // no port
		{"hy2://a@[2001:db8::1]/?x=1", "hy2://a@[2001:db8::1]/?x=1", ""},                       // bracket colons are not a port
		{"hy2://a-b@h.example.com:443", "hy2://a-b@h.example.com:443", ""},                     // '-' in the auth is not a range
		{"hy2://a@h.example.com:44x-3,1/?q", "hy2://a@h.example.com:44x-3,1/?q", ""},           // not a port list
		{"hy2://a@h.example.com:443,,5/", "hy2://a@h.example.com:443,,5/", ""},                 // empty entry
		{"hy2://a:b@h.example.com:1000-2000#f", "hy2://a:b@h.example.com:1000#f", "1000-2000"}, // userpass auth
	} {
		out, ports := splitAuthorityPortList(tc.in)
		if out != tc.out || ports != tc.ports {
			t.Errorf("splitAuthorityPortList(%q) = %q, %q; want %q, %q", tc.in, out, ports, tc.out, tc.ports)
		}
	}
}

// TestClashRealWorldShapes covers mihomo spellings that used to import as the wrong thing.
func TestClashRealWorldShapes(t *testing.T) {
	yaml := `proxies:
  - name: up
    type: vless
    server: 203.0.113.110
    port: 443
    uuid: ` + rwUUID + `
    tls: true
    servername: up.example.com
    network: ws
    ws-opts:
      path: /up
      headers:
        Host: up.example.com
      v2ray-http-upgrade: true
  - name: plainws
    type: vmess
    server: 203.0.113.111
    port: 443
    uuid: ` + rwUUID + `
    alterId: 0
    cipher: auto
    network: ws
    ws-opts:
      path: /ws
  - name: xh
    type: vless
    server: 203.0.113.112
    port: 443
    uuid: ` + rwUUID + `
    network: xhttp
    xhttp-opts:
      path: /x
  - name: enc
    type: vless
    server: 203.0.113.113
    port: 443
    uuid: ` + rwUUID + `
    encryption: mlkem768x25519plus.native.0rtt.SYNTHETICKEYMATERIAL
`
	eps, errs := ParseClash(yaml)
	if len(eps) != 2 {
		t.Fatalf("want 2 endpoints (up, plainws), got %d; errs=%v", len(eps), errs)
	}
	if got := eps[0].Transport; got == nil || got.Type != "httpupgrade" || got.Path != "/up" || got.Host != "up.example.com" {
		t.Errorf("ws-opts.v2ray-http-upgrade: transport = %+v, want httpupgrade /up up.example.com", got)
	}
	if got := eps[1].Transport; got == nil || got.Type != "ws" {
		t.Errorf("plain ws became %+v", got)
	}
	joined := strings.Join(errs, "\n")
	if len(errs) != 2 || !strings.Contains(joined, "XHTTP") || !strings.Contains(joined, "VLESS encryption") {
		t.Errorf("want an XHTTP and a VLESS-encryption refusal, got %v", errs)
	}
	if strings.Contains(joined, "SYNTHETICKEYMATERIAL") {
		t.Errorf("refusal echoes the encryption key: %v", errs)
	}
}

// TestSingboxWSEarlyDataRoundTrip: a sing-box ws transport with Xray-style early data comes back as
// the "?ed=N" path the generator turns into max_early_data again.
func TestSingboxWSEarlyDataRoundTrip(t *testing.T) {
	cfg := `{"outbounds":[{"type":"vless","tag":"v","server":"203.0.113.120","server_port":443,"uuid":"` + rwUUID + `",
	  "tls":{"enabled":true,"server_name":"e.example.com"},
	  "transport":{"type":"ws","path":"/ed","headers":{"Host":"e.example.com"},"max_early_data":2048,"early_data_header_name":"Sec-WebSocket-Protocol"}},
	 {"type":"vless","tag":"w","server":"203.0.113.121","server_port":443,"uuid":"` + rwUUID + `",
	  "transport":{"type":"ws","path":"/other","max_early_data":2048,"early_data_header_name":"X-Custom"}}]}`
	eps, errs := ParseSingbox(cfg)
	if len(errs) != 0 || len(eps) != 2 {
		t.Fatalf("ParseSingbox: %d eps, errs %v", len(eps), errs)
	}
	if got := eps[0].Transport.Path; got != "/ed?ed=2048" {
		t.Errorf("early data path = %q, want /ed?ed=2048", got)
	}
	if got := eps[1].Transport.Path; got != "/other" {
		t.Errorf("a non-Xray early-data header must leave the path alone, got %q", got)
	}
}
