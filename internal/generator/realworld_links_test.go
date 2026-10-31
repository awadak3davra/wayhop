package generator

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/exporter"
	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// rwlKey is a synthetic 32-byte key (std base64) whose last bytes put '+' and '/' into it.
func rwlKey(b byte) string {
	return base64.StdEncoding.EncodeToString(append(bytes.Repeat([]byte{b}, 30), 0xfb, 0xff))
}

// realWorldInputs are client exports in today's shapes (v2rayN / NekoBox / Hiddify share links, the
// official Hysteria 2 URI, a mihomo proxy list, a sing-box outbound, an AmneziaWG 2.0 .conf). All
// keys, passwords and hosts are SYNTHETIC (RFC 5737 / RFC 3849 / example.com).
func realWorldInputs() map[string]string {
	const uuid = "a3482e88-686a-4a58-8126-99c9df64b7bf"
	pbk := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	priv, pub, psk := rwlKey(0x11), rwlKey(0x22), rwlKey(0x33)
	ss256 := rwlKey(0x44)
	ss128 := base64.StdEncoding.EncodeToString(append(bytes.Repeat([]byte{0x55}, 14), 0xfb, 0xff))
	ss128u := base64.StdEncoding.EncodeToString(append(bytes.Repeat([]byte{0x66}, 14), 0xfb, 0xff))
	qe, pe := url.QueryEscape, url.PathEscape
	vmess := func(m map[string]any) string {
		b, _ := json.Marshal(m)
		return "vmess://" + base64.StdEncoding.EncodeToString(b)
	}
	return map[string]string{
		"vless-reality-vision": "vless://" + uuid + "@203.0.113.10:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=" + pbk + "&sid=6ba85179e30d4fc2&spx=%2F&type=tcp&headerType=none#r",
		"vless-raw-reality":    "vless://" + uuid + "@203.0.113.11:443?security=reality&sni=www.example.com&pbk=" + pbk + "&type=raw&flow=xtls-rprx-vision#raw",
		"vless-ws-early-data":  "vless://" + uuid + "@203.0.113.12:443?encryption=none&security=tls&sni=ws.example.com&fp=chrome&alpn=" + qe("h2,http/1.1") + "&type=ws&host=ws.example.com&path=" + qe("/vless?ed=2560") + "#ws",
		"vless-grpc-reality":   "vless://" + uuid + "@203.0.113.13:443?encryption=none&security=reality&sni=www.example.com&fp=firefox&pbk=" + pbk + "&sid=ab&type=grpc&serviceName=grpc-svc&mode=gun#g",
		"vless-httpupgrade":    "vless://" + uuid + "@203.0.113.14:80?encryption=none&security=none&type=httpupgrade&host=up.example.com&path=%2Fup#up",
		"vmess-ws-tls":         vmess(map[string]any{"v": "2", "ps": "vm", "add": "203.0.113.20", "port": "443", "id": uuid, "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": "vm.example.com", "path": "/vm", "tls": "tls", "sni": "vm.example.com", "fp": "chrome"}),
		"vmess-grpc":           vmess(map[string]any{"v": "2", "ps": "vg", "add": "203.0.113.21", "port": 8443, "id": uuid, "aid": 0, "net": "grpc", "type": "gun", "path": "vm-grpc", "tls": "tls", "sni": "g.example.com"}),
		"trojan-tls":           "trojan://" + pe("p@ss w0rd") + "@203.0.113.30:443?security=tls&sni=tj.example.com&fp=firefox&type=tcp&headerType=none#tj",
		"trojan-grpc":          "trojan://pw@203.0.113.31:443?security=tls&sni=tg.example.com&type=grpc&serviceName=tj-grpc#tg",
		"ss-2022-256":          "ss://2022-blake3-aes-256-gcm:" + qe(ss256) + "@203.0.113.40:8388#ss22",
		"ss-2022-eih":          "ss://2022-blake3-aes-128-gcm:" + qe(ss128) + "%3A" + qe(ss128u) + "@203.0.113.41:8388#eih",
		"ss-obfs-local":        "ss://" + base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw")) + "@203.0.113.42:8388/?plugin=" + qe("obfs-local;obfs=http;obfs-host=www.example.com") + "#obfs",
		"ss-v2ray-plugin":      "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pw")) + "@203.0.113.43:443?plugin=" + qe("v2ray-plugin;mode=websocket;tls;host=ss.example.com;path=/ss") + "#v2p",
		"hy2-official-ports":   "hysteria2://letmein@203.0.113.50:443,20000-30000/?insecure=1&obfs=salamander&obfs-password=gawrgura&sni=real.example.com#cool",
		"hy2-range-only":       "hy2://pw@hy.example.com:20000-50000?sni=hy.example.com#range",
		"hy2-v6-ports":         "hysteria2://pw@[2001:db8::50]:443,5000-6000/?sni=v6.example.com#v6",
		"hy2-mport":            "hysteria2://pw@203.0.113.51:443?sni=hq.example.com&insecure=0&mport=1000-2000#mport",
		"tuic-v5":              "tuic://" + uuid + ":tpass@203.0.113.60:443?sni=tuic.example.com&alpn=h3&congestion_control=bbr&allow_insecure=1#tuic",
		"tuic-quic-relay":      "tuic://" + uuid + ":tpass@203.0.113.61:443?congestion_control=cubic&udp_relay_mode=quic&alpn=h3&sni=tn.example.com#nb",
		"anytls":               "anytls://apw@203.0.113.70:443?sni=anytls.example.com&insecure=1#at",
		"wg-v2rayn-warp":       "wireguard://" + pe(priv) + "@203.0.113.80:2408?publickey=" + qe(pub) + "&reserved=1,2,3&address=" + qe("172.16.0.2/32,2001:db8::2/128") + "&mtu=1280#warp",
		"wg-hiddify":           "wg://203.0.113.81:51820?pk=" + qe(priv) + "&peer_pk=" + qe(pub) + "&psk=" + qe(psk) + "&local_address=10.8.0.2/32&mtu=1420#hid",
		"wg-awg-params":        "wg://" + pe(priv) + "@203.0.113.82:51820?publickey=" + qe(pub) + "&address=10.9.0.2/32&jc=4&jmin=40&jmax=70&s1=0&s2=0&h1=1&h2=2&h3=3&h4=4#awg",
		"awg2-conf-bom":        string(rune(0xFEFF)) + "[Interface]\r\nPrivateKey = " + priv + "\r\nAddress = 10.7.0.2/32\r\nJc = 4\r\nJmin = 10\r\nJmax = 50\r\nS1 = 15\r\nS2 = 18\r\nS3 = 20\r\nS4 = 22\r\nH1 = 1000-2000\r\nH2 = 3000-4000\r\nH3 = 5000-6000\r\nH4 = 7000-8000\r\n\r\n[Peer]\r\nPublicKey = " + pub + "\r\nEndpoint = 203.0.113.90:51820\r\nAllowedIPs = 0.0.0.0/0\r\n",
	}
}

// realWorldClash is a mihomo proxy list (httpupgrade spelled the mihomo way, hysteria2 with ports).
const realWorldClash = `proxies:
  - name: mihomo-httpupgrade
    type: vless
    server: 203.0.113.110
    port: 443
    uuid: a3482e88-686a-4a58-8126-99c9df64b7bf
    tls: true
    servername: up.example.com
    network: ws
    ws-opts:
      path: /up
      headers:
        Host: up.example.com
      v2ray-http-upgrade: true
  - name: mihomo-hy2
    type: hysteria2
    server: 203.0.113.111
    port: 443
    ports: 443,8000-9000
    password: pw
    sni: hy.example.com
    skip-cert-verify: true
`

// realWorldSingbox is a sing-box outbound with Xray-style ws early data.
const realWorldSingbox = `{"outbounds":[{"type":"vless","tag":"singbox-ws-ed","server":"203.0.113.120","server_port":443,
  "uuid":"a3482e88-686a-4a58-8126-99c9df64b7bf","tls":{"enabled":true,"server_name":"e.example.com"},
  "transport":{"type":"ws","path":"/ed","headers":{"Host":"e.example.com"},"max_early_data":2048,"early_data_header_name":"Sec-WebSocket-Protocol"}}]}`

func realWorldEndpoints(t *testing.T) []model.Endpoint {
	t.Helper()
	var eps []model.Endpoint
	for name, in := range realWorldInputs() {
		e, err := importer.Parse(in)
		if err != nil {
			t.Fatalf("%s: import: %v", name, err)
		}
		e.ID, e.Name, e.Enabled = name, name, true
		eps = append(eps, *e)
	}
	cl, errs := importer.ParseClash(realWorldClash)
	if len(errs) != 0 || len(cl) != 2 {
		t.Fatalf("clash import: %d endpoints, errs %v", len(cl), errs)
	}
	sb, errs := importer.ParseSingbox(realWorldSingbox)
	if len(errs) != 0 || len(sb) != 1 {
		t.Fatalf("sing-box import: %d endpoints, errs %v", len(sb), errs)
	}
	for _, e := range append(cl, sb...) {
		e.ID, e.Enabled = e.Name, true
		eps = append(eps, e)
	}
	return eps
}

// generatedByTag indexes a config's outbounds and endpoints by tag.
func generatedByTag(cfg map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, key := range []string{"outbounds", "endpoints"} {
		list, _ := cfg[key].([]map[string]any)
		for _, ob := range list {
			if tag, _ := ob["tag"].(string); tag != "" {
				out[tag] = ob
			}
		}
	}
	return out
}

// TestRealWorldLinksSingBoxCheck: every input imports, generates into ONE config (checked by a real
// sing-box when WR_SINGBOX is set, rendered for that binary's version), and survives the
// export -> re-import round trip: the re-imported endpoint generates exactly the same outbound.
func TestRealWorldLinksSingBoxCheck(t *testing.T) {
	eps := realWorldEndpoints(t)
	prof := &model.Profile{Endpoints: eps, Rules: []model.Rule{{ID: "def", Default: true, Outbound: model.OutboundDirect}}}
	res, err := Generate(prof, Options{MixedPort: 7890, CacheFile: filepath.Join(t.TempDir(), "c.db")})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	gen := generatedByTag(res.Config)

	// Spot checks on what the fixes carry through to the core.
	ports := func(tag string) []string { p, _ := gen[tag]["server_ports"].([]string); return p }
	for tag, want := range map[string][]string{
		"hy2-official-ports": {"443:443", "20000:30000"},
		"hy2-range-only":     {"20000:50000"},
		"hy2-v6-ports":       {"443:443", "5000:6000"},
		"mihomo-hy2":         {"443:443", "8000:9000"},
	} {
		if got := ports(tag); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: server_ports = %v, want %v", tag, got, want)
		}
	}
	if tr, _ := gen["mihomo-httpupgrade"]["transport"].(map[string]any); tr["type"] != "httpupgrade" {
		t.Errorf("mihomo v2ray-http-upgrade: transport = %v, want httpupgrade", tr)
	}
	if tr, _ := gen["singbox-ws-ed"]["transport"].(map[string]any); tr["max_early_data"] != 2048 || tr["path"] != "/ed" {
		t.Errorf("sing-box ws early data lost on import: %v", tr)
	}
	if gen["wg-hiddify"]["type"] != "wireguard" {
		t.Errorf("Hiddify wg:// did not become a WireGuard endpoint: %v", gen["wg-hiddify"])
	}
	awgPlugins := 0
	for _, p := range res.Plugins {
		if p.Endpoint.Engine == model.EngineAmneziaWG {
			awgPlugins++
		}
	}
	if awgPlugins != 2 {
		t.Errorf("want 2 AmneziaWG plugin endpoints (wg:// with AWG params, BOM .conf), got %d", awgPlugins)
	}

	// Export -> re-import -> generate must reproduce each outbound exactly.
	for _, e := range eps {
		r, ok := exporter.Export(e)
		if !ok {
			t.Errorf("%s: no export form", e.ID)
			continue
		}
		back, err := importer.Parse(r.Text)
		if err != nil {
			t.Errorf("%s: re-import of the export failed: %v\n%s", e.ID, err, r.Text)
			continue
		}
		if importer.ContentKey(*back) != importer.ContentKey(e) {
			t.Errorf("%s: export round trip changed the endpoint identity\n got %s\nwant %s", e.ID, importer.ContentKey(*back), importer.ContentKey(e))
		}
		back.ID, back.Name, back.Enabled = e.ID, e.Name, true
		again, err := Generate(&model.Profile{Endpoints: []model.Endpoint{*back}}, Options{MixedPort: 7890})
		if err != nil {
			t.Errorf("%s: generate after round trip: %v", e.ID, err)
			continue
		}
		if g, w := generatedByTag(again.Config)[e.ID], gen[e.ID]; !reflect.DeepEqual(g, w) {
			gj, _ := json.Marshal(g)
			wj, _ := json.Marshal(w)
			t.Errorf("%s: round trip changed the generated outbound\n got %s\nwant %s", e.ID, gj, wj)
		}
	}

	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — ran import+generate+export only (set it for a real sing-box check)")
	}
	ver := singboxVersionOf(t, bin)
	checked, err := Generate(prof, Options{MixedPort: 7890, CoreVersion: ver, CacheFile: filepath.Join(t.TempDir(), "c.db")})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.MarshalIndent(checked.Config, "", "  ")
	f := filepath.Join(t.TempDir(), "realworld.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", f).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check rejected the real-world config: %v\n%s", err, strings.TrimSpace(string(out)))
	}
}
