package exporter

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// QA-136: a link's Xray finalmask is exported as it came, on every format that carries it, and reads
// back the same; a VMess link carries it as 3x-ui writes it, a string in the JSON.
func TestFinalMask_RoundTrip(t *testing.T) {
	const fm = `{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"100-200"}}],"udp":[{"type":"noise"}]}`
	const uuid = "00000000-0000-4000-8000-000000000136"
	esc := url.QueryEscape(fm)
	vm, _ := json.Marshal(map[string]any{"v": "2", "ps": "vm", "add": "192.0.2.136", "port": "443", "id": uuid,
		"aid": "0", "net": "ws", "path": "/w", "tls": "tls", "sni": "example.com", "fm": fm})
	for _, link := range []string{
		"vless://" + uuid + "@192.0.2.136:443?security=tls&sni=example.com&type=ws&path=%2Fw&fm=" + esc + "#v",
		"trojan://invented-pw@192.0.2.136:443?sni=example.com&fm=" + esc + "#t",
		"anytls://invented-pw@192.0.2.136:443?sni=example.com&fm=" + esc + "#a",
		"tuic://" + uuid + ":invented-pw@192.0.2.136:443?sni=example.com&fm=" + esc + "#u",
		"hysteria2://invented-pw@192.0.2.136:443/?sni=example.com&obfs=salamander&obfs-password=invented-obfs&fm=" + esc + "#h",
		"hysteria2+realm://tok@example.net/r1?auth=invented-pw&fm=" + esc + "#r",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:invented-pw")) + "@192.0.2.136:8388?fm=" + esc + "#s",
		"vmess://" + base64.StdEncoding.EncodeToString(vm),
	} {
		e, err := importer.Parse(link)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		out, ok := ShareLink(*e)
		if !ok {
			t.Fatalf("%s: not exported", link)
		}
		if strings.HasPrefix(out, "vmess://") {
			b, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(out, "vmess://"))
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil || m["fm"] != fm {
				t.Errorf("vmess export fm = %v (%v)", m["fm"], err)
			}
		} else if !strings.Contains(out, "fm="+esc) {
			t.Errorf("%s: export %s lacks fm", e.Protocol, out)
		}
		back, err := importer.Parse(out)
		if err != nil || back.Params[model.ParamFinalMask] != fm {
			t.Errorf("%s: re-import %v, fm %v", out, err, back)
		}
	}
	// Without fm, no fm= and no "fm" key: such a link is exported as before.
	e := model.Endpoint{Protocol: model.ProtoVMess, Server: "192.0.2.136", Port: 443,
		Params: map[string]any{"uuid": uuid}, TLS: &model.TLS{Enabled: true, Type: "tls"}}
	out, _ := ShareLink(e)
	if b, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(out, "vmess://")); strings.Contains(string(b), `"fm"`) {
		t.Errorf("vmess without fm exports %s", b)
	}
	e.Protocol, e.Params = model.ProtoTrojan, map[string]any{"password": "invented-pw"}
	if out, _ := ShareLink(e); linkQuery(t, out).Has("fm") {
		t.Errorf("trojan without fm exports %s", out)
	}
}

// fm is escaped as v2rayN escapes it (Uri.EscapeDataString): a space as %20, never '+', which v2rayN
// and the importer read as '+'. A '+', ';' and space in it come back as they were.
func TestFinalMask_EscapedAsV2rayNReadsIt(t *testing.T) {
	const fm = `{"udp":[{"type":"noise","settings":{"noise":[{"type":"str","packet":"a+b c;d%41"}]}}]}`
	for _, e := range []model.Endpoint{
		{Protocol: model.ProtoTrojan, Server: "192.0.2.136", Port: 443, Params: map[string]any{"password": "invented-pw", model.ParamFinalMask: fm},
			TLS: &model.TLS{Enabled: true, Type: "tls", SNI: "example.com"}},
		{Protocol: model.ProtoShadowsocks, Server: "192.0.2.136", Port: 8388, Params: map[string]any{"method": "aes-256-gcm", "password": "invented-pw", model.ParamFinalMask: fm}},
		{Protocol: model.ProtoHysteria2, Server: "192.0.2.136", Port: 443, Params: map[string]any{"password": "invented-pw", model.ParamFinalMask: fm},
			TLS: &model.TLS{Enabled: true, Type: "tls", SNI: "example.com"}},
	} {
		out, ok := ShareLink(e)
		if !ok {
			t.Fatalf("%s: not exported", e.Protocol)
		}
		_, q, _ := strings.Cut(out, "fm=")
		q, _, _ = strings.Cut(q, "#")
		if strings.ContainsAny(q, "+; ") || !strings.Contains(q, "%20") || !strings.Contains(q, "%2B") {
			t.Errorf("%s: fm written %q", e.Protocol, q)
		}
		back, err := importer.Parse(out)
		if err != nil || back.Params[model.ParamFinalMask] != fm {
			t.Errorf("%s: %s re-imports %v, fm %v", e.Protocol, out, err, back)
		}
	}
}

// A VMess connection with certificate checks off is exported with v2rayN's "insecure": "1"
// (VmessQRCode, the only key v2rayN reads) beside allowInsecure, and reads back off; with checks on,
// neither key is written.
func TestVMess_InsecureRoundTrip(t *testing.T) {
	e := model.Endpoint{Protocol: model.ProtoVMess, Server: "192.0.2.136", Port: 443, Name: "vm",
		Params: map[string]any{"uuid": "00000000-0000-4000-8000-000000000137", "security": "auto"},
		TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "example.com", Insecure: true}}
	decode := func(link string) map[string]any {
		b, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return m
	}
	out, _ := ShareLink(e)
	if m := decode(out); m["insecure"] != "1" || m["allowInsecure"] != "true" {
		t.Errorf("insecure export = %v", m)
	}
	// What v2rayN writes and reads, alone.
	m := decode(out)
	delete(m, "allowInsecure")
	b, _ := json.Marshal(m)
	back, err := importer.Parse("vmess://" + base64.StdEncoding.EncodeToString(b))
	if err != nil || back.TLS == nil || !back.TLS.Insecure {
		t.Errorf("v2rayN's insecure alone: %v %+v", err, back)
	}
	e.TLS.Insecure = false
	out, _ = ShareLink(e)
	if m := decode(out); m["insecure"] != nil || m["allowInsecure"] != nil {
		t.Errorf("checks on exports %v", m)
	}
}
