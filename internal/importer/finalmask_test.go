package importer

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"wayhop/internal/model"
)

const (
	fmUUID     = "00000000-0000-4000-8000-000000000136"
	fmFragment = `{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"100-200","delay":"10-20"}}]}`
	fmNoiseHop = `{"udp":[{"type":"noise","settings":{"noise":[{"type":"rand","packet":"10-20"}]}},{"type":"udphop","settings":{"remotePorts":"20000-30000"}}]}`
	fmFilter   = `{"tcp":[{"type":"filter","settings":{"allowedSourceIPs":["192.0.2.0/24"]}}]}`
	fmSalam    = `{"udp":[{"type":"salamander","settings":{"password":"invented-obfs-secret"}}]}`
)

// fmLinks is one share link per format that carries fm= (v2rayN: VLESS, Trojan, AnyTLS, TUIC,
// Hysteria2 and its realm form; 3x-ui: VLESS, Trojan, Shadowsocks and VMess's JSON), with fm as given.
func fmLinks(fm string) map[string]string {
	esc := url.QueryEscape(fm)
	vm, _ := json.Marshal(map[string]any{"v": "2", "ps": "vm", "add": "192.0.2.136", "port": "443", "id": fmUUID,
		"aid": "0", "net": "tcp", "tls": "tls", "sni": "example.com", "fm": fm})
	return map[string]string{
		"vless":     "vless://" + fmUUID + "@192.0.2.136:443?security=tls&sni=example.com&type=tcp&fm=" + esc + "#v",
		"trojan":    "trojan://invented-pw@192.0.2.136:443?sni=example.com&fm=" + esc + "#t",
		"anytls":    "anytls://invented-pw@192.0.2.136:443?sni=example.com&fm=" + esc + "#a",
		"tuic":      "tuic://" + fmUUID + ":invented-pw@192.0.2.136:443?sni=example.com&fm=" + esc + "#u",
		"hysteria2": "hysteria2://invented-pw@192.0.2.136:443/?sni=example.com&fm=" + esc + "#h",
		"realm":     "hysteria2+realm://tok@example.net/r1?auth=invented-pw&fm=" + esc + "#r",
		"ss": "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:invented-pw")) +
			"@192.0.2.136:8388?type=tcp&fm=" + esc + "#s",
		"vmess": "vmess://" + base64.StdEncoding.EncodeToString(vm),
	}
}

// QA-136: fm= used to be dropped without a word. Masks the client applies alone (or that do nothing
// on a client) import, and fm is kept exactly as the link held it, to be exported again.
func TestLinkFinalMask_KeptWhenTheServerDoesNotNeedIt(t *testing.T) {
	for _, fm := range []string{fmFragment, fmNoiseHop, fmFilter, `{"quicParams":{"congestion":"bbr"}}`} {
		for proto, link := range fmLinks(fm) {
			e, err := Parse(link)
			if err != nil {
				t.Errorf("%s with %s: %v", proto, fm, err)
				continue
			}
			if got, _ := e.Params[model.ParamFinalMask].(string); got != fm {
				t.Errorf("%s: params fm = %q, want %q", proto, got, fm)
			}
		}
	}
	// 3x-ui writes VMess's fm as a string; an object is read as the same finalmask.
	vm, _ := json.Marshal(map[string]any{"v": "2", "add": "192.0.2.136", "port": 443, "id": fmUUID, "tls": "tls",
		"fm": map[string]any{"tcp": []any{map[string]any{"type": "fragment"}}}})
	e, err := Parse("vmess://" + base64.StdEncoding.EncodeToString(vm))
	if err != nil || e.Params[model.ParamFinalMask] != `{"tcp":[{"type":"fragment"}]}` {
		t.Errorf("vmess fm object: %v, params %v", err, e)
	}
	// No fm: no parameter, so a link without it imports as before.
	for proto, link := range fmLinks("") {
		if e, err := Parse(strings.Replace(link, "&fm=", "&x=", 1)); err != nil {
			t.Errorf("%s without fm: %v", proto, err)
		} else if _, ok := e.Params[model.ParamFinalMask]; ok {
			t.Errorf("%s without fm carries %v", proto, e.Params)
		}
	}
}

// A mask the server undoes, and fm Xray itself would refuse, refuse the link, naming the mask or the
// fault and never a mask's settings.
func TestLinkFinalMask_RefusedWhenTheServerNeedsIt(t *testing.T) {
	for _, c := range []struct{ fm, want string }{
		{fmSalam, "the salamander mask"},
		{`{"tcp":[{"type":"fragment"}],"udp":[{"type":"xdns"},{"type":"mkcp-legacy","settings":{"header":"wechat"}}]}`, "the xdns, mkcp-legacy mask"},
		{`{"tcp":[{"type":"header-custom"}]}`, "header-custom"},
		{`{"tcp":[{"type":"sudoku","settings":{"password":"invented-obfs-secret"}}]}`, "sudoku"},
		{`{"tcp":[{"type":"xmc","settings":{"password":"invented-obfs-secret"}}]}`, "xmc"},
		{`{"udp":[{"type":"xicmp"}]}`, "xicmp"},
		{`{"udp":[{"type":"realm"}]}`, "realm"},
		{`{"tcp":[{"type":"fragment"`, "is not valid JSON"},
		{`{"udp":[{"type":"fragment","settings":{"password":"invented-obfs-secret"}}]}`, `unknown udp mask "fragment"`},
	} {
		for proto, link := range fmLinks(c.fm) {
			_, err := Parse(link)
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "fm= (Xray finalmask)") {
				t.Errorf("%s with %s: err = %v, want %q", proto, c.fm, err, c.want)
				continue
			}
			for _, secret := range []string{"invented-obfs-secret", "invented-pw", fmUUID} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("%s: the reason carries %q: %v", proto, secret, err)
				}
			}
		}
	}
}

// fm= is read as v2rayN reads it (Utils.ParseQueryString), not as url.Values does: a raw ';' or a bad
// escape in it, or the key in capitals, used to drop it without a word, and a raw '+' came back as a
// space. A mask the server undoes is refused however the link spells fm, and a kept fm is kept as
// written.
func TestLinkFinalMask_ReadAsV2rayNReadsIt(t *testing.T) {
	type spelled struct{ name, query, want string }
	esc := func(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "+", "%20") }
	sudoku := `{"tcp":[{"type":"sudoku","settings":{"password":"p;q"}}]}`
	salam := `{"udp":[{"type":"salamander","settings":{"password":"a%zzb"}}]}`
	noise := `{"udp":[{"type":"noise","settings":{"noise":[{"type":"str","packet":"a+b c;d"}]}}]}`
	for _, c := range []spelled{
		{"raw ';'", "fm=" + strings.ReplaceAll(esc(sudoku), "%3B", ";"), "sudoku"},
		{"bad escape", "fm=" + strings.ReplaceAll(esc(salam), "%25zz", "%zz"), "salamander"},
		{"key in capitals", "FM=" + esc(sudoku), "sudoku"},
		{"key mixed case, first pair kept", "Fm=" + esc(sudoku) + "&fm=" + esc(fmFragment), "sudoku"},
	} {
		for proto, link := range fmLinks("") {
			if proto == "vmess" {
				continue
			}
			link = strings.Replace(link, "fm=", c.query+"&x=", 1)
			if _, err := Parse(link); err == nil || !strings.Contains(err.Error(), "the "+c.want+" mask") {
				t.Errorf("%s, %s: err = %v, want the %s mask refused", c.name, proto, err, c.want)
			}
		}
	}
	// Kept exactly as written: a raw '+' and ';' and %20 for a space.
	raw := strings.ReplaceAll(strings.ReplaceAll(esc(noise), "%2B", "+"), "%3B", ";")
	for proto, link := range fmLinks("") {
		if proto == "vmess" {
			continue
		}
		e, err := Parse(strings.Replace(link, "fm=", "fm="+raw+"&x=", 1))
		if err != nil || e.Params[model.ParamFinalMask] != noise {
			t.Errorf("%s: %v, fm %q, want %q", proto, err, e.Params[model.ParamFinalMask], noise)
		}
	}
	if got := lenientUnescape("%41%zz%4+%2"); got != "A%zz%4+%2" {
		t.Errorf("lenientUnescape = %q", got)
	}
}

// Hysteria's own obfs=salamander is not Xray's finalmask: it imports as it always has.
func TestLinkFinalMask_Hysteria2ObfsUnchanged(t *testing.T) {
	e, err := Parse("hysteria2://invented-pw@192.0.2.136:443/?sni=example.com&obfs=salamander&obfs-password=invented-obfs#h")
	if err != nil {
		t.Fatal(err)
	}
	if e.Params["obfs"] != "salamander" || e.Params["obfs_password"] != "invented-obfs" {
		t.Errorf("params = %v", e.Params)
	}
	if _, ok := e.Params[model.ParamFinalMask]; ok {
		t.Errorf("obfs read as a finalmask: %v", e.Params)
	}
}

// v2rayN's VMess JSON says "insecure": "1" for certificate checks off (VmessQRCode), and nothing
// else; WayHop read only allowInsecure.
func TestParseVMess_InsecureKey(t *testing.T) {
	for _, c := range []struct {
		v    any
		want bool
	}{{"1", true}, {"0", false}, {"", false}, {1, true}, {true, true}, {nil, false}} {
		m := map[string]any{"v": "2", "add": "192.0.2.136", "port": "443", "id": fmUUID, "tls": "tls"}
		if c.v != nil {
			m["insecure"] = c.v
		}
		b, _ := json.Marshal(m)
		e, err := Parse("vmess://" + base64.StdEncoding.EncodeToString(b))
		if err != nil {
			t.Fatalf("%v: %v", c.v, err)
		}
		if e.TLS == nil || e.TLS.Insecure != c.want {
			t.Errorf("insecure %#v: tls %+v, want insecure %v", c.v, e.TLS, c.want)
		}
	}
}
