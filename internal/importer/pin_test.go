package importer

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// Invented hashes: two whole-certificate pins and a public-key pin.
var (
	pinA    = sha256.Sum256([]byte("wayhop invented certificate A"))
	pinB    = sha256.Sum256([]byte("wayhop invented certificate B"))
	pinK    = sha256.Sum256([]byte("wayhop invented public key"))
	pinAHex = hex.EncodeToString(pinA[:])
	pinBHex = hex.EncodeToString(pinB[:])
	pinKB64 = base64.StdEncoding.EncodeToString(pinK[:])
)

// opensslColons is a hash as `openssl x509 -fingerprint -sha256` prints it, which Xray and mihomo take.
func opensslColons(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	parts := make([]string, 0, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// QA-135: a current Xray panel's link to a self-signed server carries pcs= alone (Xray removed
// allowInsecure). It imported with certificate checks on and no pin, and failed with nothing said.
func TestLinkPinsFromShareLinks(t *testing.T) {
	esc := url.QueryEscape
	pcs := esc(opensslColons(pinA[:]) + "," + pinBHex)
	both := []string{pinAHex, pinBHex}
	const uuid = "00000000-0000-4000-8000-000000000035"
	for _, c := range []struct {
		name, link string
		pins       []string
		vcn        string
	}{
		{"vless, pcs and vcn (v2rayN)", "vless://" + uuid + "@192.0.2.35:443?security=tls&sni=cdn.example.com&pcs=" + pcs + "&vcn=real.example.com#v", both, "real.example.com"},
		{"vless, pcs alone (Xray panel, self-signed)", "vless://" + uuid + "@192.0.2.35:443?security=tls&sni=example.com&pcs=" + pinAHex + "#v", []string{pinAHex}, ""},
		{"trojan", "trojan://pw@192.0.2.36:443?sni=example.com&pcs=" + pcs + "#t", both, ""},
		{"anytls", "anytls://pw@192.0.2.37:443?sni=example.com&pcs=" + pinAHex + "&vcn=a.example.com,b.example.com#a", []string{pinAHex}, "a.example.com,b.example.com"},
		{"tuic (v2rayN reads them)", "tuic://" + uuid + ":pw@192.0.2.38:443?sni=example.com&pcs=" + pinAHex + "#u", []string{pinAHex}, ""},
		{"hysteria2 pinSHA256 (Hysteria's own)", "hysteria2://pw@192.0.2.39:443/?sni=example.com&insecure=1&pinSHA256=" + opensslColons(pinA[:]) + "#h", []string{pinAHex}, ""},
		{"hysteria2 pinSHA256 with dashes", "hy2://pw@192.0.2.39:443/?pinSHA256=" + strings.ReplaceAll(opensslColons(pinA[:]), ":", "-") + "#h", []string{pinAHex}, ""},
		{"hysteria2 pinSHA256 and pcs (v2rayN)", "hysteria2://pw@192.0.2.39:443/?pinSHA256=" + pinAHex + "&pcs=" + pcs + "#h", both, ""},
		{"hysteria2 realm", "hysteria2+realm://tok@example.net/r1?auth=pw&pinSHA256=" + pinAHex + "#r", []string{pinAHex}, ""},
		// A Reality link's pins are kept to be exported again; the generator never renders them.
		{"reality keeps them", "vless://" + uuid + "@192.0.2.35:443?security=reality&sni=example.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&pcs=" + pinAHex + "#r", []string{pinAHex}, ""},
		// No TLS: nothing to pin, and nothing to check a name against.
		{"no TLS ignores them", "vless://" + uuid + "@192.0.2.35:80?pcs=" + pinAHex + "&vcn=real.example.com#n", nil, ""},
		{"empty pcs", "trojan://pw@192.0.2.36:443?sni=example.com&pcs=&vcn=#t", nil, ""},
	} {
		e, err := Parse(c.link)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var got []string
		if e.TLS != nil {
			got = e.TLS.PinCertSHA256
		}
		if !reflect.DeepEqual(got, c.pins) {
			t.Errorf("%s: pins = %q, want %q", c.name, got, c.pins)
		}
		if v, _ := e.Params[model.ParamVerifyCertName].(string); v != c.vcn {
			t.Errorf("%s: vcn = %q, want %q", c.name, v, c.vcn)
		}
		if e.Params[model.ParamLegacyPin] != nil {
			t.Errorf("%s: the legacy parameter is no longer written: %v", c.name, e.Params)
		}
		// vcn never becomes the SNI: that would send the real name in the clear.
		for _, n := range strings.Split(c.vcn, ",") {
			if n != "" && e.TLS.SNI == n {
				t.Errorf("%s: SNI = %q", c.name, e.TLS.SNI)
			}
		}
		if err := (&model.Profile{Endpoints: []model.Endpoint{*e}}).Validate(); err != nil {
			t.Errorf("%s: the import fails Validate: %v", c.name, err)
		}
	}
}

// A pin that is not a SHA-256 hash refuses the link: Xray and mihomo refuse such a config and
// Hysteria matches nothing with it, and importing without it would trust what the link ruled out.
func TestLinkPinsRefuseMalformed(t *testing.T) {
	for name, link := range map[string]string{
		"pcs too short":         "vless://00000000-0000-4000-8000-000000000035@192.0.2.35:443?security=tls&pcs=" + pinAHex[:40] + "#v",
		"pcs, one bad of two":   "trojan://pw@192.0.2.36:443?pcs=" + pinAHex + ",xyz#t",
		"hysteria placeholder":  "hysteria2://pw@192.0.2.39:443/?insecure=1&pinSHA256=deadbeef#h",
		"tuic, sha1 thumbprint": "tuic://00000000-0000-4000-8000-000000000035:pw@192.0.2.38:443?pcs=" + opensslColons(pinA[:20]) + "#u",
	} {
		_, err := Parse(link)
		if err == nil || !strings.Contains(err.Error(), "not a SHA-256") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestVMessPins(t *testing.T) {
	m := map[string]any{"v": "2", "ps": "vm", "add": "192.0.2.40", "port": "443", "id": "00000000-0000-4000-8000-000000000035",
		"aid": "0", "net": "ws", "path": "/w", "host": "cdn.example.com", "tls": "tls", "sni": "cdn.example.com",
		"pcs": opensslColons(pinA[:]) + "," + pinBHex, "vcn": "real.example.com"}
	b, _ := json.Marshal(m)
	e, err := Parse("vmess://" + base64.StdEncoding.EncodeToString(b))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(e.TLS.PinCertSHA256, []string{pinAHex, pinBHex}) || e.Params[model.ParamVerifyCertName] != "real.example.com" ||
		e.TLS.SNI != "cdn.example.com" {
		t.Errorf("vmess: tls %+v, params %v", e.TLS, e.Params)
	}
	m["pcs"] = "nothex"
	b, _ = json.Marshal(m)
	if _, err := Parse("vmess://" + base64.StdEncoding.EncodeToString(b)); err == nil || !strings.Contains(err.Error(), "pcs") {
		t.Errorf("vmess malformed pcs: %v", err)
	}
	m["tls"], m["pcs"] = "", pinAHex // no TLS, nothing to pin
	b, _ = json.Marshal(m)
	if e, err := Parse("vmess://" + base64.StdEncoding.EncodeToString(b)); err != nil || e.TLS != nil {
		t.Errorf("vmess without TLS: %+v %v", e, err)
	}
}

// mihomo's `fingerprint` is a certificate pin (hex, ':' allowed, matched against any certificate in
// the chain); client-fingerprint is uTLS. An old config's browser name in `fingerprint` still reads
// as the uTLS fingerprint it meant, and is no pin.
func TestClashFingerprintIsAPin(t *testing.T) {
	yaml := `proxies:
  - {name: vless-pin, type: vless, server: 192.0.2.41, port: 443, uuid: 00000000-0000-4000-8000-000000000035, tls: true, servername: example.com, fingerprint: "` + opensslColons(pinA[:]) + `", client-fingerprint: chrome}
  - {name: trojan-pin, type: trojan, server: 192.0.2.42, port: 443, password: pw, sni: example.com, fingerprint: ` + pinAHex + `}
  - name: hy2-pin
    type: hysteria2
    server: 192.0.2.43
    port: 443
    password: pw
    sni: example.com
    skip-cert-verify: true
    fingerprint: ` + pinBHex + `
  - {name: vmess-old-utls, type: vmess, server: 192.0.2.44, port: 443, uuid: 00000000-0000-4000-8000-000000000035, cipher: auto, tls: true, fingerprint: firefox}
  - {name: anytls-bad, type: anytls, server: 192.0.2.45, port: 443, password: pw, fingerprint: notahash}
  - {name: ss-no-tls, type: ss, server: 192.0.2.46, port: 8388, cipher: aes-128-gcm, password: pw, fingerprint: ` + pinAHex + `}
`
	eps, errs := ParseClash(yaml)
	if len(errs) != 1 || !strings.Contains(errs[0], "anytls-bad") || !strings.Contains(errs[0], "not a SHA-256") {
		t.Errorf("errs = %v", errs)
	}
	got := map[string]*model.TLS{}
	for i := range eps {
		got[eps[i].Name] = eps[i].TLS
	}
	for name, want := range map[string]struct {
		pins []string
		utls string
	}{
		"vless-pin":      {[]string{pinAHex}, "chrome"},
		"trojan-pin":     {[]string{pinAHex}, ""},
		"hy2-pin":        {[]string{pinBHex}, ""},
		"vmess-old-utls": {nil, "firefox"},
	} {
		tl := got[name]
		if tl == nil || !reflect.DeepEqual(tl.PinCertSHA256, want.pins) || tl.Fingerprint != want.utls {
			t.Errorf("%s: tls = %+v", name, tl)
		}
	}
	if tl := got["ss-no-tls"]; tl != nil {
		t.Errorf("shadowsocks has no TLS to pin: %+v", tl)
	}
}

func TestSingboxConfigPins(t *testing.T) {
	cfg := `{"outbounds":[
  {"type":"trojan","tag":"list","server":"192.0.2.47","server_port":443,"password":"pw",
   "tls":{"enabled":true,"server_name":"example.com","certificate_sha256":["` + base64.StdEncoding.EncodeToString(pinA[:]) + `"],"certificate_public_key_sha256":["` + pinKB64 + `"]}},
  {"type":"hysteria2","tag":"single","server":"192.0.2.48","server_port":443,"password":"pw",
   "tls":{"enabled":true,"server_name":"example.com","insecure":true,"certificate_public_key_sha256":"` + pinKB64 + `"}},
  {"type":"vless","tag":"bad","server":"192.0.2.49","server_port":443,"uuid":"00000000-0000-4000-8000-000000000035",
   "tls":{"enabled":true,"server_name":"example.com","certificate_sha256":["AAAA"]}}
]}`
	eps, errs := ParseSingbox(cfg)
	if len(errs) != 1 || !strings.Contains(errs[0], "certificate_sha256") {
		t.Errorf("errs = %v", errs)
	}
	got := map[string]*model.TLS{}
	for i := range eps {
		got[eps[i].Name] = eps[i].TLS
	}
	if tl := got["list"]; tl == nil || !reflect.DeepEqual(tl.PinCertSHA256, []string{pinAHex}) || !reflect.DeepEqual(tl.PinPubKeySHA256, []string{pinKB64}) {
		t.Errorf("list: %+v", tl)
	}
	if tl := got["single"]; tl == nil || tl.PinCertSHA256 != nil || !reflect.DeepEqual(tl.PinPubKeySHA256, []string{pinKB64}) || !tl.Insecure {
		t.Errorf("single: %+v", tl)
	}
}

// Where a pin came from decides what the Apply review says about it: pcs= and mihomo's fingerprint
// may name a CA in the chain, Hysteria's pinSHA256 is checked beside the chain with checks on, and a
// sing-box config's pins mean what sing-box does with them.
func TestPinProvenance(t *testing.T) {
	link := func(l string) *model.TLS {
		e, err := Parse(l)
		if err != nil {
			t.Fatalf("%s: %v", l, err)
		}
		return e.TLS
	}
	for name, c := range map[string]struct {
		tls          *model.TLS
		ca, besideCh bool
	}{
		"hysteria2 pinSHA256": {link("hysteria2://pw@192.0.2.39:443/?pinSHA256=" + pinAHex + "#h"), false, true},
		"hysteria2 pcs":       {link("hysteria2://pw@192.0.2.39:443/?pcs=" + pinAHex + "#h"), true, false},
		"hysteria2 both":      {link("hysteria2://pw@192.0.2.39:443/?pinSHA256=" + pinAHex + "&pcs=" + pinBHex + "#h"), true, true},
		"vless pcs":           {link("vless://00000000-0000-4000-8000-000000000035@192.0.2.35:443?security=tls&pcs=" + pinAHex + "#v"), true, false},
		"trojan without pins": {link("trojan://pw@192.0.2.36:443?sni=example.com#t"), false, false},
	} {
		if c.tls.PinCertMayBeCA != c.ca || c.tls.PinCertBesideChain != c.besideCh {
			t.Errorf("%s: may-be-CA %v, beside-chain %v", name, c.tls.PinCertMayBeCA, c.tls.PinCertBesideChain)
		}
	}
	eps, _ := ParseClash("proxies:\n  - {name: t, type: trojan, server: 192.0.2.42, port: 443, password: pw, fingerprint: " + pinAHex + "}\n")
	if len(eps) != 1 || !eps[0].TLS.PinCertMayBeCA || eps[0].TLS.PinCertBesideChain {
		t.Errorf("clash fingerprint: %+v", eps)
	}
	sb, _ := ParseSingbox(`{"outbounds":[{"type":"trojan","tag":"s","server":"192.0.2.47","server_port":443,"password":"pw",
   "tls":{"enabled":true,"server_name":"example.com","certificate_sha256":"` + base64.StdEncoding.EncodeToString(pinA[:]) + `"}}]}`)
	if len(sb) != 1 || sb[0].TLS.PinCertMayBeCA || sb[0].TLS.PinCertBesideChain || len(sb[0].TLS.PinCertSHA256) != 1 {
		t.Errorf("sing-box pins: %+v", sb)
	}
}
