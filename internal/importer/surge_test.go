package importer

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// A Surge profile imports its [Proxy] section through the Clash mappers, plus Snell v6, which only
// Surge declares. The declarations are the Surge manual's own examples with documentation addresses.
func TestParseSurge_Profile(t *testing.T) {
	profile := strings.Join([]string{
		"[General]",
		"loglevel = notify",
		"",
		"[Proxy]",
		"# Snell, the reason this format is read",
		"Direct-Alias = direct",
		"Proxy-Snell = snell, 192.0.2.1, 8000, psk=abcdefghijkl, version=4, obfs=http, obfs-host=bing.com, reuse=true",
		"Proxy-Snell-v6 = snell, 192.0.2.2, 8001, psk=abcdefghijkl, version=6, mode=unshaped, udp-port=8002",
		"Proxy-SS = ss, 192.0.2.3, 8388, encrypt-method=chacha20-ietf-poly1305, password=abcd1234, obfs=tls, obfs-host=example.com",
		"Proxy-Trojan = trojan, trojan.example.com, 443, password=password1, ws=true, ws-path=/v2, ws-headers=Host:cdn.example.com|X-Token:abc, skip-cert-verify=true",
		`Proxy-Hysteria = hysteria2, 192.0.2.4, 443, password=pwd, download-bandwidth=100, port-hopping=1234;5000-6000, port-hopping-interval=40, gecko-password=gp, sni=hy.example.com`,
		`Proxy-TUIC-v5 = tuic-v5, 192.0.2.5, 443, uuid=0233d11c-15a4-47d3-ade3-48ffca0ce119, password=pwd, alpn="h3,h3-29"`,
		"Proxy-AnyTLS = anytls, 192.0.2.6, 443, password=pwd",
		"",
		"[Proxy Group]",
		"Group = select, Proxy-Snell, Proxy-SS",
	}, "\n")
	eps, errs := ParseSubscription(profile)
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	by := map[string]model.Endpoint{}
	for _, e := range eps {
		by[e.Name] = e
	}
	if len(by) != 7 {
		t.Fatalf("imported %d (%v), want the seven proxies and no alias or group", len(by), by)
	}
	s4 := by["Proxy-Snell"]
	if s4.Protocol != model.ProtoSnell || s4.Params["version"] != 4 || s4.Params["obfs_mode"] != "http" ||
		s4.Params["obfs_host"] != "bing.com" || s4.Params["reuse"] != true || s4.Params["network"] != nil {
		t.Errorf("snell v4 (UDP relayed by default) = %+v", s4)
	}
	s6 := by["Proxy-Snell-v6"]
	if s6.Params["version"] != 6 || s6.Params["mode"] != "unshaped" || s6.Params["network"] != "tcp" || s6.Port != 8001 {
		t.Errorf("snell v6 with its own udp-port (TCP only) = %+v", s6)
	}
	ss := by["Proxy-SS"]
	if ss.Protocol != model.ProtoShadowsocks || ss.Params["method"] == nil && ss.Params["cipher"] == nil {
		t.Errorf("ss = %+v", ss)
	}
	if !strings.Contains(paramString(ss), "obfs=tls") || !strings.Contains(paramString(ss), "obfs-host=example.com") {
		t.Errorf("ss lost its simple-obfs plugin: %+v", ss.Params)
	}
	tr := by["Proxy-Trojan"]
	if tr.Transport == nil || tr.Transport.Type != "ws" || tr.Transport.Path != "/v2" || tr.Transport.Host != "cdn.example.com" ||
		tr.TLS == nil || !tr.TLS.Insecure {
		t.Errorf("trojan ws = %+v / %+v / %+v", tr, tr.Transport, tr.TLS)
	}
	hy := by["Proxy-Hysteria"]
	if hy.Params["hop_ports"] != "1234,5000-6000" || hy.Params["hop_interval"] != "40s" || hy.Params["obfs"] != "gecko" ||
		hy.Params["obfs_password"] != "gp" || hy.Params["down_mbps"] != 100 || hy.TLS == nil || hy.TLS.SNI != "hy.example.com" {
		t.Errorf("hysteria2 = %+v / %+v", hy.Params, hy.TLS)
	}
	tu := by["Proxy-TUIC-v5"]
	if tu.Protocol != model.ProtoTUIC || tu.TLS == nil || strings.Join(tu.TLS.ALPN, ",") != "h3,h3-29" {
		t.Errorf("tuic-v5 (quoted alpn keeps both) = %+v / %+v", tu, tu.TLS)
	}
	if by["Proxy-AnyTLS"].Protocol != model.ProtoAnyTLS {
		t.Errorf("anytls = %+v", by["Proxy-AnyTLS"])
	}
}

// paramString flattens params for a substring check that does not depend on the plugin key names.
func paramString(e model.Endpoint) string {
	var b strings.Builder
	for k, v := range e.Params {
		b.WriteString(k + ":" + strings.TrimSpace(strings.ReplaceAll(toString(v), " ", "")) + ";")
	}
	return b.String()
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// What WayHop cannot carry is refused by name, line by line; the rest of the section still imports.
func TestParseSurge_Refusals(t *testing.T) {
	lines := strings.Join([]string{
		"ok = snell, 192.0.2.1, 1, psk=abcdefghijkl, version=4",
		"v1 = snell, 192.0.2.2, 2, psk=abcdefghijkl",
		"stls = snell, 192.0.2.3, 443, psk=pwd1, version=4, reuse=true, shadow-tls-password=pwd2",
		"pin = trojan, 192.0.2.4, 443, password=p, server-cert-fingerprint-sha256=" + strings.Repeat("ab", 31),
		"t4 = tuic, 192.0.2.5, 443, token=pwd",
		"v6obfs = snell, 192.0.2.6, 3, psk=abcdefghijkl, version=6, obfs=http",
		"both = hysteria2, 192.0.2.7, 443, password=p, salamander-password=a, gecko-password=b",
		"vm = vmess, 192.0.2.8, 8000, username=0233d11c-15a4-47d3-ade3-48ffca0ce119",
		"port = snell, 192.0.2.9, 70000, psk=abcdefghijkl, version=6",
	}, "\n")
	eps, errs := ParseSubscription(lines)
	if len(eps) != 1 || eps[0].Name != "ok" {
		t.Fatalf("imported %v, want only ok; errors %v", eps, errs)
	}
	joined := strings.Join(errs, "\n")
	for _, want := range []string{
		`"v1" (line 2)`, "version 1",
		"Shadow TLS", "server-cert-fingerprint-sha256 \"" + strings.Repeat("ab", 31) + "\" is not a SHA-256", "TUIC v4",
		"no obfuscation", "mutually exclusive", `type "vmess"`, "out of range",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("errors lack %q:\n%s", want, joined)
		}
	}
	for _, secret := range []string{"pwd1", "pwd2", "abcdefghijkl"} {
		if strings.Contains(joined, secret) {
			t.Errorf("an error carries the credential %q:\n%s", secret, joined)
		}
	}
}

// server-cert-fingerprint-sha256 is a whole-certificate pin (Surge manual, policies/tls.html: a SHA-256
// fingerprint, 64 hex digits, pinning the server certificate instead of the X.509 validation). It is
// read as the other formats' pins are, as the server's own certificate (no CA, no chain beside it),
// and means nothing without TLS.
func TestParseSurge_CertificatePin(t *testing.T) {
	pin := sha256.Sum256([]byte("wayhop invented surge certificate"))
	pinHex := hex.EncodeToString(pin[:])
	for _, line := range []string{
		"t = trojan, 192.0.2.4, 443, password=invented-pw, sni=example.com, server-cert-fingerprint-sha256=" + pinHex,
		"a = anytls, 192.0.2.4, 443, password=invented-pw, server-cert-fingerprint-sha256=" + strings.ToUpper(pinHex),
		"h = hysteria2, 192.0.2.4, 443, password=invented-pw, server-cert-fingerprint-sha256=" + opensslColons(pin[:]),
		"u = tuic-v5, 192.0.2.4, 443, uuid=00000000-0000-4000-8000-000000000004, password=invented-pw, server-cert-fingerprint-sha256=" + pinHex,
	} {
		e, err := Parse(line)
		if err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		if e.TLS == nil || !reflect.DeepEqual(e.TLS.PinCertSHA256, []string{pinHex}) || e.TLS.PinCertMayBeCA || e.TLS.PinCertBesideChain {
			t.Errorf("%s: tls %+v, want the pin as the server's own certificate", line, e.TLS)
		}
	}
	e, err := Parse("s = ss, 192.0.2.4, 8388, encrypt-method=aes-256-gcm, password=invented-pw, server-cert-fingerprint-sha256=" + pinHex)
	if err != nil || (e.TLS != nil && len(e.TLS.PinCertSHA256) > 0) {
		t.Errorf("ss (no TLS): %v %+v", err, e)
	}
	// A pin that is not a hash is refused on every line, one without TLS (where it is not kept) included.
	for _, line := range []string{
		"t = trojan, 192.0.2.4, 443, password=invented-pw, server-cert-fingerprint-sha256=deadbeef",
		"s = ss, 192.0.2.4, 8388, encrypt-method=aes-256-gcm, password=invented-pw, server-cert-fingerprint-sha256=zz",
		"n4 = snell, 192.0.2.4, 8000, psk=abcdefghijkl, version=4, server-cert-fingerprint-sha256=zz",
		"n6 = snell, 192.0.2.4, 8001, psk=abcdefghijkl, version=6, server-cert-fingerprint-sha256=zz",
	} {
		if _, err := Parse(line); err == nil || !strings.Contains(err.Error(), "server-cert-fingerprint-sha256") ||
			!strings.Contains(err.Error(), "not a SHA-256") {
			t.Errorf("%s: %v", line, err)
		}
	}
	// skip-cert-verify stays beside the pin, as on the other formats (gap 19): on a core older than
	// 1.15 the pin is left out and the Apply review says the connection accepts any certificate.
	e, err = Parse("t = trojan, 192.0.2.4, 443, password=invented-pw, skip-cert-verify=true, server-cert-fingerprint-sha256=" + pinHex)
	if err != nil || e.TLS == nil || !e.TLS.Insecure || !reflect.DeepEqual(e.TLS.PinCertSHA256, []string{pinHex}) {
		t.Errorf("skip-cert-verify with a pin: %v %+v", err, e)
	}
}

// Parse (Paste link) takes one Surge line and points a profile with several at Subscription; share
// links, base64 and INI-like lines that are not Surge proxies are not read as Surge.
func TestParse_SurgeLine(t *testing.T) {
	e, err := Parse("Proxy-Snell = snell, 192.0.2.1, 8000, psk=abcdefghijkl, version=5")
	if err != nil || e.Protocol != model.ProtoSnell || e.Params["version"] != 4 || e.ID == "" {
		t.Fatalf("one line: %+v, %v", e, err)
	}
	_, err = Parse("[Proxy]\na = snell, 192.0.2.1, 1, psk=abcdefghijkl, version=4\nb = snell, 192.0.2.2, 2, psk=abcdefghijkl, version=4")
	if err == nil || !strings.Contains(err.Error(), "Subscription") {
		t.Errorf("two proxies via Parse: %v", err)
	}
	for _, not := range []string{
		"loglevel = notify, verbose",
		"vless://11111111-1111-1111-1111-111111111111@192.0.2.1:443?security=reality&type=tcp#a = snell, x",
		"c3M6Ly9hZXMtMjU2LWdjbTpwQDE5Mi4wLjIuMTo4Mzg4==",
	} {
		if looksLikeSurge(not) {
			t.Errorf("%q read as Surge", not)
		}
	}
}
