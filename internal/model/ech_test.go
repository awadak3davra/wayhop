package model

import (
	"encoding/base64"
	"strings"
	"testing"
)

// testECHConfig is an ECHConfigList `sing-box generate ech-keypair example.com` printed (1.13.21):
// version 0xfe0d, X25519, three cipher suites, public name example.com. It holds '+' and '/', so
// the alphabet and the escaping of share links are exercised too.
const testECHConfig = "AEb+DQBCAAAgACDv1FlTLOHACGPvieDrkqLa8zJ86loXc/u6LLmehtFpUQAMAAEAAQABAAIAAQADAAtleGFtcGxlLmNvbQAA"

const testECHPEM = "-----BEGIN ECH CONFIGS-----\nAEb+DQBCAAAgACDv1FlTLOHACGPvieDrkqLa8zJ86loXc/u6LLmehtFpUQAMAAEA\nAQABAAIAAQADAAtleGFtcGxlLmNvbQAA\n-----END ECH CONFIGS-----\n"

func TestParseECHConfigListAcceptsEveryCarriedForm(t *testing.T) {
	want, _ := base64.StdEncoding.DecodeString(testECHConfig)
	urlSafe := strings.NewReplacer("+", "-", "/", "_").Replace(testECHConfig)
	for name, in := range map[string]string{
		"std base64":            testECHConfig,
		"url-safe base64":       urlSafe,
		"PEM block":             testECHPEM,
		"PEM with CRLF":         strings.ReplaceAll(testECHPEM, "\n", "\r\n"),
		"wrapped base64":        testECHConfig[:40] + "\n" + testECHConfig[40:],
		"'+' decoded as space":  strings.ReplaceAll(testECHConfig, "+", " "),
		"surrounding blanks":    "  " + testECHConfig + "\n",
		"padded std (sing-box)": base64.StdEncoding.EncodeToString(want),
	} {
		got, err := ParseECHConfigList(in)
		if err != nil || string(got) != string(want) {
			t.Errorf("%s: got %x, %v", name, got, err)
		}
		if c := CanonicalECHConfig(in); c != testECHConfig {
			t.Errorf("%s: canonical = %q", name, c)
		}
	}
}

func TestParseECHConfigListRefusesWhatFailsEveryHandshake(t *testing.T) {
	raw, _ := base64.StdEncoding.DecodeString(testECHConfig)
	enc := base64.StdEncoding.EncodeToString
	otherVersion := append([]byte{}, raw...)
	otherVersion[2], otherVersion[3] = 0xfe, 0x0a // only a pre-standard draft entry
	longer := append(append([]byte{}, raw...), 0)
	cut := raw[:len(raw)-1]
	cut = append([]byte{byte((len(cut) - 2) >> 8), byte(len(cut) - 2)}, cut[2:]...) // list length fixed, entry cut
	for name, in := range map[string]string{
		"empty":                      "",
		"not base64":                 "not*base64!",
		"garbage sing-box passes":    "AAAA",
		"list length mismatch":       enc(longer),
		"entry cut short":            enc(cut),
		"no 0xfe0d entry":            enc(otherVersion),
		"PEM of another type":        strings.Replace(testECHPEM, "ECH CONFIGS", "CERTIFICATE", 2),
		"two PEM blocks":             testECHPEM + testECHPEM,
		"PEM header only":            "-----BEGIN ECH CONFIGS-----",
		"list length only":           enc([]byte{0, 0}),
		"one byte":                   enc([]byte{0}),
		"x25519 key, no public name": enc([]byte{0, 16, 0xfe, 0x0d, 0, 12, 1, 0, 0x20, 0, 1, 7, 0, 4, 0, 1, 0, 1}),
	} {
		if _, err := ParseECHConfigList(in); err == nil {
			t.Errorf("%s: accepted %q", name, in)
		}
	}
	if c := CanonicalECHConfig(" AAAA "); c != "AAAA" {
		t.Errorf("an unparseable config is kept as given, trimmed: %q", c)
	}
}

func TestECHParamProblem(t *testing.T) {
	ep := func(p Protocol, server string, tls *TLS) *Endpoint {
		return &Endpoint{ID: "e", Engine: EngineSingBox, Protocol: p, Server: server, Port: 443, Enabled: true,
			Params: map[string]any{"uuid": "00000000-0000-4000-8000-000000000001", "password": "x"}, TLS: tls}
	}
	tlsWith := func(typ, sni string, e *ECH) *TLS {
		return &TLS{Enabled: true, Type: typ, SNI: sni, PublicKey: "k", ECH: e}
	}
	for _, c := range []struct {
		name string
		e    *Endpoint
		want string // substring; "" = no problem
	}{
		{"no ECH", ep(ProtoVLESS, "192.0.2.1", tlsWith("tls", "example.com", nil)), ""},
		{"static config", ep(ProtoVLESS, "192.0.2.1", tlsWith("tls", "example.com", &ECH{Enabled: true, Config: testECHConfig})), ""},
		{"static PEM", ep(ProtoTrojan, "192.0.2.1", tlsWith("tls", "", &ECH{Enabled: true, Config: testECHPEM})), ""},
		{"static over QUIC", ep(ProtoHysteria2, "192.0.2.1", tlsWith("tls", "example.com", &ECH{Enabled: true, Config: testECHConfig})), ""},
		{"DNS by SNI", ep(ProtoVLESS, "192.0.2.1", tlsWith("tls", "example.com", &ECH{Enabled: true})), ""},
		{"DNS by server name", ep(ProtoAnyTLS, "example.net", tlsWith("tls", "", &ECH{Enabled: true})), ""},
		{"DNS by query name", ep(ProtoVMess, "192.0.2.1", tlsWith("tls", "192.0.2.1", &ECH{Enabled: true, QueryServerName: "example.net"})), ""},
		{"switched off", ep(ProtoVLESS, "192.0.2.1", tlsWith("tls", "example.com", &ECH{Config: "AAAA"})), ""},
		{"TLS off", ep(ProtoVLESS, "192.0.2.1", &TLS{ECH: &ECH{Enabled: true, Config: "AAAA"}}), ""},
		{"Reality keeps a link's config off", ep(ProtoVLESS, "192.0.2.1", tlsWith("reality", "example.com", &ECH{Config: testECHConfig})), ""},
		{"Reality with ECH on", ep(ProtoVLESS, "192.0.2.1", tlsWith("reality", "example.com", &ECH{Enabled: true, Config: testECHConfig})), "Reality"},
		{"garbage config", ep(ProtoVLESS, "192.0.2.1", tlsWith("tls", "example.com", &ECH{Enabled: true, Config: "AAAA"})), "invalid ECH config"},
		{"DNS over hysteria2", ep(ProtoHysteria2, "192.0.2.1", tlsWith("tls", "example.com", &ECH{Enabled: true})), "QUIC"},
		{"DNS over tuic", ep(ProtoTUIC, "192.0.2.1", tlsWith("tls", "example.com", &ECH{Enabled: true, QueryServerName: "example.net"})), "QUIC"},
		{"DNS with an IP SNI", ep(ProtoVLESS, "192.0.2.1", tlsWith("tls", "192.0.2.1", &ECH{Enabled: true})), "SNI"},
		{"DNS with no name at all", ep(ProtoTrojan, "192.0.2.1", tlsWith("tls", "", &ECH{Enabled: true})), "SNI"},
		{"DNS with an IP query name", ep(ProtoVLESS, "192.0.2.1", tlsWith("tls", "example.com", &ECH{Enabled: true, QueryServerName: "192.0.2.9"})), "query server name"},
		// A name with letters outside ASCII has a name to look up, in the punycode form DNS asks for.
		{"DNS with a non-ASCII SNI", ep(ProtoVLESS, "192.0.2.1", tlsWith("tls", "bücher.example", &ECH{Enabled: true})), "punycode"},
		{"DNS with a non-ASCII server", ep(ProtoTrojan, "bücher.example", tlsWith("tls", "", &ECH{Enabled: true})), "punycode"},
		{"DNS with a non-ASCII query name", ep(ProtoVLESS, "192.0.2.1", tlsWith("tls", "example.com", &ECH{Enabled: true, QueryServerName: "bücher.example"})), "punycode"},
		{"DNS with the punycode SNI", ep(ProtoVLESS, "192.0.2.1", tlsWith("tls", "xn--bcher-kva.example", &ECH{Enabled: true})), ""},
	} {
		got := EndpointParamProblem(c.e)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: EndpointParamProblem = %q, want %q", c.name, got, c.want)
		}
	}
	// Validate (Generate's gate) refuses what the panel would: the shared config never sees it.
	p := &Profile{Endpoints: []Endpoint{*ep(ProtoVLESS, "192.0.2.1", tlsWith("tls", "example.com", &ECH{Enabled: true, Config: "AAAA"}))}}
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "invalid ECH config") {
		t.Errorf("Validate = %v", err)
	}
}

func TestIsDNSName(t *testing.T) {
	for s, want := range map[string]bool{
		"example.com": true, "a.example.net.": true, "_ech.example.com": true, "x-1.example.com": true,
		"": false, "192.0.2.1": false, "2001:db8::1": false, "[2001:db8::1]": false, "exa mple.com": false,
		"a..b": false, strings.Repeat("a", 64) + ".com": false, "пример.рф": false,
	} {
		if IsDNSName(s) != want {
			t.Errorf("IsDNSName(%q) = %v", s, !want)
		}
	}
}
