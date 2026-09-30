package plugin

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"wayhop/internal/awg"
	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// Keys are made at run time from a repeated byte, so no key-shaped literal sits in the source.
func b64Key(b byte, enc *base64.Encoding) string {
	return enc.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

func hexKey(b byte) string { return strings.Repeat(fmt.Sprintf("%02x", b), 32) }

var testPeer = netip.MustParseAddrPort("192.0.2.1:51820")

// awg31Endpoint is a full 3.1 client: every generation's parameters, as the importer stores them.
func awg31Endpoint() model.Endpoint {
	return model.Endpoint{
		Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
		Server: "vpn.example.test", Port: 51820,
		Params: map[string]any{
			"private_key": b64Key(1, base64.StdEncoding), "peer_public_key": b64Key(2, base64.StdEncoding),
			"pre_shared_key": b64Key(3, base64.StdEncoding),
			"jc":             4, "jmin": 40, "jmax": 70, "s1": 40, "s2": 50, "s3": 20, "s4": 16,
			"h1": "100000-200000", "h2": "300000-400000", "h3": "500000", "h4": "700000-800000",
			"i1": "<b 0xc0ff00><r 16><t>", "header_protection_key": b64Key(4, base64.StdEncoding),
			"rekey_timeout": "5-5", "random_trailers": false, "disable_cookies": true,
			"persistent_keepalive": 25,
		},
	}
}

// The exact request, in amneziawg-tools' own order (src/ipc-uapi.h): keys in hex, ranges in the
// form amneziawg-go prints back, booleans as 0/1.
func TestAWGUAPI_Full31Config(t *testing.T) {
	lines, warnings, err := awgUAPI(awg31Endpoint(), testPeer)
	if err != nil {
		t.Fatalf("a valid 3.1 endpoint was refused: %v", err)
	}
	want := []awg.KV{
		{Key: "private_key", Value: hexKey(1)}, {Key: "replace_peers", Value: "true"},
		{Key: "jc", Value: "4"}, {Key: "jmin", Value: "40"}, {Key: "jmax", Value: "70"},
		{Key: "s1", Value: "40"}, {Key: "s2", Value: "50"}, {Key: "s3", Value: "20"}, {Key: "s4", Value: "16"},
		{Key: "h1", Value: "100000-200000"}, {Key: "h2", Value: "300000-400000"},
		{Key: "h3", Value: "500000"}, {Key: "h4", Value: "700000-800000"},
		{Key: "i1", Value: "<b 0xc0ff00><r 16><t>"},
		{Key: "header_protection_key", Value: hexKey(4)},
		{Key: "rekey_timeout", Value: "5"},
		{Key: "random_trailers", Value: "0"}, {Key: "disable_cookies", Value: "1"},
		{Key: "public_key", Value: hexKey(2)}, {Key: "preshared_key", Value: hexKey(3)},
		{Key: "endpoint", Value: "192.0.2.1:51820"}, {Key: "persistent_keepalive_interval", Value: "25"},
		{Key: "replace_allowed_ips", Value: "true"}, {Key: "allowed_ip", Value: "0.0.0.0/0"},
	}
	if fmt.Sprint(lines) != fmt.Sprint(want) {
		t.Fatalf("UAPI lines:\n%v\nwant\n%v", lines, want)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings: %q", warnings)
	}
}

// A key reaches WayHop in whichever base64 the config used; UAPI gets the same hex from each.
func TestAWGUAPI_KeysFromEveryBase64Spelling(t *testing.T) {
	for name, enc := range map[string]*base64.Encoding{
		"std": base64.StdEncoding, "raw std": base64.RawStdEncoding,
		"url": base64.URLEncoding, "raw url": base64.RawURLEncoding,
	} {
		e := awg31Endpoint()
		e.Params["private_key"] = b64Key(0xfb, enc) // 0xfb makes '+' and '/' (or '-' and '_') appear
		lines, _, err := awgUAPI(e, testPeer)
		if err != nil || lines[0].Value != hexKey(0xfb) {
			t.Errorf("%s base64: got %v, %v", name, lines, err)
		}
	}
}

// Each refusal is a value amneziawg-go would either reject after applying part of the set, or not
// reject at all and misbehave on.
func TestAWGUAPI_Refusals(t *testing.T) {
	cases := []struct {
		why string
		mod func(p map[string]any)
	}{
		{"Jc above the documented 128", func(p map[string]any) { p["jc"] = 129 }},
		{"Jmin above Jmax: a near-4 GiB junk packet per handshake", func(p map[string]any) { p["jmin"] = 80 }},
		{"Jmin alone is above the default Jmax of 0", func(p map[string]any) { delete(p, "jmax") }},
		{"a junk size one datagram cannot carry", func(p map[string]any) { p["jmax"] = 70000 }},
		{"S above 16 bits", func(p map[string]any) { p["s2"] = 70000 }},
		{"S below the protection nonce", func(p map[string]any) { p["s4"] = 11 }},
		{"S unset with a protection key", func(p map[string]any) { delete(p, "s3") }},
		{"overlapping H ranges", func(p map[string]any) { p["h2"] = "150000-350000" }},
		{"an H range over a default message type", func(p map[string]any) { delete(p, "h2"); p["h1"] = "1-100" }},
		{"a backwards H range", func(p map[string]any) { p["h4"] = "800000-700000" }},
		{"an unknown I-packet tag", func(p map[string]any) { p["i2"] = "<x 1>" }},
		{"a negative I-packet length: amneziawg-go panics", func(p map[string]any) { p["i3"] = "<r -1>" }},
		{"a private key that is not 32 bytes", func(p map[string]any) { p["private_key"] = "AAAA" }},
		{"no private key", func(p map[string]any) { delete(p, "private_key") }},
		{"no peer key", func(p map[string]any) { delete(p, "peer_public_key") }},
		{"a broken header protection key", func(p map[string]any) { p["header_protection_key"] = "not-a-key" }},
		{"an unreadable RandomTrailers", func(p map[string]any) { p["random_trailers"] = "maybe" }},
		{"a backwards timer range", func(p map[string]any) { p["rekey_after_time"] = "9-1" }},
		{"a timer above 16 bits", func(p map[string]any) { p["keepalive_timeout"] = "70000" }},
		{"an unreadable keepalive", func(p map[string]any) { p["persistent_keepalive"] = "soon" }},
	}
	for _, c := range cases {
		e := awg31Endpoint()
		c.mod(e.Params)
		if lines, _, err := awgUAPI(e, testPeer); err == nil {
			t.Errorf("%s: accepted as %v", c.why, lines)
		}
	}
	if _, _, err := awgUAPI(awg31Endpoint(), netip.AddrPort{}); err == nil {
		t.Error("an unresolved endpoint was accepted")
	}
}

// With Jc 0 no junk packet is built, so Jmin and Jmax are never used and cannot overflow.
func TestAWGUAPI_JcZeroLeavesJunkSizesAlone(t *testing.T) {
	e := awg31Endpoint()
	e.Params["jc"], e.Params["jmin"], e.Params["jmax"] = 0, 80, 40
	if _, _, err := awgUAPI(e, testPeer); err != nil {
		t.Fatalf("refused: %v", err)
	}
}

// The configs that run today stay running: AmneziaVPN's bare-hex I1-I5 (the shape awg2_test.go's
// 2.0 fixture carries) and a kernel-module <c> are rewritten with a warning, not refused.
func TestAWGUAPI_RewritesWithWarnings(t *testing.T) {
	e := awg31Endpoint()
	e.Params["i1"] = "0xc0ffee00c0ffee00"
	e.Params["i2"] = "<b 0x01><c>"
	e.Params["i3"] = 12345 // a number, which awgConfig drops on the kernel path too
	lines, warnings, err := awgUAPI(e, testPeer)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	got := map[string]string{}
	for _, kv := range lines {
		got[kv.Key] = kv.Value
	}
	if _, sent := got["i1"]; sent {
		t.Error("bare-hex I1 was sent")
	}
	if got["i2"] != "<b 0x01><r 4>" {
		t.Errorf("I2 = %q, want <c> as <r 4>", got["i2"])
	}
	if _, sent := got["i3"]; sent {
		t.Error("a numeric I3 was sent")
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{"I1: no <tag>", "I2: <c>", "I3 is not a string"} {
		if !strings.Contains(joined, want) {
			t.Errorf("no warning containing %q in:\n%s", want, joined)
		}
	}
}

// The two measured or documented hazards warn without refusing: RandomTrailers with J + S + H
// ranges (37-55% loss measured), and S1 + 56 = S2 (upstream's documentation).
func TestAWGUAPI_HazardWarnings(t *testing.T) {
	e := awg31Endpoint()
	e.Params["random_trailers"] = true
	_, warnings, err := awgUAPI(e, testPeer)
	if err != nil || !strings.Contains(strings.Join(warnings, "\n"), "RandomTrailers") {
		t.Errorf("RT + J + S + H ranges: warnings %q, err %v", warnings, err)
	}
	// Measured clean: RandomTrailers with J and S but single-value headers.
	for i := 1; i <= 4; i++ {
		e.Params[fmt.Sprintf("h%d", i)] = fmt.Sprint(100000 * i)
	}
	_, warnings, _ = awgUAPI(e, testPeer)
	if strings.Contains(strings.Join(warnings, "\n"), "RandomTrailers") {
		t.Errorf("warned without H ranges: %q", warnings)
	}
	e = awg31Endpoint()
	e.Params["s1"], e.Params["s2"] = 40, 96
	_, warnings, _ = awgUAPI(e, testPeer)
	if !strings.Contains(strings.Join(warnings, "\n"), "S1 + 56 = S2") {
		t.Errorf("S1 + 56 = S2 did not warn: %q", warnings)
	}
}

func TestAWGUAPI_EndpointAndAllowedIPs(t *testing.T) {
	e := awg31Endpoint()
	e.Params["local_address"] = []any{"10.8.0.2/32", "fd00::2/128"}
	lines, _, err := awgUAPI(e, netip.MustParseAddrPort("[2001:db8::1]:443"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	for _, kv := range lines {
		got[kv.Key] = append(got[kv.Key], kv.Value)
	}
	if got["endpoint"][0] != "[2001:db8::1]:443" {
		t.Errorf("IPv6 endpoint %q", got["endpoint"])
	}
	if strings.Join(got["allowed_ip"], ",") != "0.0.0.0/0,::/0" {
		t.Errorf("a dual-stack tunnel routes %q", got["allowed_ip"])
	}
	lines, _, _ = awgUAPI(e, netip.MustParseAddrPort("[::ffff:192.0.2.7]:443"))
	for _, kv := range lines {
		if kv.Key == "endpoint" && kv.Value != "192.0.2.7:443" {
			t.Errorf("an IPv4-mapped endpoint went out as %q", kv.Value)
		}
	}
}

// End to end: a 3.1 .conf, as the tools read it, through the importer and into UAPI - what a user's
// imported file becomes on the userspace path. The storage types the importer picks (ints, strings,
// bools) are exactly what awgUAPI has to read.
func TestAWGUAPI_FromAnImported31Conf(t *testing.T) {
	conf := strings.Join([]string{
		"[Interface]", "PrivateKey = " + b64Key(1, base64.StdEncoding),
		"Jc = 4", "Jmin = 40", "Jmax = 70", "S1 = 40", "S2 = 50", "S3 = 20", "S4 = 16",
		"H1 = 100000-200000", "H2 = 300000-400000", "H3 = 500000-600000", "H4 = 700000-800000",
		"I1 = <b 0xc0ff00><r 16><c>", "I2 = 0xc0ffee00c0ffee00",
		"HeaderProtectionKey = " + b64Key(4, base64.StdEncoding), "MaxHandshakeAttempts = 3-5",
		"RandomTrailers = off", "DisableCookies = on",
		"[Peer]", "PublicKey = " + b64Key(2, base64.StdEncoding), "Endpoint = 192.0.2.1:51820",
		"AllowedIPs = 0.0.0.0/0", "PersistentKeepalive = 25",
	}, "\n")
	e, err := importer.Parse(conf)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if n := awg.Need(e.Params); n != awg.Gen31 {
		t.Errorf("an imported 3.1 config needs generation %v, want 3.1", n)
	}
	lines, warnings, err := awgUAPI(*e, testPeer)
	if err != nil {
		t.Fatalf("translate: %v", err)
	}
	got := map[string]string{}
	for _, kv := range lines {
		got[kv.Key] = kv.Value
	}
	for k, v := range map[string]string{
		"private_key": hexKey(1), "jc": "4", "s4": "16", "h3": "500000-600000",
		"i1": "<b 0xc0ff00><r 16><r 4>", "header_protection_key": hexKey(4),
		"max_handshake_attempts": "3-5", "random_trailers": "0", "disable_cookies": "1",
		"public_key": hexKey(2), "persistent_keepalive_interval": "25",
	} {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, sent := got["i2"]; sent || len(warnings) != 2 {
		t.Errorf("bare-hex I2 sent=%v; warnings %q", sent, warnings)
	}
}

// Every setting awg.Need weighs is one the userspace path carries: a connection the planner sends to
// amneziawg-go because of a setting must not lose that setting on the way. A setting added to awg's
// table without a translation here fails this test, and so does one with no sample below.
func TestAWGUAPI_CarriesEverySetting(t *testing.T) {
	samples := map[string]any{
		"i2": "<r 8>", "i3": "<r 8>", "i4": "<r 8>", "i5": "<r 8>",
		"content_padding_addition": "16", "rekey_after_time": "120", "reject_after_time": "180",
		"keepalive_timeout": "10", "max_handshake_attempts": "3-5",
	}
	for _, key := range awg.Settings() {
		e := awg31Endpoint()
		if v, ok := samples[key]; ok {
			e.Params[key] = v
		}
		if e.Params[key] == nil {
			t.Fatalf("%s has no sample value in the fixture or in this test; add one", key)
		}
		lines, _, err := awgUAPI(e, testPeer)
		if err != nil {
			t.Fatalf("%s: a valid endpoint was refused: %v", key, err)
		}
		carried := false
		for _, kv := range lines {
			carried = carried || kv.Key == key
		}
		if !carried {
			t.Errorf("%s is a setting awg.Need weighs, but awgUAPI sent no line for it", key)
		}
	}
}
