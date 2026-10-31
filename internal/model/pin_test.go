package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// testPin is an invented whole-certificate hash; testPinB64 is a 32-byte value whose base64 holds
// '+' and '/', so the alphabets and a share link's '+' read as a space are exercised.
var (
	testPinSum = sha256.Sum256([]byte("wayhop invented certificate"))
	testPin    = hex.EncodeToString(testPinSum[:])
	testPinRaw = append([]byte{0xfb, 0xef, 0xff}, testPinSum[3:]...)
	testPinB64 = base64.StdEncoding.EncodeToString(testPinRaw)
)

// nextB64 is the base64 digit after c, so a last digit with its unused bits set reads as non-canonical.
func nextB64(c byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	return string(alphabet[(strings.IndexByte(alphabet, c)+1)%64])
}

func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{c}))
	}
	return strings.Join(parts, ":")
}

func TestParsePinSHA256AcceptsEveryCarriedForm(t *testing.T) {
	if !strings.ContainsAny(testPinB64, "+/") {
		t.Fatalf("test value %q should hold '+' or '/'", testPinB64)
	}
	for name, c := range map[string]struct {
		in   string
		want []byte
	}{
		"lowercase hex (Hysteria, our stored form)": {testPin, testPinSum[:]},
		"uppercase hex":                 {strings.ToUpper(testPin), testPinSum[:]},
		"OpenSSL colons (Xray, mihomo)": {colonHex(testPinSum[:]), testPinSum[:]},
		"dashes (Hysteria's normalize)": {strings.ReplaceAll(colonHex(testPinSum[:]), ":", "-"), testPinSum[:]},
		"std base64 (sing-box)":         {testPinB64, testPinRaw},
		"surrounding blanks":            {"  " + testPin + "\n", testPinSum[:]},
	} {
		got, err := ParsePinSHA256(c.in)
		if err != nil || !bytes.Equal(got, c.want) {
			t.Errorf("%s: %q -> %x, %v", name, c.in, got, err)
		}
	}
}

func TestParsePinSHA256RefusesWhatIsNotASHA256(t *testing.T) {
	for name, in := range map[string]string{
		"empty":                     "",
		"blank":                     "   ",
		"upstream doc placeholder":  "deadbeef",
		"31 bytes hex":              testPin[:62],
		"33 bytes hex":              testPin + "00",
		"base64 of 16 bytes":        base64.StdEncoding.EncodeToString(testPinRaw[:16]),
		"browser name, not a pin":   "chrome",
		"not hex nor base64":        "zz!!",
		"two pins in one":           testPin + testPin,
		"sha1 fingerprint (20 B)":   colonHex(testPinSum[:20]),
		"base64 with a bad padding": testPinB64[:40] + "=",
		// Hex digits only: exactly 64, never read as base64 of something else.
		"43 hex digits (base64-shaped)": testPin[:43],
		"44 hex digits":                 testPin[:44],
		"63 hex digits":                 testPin[:63],
		// Base64: the canonical padded standard form only, which sing-box's own decoder takes.
		"raw std base64 (43)":      base64.RawStdEncoding.EncodeToString(testPinRaw),
		"url-safe base64":          base64.URLEncoding.EncodeToString(testPinRaw),
		"non-canonical last digit": testPinB64[:42] + nextB64(testPinB64[42]) + "=",
		"'+' read as a space":      strings.ReplaceAll(testPinB64, "+", " "),
		// White space separates pins (SplitPinList, the panel), so it is never inside one.
		"space-separated hex bytes": strings.ReplaceAll(colonHex(testPinSum[:]), ":", " "),
	} {
		if b, err := ParsePinSHA256(in); err == nil {
			t.Errorf("%s: %q accepted as %x", name, in, b)
		}
	}
}

func TestCanonicalPins(t *testing.T) {
	if got := CanonicalCertPin(colonHex(testPinSum[:])); got != testPin {
		t.Errorf("cert pin canonical = %q, want %q", got, testPin)
	}
	if got := CanonicalCertPin(base64.StdEncoding.EncodeToString(testPinSum[:])); got != testPin {
		t.Errorf("a base64 cert pin is stored as hex: %q", got)
	}
	if got := CanonicalPubKeyPin(hex.EncodeToString(testPinRaw)); got != testPinB64 {
		t.Errorf("pubkey pin canonical = %q, want %q", got, testPinB64)
	}
	if got := CanonicalCertPin(" deadbeef "); got != "deadbeef" {
		t.Errorf("a malformed pin is kept trimmed for Validate to name: %q", got)
	}
	tl := &TLS{
		PinCertSHA256:   []string{strings.ToUpper(testPin), " ", colonHex(testPinSum[:]), "deadbeef"},
		PinPubKeySHA256: []string{hex.EncodeToString(testPinRaw), testPinB64},
	}
	tl.CanonicalizePins()
	if strings.Join(tl.PinCertSHA256, ",") != testPin+",deadbeef" {
		t.Errorf("cert pins = %q", tl.PinCertSHA256)
	}
	if strings.Join(tl.PinPubKeySHA256, ",") != testPinB64 {
		t.Errorf("pubkey pins = %q", tl.PinPubKeySHA256)
	}
	// QA-137: the pins a provenance flag is about are stored as the pins are, so the panel's next edit
	// finds them however they were written.
	of := &TLS{PinCertMayBeCAOf: []string{colonHex(testPinSum[:]), strings.ToUpper(testPin)},
		PinCertBesideChainOf: []string{base64.StdEncoding.EncodeToString(testPinSum[:])}}
	of.CanonicalizePins()
	if strings.Join(of.PinCertMayBeCAOf, ",") != testPin || strings.Join(of.PinCertBesideChainOf, ",") != testPin {
		t.Errorf("provenance lists = %q %q", of.PinCertMayBeCAOf, of.PinCertBesideChainOf)
	}
	var none *TLS
	none.CanonicalizePins() // nil-safe
	empty := &TLS{PinCertSHA256: []string{""}}
	empty.CanonicalizePins()
	if empty.PinCertSHA256 != nil {
		t.Errorf("an empty list stays nil, so the JSON is unchanged: %q", empty.PinCertSHA256)
	}
}

func TestSplitPinList(t *testing.T) {
	got := SplitPinList(" " + testPin + ", " + colonHex(testPinSum[:]) + ";;\n" + testPinB64 + ",")
	if len(got) != 3 || got[0] != testPin || got[1] != colonHex(testPinSum[:]) || got[2] != testPinB64 {
		t.Errorf("SplitPinList = %q", got)
	}
	if len(SplitPinList(" , ")) != 0 {
		t.Error("nothing to split is empty")
	}
	if got := SplitPinList(testPin + " " + strings.ToUpper(testPin) + "\t" + testPinB64); len(got) != 3 {
		t.Errorf("white space separates pins, as in the panel: %q", got)
	}
}

func TestCertPinsOfReadsTheLegacyHysteriaParam(t *testing.T) {
	other := sha256.Sum256([]byte("another invented certificate"))
	e := &Endpoint{Protocol: ProtoHysteria2, TLS: &TLS{Enabled: true, PinCertSHA256: []string{testPin, "deadbeef"}},
		Params: map[string]any{ParamLegacyPin: colonHex(other[:])}}
	got := CertPinsOf(e)
	if len(got) != 2 || got[0] != testPin || got[1] != hex.EncodeToString(other[:]) {
		t.Errorf("CertPinsOf = %q", got)
	}
	e.Params[ParamLegacyPin] = strings.ToUpper(testPin) // the same pin twice is one
	if got := CertPinsOf(e); len(got) != 1 {
		t.Errorf("duplicates folded: %q", got)
	}
	e.Params[ParamLegacyPin] = "deadbeef"
	e.TLS.PinCertSHA256 = nil
	if got := CertPinsOf(e); got != nil {
		t.Errorf("a malformed legacy pin is no pin: %q", got)
	}
	if !HasPinIntent(e) {
		t.Error("a malformed legacy pin is still a pin the link asked for")
	}
	if CertPinsOf(&Endpoint{}) != nil || PubKeyPinsOf(&Endpoint{}) != nil || HasPinIntent(&Endpoint{}) {
		t.Error("no TLS, no pins")
	}
	e.TLS.PinPubKeySHA256 = []string{hex.EncodeToString(testPinRaw), "x"}
	if got := PubKeyPinsOf(e); len(got) != 1 || got[0] != testPinB64 {
		t.Errorf("PubKeyPinsOf = %q", got)
	}
}

func TestVerifyCertNames(t *testing.T) {
	e := &Endpoint{Params: map[string]any{ParamVerifyCertName: " real.example.com , ,cdn.example.net"}}
	if got := VerifyCertNames(e); len(got) != 2 || got[0] != "real.example.com" || got[1] != "cdn.example.net" {
		t.Errorf("VerifyCertNames = %q", got)
	}
	if VerifyCertNames(&Endpoint{}) != nil || VerifyCertNames(nil) != nil {
		t.Error("no vcn, no names")
	}
}

// A pin that is not a SHA-256 hash is refused on an enabled connection (the generator could only
// leave it out, and the connection would run without the check its owner asked for); a draft may
// keep it, and the legacy Hysteria2 parameter an older WayHop stored is never refused.
func TestValidateRefusesAMalformedPin(t *testing.T) {
	ep := func(enabled bool, edit func(*Endpoint)) *Profile {
		e := Endpoint{ID: "t1", Name: "t1", Engine: EngineSingBox, Protocol: ProtoTrojan, Server: "192.0.2.7", Port: 443,
			Enabled: enabled, Params: map[string]any{"password": "pw"}, TLS: &TLS{Enabled: true, Type: "tls", SNI: "example.com"}}
		edit(&e)
		return &Profile{Endpoints: []Endpoint{e}, Rules: []Rule{{ID: "def", Default: true, Outbound: OutboundDirect}}}
	}
	if err := ep(true, func(e *Endpoint) {
		e.TLS.PinCertSHA256 = []string{colonHex(testPinSum[:])}
		e.TLS.PinPubKeySHA256 = []string{testPinB64}
	}).Validate(); err != nil {
		t.Errorf("well-formed pins refused: %v", err)
	}
	for name, edit := range map[string]func(*Endpoint){
		"cert pin":   func(e *Endpoint) { e.TLS.PinCertSHA256 = []string{"deadbeef"} },
		"pubkey pin": func(e *Endpoint) { e.TLS.PinPubKeySHA256 = []string{testPin[:60]} },
	} {
		err := ep(true, edit).Validate()
		if err == nil || !strings.Contains(err.Error(), "not a SHA-256 hash") {
			t.Errorf("%s: Validate = %v", name, err)
		}
		if p := EndpointParamProblem(&ep(true, edit).Endpoints[0]); p == "" {
			t.Errorf("%s: the save does not refuse it", name)
		}
		if err := ep(false, edit).Validate(); err != nil {
			t.Errorf("%s: a disabled draft is refused: %v", name, err)
		}
	}
	if err := ep(true, func(e *Endpoint) {
		e.Protocol = ProtoHysteria2
		e.Params[ParamLegacyPin] = "deadbeef"
	}).Validate(); err != nil {
		t.Errorf("the legacy parameter an older WayHop stored stops the profile: %v", err)
	}
}
