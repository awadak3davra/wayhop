package generator

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// Invented pins: a whole-certificate hash (stored as hex) and a public-key hash (stored as base64).
var (
	pinCertSum = sha256.Sum256([]byte("wayhop invented leaf certificate"))
	pinKeySum  = sha256.Sum256([]byte("wayhop invented public key"))
	pinCertHex = hex.EncodeToString(pinCertSum[:])
	pinCertB64 = base64.StdEncoding.EncodeToString(pinCertSum[:])
	pinKeyB64  = base64.StdEncoding.EncodeToString(pinKeySum[:])
)

const (
	pinCore1217 = "1.12.17"
	pinCore1321 = "1.13.21"
	pinCore1144 = "1.14.4"
	pinCore115  = "sing-box version 1.15.0-alpha.13\n\nEnvironment: go1.25.12 linux/amd64"
)

func pinTestEndpoint(id string, p model.Protocol, edit func(*model.Endpoint)) model.Endpoint {
	e := model.Endpoint{ID: id, Name: id, Enabled: true, Engine: model.EngineSingBox, Protocol: p, Server: "192.0.2.21", Port: 443,
		Params: map[string]any{"uuid": "00000000-0000-4000-8000-000000000021", "password": "pw"},
		TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "example.com"}}
	if edit != nil {
		edit(&e)
	}
	return e
}

func pinTLS(t *testing.T, e *model.Endpoint, coreVersion string) map[string]any {
	t.Helper()
	ob, err := OutboundForCore(e, coreVersion)
	if err != nil {
		t.Fatalf("%s on %q: %v", e.ID, coreVersion, err)
	}
	tl, _ := ob["tls"].(map[string]any)
	return tl
}

func TestPinCoreVersionGates(t *testing.T) {
	both := func(insecure bool) func(*model.Endpoint) {
		return func(e *model.Endpoint) {
			e.TLS.PinCertSHA256, e.TLS.PinPubKeySHA256, e.TLS.Insecure = []string{pinCertHex}, []string{pinKeyB64}, insecure
		}
	}
	for _, c := range []struct {
		core           string
		cert, pub, ins bool // rendered: certificate_sha256, certificate_public_key_sha256, insecure (asked for)
	}{
		{"", false, false, true},
		{"not a version", false, false, true},
		{pinCore1217, false, false, true},
		{pinCore1321, false, true, false},
		{pinCore1144, false, true, false},
		{pinCore115, true, true, false},
	} {
		for _, p := range []model.Protocol{model.ProtoVLESS, model.ProtoVMess, model.ProtoTrojan, model.ProtoAnyTLS,
			model.ProtoHysteria2, model.ProtoTUIC, model.ProtoHTTP} {
			e := pinTestEndpoint("x", p, both(true))
			tl := pinTLS(t, &e, c.core)
			if got := tl["certificate_sha256"]; (got != nil) != c.cert || (c.cert && !reflect.DeepEqual(got, []string{pinCertB64})) {
				t.Errorf("%s on %q: certificate_sha256 = %v", p, c.core, got)
			}
			if got := tl["certificate_public_key_sha256"]; (got != nil) != c.pub || (c.pub && !reflect.DeepEqual(got, []string{pinKeyB64})) {
				t.Errorf("%s on %q: certificate_public_key_sha256 = %v", p, c.core, got)
			}
			if got := tl["insecure"] == true; got != c.ins {
				t.Errorf("%s on %q: insecure = %v; a rendered pin replaces it, else the link's choice stays", p, c.core, tl["insecure"])
			}
			// Certificate checks on: never switched off by the pin code, rendered or not.
			e = pinTestEndpoint("x", p, both(false))
			if tl := pinTLS(t, &e, c.core); tl["insecure"] != nil {
				t.Errorf("%s on %q: insecure appeared: %v", p, c.core, tl)
			}
		}
	}
	// Only a whole-certificate pin, on a core that cannot check it: left out, insecure kept.
	e := pinTestEndpoint("x", model.ProtoTrojan, func(e *model.Endpoint) { e.TLS.PinCertSHA256, e.TLS.Insecure = []string{pinCertHex}, true })
	if tl := pinTLS(t, &e, pinCore1144); tl["certificate_sha256"] != nil || tl["insecure"] != true {
		t.Errorf("1.14 with a whole-certificate pin: %v", tl)
	}
}

func TestPinRenderShapes(t *testing.T) {
	other := sha256.Sum256([]byte("wayhop invented second certificate"))
	e := pinTestEndpoint("hy", model.ProtoHysteria2, func(e *model.Endpoint) {
		// The legacy parameter an older WayHop kept, an uppercase colon form, and a duplicate of it.
		e.Params[model.ParamLegacyPin] = strings.ToUpper(hex.EncodeToString(other[:]))
		e.TLS.PinCertSHA256 = []string{pinCertHex, pinCertB64}
		e.TLS.Insecure = true
	})
	tl := pinTLS(t, &e, pinCore115)
	want := []string{pinCertB64, base64.StdEncoding.EncodeToString(other[:])}
	if !reflect.DeepEqual(tl["certificate_sha256"], want) {
		t.Errorf("certificate_sha256 = %v, want %v", tl["certificate_sha256"], want)
	}
	if tl["insecure"] != nil {
		t.Errorf("insecure beside an enforced pin: %v", tl)
	}
	// Reality authenticates by its own key: a Reality link's pins are kept, never rendered.
	r := pinTestEndpoint("r", model.ProtoVLESS, func(e *model.Endpoint) {
		e.TLS.Type, e.TLS.PublicKey = "reality", "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
		e.TLS.PinCertSHA256, e.TLS.PinPubKeySHA256 = []string{pinCertHex}, []string{pinKeyB64}
	})
	if tl := pinTLS(t, &r, pinCore115); tl["reality"] == nil || tl["certificate_sha256"] != nil || tl["certificate_public_key_sha256"] != nil {
		t.Errorf("Reality with pins: %v", tl)
	}
	// No TLS block to put a pin in: a stray TLS on Shadowsocks is dropped whole, pins with it.
	ss := pinTestEndpoint("ss", model.ProtoShadowsocks, func(e *model.Endpoint) {
		e.Params = map[string]any{"method": "aes-128-gcm", "password": "pw"}
		e.TLS.PinCertSHA256 = []string{pinCertHex}
	})
	ob, err := OutboundForCore(&ss, pinCore115)
	if err != nil || ob["tls"] != nil {
		t.Errorf("shadowsocks: %v %v", ob, err)
	}
	// Generate renders exactly what OutboundForCore does.
	prof := &model.Profile{Endpoints: []model.Endpoint{e}, Rules: []model.Rule{{ID: "def", Default: true, Outbound: "hy"}}}
	res, err := Generate(prof, Options{MixedPort: 7890, CoreVersion: pinCore115})
	if err != nil {
		t.Fatal(err)
	}
	for _, ob := range res.Config["outbounds"].([]map[string]any) {
		if ob["tag"] == "hy" && !reflect.DeepEqual(ob["tls"], tl) {
			t.Errorf("Generate tls = %v, OutboundForCore tls = %v", ob["tls"], tl)
		}
	}
}

// A connection without pins goes through pinCoreExtras untouched on every core: its render is
// whatever it was before pinning existed. (The whole-profile comparison against the previous
// commit's output, TUN and hybrid included, is in the change's verification notes.)
func TestPinlessOutboundsUntouched(t *testing.T) {
	for _, core := range []string{"", pinCore1217, pinCore1321, pinCore1144, pinCore115} {
		for _, e := range allProtocolProfile().Endpoints {
			e := e
			if model.HasPinIntent(&e) {
				t.Fatalf("%s: the all-protocols fixture has a pin", e.ID)
			}
			ob, err := OutboundForCore(&e, core)
			if err != nil {
				continue // a protocol this core cannot carry; Generate says so, not this test
			}
			before, _ := json.Marshal(ob)
			pinCoreExtras(&e, ob, core)
			after, _ := json.Marshal(ob)
			if string(before) != string(after) {
				t.Errorf("%s on %q changed:\n%s\n%s", e.ID, core, before, after)
			}
			// vcn alone (a link's verify name) changes nothing in the render either.
			e.Params = cloneParams(e.Params)
			e.Params[model.ParamVerifyCertName] = "real.example.net"
			ob2, _ := OutboundForCore(&e, core)
			if again, _ := json.Marshal(ob2); string(again) != string(before) {
				t.Errorf("%s on %q: vcn changed the render:\n%s\n%s", e.ID, core, before, again)
			}
		}
	}
}

func cloneParams(p map[string]any) map[string]any {
	out := make(map[string]any, len(p)+1)
	for k, v := range p {
		out[k] = v
	}
	return out
}

func TestPinReviewPredicates(t *testing.T) {
	ep := func(edit func(*model.Endpoint)) *model.Endpoint {
		e := pinTestEndpoint("x", model.ProtoTrojan, edit)
		return &e
	}
	certOnly := func(insecure bool) *model.Endpoint {
		return ep(func(e *model.Endpoint) { e.TLS.PinCertSHA256, e.TLS.Insecure = []string{pinCertHex}, insecure })
	}
	keyOnly := ep(func(e *model.Endpoint) { e.TLS.PinPubKeySHA256 = []string{pinKeyB64} })
	fromPCS := func(e *model.Endpoint) { e.TLS.PinCertSHA256, e.TLS.PinCertMayBeCA = []string{pinCertHex}, true }
	legacyBad := ep(func(e *model.Endpoint) {
		e.Protocol, e.TLS.Insecure = model.ProtoHysteria2, true
		e.Params[model.ParamLegacyPin] = "deadbeef"
	})

	for _, c := range []struct {
		name     string
		e        *model.Endpoint
		core     string
		leftOut  bool
		insecure bool
		ca       bool
	}{
		{"cert pin, 1.14, checks on", certOnly(false), pinCore1144, true, false, false},
		{"cert pin, 1.14, insecure", certOnly(true), pinCore1144, true, true, false},
		{"cert pin, unknown core, insecure", certOnly(true), "", true, true, false},
		// The CA condition only for pins from a format that allows a CA (pcs=, mihomo's fingerprint).
		{"cert pin from the form, 1.15", certOnly(true), pinCore115, false, false, false},
		{"cert pin from pcs, 1.15", ep(fromPCS), pinCore115, false, false, true},
		{"cert pin from pcs, 1.14", ep(fromPCS), pinCore1144, true, false, false},
		{"key pin, 1.12", keyOnly, pinCore1217, true, false, false},
		{"key pin, 1.13", keyOnly, pinCore1321, false, false, false},
		// A malformed pin is no core's to check: PinMalformed, not PinsLeftOut.
		{"legacy malformed pin, 1.15, insecure", legacyBad, pinCore115, false, true, false},
	} {
		cov, left := PinsLeftOut(c.e, c.core)
		if left != c.leftOut || cov.Insecure != c.insecure {
			t.Errorf("%s: PinsLeftOut = %+v, %v", c.name, cov, left)
		}
		if got := PinsMayNameCA(c.e, c.core); got != c.ca {
			t.Errorf("%s: PinsMayNameCA = %v", c.name, got)
		}
	}
	if !PinMalformed(legacyBad) || PinMalformed(certOnly(true)) || PinMalformed(ep(nil)) {
		t.Error("PinMalformed: only the pin that is not a SHA-256 hash")
	}

	// Hysteria's pinSHA256 with certificate checks on: Hysteria checks the chain beside it, sing-box
	// the pin instead. Said only where the pin is rendered and checks were on.
	hy := func(insecure, besideChain bool, legacy string) *model.Endpoint {
		return ep(func(e *model.Endpoint) {
			e.Protocol, e.TLS.Insecure = model.ProtoHysteria2, insecure
			if legacy != "" {
				e.Params[model.ParamLegacyPin] = legacy
			} else {
				e.TLS.PinCertSHA256, e.TLS.PinCertBesideChain = []string{pinCertHex}, besideChain
			}
		})
	}
	for _, c := range []struct {
		name string
		e    *model.Endpoint
		core string
		want bool
	}{
		{"pinSHA256, checks on, 1.15", hy(false, true, ""), pinCore115, true},
		{"pinSHA256, checks on, 1.14 (not rendered)", hy(false, true, ""), pinCore1144, false},
		{"pinSHA256, insecure, 1.15", hy(true, true, ""), pinCore115, false},
		{"legacy pin, checks on, 1.15", hy(false, false, pinCertHex), pinCore115, true},
		{"legacy malformed pin, checks on", hy(false, false, "deadbeef"), pinCore115, false},
		{"pin from the form, checks on", hy(false, false, ""), pinCore115, false},
	} {
		if got := PinReplacesChainCheck(c.e, c.core); got != c.want {
			t.Errorf("PinReplacesChainCheck %s = %v", c.name, got)
		}
	}

	// Pins on a Reality connection are kept and not used.
	realityPins := ep(func(e *model.Endpoint) {
		e.Protocol, e.TLS.Type, e.TLS.PublicKey = model.ProtoVLESS, "reality", "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
		e.TLS.PinCertSHA256 = []string{pinCertHex}
	})
	if !PinsUnusedByReality(realityPins) || PinsUnusedByReality(certOnly(false)) {
		t.Error("PinsUnusedByReality: only pins beside Reality")
	}

	// Both kinds on 1.14: the key pin is checked, the certificate pin is left out and said.
	both := ep(func(e *model.Endpoint) {
		e.TLS.PinCertSHA256, e.TLS.PinPubKeySHA256 = []string{pinCertHex}, []string{pinKeyB64}
	})
	if cov, left := PinsLeftOut(both, pinCore1144); !left || !cov.Enforced || cov.CertLeftOut != 1 || cov.Insecure {
		t.Errorf("both kinds on 1.14: %+v %v", cov, left)
	}
	// No pin, Reality, or another engine: nothing to say.
	reality := ep(func(e *model.Endpoint) {
		e.Protocol, e.TLS.Type, e.TLS.PublicKey = model.ProtoVLESS, "reality", "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
		e.TLS.PinCertSHA256 = []string{pinCertHex}
	})
	for name, e := range map[string]*model.Endpoint{"none": ep(nil), "reality": reality} {
		if _, ok := PinsOf(e, pinCore1217); ok {
			t.Errorf("%s: PinsOf reports pins", name)
		}
	}

	// vcn: said only where sing-box checks a name, and only for names other than the SNI.
	vcn := func(names string, edit func(*model.Endpoint)) *model.Endpoint {
		return ep(func(e *model.Endpoint) {
			e.Params[model.ParamVerifyCertName] = names
			if edit != nil {
				edit(e)
			}
		})
	}
	if got := CertNameUnchecked(vcn("real.example.net, example.com", nil), pinCore115); len(got) != 1 || got[0] != "real.example.net" {
		t.Errorf("vcn beside the SNI: %v", got)
	}
	if got := CertNameUnchecked(vcn("EXAMPLE.com", nil), pinCore115); got != nil {
		t.Errorf("vcn equal to the SNI: %v", got)
	}
	if got := CertNameUnchecked(vcn("real.example.net", func(e *model.Endpoint) { e.TLS.SNI = "" }), pinCore115); len(got) != 1 {
		t.Errorf("no SNI: sing-box checks the server address: %v", got)
	}
	if got := CertNameUnchecked(vcn("real.example.net", func(e *model.Endpoint) { e.TLS.Insecure = true }), pinCore115); got != nil {
		t.Errorf("checks off: no name is checked: %v", got)
	}
	pinned := func(e *model.Endpoint) { e.TLS.PinCertSHA256 = []string{pinCertHex} }
	if got := CertNameUnchecked(vcn("real.example.net", pinned), pinCore115); got != nil {
		t.Errorf("an enforced pin replaces the name check: %v", got)
	}
	if got := CertNameUnchecked(vcn("real.example.net", pinned), pinCore1144); len(got) != 1 {
		t.Errorf("a pin the core leaves out does not: %v", got)
	}
}

// A config WayHop wrote reads back with the same pins (sing-box JSON import), so a sing-box export
// round-trips. The insecure flag the render left out beside the pins does not come back: on this
// core the pins are the whole check either way.
func TestPinSingboxRoundTrip(t *testing.T) {
	e := pinTestEndpoint("tr", model.ProtoTrojan, func(e *model.Endpoint) {
		e.TLS.PinCertSHA256, e.TLS.PinPubKeySHA256, e.TLS.Insecure = []string{pinCertHex}, []string{pinKeyB64}, true
	})
	prof := &model.Profile{Endpoints: []model.Endpoint{e}, Rules: []model.Rule{{ID: "def", Default: true, Outbound: "tr"}}}
	res, err := Generate(prof, Options{MixedPort: 7890, CoreVersion: pinCore115})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(res.Config)
	back, errs := importer.ParseSingbox(string(raw))
	if len(errs) > 0 || len(back) != 1 {
		t.Fatalf("ParseSingbox: %v %v", back, errs)
	}
	tl := back[0].TLS
	if !reflect.DeepEqual(tl.PinCertSHA256, []string{pinCertHex}) || !reflect.DeepEqual(tl.PinPubKeySHA256, []string{pinKeyB64}) || tl.Insecure {
		t.Errorf("read back: %+v", tl)
	}
}
