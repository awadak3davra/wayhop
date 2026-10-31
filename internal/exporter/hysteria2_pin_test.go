package exporter

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

var (
	expPinA    = sha256.Sum256([]byte("wayhop invented certificate A"))
	expPinB    = sha256.Sum256([]byte("wayhop invented certificate B"))
	expPinAHex = hex.EncodeToString(expPinA[:])
	expPinBHex = hex.EncodeToString(expPinB[:])
)

func expColons(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func linkQuery(t *testing.T, link string) url.Values {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("%q: %v", link, err)
	}
	return u.Query()
}

// The pin a Hysteria2 link carries survives an import and comes back out on export, in the form
// Hysteria's own share link writes (lowercase hex); the import reads it back to the same pin.
func TestHysteria2PinRoundTrips(t *testing.T) {
	for _, in := range []string{
		"hysteria2+realm://mytoken@rendezvous.example.com/my-cabin-1f3a8c2e9b?auth=your_password&insecure=1&pinSHA256=" + expColons(expPinA[:]),
		"hysteria2://letmein@example.com:443/?insecure=1&pinSHA256=" + expColons(expPinA[:]) + "&sni=real.example.com",
	} {
		e, err := importer.Parse(in)
		if err != nil {
			t.Fatalf("parse %q: %v", in, err)
		}
		link, ok := ShareLink(*e)
		if !ok || linkQuery(t, link).Get("pinSHA256") != expPinAHex || linkQuery(t, link).Has("pcs") {
			t.Fatalf("%q exported as %q (%v), want the pin back", in, link, ok)
		}
		back, err := importer.Parse(link)
		if err != nil || !reflect.DeepEqual(back.TLS.PinCertSHA256, e.TLS.PinCertSHA256) {
			t.Errorf("%q re-imported as %+v, %v", link, back, err)
		}
	}
}

// Connections an older WayHop imported keep the pin in the legacy parameter: exported as the pin it
// is, and one that is not a SHA-256 hash given back as it came.
func TestHysteria2LegacyPinExport(t *testing.T) {
	e := model.Endpoint{ID: "h", Name: "h", Protocol: model.ProtoHysteria2, Server: "192.0.2.50", Port: 443,
		Params: map[string]any{"password": "pw", model.ParamLegacyPin: expColons(expPinA[:])},
		TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "example.com", Insecure: true}}
	if link, _ := ShareLink(e); linkQuery(t, link).Get("pinSHA256") != expPinAHex {
		t.Errorf("legacy pin exported as %q", link)
	}
	e.Params[model.ParamLegacyPin] = "deadbeef"
	if link, _ := ShareLink(e); linkQuery(t, link).Get("pinSHA256") != "deadbeef" {
		t.Errorf("a malformed legacy pin is given back as it came: %q", link)
	}
	// Several pins: the official client checks pinSHA256 (the first), v2rayN reads them all in pcs=.
	e.Params[model.ParamLegacyPin] = ""
	e.TLS.PinCertSHA256 = []string{expPinAHex, expPinBHex}
	q := linkQuery(t, mustLink(t, e))
	if q.Get("pinSHA256") != expPinAHex || q.Get("pcs") != expPinAHex+","+expPinBHex {
		t.Errorf("two pins: %v", q)
	}
	back, err := importer.Parse(mustLink(t, e))
	if err != nil || !reflect.DeepEqual(back.TLS.PinCertSHA256, e.TLS.PinCertSHA256) {
		t.Errorf("two pins re-imported as %+v, %v", back, err)
	}
}

func mustLink(t *testing.T, e model.Endpoint) string {
	t.Helper()
	link, ok := ShareLink(e)
	if !ok {
		t.Fatalf("%s: no share link", e.ID)
	}
	return link
}

// QA-135: pcs= and vcn= (Xray's pinnedPeerCertSha256 and verifyPeerCertByName, as v2rayN writes
// them) survive import and export on every link that carries them, Reality included (kept, not
// used), and the verify name never moves into the SNI.
func TestPinShareLinksRoundTrip(t *testing.T) {
	esc := url.QueryEscape
	pcs := esc(expColons(expPinA[:]) + "," + expPinBHex)
	const uuid = "00000000-0000-4000-8000-000000000050"
	for _, in := range []string{
		"vless://" + uuid + "@192.0.2.51:443?security=tls&sni=cdn.example.com&type=ws&path=%2Fw&host=cdn.example.com&pcs=" + pcs + "&vcn=real.example.com#v",
		"vless://" + uuid + "@192.0.2.51:443?security=reality&sni=example.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0&sid=ab&pcs=" + expPinAHex + "#r",
		"trojan://pw@192.0.2.52:443?sni=example.com&pcs=" + pcs + "&vcn=real.example.com,alt.example.com#t",
		"anytls://pw@192.0.2.53:443?sni=example.com&pcs=" + expPinAHex + "#a",
		"tuic://" + uuid + ":pw@192.0.2.54:443?sni=example.com&pcs=" + expPinAHex + "&vcn=real.example.com#u",
		"hysteria2://pw@192.0.2.55:443/?sni=example.com&pinSHA256=" + expPinAHex + "&vcn=real.example.com#h",
	} {
		e, err := importer.Parse(in)
		if err != nil {
			t.Fatalf("parse %q: %v", in, err)
		}
		if len(e.TLS.PinCertSHA256) == 0 {
			t.Fatalf("%q: no pin imported", in)
		}
		link := mustLink(t, *e)
		back, err := importer.Parse(link)
		if err != nil {
			t.Fatalf("re-import %q: %v", link, err)
		}
		if !reflect.DeepEqual(back.TLS.PinCertSHA256, e.TLS.PinCertSHA256) || back.Params[model.ParamVerifyCertName] != e.Params[model.ParamVerifyCertName] ||
			back.TLS.SNI != e.TLS.SNI {
			t.Errorf("%q -> %q: pins %q vcn %v sni %q, want %q %v %q", in, link, back.TLS.PinCertSHA256,
				back.Params[model.ParamVerifyCertName], back.TLS.SNI, e.TLS.PinCertSHA256, e.Params[model.ParamVerifyCertName], e.TLS.SNI)
		}
		if p := linkQuery(t, link).Get("pcs"); p != "" && p != strings.Join(e.TLS.PinCertSHA256, ",") {
			t.Errorf("%q: pcs = %q, want the stored lowercase hex", link, p)
		}
	}
	// VMess carries both in its JSON.
	vm := model.Endpoint{ID: "vm", Name: "vm", Protocol: model.ProtoVMess, Server: "192.0.2.56", Port: 443,
		Params: map[string]any{"uuid": uuid, "security": "auto", model.ParamVerifyCertName: "real.example.com"},
		TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "cdn.example.com", PinCertSHA256: []string{expPinAHex, expPinBHex}}}
	back, err := importer.Parse(mustLink(t, vm))
	if err != nil || !reflect.DeepEqual(back.TLS.PinCertSHA256, vm.TLS.PinCertSHA256) || back.Params[model.ParamVerifyCertName] != "real.example.com" {
		t.Errorf("vmess round trip: %+v, %v", back, err)
	}
	// Public-key pins have no share-link form: nothing is written for them.
	tr := model.Endpoint{ID: "t", Name: "t", Protocol: model.ProtoTrojan, Server: "192.0.2.57", Port: 443,
		Params: map[string]any{"password": "pw"},
		TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "example.com", PinPubKeySHA256: []string{base64.StdEncoding.EncodeToString(expPinB[:])}}}
	if q := linkQuery(t, mustLink(t, tr)); q.Has("pcs") || q.Has("vcn") {
		t.Errorf("public-key pin exported: %v", q)
	}
}

// A share link is never weaker than the connection it shares: a public-key pin cannot travel in a
// link, so where it is the only pin and certificate checks are off the link would carry "insecure"
// and no pin, and accept any certificate. That export is refused with the reason. With a
// whole-certificate pin beside it, with checks on, or under Reality, the link is given as before.
func TestExportRefusesALinkWeakerThanTheConnection(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(expPinB[:])
	ep := func(p model.Protocol, edit func(*model.TLS)) model.Endpoint {
		e := model.Endpoint{ID: "x", Name: "x", Protocol: p, Server: "192.0.2.58", Port: 443,
			Params: map[string]any{"password": "pw", "uuid": "00000000-0000-4000-8000-000000000058"},
			TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "example.com", Insecure: true, PinPubKeySHA256: []string{key}}}
		if edit != nil {
			edit(e.TLS)
		}
		return e
	}
	for _, p := range []model.Protocol{model.ProtoVLESS, model.ProtoVMess, model.ProtoTrojan, model.ProtoAnyTLS,
		model.ProtoHysteria2, model.ProtoTUIC} {
		e := ep(p, nil)
		if why := Refusal(e); !strings.Contains(why, "public-key pin") || !strings.Contains(why, "any certificate") {
			t.Errorf("%s: Refusal = %q", p, why)
		}
		if r, ok := Export(e); ok {
			t.Errorf("%s: exported anyway: %q", p, r.Text)
		}
		if _, ok := ShareLink(e); ok {
			t.Errorf("%s: ShareLink gave a link", p)
		}
		for name, edit := range map[string]func(*model.TLS){
			"with a whole-certificate pin": func(t *model.TLS) { t.PinCertSHA256 = []string{expPinAHex} },
			"checks on":                    func(t *model.TLS) { t.Insecure = false },
			"no pin":                       func(t *model.TLS) { t.PinPubKeySHA256 = nil },
		} {
			e := ep(p, edit)
			r, ok := Export(e)
			if Refusal(e) != "" || !ok {
				t.Errorf("%s %s: refused: %q", p, name, Refusal(e))
				continue
			}
			if name == "with a whole-certificate pin" && !strings.Contains(r.Text, expPinAHex) && p != model.ProtoVMess {
				t.Errorf("%s %s: the pin did not travel: %q", p, name, r.Text)
			}
		}
	}
	reality := ep(model.ProtoVLESS, func(t *model.TLS) {
		t.Type, t.PublicKey = "reality", "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
	})
	if why := Refusal(reality); why != "" {
		t.Errorf("Reality uses no pin, so its link is not weaker: %q", why)
	}
}
