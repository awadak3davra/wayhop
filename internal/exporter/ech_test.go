package exporter

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// testECHConfig is an ECHConfigList `sing-box generate ech-keypair example.com` printed (1.13.21).
const testECHConfig = "AEb+DQBCAAAgACDv1FlTLOHACGPvieDrkqLa8zJ86loXc/u6LLmehtFpUQAMAAEAAQABAAIAAQADAAtleGFtcGxlLmNvbQAA"

func echEndpoint(p model.Protocol, e *model.ECH) model.Endpoint {
	return model.Endpoint{Engine: model.EngineSingBox, Protocol: p, Name: "n", Server: "192.0.2.9", Port: 443,
		Params: map[string]any{"uuid": "00000000-0000-4000-8000-000000000009", "password": "pw"},
		TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "example.com", ECH: e}}
}

func linkECH(t *testing.T, link string) (string, bool) {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("%q: %v", link, err)
	}
	v, ok := u.Query()["ech"]
	if !ok {
		return "", false
	}
	return v[0], true
}

func TestECHShareLinkRoundTrip(t *testing.T) {
	urlSafe := strings.NewReplacer("+", "-", "/", "_").Replace(testECHConfig)
	for _, p := range []model.Protocol{model.ProtoVLESS, model.ProtoTrojan, model.ProtoAnyTLS, model.ProtoHysteria2, model.ProtoTUIC} {
		// Stored in another alphabet (or as PEM), exported as the standard base64 every format carries.
		for _, stored := range []string{testECHConfig, urlSafe} {
			e := echEndpoint(p, &model.ECH{Enabled: true, Config: stored})
			link, ok := ShareLink(e)
			if !ok {
				t.Fatalf("%s: no link", p)
			}
			if v, ok := linkECH(t, link); !ok || v != testECHConfig {
				t.Errorf("%s: ech= %q in %s", p, v, link)
			}
			// '+' and '/' are escaped in the link (encodeURIComponent, as Xray's standard asks).
			if strings.Contains(link, "ech="+testECHConfig[:5]) {
				t.Errorf("%s: ech= left unescaped: %s", p, link)
			}
			got, err := importer.Parse(link)
			if err != nil {
				t.Fatalf("%s: re-import: %v", p, err)
			}
			if got.TLS == nil || got.TLS.ECH == nil || *got.TLS.ECH != (model.ECH{Enabled: true, Config: testECHConfig}) {
				t.Errorf("%s: round trip lost ECH: %+v", p, got.TLS)
			}
		}
	}
	// A Hysteria realm link carries it like the plain one.
	realm := echEndpoint(model.ProtoHysteria2, &model.ECH{Enabled: true, Config: testECHConfig})
	realm.Server, realm.Port = "", 0
	realm.Params["realm"] = "realm://tok@example.net/r1"
	link, _ := ShareLink(realm)
	if got, err := importer.Parse(link); err != nil || got.TLS.ECH == nil || got.TLS.ECH.Config != testECHConfig {
		t.Errorf("realm round trip: %v, %+v (%s)", err, got, link)
	}
}

func TestECHShareLinkLeavesOut(t *testing.T) {
	for name, e := range map[string]model.Endpoint{
		// The link form names a resolver URL, and the router looks the record up through its own DNS.
		"DNS lookup":        echEndpoint(model.ProtoVLESS, &model.ECH{Enabled: true, QueryServerName: "example.net"}),
		"switched off":      echEndpoint(model.ProtoTrojan, &model.ECH{Config: testECHConfig}),
		"no ECH":            echEndpoint(model.ProtoAnyTLS, nil),
		"vmess has no form": echEndpoint(model.ProtoVMess, &model.ECH{Enabled: true, Config: testECHConfig}),
	} {
		link, ok := ShareLink(e)
		if !ok {
			t.Fatalf("%s: no link", name)
		}
		if e.Protocol == model.ProtoVMess {
			raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
			if strings.Contains(string(raw), "ech") {
				t.Errorf("%s: %s", name, raw)
			}
			continue
		}
		if v, ok := linkECH(t, link); ok {
			t.Errorf("%s: ech=%q", name, v)
		}
	}
	// A Reality link gives back the config it brought, kept off on re-import as on import.
	r := echEndpoint(model.ProtoVLESS, &model.ECH{Config: testECHConfig})
	r.TLS.Type, r.TLS.PublicKey = "reality", "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
	link, _ := ShareLink(r)
	if v, _ := linkECH(t, link); v != testECHConfig {
		t.Errorf("reality: ech=%q", v)
	}
	got, err := importer.Parse(link)
	if err != nil || got.TLS.ECH == nil || *got.TLS.ECH != (model.ECH{Config: testECHConfig}) {
		t.Errorf("reality round trip: %v %+v", err, got.TLS)
	}
}

// FuzzECHRoundTrip: whatever bytes a config holds, Export must not panic, and a config the model
// accepts must come back from the link exactly (as standard base64) on every link protocol.
func FuzzECHRoundTrip(f *testing.F) {
	raw, _ := base64.StdEncoding.DecodeString(testECHConfig)
	f.Add(uint8(0), raw, false)
	f.Add(uint8(3), raw, true)
	f.Add(uint8(4), []byte{0, 0}, false)
	f.Add(uint8(1), []byte("AAAA"), true)
	protos := []model.Protocol{model.ProtoVLESS, model.ProtoTrojan, model.ProtoAnyTLS, model.ProtoHysteria2, model.ProtoTUIC}
	f.Fuzz(func(t *testing.T, which uint8, cfg []byte, urlAlphabet bool) {
		enc := base64.StdEncoding
		if urlAlphabet {
			enc = base64.RawURLEncoding
		}
		p := protos[int(which)%len(protos)]
		e := echEndpoint(p, &model.ECH{Enabled: true, Config: enc.EncodeToString(cfg)})
		link, ok := ShareLink(e)
		if !ok {
			t.Fatalf("%s: no link", p)
		}
		got, err := importer.Parse(link)
		if err != nil {
			t.Fatalf("%s: re-import of %q: %v", p, link, err)
		}
		if _, perr := model.ParseECHConfigList(e.TLS.ECH.Config); perr != nil {
			return // malformed: refused at save; the link only has to survive
		}
		want := base64.StdEncoding.EncodeToString(cfg)
		if got.TLS == nil || got.TLS.ECH == nil || got.TLS.ECH.Config != want || !got.TLS.ECH.Enabled {
			t.Fatalf("%s: %q came back as %+v", p, want, got.TLS)
		}
	})
}
