package generator

import (
	"testing"

	"velinx/internal/model"
)

// generatorTestPBK is a real x25519 reality public key (base64url of 32 bytes) for
// fixtures — the generator now validates the key (a fake one degrades to plain TLS).
const generatorTestPBK = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"

// A Reality endpoint with no fingerprint must still emit a utls block (sing-box
// requires uTLS for Reality), defaulting to chrome — otherwise sing-box rejects
// the generated config.
func TestRealityWithoutFingerprintGetsUTLS(t *testing.T) {
	e := model.Endpoint{
		ID: "r", Name: "R", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: "s", Port: 443, Enabled: true,
		Params: map[string]any{"uuid": "u"},
		// Reality, but NO Fingerprint set.
		TLS: &model.TLS{Enabled: true, Type: "reality", SNI: "yandex.ru", PublicKey: generatorTestPBK, ShortID: "ab12"},
	}
	p := &model.Profile{
		Endpoints: []model.Endpoint{e},
		Rules:     []model.Rule{{ID: "d", Default: true, Outbound: "r"}},
	}
	res, err := Generate(p, Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	obs := res.Config["outbounds"].([]map[string]any)
	var vless map[string]any
	for _, o := range obs {
		if o["tag"] == "r" {
			vless = o
		}
	}
	if vless == nil {
		t.Fatal("vless outbound missing")
	}
	tls := vless["tls"].(map[string]any)
	utls, ok := tls["utls"].(map[string]any)
	if !ok {
		t.Fatal("reality outbound must include a utls block (sing-box requires it)")
	}
	if utls["enabled"] != true || utls["fingerprint"] != "chrome" {
		t.Fatalf("utls = %v, want enabled + chrome default", utls)
	}
	if _, ok := tls["reality"].(map[string]any); !ok {
		t.Fatal("reality block missing")
	}
}

// An explicit fingerprint must be preserved (not overridden by the chrome default).
func TestRealityKeepsExplicitFingerprint(t *testing.T) {
	e := model.Endpoint{
		ID: "r", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "s", Port: 443, Enabled: true,
		Params: map[string]any{"uuid": "u"},
		TLS:    &model.TLS{Enabled: true, Type: "reality", Fingerprint: "firefox", PublicKey: generatorTestPBK},
	}
	res, err := Generate(&model.Profile{Endpoints: []model.Endpoint{e}}, Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	obs := res.Config["outbounds"].([]map[string]any)
	for _, o := range obs {
		if o["tag"] == "r" {
			utls := o["tls"].(map[string]any)["utls"].(map[string]any)
			if utls["fingerprint"] != "firefox" {
				t.Fatalf("fingerprint = %v, want firefox (explicit value preserved)", utls["fingerprint"])
			}
			return
		}
	}
	t.Fatal("vless outbound missing")
}
