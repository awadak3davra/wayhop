package plugin

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

func TestAwgConfig(t *testing.T) {
	e := model.Endpoint{
		ID: "awg1", Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
		Server: "198.51.100.20", Port: 51820,
		Params: map[string]any{
			"private_key": "PRIV", "peer_public_key": "PUB", "pre_shared_key": "PSK",
			"local_address":        []string{"10.8.0.2/32"},
			"persistent_keepalive": 25,
			"jc":                   4, "jmin": 40, "jmax": 70, "s1": 0, "s2": 0,
			"h1": 1, "h2": 2, "h3": 3, "h4": float64(4), // float64 simulates a JSON round-trip
		},
	}
	cfg, fname, err := NativeConfig(e, 0)
	if err != nil {
		t.Fatal(err)
	}
	if fname != "awg1.conf" {
		t.Fatalf("filename = %s", fname)
	}
	for _, want := range []string{
		"[Interface]", "PrivateKey = PRIV", "Address = 10.8.0.2/32",
		"Jc = 4", "Jmin = 40", "Jmax = 70", "H4 = 4",
		"[Peer]", "PublicKey = PUB", "PresharedKey = PSK",
		"Endpoint = 198.51.100.20:51820", "AllowedIPs = 0.0.0.0/0",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("awg config missing %q\n---\n%s", want, cfg)
		}
	}
}

func TestOlcConfig(t *testing.T) {
	e := model.Endpoint{
		ID: "olc1", Engine: model.EngineOlcRTC, Protocol: model.ProtoOlcRTC,
		Server: "meet.x", Port: 443,
		Params: map[string]any{"provider": "telemost", "room": "https://telemost.yandex.ru/j/1", "key": "KEY", "transport": "vp8channel"},
	}
	cfg, fname, err := NativeConfig(e, 17901)
	if err != nil {
		t.Fatal(err)
	}
	if fname != "olc1.yaml" {
		t.Fatalf("filename = %s", fname)
	}
	for _, want := range []string{"mode: cnc", `provider: "telemost"`, `id: "https://telemost.yandex.ru/j/1"`, `key: "KEY"`, `transport: "vp8channel"`, "port: 17901", `dns: "8.8.8.8:53"`} {
		if !strings.Contains(cfg, want) {
			t.Errorf("olc config missing %q\n---\n%s", want, cfg)
		}
	}
}

// TestOlcConfig_EscapesSpecialChars: a room id / key / provider is untrusted free
// text (imported config or API). The renderer must escape it into a valid YAML
// double-quoted scalar so a value containing a quote can't break the document or
// inject extra keys — the old render interpolated id/key raw inside quotes (and left
// provider/transport unquoted), so `room"id` or a newline produced invalid YAML and
// broke olcRTC bring-up.
func TestOlcConfig_EscapesSpecialChars(t *testing.T) {
	e := model.Endpoint{
		ID: "olc2", Engine: model.EngineOlcRTC, Protocol: model.ProtoOlcRTC,
		Server: "meet.x", Port: 443,
		Params: map[string]any{
			"provider": "prov with space",
			"room":     `room"break: injected`,
			"key":      "key\nwith\nnewlines",
		},
	}
	cfg, _, err := NativeConfig(e, 8808)
	if err != nil {
		t.Fatal(err)
	}
	// The embedded quote must be escaped, not left raw (raw would terminate the scalar).
	if strings.Contains(cfg, `id: "room"break`) {
		t.Errorf("room id quote left UNESCAPED (YAML breaks / injects):\n%s", cfg)
	}
	if !strings.Contains(cfg, `id: "room\"break: injected"`) {
		t.Errorf("room id not properly escaped:\n%s", cfg)
	}
	// A raw newline in the rendered value would split the YAML line; it must be \n-escaped.
	if strings.Contains(cfg, "key\nwith") {
		t.Errorf("key newline left raw (splits the YAML line):\n%s", cfg)
	}
	if !strings.Contains(cfg, `key: "key\nwith\nnewlines"`) {
		t.Errorf("key newlines not escaped:\n%s", cfg)
	}
	if !strings.Contains(cfg, `provider: "prov with space"`) {
		t.Errorf("provider not quoted:\n%s", cfg)
	}
}

func TestNativeConfigUnknownEngine(t *testing.T) {
	if _, _, err := NativeConfig(model.Endpoint{Engine: model.EngineSingBox}, 0); err == nil {
		t.Fatal("expected error for a sing-box engine")
	}
}
