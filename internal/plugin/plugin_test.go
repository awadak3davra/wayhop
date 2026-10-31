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

func TestNativeConfigUnknownEngine(t *testing.T) {
	if _, _, err := NativeConfig(model.Endpoint{Engine: model.EngineSingBox}, 0); err == nil {
		t.Fatal("expected error for a sing-box engine")
	}
}
