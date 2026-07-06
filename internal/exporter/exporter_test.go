package exporter

import (
	"strings"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

func TestRoundTripShareLinks(t *testing.T) {
	cases := []model.Endpoint{
		{
			Name: "Reality", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
			Server: "203.0.113.10", Port: 443,
			Params: map[string]any{"uuid": "11111111-2222-3333-4444-555555555555", "flow": "xtls-rprx-vision"},
			TLS:    &model.TLS{Enabled: true, Type: "reality", SNI: "www.microsoft.com", Fingerprint: "chrome", PublicKey: "PUBKEYabc", ShortID: "ab12"},
		},
		{
			Name: "Trojan WS", Engine: model.EngineSingBox, Protocol: model.ProtoTrojan,
			Server: "1.2.3.4", Port: 443, Params: map[string]any{"password": "s3cret"},
			Transport: &model.Transport{Type: "ws", Path: "/tj", Host: "cdn.example.com"},
			TLS:       &model.TLS{Enabled: true, Type: "tls", SNI: "cdn.example.com"},
		},
		{
			Name: "HY2", Engine: model.EngineSingBox, Protocol: model.ProtoHysteria2,
			Server: "5.6.7.8", Port: 8443,
			Params: map[string]any{"password": "hpass", "obfs": "salamander", "obfs_password": "ob"},
			TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "example.org"},
		},
		{
			Name: "SS", Engine: model.EngineSingBox, Protocol: model.ProtoShadowsocks,
			Server: "9.9.9.9", Port: 8388,
			Params: map[string]any{"method": "aes-256-gcm", "password": "sspw"},
		},
	}
	for _, e := range cases {
		link, ok := ShareLink(e)
		if !ok {
			t.Fatalf("%s: ShareLink not ok", e.Name)
		}
		got, err := importer.Parse(link)
		if err != nil {
			t.Fatalf("%s: re-import failed: %v\nlink=%s", e.Name, err, link)
		}
		if got.Protocol != e.Protocol || got.Server != e.Server || got.Port != e.Port {
			t.Errorf("%s: core mismatch: %+v (link=%s)", e.Name, got, link)
		}
		for k, v := range e.Params {
			if gv, ok := got.Params[k]; !ok || gv != v {
				t.Errorf("%s: param %q = %v, want %v", e.Name, k, gv, v)
			}
		}
		if e.TLS != nil {
			if got.TLS == nil || got.TLS.Type != e.TLS.Type {
				t.Errorf("%s: tls type mismatch: %+v", e.Name, got.TLS)
			} else if e.TLS.Type == "reality" && (got.TLS.PublicKey != e.TLS.PublicKey || got.TLS.ShortID != e.TLS.ShortID) {
				t.Errorf("%s: reality keys lost: %+v", e.Name, got.TLS)
			}
		}
		if e.Transport != nil && (got.Transport == nil || got.Transport.Type != e.Transport.Type || got.Transport.Path != e.Transport.Path) {
			t.Errorf("%s: transport mismatch: %+v", e.Name, got.Transport)
		}
	}
}

func TestRoundTripAmneziaWGConf(t *testing.T) {
	e := model.Endpoint{
		Name: "AWG", Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
		Server: "198.51.100.20", Port: 51820,
		Params: map[string]any{
			"private_key": "PRIV=", "peer_public_key": "PUB=", "local_address": []string{"10.13.13.2/32"},
			"jc": 4, "jmin": 40, "jmax": 70, "h1": 1, "h2": 2, "h3": 3, "h4": 4,
		},
	}
	r, ok := Export(e)
	if !ok || r.Kind != "conf" {
		t.Fatalf("export = %+v ok=%v", r, ok)
	}
	if !strings.Contains(r.Text, "Endpoint = 198.51.100.20:51820") || !strings.Contains(r.Text, "Jc = 4") {
		t.Errorf("awg conf missing fields:\n%s", r.Text)
	}
	got, err := importer.Parse(r.Text)
	if err != nil {
		t.Fatalf("re-import conf: %v", err)
	}
	if got.Server != e.Server || got.Port != e.Port {
		t.Errorf("conf round-trip host/port: %s:%d", got.Server, got.Port)
	}
}

// TestExportTypedMTUKeepalive: MTU + PersistentKeepalive set on the TYPED Endpoint fields
// (as the UI now writes them, dropping the legacy Params copy on edit) must still appear in
// the exported .conf — else a UI-edited tunnel would export without them.
func TestExportTypedMTUKeepalive(t *testing.T) {
	e := model.Endpoint{
		Name: "WG", Engine: model.EngineSingBox, Protocol: model.ProtoWireGuard,
		Server: "203.0.113.7", Port: 51820,
		MTU: 1280, PersistentKeepalive: 25,
		Params: map[string]any{"private_key": "PRIV=", "peer_public_key": "PUB="},
	}
	r, ok := Export(e)
	if !ok || r.Kind != "conf" {
		t.Fatalf("export = %+v ok=%v", r, ok)
	}
	if !strings.Contains(r.Text, "MTU = 1280") {
		t.Errorf("typed MTU not exported:\n%s", r.Text)
	}
	if !strings.Contains(r.Text, "PersistentKeepalive = 25") {
		t.Errorf("typed PersistentKeepalive not exported:\n%s", r.Text)
	}
}

func TestExportUnsupported(t *testing.T) {
	if _, ok := Export(model.Endpoint{Protocol: model.ProtoOlcRTC}); ok {
		t.Error("olcrtc should not be exportable as a link/conf")
	}
}
