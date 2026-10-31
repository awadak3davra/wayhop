package exporter

import (
	"testing"

	"wayhop/internal/model"
)

// TestMultiplexLeavesLinksUnchanged: no share-link convention for sing-mux is common to the clients
// that read these links (v2rayN, NekoBox and husi have none; Hiddify's mux parameters are its own), so
// a connection exports the same link with multiplex as without it; the profile JSON carries it.
func TestMultiplexLeavesLinksUnchanged(t *testing.T) {
	uuid := "00000000-0000-4000-8000-000000000021"
	tls := &model.TLS{Enabled: true, Type: "tls", SNI: "example.com"}
	for _, e := range []model.Endpoint{
		{Protocol: model.ProtoVLESS, Params: map[string]any{"uuid": uuid, "flow": "xtls-rprx-vision"}, TLS: tls},
		{Protocol: model.ProtoVMess, Params: map[string]any{"uuid": uuid, "alter_id": 0, "security": "auto"}, TLS: tls,
			Transport: &model.Transport{Type: "ws", Path: "/m"}},
		{Protocol: model.ProtoTrojan, Params: map[string]any{"password": "pw"}, TLS: tls},
		{Protocol: model.ProtoShadowsocks, Params: map[string]any{"method": "aes-128-gcm", "password": "pw"}},
	} {
		e.ID, e.Name, e.Engine, e.Server, e.Port, e.Enabled = "m", "m", model.EngineSingBox, "192.0.2.60", 443, true
		plain, ok := ShareLink(e)
		if !ok {
			t.Fatalf("%s: no link", e.Protocol)
		}
		e.Multiplex = &model.Multiplex{Enabled: true, Protocol: "smux", MaxConnections: 4, MinStreams: 4, Padding: true,
			Brutal: &model.Brutal{Enabled: true, UpMbps: 50, DownMbps: 100}}
		if withMux, _ := ShareLink(e); withMux != plain {
			t.Errorf("%s: multiplex changed the link:\n%s\n%s", e.Protocol, plain, withMux)
		}
	}
}
