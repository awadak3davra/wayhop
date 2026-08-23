package generator

import (
	"testing"

	"wayhop/internal/model"
)

// TestOutboundTUIC_StrayTransportKeepsALPN (round-5): a stray grpc/http/ws transport on a QUIC
// protocol (TUIC) is dropped from output (transportCapable=false), but the ALPN-strip blocks used to
// still fire on e.Transport.Type and delete TUIC's h3 ALPN — producing a QUIC outbound with no ALPN
// that passes `sing-box check` but fails every connection. The strip now gates on transportCapable,
// so the h3 ALPN survives and no stray transport is emitted.
func TestOutboundTUIC_StrayTransportKeepsALPN(t *testing.T) {
	const tuicUUID = "11111111-2222-3333-4444-555555555555"
	for _, tr := range []string{"grpc", "http", "ws"} {
		e := model.Endpoint{
			ID: "tuic-tr", Engine: model.EngineSingBox, Protocol: model.ProtoTUIC,
			Server: "s", Port: 443, Enabled: true,
			Params:    map[string]any{"uuid": tuicUUID, "password": "p"},
			TLS:       &model.TLS{Enabled: true, Type: "tls", SNI: "x"},
			Transport: &model.Transport{Type: tr}, // stray transport on a QUIC protocol
		}
		ob := generator_genOne(t, e)
		tl, _ := ob["tls"].(map[string]any)
		if tl == nil {
			t.Fatalf("%s: no tls block emitted", tr)
		}
		if got, _ := tl["alpn"].([]string); len(got) != 1 || got[0] != "h3" {
			t.Errorf("stray %s transport must not strip TUIC's h3 ALPN, got alpn=%v", tr, tl["alpn"])
		}
		if _, hasT := ob["transport"]; hasT {
			t.Errorf("%s: a stray transport must not be emitted on a QUIC (non-transport-capable) protocol", tr)
		}
	}
}
