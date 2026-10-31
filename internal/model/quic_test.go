package model

import (
	"strings"
	"testing"
)

// QUICTuningOf reads the shapes a param takes on its way in (an import's int, the store's float64,
// the API's string) and leaves out a packet size quic-go would not use as given, and anything on a
// protocol whose outbound has no QUIC fields.
func TestQUICTuningOf(t *testing.T) {
	ep := func(proto Protocol, params map[string]any) *Endpoint {
		return &Endpoint{ID: "q", Protocol: proto, Params: params}
	}
	cases := []struct {
		name    string
		e       *Endpoint
		size    int
		noPMTUD bool
	}{
		{"int", ep(ProtoTUIC, map[string]any{ParamQUICInitialPacketSize: 1232}), 1232, false},
		{"store float", ep(ProtoHysteria2, map[string]any{ParamQUICInitialPacketSize: float64(1452), ParamQUICDisablePMTUD: true}), 1452, true},
		{"api string", ep(ProtoTUIC, map[string]any{ParamQUICInitialPacketSize: " 1200 ", ParamQUICDisablePMTUD: "true"}), 1200, true},
		{"below range", ep(ProtoTUIC, map[string]any{ParamQUICInitialPacketSize: 1199}), 0, false},
		{"above range", ep(ProtoTUIC, map[string]any{ParamQUICInitialPacketSize: 1453}), 0, false},
		{"wraps uint16", ep(ProtoTUIC, map[string]any{ParamQUICInitialPacketSize: 65536 + 1280}), 0, false},
		{"fraction", ep(ProtoTUIC, map[string]any{ParamQUICInitialPacketSize: 1280.5}), 0, false},
		{"garbage", ep(ProtoTUIC, map[string]any{ParamQUICInitialPacketSize: "big"}), 0, false},
		{"pmtud false", ep(ProtoHysteria2, map[string]any{ParamQUICDisablePMTUD: false}), 0, false},
		{"not quic", ep(ProtoVLESS, map[string]any{ParamQUICInitialPacketSize: 1280, ParamQUICDisablePMTUD: true}), 0, false},
		{"nil params", ep(ProtoTUIC, nil), 0, false},
	}
	for _, c := range cases {
		size, off := QUICTuningOf(c.e)
		if size != c.size || off != c.noPMTUD {
			t.Errorf("%s: QUICTuningOf = (%d, %v), want (%d, %v)", c.name, size, off, c.size, c.noPMTUD)
		}
		if HasQUICTuning(c.e) != (c.size > 0 || c.noPMTUD) {
			t.Errorf("%s: HasQUICTuning disagrees with QUICTuningOf", c.name)
		}
	}
	if s, off := QUICTuningOf(nil); s != 0 || off {
		t.Error("a nil endpoint has no tuning")
	}
}

// Saving refuses a Hysteria2 or TUIC size quic-go would not run as given (sing-box takes 9000 and the
// connection then runs at 1452), as it refuses an out-of-range MTU. No size, or 0 (sing-box's unset),
// is fine, and the key means nothing on another protocol.
func TestValidateRefusesAnOutOfRangeQUICSize(t *testing.T) {
	prof := func(proto Protocol, size any) *Profile {
		params := map[string]any{"uuid": "2dd61d93-75d8-4da4-ac0e-6aece7eac365", "password": "pw"}
		if size != nil {
			params[ParamQUICInitialPacketSize] = size
		}
		return &Profile{Endpoints: []Endpoint{{ID: "q", Name: "q", Enabled: true, Engine: EngineSingBox, Protocol: proto,
			Server: "192.0.2.5", Port: 8443, TLS: &TLS{Enabled: true, Type: "tls", SNI: "q.example.com"}, Params: params}}}
	}
	for _, proto := range []Protocol{ProtoTUIC, ProtoHysteria2} {
		for _, bad := range []any{9000, float64(1199), "1453", "big", 1280.5, -1} {
			err := prof(proto, bad).Validate()
			if err == nil || !strings.Contains(err.Error(), ParamQUICInitialPacketSize) {
				t.Errorf("%s size %v: Validate = %v, want it refused", proto, bad, err)
			}
		}
		for _, ok := range []any{nil, 1200, float64(1452), "1232", "", 0} {
			if err := prof(proto, ok).Validate(); err != nil {
				t.Errorf("%s size %v: Validate = %v, want it accepted", proto, ok, err)
			}
		}
	}
	if err := prof(ProtoVLESS, 9000).Validate(); err != nil {
		t.Errorf("vless carries no QUIC fields, so the key is not judged: %v", err)
	}
}

// An imported size is the one the source config ran with: sing-quic cuts it to 16 bits and quic-go
// clamps it into 1200..1452; 0 and anything that cuts to 0 is the default.
func TestQUICEffectiveInitialPacketSize(t *testing.T) {
	for in, want := range map[int]int{0: 0, -5: 0, 1000: 1200, 1200: 1200, 1232: 1232, 1452: 1452, 9000: 1452,
		65536: 0, 65536 + 1000: 1200, 65536 + 1300: 1300, 70000: 1452} {
		if got := QUICEffectiveInitialPacketSize(in); got != want {
			t.Errorf("QUICEffectiveInitialPacketSize(%d) = %d, want %d", in, got, want)
		}
	}
}
