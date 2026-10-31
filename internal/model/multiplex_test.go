package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func muxEndpoint(p Protocol, m *Multiplex) Endpoint {
	params := map[string]any{"uuid": "00000000-0000-4000-8000-000000000021", "password": "pw"}
	if p == ProtoShadowsocks {
		params = map[string]any{"method": "aes-128-gcm", "password": "pw"}
	}
	return Endpoint{ID: "m", Name: "m", Engine: EngineSingBox, Protocol: p, Server: "192.0.2.21", Port: 443,
		Enabled: true, Params: params, Multiplex: m}
}

// TestMuxProblem: what the save refuses (the core would fail the whole config over it, or sing-box
// documents it as a conflict) and what it lets through.
func TestMuxProblem(t *testing.T) {
	brutal := func(up, down int) *Brutal { return &Brutal{Enabled: true, UpMbps: up, DownMbps: down} }
	cases := []struct {
		name  string
		proto Protocol
		m     *Multiplex
		want  string // substring of the refusal; "" = accepted
	}{
		{"none", ProtoVLESS, nil, ""},
		{"off on a protocol without it", ProtoHysteria2, &Multiplex{Protocol: "mux.cool", MaxStreams: -1}, ""},
		{"bare", ProtoVLESS, &Multiplex{Enabled: true}, ""},
		{"each protocol", ProtoTrojan, &Multiplex{Enabled: true, Protocol: "yamux", MaxConnections: 4, MinStreams: 4, Padding: true}, ""},
		{"shadowsocks", ProtoShadowsocks, &Multiplex{Enabled: true, Protocol: "smux", MaxStreams: 8}, ""},
		{"vmess h2mux", ProtoVMess, &Multiplex{Enabled: true, Protocol: "h2mux"}, ""},
		{"brutal at its bounds", ProtoVLESS, &Multiplex{Enabled: true, Brutal: brutal(1, BrutalMaxMbps)}, ""},
		{"brutal off with no rates", ProtoVLESS, &Multiplex{Enabled: true, Brutal: &Brutal{}}, ""},
		{"hysteria2", ProtoHysteria2, &Multiplex{Enabled: true}, "only on vless, vmess, trojan and shadowsocks"},
		{"tuic", ProtoTUIC, &Multiplex{Enabled: true}, "not tuic"},
		{"anytls", ProtoAnyTLS, &Multiplex{Enabled: true}, "not anytls"},
		{"wireguard", ProtoWireGuard, &Multiplex{Enabled: true}, "not wireguard"},
		{"socks", ProtoSOCKS, &Multiplex{Enabled: true}, "not socks"},
		{"mux.cool", ProtoVLESS, &Multiplex{Enabled: true, Protocol: "mux.cool"}, `unknown multiplex protocol "mux.cool"`},
		{"protocol case", ProtoVLESS, &Multiplex{Enabled: true, Protocol: "SMUX"}, "unknown multiplex protocol"},
		{"negative", ProtoVLESS, &Multiplex{Enabled: true, MaxConnections: -1}, "cannot be negative"},
		{"max_streams with max_connections", ProtoVLESS, &Multiplex{Enabled: true, MaxConnections: 4, MaxStreams: 8}, "cannot be combined"},
		{"max_streams with min_streams", ProtoVLESS, &Multiplex{Enabled: true, MinStreams: 4, MaxStreams: 8}, "cannot be combined"},
		{"brutal up missing", ProtoVLESS, &Multiplex{Enabled: true, Brutal: brutal(0, 50)}, "TCP Brutal needs"},
		{"brutal down negative", ProtoVLESS, &Multiplex{Enabled: true, Brutal: brutal(50, -1)}, "TCP Brutal needs"},
		{"brutal past the bound", ProtoVLESS, &Multiplex{Enabled: true, Brutal: brutal(BrutalMaxMbps+1, 50)}, "TCP Brutal needs"},
		{"brutal with max_connections", ProtoVLESS, &Multiplex{Enabled: true, MaxConnections: 4, Brutal: brutal(50, 100)}, "combined with TCP Brutal"},
		{"brutal with min_streams", ProtoTrojan, &Multiplex{Enabled: true, MinStreams: 4, Brutal: brutal(50, 100)}, "combined with TCP Brutal"},
		{"brutal with max_streams", ProtoShadowsocks, &Multiplex{Enabled: true, MaxStreams: 8, Brutal: brutal(50, 100)}, "combined with TCP Brutal"},
		{"brutal off keeps the pool", ProtoVLESS, &Multiplex{Enabled: true, MaxConnections: 4, MinStreams: 4, Brutal: &Brutal{UpMbps: 50}}, ""},
	}
	for _, c := range cases {
		e := muxEndpoint(c.proto, c.m)
		if c.proto == ProtoWireGuard {
			e.Params = map[string]any{"private_key": "k", "peer_public_key": "p"}
		}
		got := muxProblem(&e)
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%s: muxProblem = %q, want %q", c.name, got, c.want)
		}
		// The save asks EndpointParamProblem, which carries it; Validate does not, because the
		// generator leaves the setting out and only this connection loses it.
		if p := EndpointParamProblem(&e); c.want != "" && p != got {
			t.Errorf("%s: EndpointParamProblem = %q, want %q", c.name, p, got)
		}
		if c.want != "" {
			prof := Profile{Endpoints: []Endpoint{e}, Rules: []Rule{{ID: "def", Default: true, Outbound: "m"}}}
			if err := prof.Validate(); err != nil && strings.Contains(err.Error(), got) {
				t.Errorf("%s: Validate refuses a profile over its multiplex: %v", c.name, err)
			}
		}
	}
}

// TestNormalizeMultiplex: what an importer keeps is what sing-mux acts on, and never something the
// save refuses.
func TestNormalizeMultiplex(t *testing.T) {
	cases := []struct {
		name  string
		proto Protocol
		in    *Multiplex
		want  *Multiplex
		note  string
	}{
		{"nil", ProtoVLESS, nil, nil, ""},
		{"off", ProtoVLESS, &Multiplex{Protocol: "smux"}, nil, ""},
		{"protocol without it", ProtoHysteria2, &Multiplex{Enabled: true}, nil, "not hysteria2"},
		{"mux.cool", ProtoTrojan, &Multiplex{Enabled: true, Protocol: "mux.cool"}, nil, `"mux.cool" is not a sing-mux protocol`},
		{"case and space", ProtoTrojan, &Multiplex{Enabled: true, Protocol: " SMux "}, &Multiplex{Enabled: true, Protocol: "smux"}, ""},
		{"max_connections wins", ProtoVLESS, &Multiplex{Enabled: true, MaxConnections: 4, MinStreams: 2, MaxStreams: 8},
			&Multiplex{Enabled: true, MaxConnections: 4, MinStreams: 2}, ""},
		{"max_streams over min_streams", ProtoVMess, &Multiplex{Enabled: true, MinStreams: 2, MaxStreams: 8},
			&Multiplex{Enabled: true, MaxStreams: 8}, ""},
		{"negative counts", ProtoShadowsocks, &Multiplex{Enabled: true, MaxConnections: -1, MaxStreams: -2, Padding: true},
			&Multiplex{Enabled: true, Padding: true}, ""},
		{"brutal kept", ProtoVLESS, &Multiplex{Enabled: true, Brutal: &Brutal{Enabled: true, UpMbps: 50, DownMbps: 100}},
			&Multiplex{Enabled: true, Brutal: &Brutal{Enabled: true, UpMbps: 50, DownMbps: 100}}, ""},
		{"brutal kept drops the pool", ProtoTrojan, &Multiplex{Enabled: true, MaxConnections: 4, MinStreams: 4, MaxStreams: 8, Padding: true,
			Brutal: &Brutal{Enabled: true, UpMbps: 50, DownMbps: 100}},
			&Multiplex{Enabled: true, Padding: true, Brutal: &Brutal{Enabled: true, UpMbps: 50, DownMbps: 100}}, ""},
		{"brutal dropped", ProtoVLESS, &Multiplex{Enabled: true, MaxConnections: 2, Brutal: &Brutal{Enabled: true, UpMbps: 0, DownMbps: 100}},
			&Multiplex{Enabled: true, MaxConnections: 2}, "TCP Brutal dropped"},
		{"brutal off", ProtoVLESS, &Multiplex{Enabled: true, Brutal: &Brutal{UpMbps: 50}}, &Multiplex{Enabled: true}, ""},
	}
	for _, c := range cases {
		got, note := NormalizeMultiplex(c.proto, c.in)
		if !reflect.DeepEqual(got, c.want) {
			gb, _ := json.Marshal(got)
			wb, _ := json.Marshal(c.want)
			t.Errorf("%s: %s, want %s", c.name, gb, wb)
		}
		if (c.note == "") != (note == "") || !strings.Contains(note, c.note) {
			t.Errorf("%s: note %q, want %q", c.name, note, c.note)
		}
		if got != nil {
			e := muxEndpoint(c.proto, got)
			if p := muxProblem(&e); p != "" {
				t.Errorf("%s: the normalised block is refused: %s", c.name, p)
			}
		}
	}
}

// TestMultiplexJSON: an endpoint without multiplex stores no key, and one with it the sing-box names.
func TestMultiplexJSON(t *testing.T) {
	b, _ := json.Marshal(muxEndpoint(ProtoTrojan, nil))
	if strings.Contains(string(b), "multiplex") {
		t.Fatalf("no multiplex, but the key is stored: %s", b)
	}
	b, _ = json.Marshal(&Multiplex{Enabled: true, Protocol: "smux", MaxConnections: 4, MinStreams: 4, MaxStreams: 8, Padding: true,
		Brutal: &Brutal{Enabled: true, UpMbps: 50, DownMbps: 100}})
	want := `{"enabled":true,"protocol":"smux","max_connections":4,"min_streams":4,"max_streams":8,"padding":true,"brutal":{"enabled":true,"up_mbps":50,"down_mbps":100}}`
	if string(b) != want {
		t.Fatalf("got %s\nwant %s", b, want)
	}
	if MuxUoTIgnored(&Endpoint{Protocol: ProtoShadowsocks, Params: map[string]any{"udp_over_tcp": true}, Multiplex: &Multiplex{Enabled: true}}) != true {
		t.Error("ss + udp_over_tcp + multiplex is not reported as ignored")
	}
}

// TestMuxUoTReadsLikeTheGenerator: udp_over_tcp is read as the generator writes it (model.ParamBool,
// the generator's boolp), so a restored profile with the switch as a string is reported, as the
// generator then writes UDP over TCP and leaves the multiplex out.
func TestMuxUoTReadsLikeTheGenerator(t *testing.T) {
	for v, want := range map[any]bool{true: true, "true": true, "1": true, "yes": true,
		false: false, "false": false, "0": false, "no": false, "": false, 1.0: false, nil: false} {
		e := muxEndpoint(ProtoShadowsocks, &Multiplex{Enabled: true})
		e.Params["udp_over_tcp"] = v
		if got := MuxUoTIgnored(&e); got != want {
			t.Errorf("udp_over_tcp %#v: MuxUoTIgnored = %v, want %v", v, got, want)
		}
		if got := ParamBool(e.Params, "udp_over_tcp"); got != want {
			t.Errorf("udp_over_tcp %#v: ParamBool = %v, want %v", v, got, want)
		}
	}
	// Only on Shadowsocks with multiplex on.
	e := muxEndpoint(ProtoTrojan, &Multiplex{Enabled: true})
	e.Params["udp_over_tcp"] = "true"
	if MuxUoTIgnored(&e) {
		t.Error("trojan with udp_over_tcp reported")
	}
	e = muxEndpoint(ProtoShadowsocks, &Multiplex{})
	e.Params["udp_over_tcp"] = "true"
	if MuxUoTIgnored(&e) {
		t.Error("multiplex off reported")
	}
}
