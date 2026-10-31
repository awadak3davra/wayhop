package generator

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// muxTestEndpoint is a capable protocol's endpoint with the params its outbound needs.
func muxTestEndpoint(p model.Protocol, m *model.Multiplex) model.Endpoint {
	params := map[string]any{"uuid": "00000000-0000-4000-8000-000000000021", "password": "pw"}
	if p == model.ProtoShadowsocks {
		params = map[string]any{"method": "aes-128-gcm", "password": "pw"}
	}
	e := generator_singBoxEndpoint("mux-"+string(p), p, params)
	if p != model.ProtoShadowsocks {
		e.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: "example.com"}
	}
	e.Multiplex = m
	return e
}

// TestMultiplexOutbound pins what multiplexJSON renders from each shape the model can hold, including
// the ones the save refuses (a profile restored from a backup or edited by hand carries them anyway):
// those degrade to what the core loads instead of failing the shared config.
func TestMultiplexOutbound(t *testing.T) {
	brutal := func(up, down int) *model.Brutal { return &model.Brutal{Enabled: true, UpMbps: up, DownMbps: down} }
	cases := []struct {
		name string
		m    *model.Multiplex
		want map[string]any // nil: no multiplex key at all
	}{
		{"nil", nil, nil},
		{"disabled with settings", &model.Multiplex{Protocol: "smux", MaxConnections: 4, Padding: true, Brutal: brutal(10, 10)}, nil},
		{"bare", &model.Multiplex{Enabled: true}, map[string]any{"enabled": true}},
		{"pool", &model.Multiplex{Enabled: true, Protocol: "smux", MaxConnections: 4, MinStreams: 4},
			map[string]any{"enabled": true, "protocol": "smux", "max_connections": 4, "min_streams": 4}},
		{"max_connections wins over max_streams", &model.Multiplex{Enabled: true, MaxConnections: 2, MaxStreams: 8},
			map[string]any{"enabled": true, "max_connections": 2}},
		{"max_streams alone", &model.Multiplex{Enabled: true, Protocol: "yamux", MinStreams: 4, MaxStreams: 8},
			map[string]any{"enabled": true, "protocol": "yamux", "max_streams": 8}},
		{"min_streams alone is never read", &model.Multiplex{Enabled: true, MinStreams: 4}, map[string]any{"enabled": true}},
		{"negative counts", &model.Multiplex{Enabled: true, MaxConnections: -1, MinStreams: -2, MaxStreams: -3}, map[string]any{"enabled": true}},
		{"padding", &model.Multiplex{Enabled: true, Protocol: "h2mux", Padding: true},
			map[string]any{"enabled": true, "protocol": "h2mux", "padding": true}},
		{"unknown protocol (an Xray mux.cool)", &model.Multiplex{Enabled: true, Protocol: "mux.cool"}, nil},
		{"protocol in another case", &model.Multiplex{Enabled: true, Protocol: "SMUX"}, nil},
		{"brutal holds one connection", &model.Multiplex{Enabled: true, MaxConnections: 4, MinStreams: 4, Padding: true, Brutal: brutal(50, 100)},
			map[string]any{"enabled": true, "padding": true, "brutal": map[string]any{"enabled": true, "up_mbps": 50, "down_mbps": 100}}},
		{"brutal at its bounds", &model.Multiplex{Enabled: true, Brutal: brutal(1, model.BrutalMaxMbps)},
			map[string]any{"enabled": true, "brutal": map[string]any{"enabled": true, "up_mbps": 1, "down_mbps": model.BrutalMaxMbps}}},
		{"brutal with no upload rate", &model.Multiplex{Enabled: true, MaxConnections: 4, Brutal: brutal(0, 100)},
			map[string]any{"enabled": true, "max_connections": 4}},
		{"brutal with a negative rate", &model.Multiplex{Enabled: true, Brutal: brutal(50, -1)}, map[string]any{"enabled": true}},
		{"brutal past the bound", &model.Multiplex{Enabled: true, Brutal: brutal(model.BrutalMaxMbps+1, 50)}, map[string]any{"enabled": true}},
		{"brutal switched off keeps the pool", &model.Multiplex{Enabled: true, MaxStreams: 8, Brutal: &model.Brutal{UpMbps: 50, DownMbps: 50}},
			map[string]any{"enabled": true, "max_streams": 8}},
	}
	for _, p := range []model.Protocol{model.ProtoVLESS, model.ProtoVMess, model.ProtoTrojan, model.ProtoShadowsocks} {
		for _, c := range cases {
			e := muxTestEndpoint(p, c.m)
			ob, err := outboundFor(&e)
			if err != nil {
				t.Fatalf("%s/%s: %v", p, c.name, err)
			}
			got, has := ob["multiplex"]
			switch {
			case c.want == nil && has:
				t.Errorf("%s/%s: multiplex = %v, want none", p, c.name, got)
			case c.want != nil && !reflect.DeepEqual(got, c.want):
				t.Errorf("%s/%s: multiplex = %#v, want %#v", p, c.name, got, c.want)
			}
		}
	}

	// Shadowsocks with UDP over TCP never builds the multiplex client, so nothing is emitted for it.
	ss := muxTestEndpoint(model.ProtoShadowsocks, &model.Multiplex{Enabled: true, Protocol: "smux"})
	ss.Params["udp_over_tcp"] = true
	if ob, _ := outboundFor(&ss); ob["multiplex"] != nil || ob["udp_over_tcp"] != true {
		t.Errorf("ss + udp_over_tcp: %v", ob)
	}
	// A restored or hand-edited profile can carry the switch as a string, which the generator writes
	// as UDP over TCP just the same; the multiplex must then go too, not ride beside it unused.
	for _, v := range []any{"true", "1", "yes"} {
		ss.Params["udp_over_tcp"] = v
		if ob, _ := outboundFor(&ss); ob["multiplex"] != nil || ob["udp_over_tcp"] != true || !model.MuxUoTIgnored(&ss) {
			t.Errorf("ss + udp_over_tcp %q: %v, MuxUoTIgnored %v", v, ob, model.MuxUoTIgnored(&ss))
		}
	}
	for _, v := range []any{false, "false", "0", "no", ""} {
		ss.Params["udp_over_tcp"] = v
		if ob, _ := outboundFor(&ss); ob["multiplex"] == nil || ob["udp_over_tcp"] != nil || model.MuxUoTIgnored(&ss) {
			t.Errorf("ss + udp_over_tcp %#v: %v, MuxUoTIgnored %v", v, ob, model.MuxUoTIgnored(&ss))
		}
	}
}

// TestMultiplexEveryProtocol puts multiplex on every endpoint of the all-protocols profile: only the
// four outbounds that have the field carry it, and on every other one it is left out, since there the
// core fails the whole config on it (`json: unknown field "multiplex"`).
func TestMultiplexEveryProtocol(t *testing.T) {
	p := allProtocolProfile()
	for i := range p.Endpoints {
		p.Endpoints[i].Multiplex = &model.Multiplex{Enabled: true, Protocol: "yamux", MaxConnections: 2}
	}
	res, err := Generate(p, Options{MixedPort: 7890, CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if err != nil {
		t.Fatal(err)
	}
	carriers := map[string]bool{"vless": true, "vmess": true, "trojan": true, "shadowsocks": true}
	seen := map[string]bool{}
	for _, ob := range res.Config["outbounds"].([]map[string]any) {
		typ, _ := ob["type"].(string)
		_, has := ob["multiplex"]
		if has != carriers[typ] {
			t.Errorf("outbound %v (%s): multiplex present = %v", ob["tag"], typ, has)
		}
		if has {
			seen[typ] = true
		}
	}
	if eps, ok := res.Config["endpoints"].([]map[string]any); ok {
		for _, ep := range eps {
			if _, has := ep["multiplex"]; has {
				t.Errorf("endpoint %v carries multiplex", ep["tag"])
			}
		}
	}
	if len(seen) != len(carriers) {
		t.Errorf("multiplex reached only %v", seen)
	}
}

// TestMultiplexOffIsByteIdentical: a profile without multiplex, one with it switched off, and one with
// it only where the core has no field for it render the same bytes, on every core line.
func TestMultiplexOffIsByteIdentical(t *testing.T) {
	render := func(p *model.Profile, core string) []byte {
		t.Helper()
		res, err := Generate(p, Options{MixedPort: 7890, CoreVersion: core, CacheFile: "/var/cache.db"})
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(res.Config)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, core := range []string{"", "sing-box version 1.12.17\n", "sing-box version 1.13.21\n", "sing-box version 1.14.4\n",
		"sing-box version 1.15.0-alpha.13\n"} {
		base := render(allProtocolProfile(), core)
		if bytes.Contains(base, []byte(`"multiplex"`)) {
			t.Fatalf("a profile without multiplex renders one:\n%s", base)
		}
		off := allProtocolProfile()
		stray := allProtocolProfile()
		for i := range off.Endpoints {
			off.Endpoints[i].Multiplex = &model.Multiplex{Protocol: "smux", MaxConnections: 4, Padding: true,
				Brutal: &model.Brutal{Enabled: true, UpMbps: 10, DownMbps: 10}}
			if !model.MultiplexCapable(stray.Endpoints[i].Protocol) {
				stray.Endpoints[i].Multiplex = &model.Multiplex{Enabled: true, Protocol: "h2mux"}
			}
		}
		if got := render(off, core); !bytes.Equal(got, base) {
			t.Errorf("core %q: multiplex switched off changed the config", core)
		}
		if got := render(stray, core); !bytes.Equal(got, base) {
			t.Errorf("core %q: multiplex where no outbound has it changed the config", core)
		}
	}
	// The stored endpoint too: no multiplex, no key.
	b, _ := json.Marshal(muxTestEndpoint(model.ProtoTrojan, nil))
	if strings.Contains(string(b), "multiplex") {
		t.Errorf("an endpoint without multiplex stores the key: %s", b)
	}
}

// TestMultiplexSingBoxCheck runs the real check on every multiplex variant the generator emits, on
// each capable protocol and transport, beside the stray cases it must keep out of the config (on a
// protocol without the field, an unknown protocol, Brutal rates the core refuses). The negative
// controls are hand-built outbounds that pin the measured refusals on this core: if one starts to
// pass, the guard it backs may be stale; if a generated config fails, the guard is missing.
func TestMultiplexSingBoxCheck(t *testing.T) {
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — set it to a sing-box binary for a real `check`")
	}
	ver := singboxVersionOf(t, bin)
	brutal := &model.Brutal{Enabled: true, UpMbps: 50, DownMbps: 100}
	variants := []*model.Multiplex{
		{Enabled: true},
		{Enabled: true, Protocol: "h2mux", MaxConnections: 4, MinStreams: 4},
		{Enabled: true, Protocol: "smux", MaxStreams: 8, Padding: true},
		{Enabled: true, Protocol: "yamux", MaxConnections: 2, MaxStreams: 8},
		{Enabled: true, Protocol: "smux", Brutal: brutal},
		{Enabled: true, Protocol: "h2mux", MaxConnections: 4, Brutal: &model.Brutal{Enabled: true, UpMbps: 0, DownMbps: 50}},
		{Enabled: true, Brutal: &model.Brutal{Enabled: true, UpMbps: -5, DownMbps: 50}},
		{Enabled: true, Protocol: "mux.cool"},
	}
	p := allProtocolProfile()
	var eps []model.Endpoint
	for _, e := range p.Endpoints {
		if model.MultiplexCapable(e.Protocol) {
			for i, m := range variants {
				x := e
				if i > 0 { // the first keeps its ID: the profile's groups and rules name it
					x.ID = e.ID + "-mux" + string(rune('a'+i))
					x.Name = x.ID
				}
				x.Multiplex = m
				eps = append(eps, x)
			}
			continue
		}
		// A stray block on each protocol without the field, which the save refuses.
		e.Multiplex = &model.Multiplex{Enabled: true, Protocol: "smux", Brutal: brutal}
		eps = append(eps, e)
	}
	// Vision with multiplex (check passes, and a sing-box pair carries it), multiplex over ws and gRPC,
	// and Shadowsocks with UDP over TCP (sing-box never builds the client there; nothing is emitted).
	vision := muxTestEndpoint(model.ProtoVLESS, &model.Multiplex{Enabled: true, Protocol: "smux"})
	vision.ID, vision.Name, vision.Params["flow"] = "vision-mux", "vision-mux", "xtls-rprx-vision"
	ws := muxTestEndpoint(model.ProtoVMess, &model.Multiplex{Enabled: true, Protocol: "yamux", Padding: true})
	ws.ID, ws.Name, ws.Params["security"], ws.Transport = "ws-mux", "ws-mux", "auto", &model.Transport{Type: "ws", Path: "/m"}
	grpc := muxTestEndpoint(model.ProtoTrojan, &model.Multiplex{Enabled: true, MaxConnections: 2})
	grpc.ID, grpc.Name, grpc.Transport = "grpc-mux", "grpc-mux", &model.Transport{Type: "grpc", ServiceName: "m"}
	uot := muxTestEndpoint(model.ProtoShadowsocks, &model.Multiplex{Enabled: true, Protocol: "smux"})
	uot.ID, uot.Name, uot.Params["udp_over_tcp"] = "ss-uot-mux", "ss-uot-mux", true
	p.Endpoints = append(eps, vision, ws, grpc, uot)

	res, err := Generate(p, Options{MixedPort: 7890, CoreVersion: ver, CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if err != nil {
		t.Fatalf("generate for %s: %v", strings.SplitN(ver, "\n", 2)[0], err)
	}
	emitted := 0
	for _, ob := range res.Config["outbounds"].([]map[string]any) {
		if _, ok := ob["multiplex"]; ok {
			emitted++
		}
	}
	// Four protocols (two Shadowsocks endpoints) times the seven variants that render, plus vision, ws
	// and gRPC: the check below is only worth something if the blocks are there.
	if want := 5*(len(variants)-1) + 3; emitted != want {
		t.Errorf("%d outbounds carry multiplex, want %d", emitted, want)
	}
	echCheck(t, bin, "multiplex.json", res.Config, true)

	raw := func(ob map[string]any) map[string]any {
		return map[string]any{"outbounds": []map[string]any{ob}}
	}
	trojan := func(mux map[string]any) map[string]any {
		return map[string]any{"type": "trojan", "tag": "x", "server": "192.0.2.21", "server_port": 443, "password": "pw",
			"tls": map[string]any{"enabled": true, "server_name": "example.com"}, "multiplex": mux}
	}
	hy2 := map[string]any{"type": "hysteria2", "tag": "x", "server": "192.0.2.21", "server_port": 443, "password": "pw",
		"tls": map[string]any{"enabled": true, "server_name": "example.com"}, "multiplex": map[string]any{"enabled": true}}
	echCheck(t, bin, "hy2-mux.json", raw(hy2), false)
	echCheck(t, bin, "mux-cool.json", raw(trojan(map[string]any{"enabled": true, "protocol": "mux.cool"})), false)
	echCheck(t, bin, "mux-cool-off.json", raw(trojan(map[string]any{"enabled": false, "protocol": "mux.cool"})), true)
	echCheck(t, bin, "brutal-zero.json", raw(trojan(map[string]any{"enabled": true,
		"brutal": map[string]any{"enabled": true, "up_mbps": 0, "down_mbps": 50}})), false)
	echCheck(t, bin, "brutal-missing.json", raw(trojan(map[string]any{"enabled": true,
		"brutal": map[string]any{"enabled": true, "up_mbps": 50}})), false)
}
