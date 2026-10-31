package importer

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/generator"
	"wayhop/internal/model"
)

func muxJSON(m *model.Multiplex) string {
	b, _ := json.Marshal(m)
	return string(b)
}

// TestClashRate reads rates the way mihomo's utils.StringToBps does, in Mbps: a bare number is Mbps,
// bps is bits and Bps bytes, K/M/G/T multiply by 1000.
func TestClashRate(t *testing.T) {
	for in, want := range map[string]int{
		"50": 50, "50 Mbps": 50, "50Mbps": 50, "1 Gbps": 1000, "10 MBps": 80, "500 Kbps": 1, "100 Kbps": 1,
		"2 Tbps": 2000000, "8 Mbps": 8, "1 GBps": 8000, "50mbps": 50, "0": 0, "99999999999999 Tbps": 1<<31 - 1,
	} {
		if got, ok := clashRate(in); !ok || got != want {
			t.Errorf("clashRate(%q) = %d, %v; want %d", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "-5", "fast", "1 Gbit/s", "Mbps", "1.5 Mbps"} {
		if got, ok := clashRate(in); ok {
			t.Errorf("clashRate(%q) = %d, read as a rate", in, got)
		}
	}
	// hysteria2 up/down kept its old reading for what the grammar does not take.
	if clashRateMbps("100 Mbit/s") != 100 || clashRateMbps("1 Gbps") != 1000 {
		t.Errorf("clashRateMbps: %d, %d", clashRateMbps("100 Mbit/s"), clashRateMbps("1 Gbps"))
	}
}

// TestClashMultiplex: mihomo's smux mapping in each YAML form the reader takes, the precedence and
// rate grammar, and what is dropped or noted.
func TestClashMultiplex(t *testing.T) {
	block := `proxies:
  - name: t-block
    type: trojan
    server: 192.0.2.21
    port: 443
    password: pw
    sni: example.com
    smux:
      enabled: true
      protocol: smux
      max-connections: 4
      min-streams: 4
      max-streams: 16
      padding: true
      statistic: true
      brutal-opts:
        enabled: true
        up: 50
        down: 1 Gbps
  - {name: v-inline, type: vless, server: 192.0.2.22, port: 443, uuid: 00000000-0000-4000-8000-000000000021, tls: true, smux: {enabled: true, protocol: yamux, max-streams: 8, brutal-opts: {enabled: true, up: "10 MBps", down: 20}}}
  - name: ss-onlytcp
    type: ss
    server: 192.0.2.23
    port: 8388
    cipher: aes-128-gcm
    password: pw
    smux: {enabled: true, only-tcp: true}
  - name: hy2-smux
    type: hysteria2
    server: 192.0.2.24
    port: 443
    password: pw
    up: 1 Gbps
    down: 10 MBps
    smux:
      enabled: true
  - name: vmess-coolmux
    type: vmess
    server: 192.0.2.25
    port: 443
    uuid: 00000000-0000-4000-8000-000000000022
    cipher: auto
    smux: {enabled: true, protocol: mux.cool}
  - name: trojan-zero-brutal
    type: trojan
    server: 192.0.2.26
    port: 443
    password: pw
    smux: {enabled: true, max-connections: 2, brutal-opts: {enabled: true, up: 0, down: 50}}
  - name: trojan-off
    type: trojan
    server: 192.0.2.27
    port: 443
    password: pw
    smux: {enabled: false, protocol: smux}
`
	eps, errs, notes := ParseSubscriptionNotes(block)
	if len(errs) != 0 || len(eps) != 7 {
		t.Fatalf("%d endpoints, errors %v", len(eps), errs)
	}
	want := map[string]*model.Multiplex{
		// TCP Brutal holds one connection, so the pool beside it is dropped (the save refuses one).
		"t-block":            {Enabled: true, Protocol: "smux", Padding: true, Brutal: &model.Brutal{Enabled: true, UpMbps: 50, DownMbps: 1000}},
		"v-inline":           {Enabled: true, Protocol: "yamux", Brutal: &model.Brutal{Enabled: true, UpMbps: 80, DownMbps: 20}},
		"ss-onlytcp":         {Enabled: true},
		"hy2-smux":           nil,
		"vmess-coolmux":      nil,
		"trojan-zero-brutal": {Enabled: true, MaxConnections: 2},
		"trojan-off":         nil,
	}
	for _, e := range eps {
		if w, ok := want[e.Name]; !ok || !reflect.DeepEqual(e.Multiplex, w) {
			t.Errorf("%s: multiplex %s, want %s", e.Name, muxJSON(e.Multiplex), muxJSON(w))
		}
		if e.Name == "hy2-smux" && (e.Params["up_mbps"] != 1000 || e.Params["down_mbps"] != 80) {
			t.Errorf("hysteria2 rates: up %v down %v, want 1000 and 80", e.Params["up_mbps"], e.Params["down_mbps"])
		}
		if e.Multiplex != nil {
			if p := model.EndpointParamProblem(&e); p != "" {
				t.Errorf("%s: imported a multiplex the save refuses: %s", e.Name, p)
			}
		}
	}
	all := strings.Join(notes, "\n")
	for _, w := range []string{`"ss-onlytcp": smux only-tcp`, `"hy2-smux": multiplex dropped`, `"vmess-coolmux": multiplex dropped: "mux.cool"`,
		`"trojan-zero-brutal": TCP Brutal dropped`} {
		if !strings.Contains(all, w) {
			t.Errorf("notes lack %q:\n%s", w, all)
		}
	}
	if len(notes) != 4 {
		t.Errorf("%d notes, want 4:\n%s", len(notes), all)
	}
	// ParseSubscription and ParseClash give the same endpoints without the notes.
	plain, perrs := ParseSubscription(block)
	if len(perrs) != 0 || !reflect.DeepEqual(plain, eps) {
		t.Error("ParseSubscription differs from ParseSubscriptionNotes")
	}
	// A whole-sequence flow form.
	flow, ferrs := ParseClash("proxies: [{name: f, type: trojan, server: 192.0.2.28, port: 443, password: pw, smux: {enabled: true, max-connections: 3, max-streams: 9}}]\n")
	if len(ferrs) != 0 || len(flow) != 1 || muxJSON(flow[0].Multiplex) != `{"enabled":true,"max_connections":3}` {
		t.Errorf("flow sequence: %v %v", ferrs, flow)
	}
}

// TestSingboxMultiplexRoundTrip: a config the generator renders imports back to the same multiplex,
// and one carrying what the core refuses is normalised with a note.
func TestSingboxMultiplexRoundTrip(t *testing.T) {
	tls := &model.TLS{Enabled: true, Type: "tls", SNI: "example.com"}
	mk := func(id string, p model.Protocol, params map[string]any, m *model.Multiplex) model.Endpoint {
		e := model.Endpoint{ID: id, Name: id, Engine: model.EngineSingBox, Protocol: p, Server: "192.0.2.30", Port: 443,
			Enabled: true, Params: params, Multiplex: m}
		if p != model.ProtoShadowsocks {
			e.TLS = tls
		}
		return e
	}
	uuid := "00000000-0000-4000-8000-000000000021"
	src := []model.Endpoint{
		mk("vless", model.ProtoVLESS, map[string]any{"uuid": uuid}, &model.Multiplex{Enabled: true, Protocol: "smux", MaxConnections: 4, MinStreams: 4, Padding: true}),
		mk("vmess", model.ProtoVMess, map[string]any{"uuid": uuid, "alter_id": 0, "security": "auto"}, &model.Multiplex{Enabled: true, Protocol: "yamux", MaxStreams: 8}),
		mk("trojan", model.ProtoTrojan, map[string]any{"password": "pw"}, &model.Multiplex{Enabled: true, Brutal: &model.Brutal{Enabled: true, UpMbps: 50, DownMbps: 100}}),
		mk("ss", model.ProtoShadowsocks, map[string]any{"method": "aes-128-gcm", "password": "pw"}, &model.Multiplex{Enabled: true, Protocol: "h2mux"}),
		mk("plain", model.ProtoTrojan, map[string]any{"password": "pw"}, nil),
	}
	res, err := generator.Generate(&model.Profile{Endpoints: src, Rules: []model.Rule{{ID: "def", Default: true, Outbound: "vless"}}}, generator.Options{})
	if err != nil {
		t.Fatal(err)
	}
	cfg, _ := json.Marshal(res.Config)
	eps, errs, notes := ParseSubscriptionNotes(string(cfg))
	if len(errs) != 0 || len(notes) != 0 {
		t.Fatalf("errors %v notes %v", errs, notes)
	}
	got := map[string]*model.Multiplex{}
	for _, e := range eps {
		got[e.Name] = e.Multiplex
	}
	for _, e := range src {
		if !reflect.DeepEqual(got[e.ID], e.Multiplex) {
			t.Errorf("%s: imported %s, generated from %s", e.ID, muxJSON(got[e.ID]), muxJSON(e.Multiplex))
		}
	}

	// What the core refuses, or ignores, verbatim in a pasted config.
	pasted := `{"outbounds":[
 {"type":"trojan","tag":"pool","server":"192.0.2.31","server_port":443,"password":"pw","multiplex":{"enabled":true,"protocol":"smux","max_connections":2,"min_streams":1,"max_streams":8}},
 {"type":"hysteria2","tag":"hy2","server":"192.0.2.32","server_port":443,"password":"pw","multiplex":{"enabled":true}},
 {"type":"vless","tag":"cool","server":"192.0.2.33","server_port":443,"uuid":"` + uuid + `","multiplex":{"enabled":true,"protocol":"mux.cool"}},
 {"type":"shadowsocks","tag":"brutal0","server":"192.0.2.34","server_port":8388,"method":"aes-128-gcm","password":"pw","multiplex":{"enabled":true,"brutal":{"enabled":true,"up_mbps":0,"down_mbps":10}}},
 {"type":"trojan","tag":"off","server":"192.0.2.35","server_port":443,"password":"pw","multiplex":{"enabled":false,"protocol":"smux"}}]}`
	eps, errs, notes = ParseSubscriptionNotes(pasted)
	if len(errs) != 0 || len(eps) != 5 {
		t.Fatalf("errors %v, %d endpoints", errs, len(eps))
	}
	want := map[string]string{
		"pool": `{"enabled":true,"protocol":"smux","max_connections":2,"min_streams":1}`, "hy2": "null", "cool": "null",
		"brutal0": `{"enabled":true}`, "off": "null",
	}
	for _, e := range eps {
		if g := muxJSON(e.Multiplex); g != want[e.Name] {
			t.Errorf("%s: %s, want %s", e.Name, g, want[e.Name])
		}
	}
	if all := strings.Join(notes, "\n"); len(notes) != 3 || !strings.Contains(all, `outbound "hy2": multiplex dropped`) ||
		!strings.Contains(all, `outbound "cool": multiplex dropped`) || !strings.Contains(all, `outbound "brutal0": TCP Brutal dropped`) {
		t.Errorf("notes:\n%s", all)
	}
}

// TestHiddifyMultiplexLinks: no share link switches multiplex on. Hiddify Panel puts muxtype and the
// rest in a link only for a server whose core is Xray (and writes muxpad as Python's True), and Xray
// drops every sing-mux connection, so reading them broke a server that worked without it. The
// subscription path and a single link agree, and the rest of the link is still read.
func TestHiddifyMultiplexLinks(t *testing.T) {
	links := []string{
		"vless://00000000-0000-4000-8000-000000000021@192.0.2.40:443?security=tls&sni=example.com&muxtype=smux&muxmaxc=4&mux=4&muxpad=True&muxup=50&muxdown=100#a",
		"trojan://pw@192.0.2.41:443?sni=example.com&MuxType=h2mux&muxsmax=8#b",
		"trojan://pw@192.0.2.42:443?sni=example.com&muxtype=yamux&muxmaxc=2&muxsmax=8&muxup=50#c",
		"trojan://pw@192.0.2.43:443?sni=example.com&muxtype=mux.cool#d",
		"trojan://pw@192.0.2.44:443?sni=example.com&mux=8&muxpad=true#e",
		"vmess://" + fuzzimporter_b64std(`{"v":"2","ps":"g","add":"192.0.2.46","port":"443","id":"00000000-0000-4000-8000-000000000022","net":"tcp","tls":"tls","muxtype":"smux","muxmaxc":4,"muxpad":"True"}`),
	}
	for _, link := range links {
		e, err := Parse(link)
		if err != nil {
			t.Fatalf("%s: %v", link, err)
		}
		if e.Multiplex != nil {
			t.Errorf("%s: multiplex %s from a share link", link, muxJSON(e.Multiplex))
		}
		if e.TLS == nil || !e.TLS.Enabled {
			t.Errorf("%s: the rest of the link was not read: TLS %+v", link, e.TLS)
		}
	}
	eps, errs, notes := ParseSubscriptionNotes(strings.Join(links, "\n"))
	if len(errs) != 0 || len(eps) != len(links) || len(notes) != 0 {
		t.Fatalf("subscription: %d endpoints, errors %v, notes %v", len(eps), errs, notes)
	}
	for _, e := range eps {
		if e.Multiplex != nil {
			t.Errorf("%s: multiplex %s from a subscription line", e.Name, muxJSON(e.Multiplex))
		}
	}
}
