package generator

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// testECHConfig is an ECHConfigList `sing-box generate ech-keypair example.com` printed (1.13.21).
const testECHConfig = "AEb+DQBCAAAgACDv1FlTLOHACGPvieDrkqLa8zJ86loXc/u6LLmehtFpUQAMAAEAAQABAAIAAQADAAtleGFtcGxlLmNvbQAA"

// testECHPEMLines is that config as the PEM lines sing-box takes (and prints).
var testECHPEMLines = []string{
	"-----BEGIN ECH CONFIGS-----",
	"AEb+DQBCAAAgACDv1FlTLOHACGPvieDrkqLa8zJ86loXc/u6LLmehtFpUQAMAAEA",
	"AQABAAIAAQADAAtleGFtcGxlLmNvbQAA",
	"-----END ECH CONFIGS-----",
}

const (
	echCore1217 = "sing-box version 1.12.17\n\nEnvironment: go1.25.6 linux/amd64\nTags: with_quic,with_utls"
	echCoreGo23 = "sing-box version 1.12.17\n\nEnvironment: go1.23.4 linux/mipsle\nTags: with_quic,with_utls"
	echCore1321 = "sing-box version 1.13.21\n\nEnvironment: go1.25.12 linux/amd64"
)

func TestECHTLSJSON(t *testing.T) {
	base := model.TLS{Enabled: true, Type: "tls", SNI: "example.com", Fingerprint: "chrome", Fragment: true}
	without := tlsJSON(&base)
	if _, ok := without["ech"]; ok {
		t.Fatalf("no ECH, no ech key: %v", without)
	}
	with := func(e *model.ECH) map[string]any {
		tl := base
		tl.ECH = e
		return tlsJSON(&tl)
	}
	// ECH switched off (or absent) leaves the block exactly as it was: existing profiles do not move.
	for _, e := range []*model.ECH{nil, {}, {Config: testECHConfig}} {
		if got := with(e); !reflect.DeepEqual(got, without) {
			t.Errorf("ECH %+v changed the block: %v", e, got)
		}
	}
	static := with(&model.ECH{Enabled: true, Config: testECHConfig})["ech"].(map[string]any)
	if !reflect.DeepEqual(static, map[string]any{"enabled": true, "config": testECHPEMLines}) {
		t.Errorf("static ECH = %#v", static)
	}
	// Every form the model may hold renders the same PEM.
	for _, in := range []string{strings.Join(testECHPEMLines, "\n"), strings.NewReplacer("+", "-", "/", "_").Replace(testECHConfig)} {
		if got := with(&model.ECH{Enabled: true, Config: in})["ech"].(map[string]any); !reflect.DeepEqual(got["config"], testECHPEMLines) {
			t.Errorf("config %q rendered %v", in, got["config"])
		}
	}
	// The 1.12 schema: no query_server_name, which 1.12 refuses as an unknown field.
	if dns := with(&model.ECH{Enabled: true, QueryServerName: "example.net"})["ech"]; !reflect.DeepEqual(dns, map[string]any{"enabled": true}) {
		t.Errorf("DNS ECH = %#v", dns)
	}
	// A config that is not an ECHConfigList is dropped, not written: sing-box's check passes garbage
	// inside a PEM block, and every handshake would then fail.
	if got := with(&model.ECH{Enabled: true, Config: "AAAA"}); !reflect.DeepEqual(got, without) {
		t.Errorf("garbage config rendered: %v", got)
	}
	// ECH and fragmentation coexist (both pass check on every core).
	if got := with(&model.ECH{Enabled: true, Config: testECHConfig}); got["fragment"] != true || got["ech"] == nil {
		t.Errorf("fragment + ECH = %v", got)
	}
	// Never beside Reality, on every core FATAL.
	reality := model.TLS{Enabled: true, Type: "reality", SNI: "example.com", PublicKey: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
		ECH: &model.ECH{Enabled: true, Config: testECHConfig}}
	if got := tlsJSON(&reality); got["reality"] == nil || got["ech"] != nil {
		t.Errorf("reality + ECH = %v", got)
	}
	// Nor on a Reality connection whose key is unusable (rendered as plain TLS, still Reality to the model).
	reality.PublicKey = "short"
	if got := tlsJSON(&reality); got["ech"] != nil {
		t.Errorf("degraded reality + ECH = %v", got)
	}
}

func echTestEndpoint(id string, p model.Protocol, e *model.ECH) model.Endpoint {
	ep := model.Endpoint{ID: id, Name: id, Enabled: true, Engine: model.EngineSingBox, Protocol: p, Server: "192.0.2.17", Port: 443,
		Params: map[string]any{"uuid": "00000000-0000-4000-8000-000000000017", "password": "pw"},
		TLS:    &model.TLS{Enabled: true, Type: "tls", SNI: "example.com", ECH: e}}
	return ep
}

func echOutbound(t *testing.T, cfg map[string]any, tag string) map[string]any {
	t.Helper()
	for _, ob := range cfg["outbounds"].([]map[string]any) {
		if ob["tag"] == tag {
			tl, _ := ob["tls"].(map[string]any)
			ech, _ := tl["ech"].(map[string]any)
			return ech
		}
	}
	t.Fatalf("no outbound %q", tag)
	return nil
}

func TestECHCoreVersionGates(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{
			echTestEndpoint("dns-qsn", model.ProtoVLESS, &model.ECH{Enabled: true, QueryServerName: "example.net"}),
			echTestEndpoint("static", model.ProtoTrojan, &model.ECH{Enabled: true, Config: testECHConfig}),
			echTestEndpoint("hy2-dns", model.ProtoHysteria2, &model.ECH{Enabled: true}),
		},
		Rules: []model.Rule{{ID: "def", Default: true, Outbound: "static"}},
	}
	// hy2 over DNS is refused at save; rendering it anyway must not leave the lookup on QUIC.
	p.Endpoints[2].Enabled = false
	for _, c := range []struct {
		core    string
		qsn     bool // query_server_name written
		dropped bool // ECH left out altogether
	}{
		{"", false, false},
		{"1.12.17", false, false}, // a bare version names no Go: kept
		{echCore1217, false, false},
		{echCoreGo23, false, true},
		{"sing-box version 1.12.17\n\nEnvironment: go1.24.0 linux/arm64", false, false},
		{"1.13.21", true, false},
		{echCore1321, true, false},
		{"1.14.4", true, false},
		{"v1.15.0-alpha.13", true, false},
		{"sing-box version 1.13.21\n\nEnvironment: go1.23.1 linux/amd64", true, false}, // 1.13 cannot be built with it
	} {
		res, err := Generate(p, Options{MixedPort: 7890, CoreVersion: c.core})
		if err != nil {
			t.Fatalf("%q: %v", c.core, err)
		}
		dns, static := echOutbound(t, res.Config, "dns-qsn"), echOutbound(t, res.Config, "static")
		if c.dropped {
			if dns != nil || static != nil {
				t.Errorf("%q: a 1.12 built with Go < 1.24 refuses any ECH, got %v / %v", c.core, dns, static)
			}
			continue
		}
		if static == nil || !reflect.DeepEqual(static["config"], testECHPEMLines) || static["query_server_name"] != nil {
			t.Errorf("%q: static = %v", c.core, static)
		}
		if got := dns["query_server_name"] != nil; dns == nil || got != c.qsn || (got && dns["query_server_name"] != "example.net") {
			t.Errorf("%q: DNS = %v, want query name %v", c.core, dns, c.qsn)
		}
		// The KeeneticOS fallback core renders the same through OutboundForCore.
		ob, err := OutboundForCore(&p.Endpoints[0], c.core)
		if err != nil {
			t.Fatal(err)
		}
		if ech := ob["tls"].(map[string]any)["ech"]; !reflect.DeepEqual(ech, dns) {
			t.Errorf("%q: OutboundForCore ech %v, Generate %v", c.core, ech, dns)
		}
	}
	ob, err := OutboundForCore(&p.Endpoints[2], echCore1321)
	if err != nil {
		t.Fatal(err)
	}
	if ech := ob["tls"].(map[string]any)["ech"]; ech != nil {
		t.Errorf("hysteria2 rendered the DNS lookup sing-quic never runs: %v", ech)
	}
	ob, err = OutboundForCore(&p.Endpoints[0], echCoreGo23)
	if err != nil {
		t.Fatal(err)
	}
	if ech := ob["tls"].(map[string]any)["ech"]; ech != nil {
		t.Errorf("OutboundForCore kept ECH on a core without it: %v", ech)
	}
}

func TestECHReviewPredicates(t *testing.T) {
	dnsQsn := echTestEndpoint("a", model.ProtoVLESS, &model.ECH{Enabled: true, QueryServerName: "example.net"})
	dns := echTestEndpoint("b", model.ProtoAnyTLS, &model.ECH{Enabled: true})
	static := echTestEndpoint("c", model.ProtoTUIC, &model.ECH{Enabled: true, Config: testECHConfig})
	quicDNS := echTestEndpoint("d", model.ProtoHysteria2, &model.ECH{Enabled: true})
	off := echTestEndpoint("e", model.ProtoVLESS, &model.ECH{Config: testECHConfig})
	reality := echTestEndpoint("f", model.ProtoVLESS, &model.ECH{Config: testECHConfig})
	reality.TLS.Type = "reality"
	plugin := echTestEndpoint("g", model.ProtoVLESS, &model.ECH{Enabled: true})
	plugin.Engine = model.EngineAmneziaWG
	ss := echTestEndpoint("h", model.ProtoShadowsocks, &model.ECH{Enabled: true, Config: testECHConfig})

	if !ECHFromDNS(&dnsQsn) || !ECHFromDNS(&dns) || ECHFromDNS(&static) || ECHFromDNS(&quicDNS) || ECHFromDNS(&off) ||
		ECHFromDNS(&reality) || ECHFromDNS(&plugin) {
		t.Error("ECHFromDNS must name exactly the connections that look the config up")
	}
	for core, want := range map[string]bool{"": false, echCore1217: true, "1.12.17": true, echCore1321: false, "1.14.4": false, echCoreGo23: false} {
		if got := ECHQueryNameNeedsNewerCore(&dnsQsn, core); got != want {
			t.Errorf("ECHQueryNameNeedsNewerCore(%q) = %v", core, got)
		}
		if ECHQueryNameNeedsNewerCore(&dns, core) {
			t.Errorf("no query name, nothing to say on %q", core)
		}
	}
	for _, e := range []model.Endpoint{dnsQsn, dns, static} {
		if !ECHDroppedByCore(&e, echCoreGo23) || ECHDroppedByCore(&e, echCore1217) || ECHDroppedByCore(&e, "") || ECHDroppedByCore(&e, "1.12.17") {
			t.Errorf("%s: ECHDroppedByCore", e.ID)
		}
	}
	for _, e := range []model.Endpoint{off, reality, quicDNS, ss} {
		if ECHDroppedByCore(&e, echCoreGo23) {
			t.Errorf("%s: nothing rendered, nothing dropped", e.ID)
		}
	}
	if !ECHConfigOnReality(&reality) || ECHConfigOnReality(&static) || ECHConfigOnReality(&off) {
		t.Error("ECHConfigOnReality must name only the Reality connection holding a config")
	}
}

// Of the uTLS fingerprints only chrome and firefox build a ClientHello that carries ECH; with any other
// every handshake fails (measured on 1.12 to 1.15). Links keep their fp=, so a connection with ECH and
// such a fingerprint is rendered with chrome, and keeps its own where ECH is not rendered.
func TestECHFingerprintCarriesECH(t *testing.T) {
	fps := []string{"", "chrome", "firefox", "edge", "safari", "ios", "android", "360", "qq", "random", "randomized", "randomizedalpn"}
	for _, fp := range fps {
		base := model.TLS{Enabled: true, Type: "tls", SNI: "example.com", Fingerprint: fp}
		plain := tlsJSON(&base)
		withECH := base
		withECH.ECH = &model.ECH{Enabled: true, Config: testECHConfig}
		got := tlsJSON(&withECH)
		want := normalizeUTLSFinger(fp)
		if fp != "" && !echCarryingFingerprints[want] {
			want = "chrome"
		}
		u, _ := got["utls"].(map[string]any)
		switch {
		case fp == "" && u != nil:
			t.Errorf("no fingerprint: ECH added one: %v", u)
		case fp != "" && (u == nil || u["fingerprint"] != want):
			t.Errorf("fp %q with ECH: utls = %v, want %q", fp, u, want)
		}
		// Without ECH the fingerprint is the one asked for.
		if pu, _ := plain["utls"].(map[string]any); fp != "" && pu["fingerprint"] != normalizeUTLSFinger(fp) {
			t.Errorf("fp %q without ECH: utls = %v", fp, pu)
		}
		e := echTestEndpoint("x", model.ProtoVLESS, withECH.ECH)
		e.TLS.Fingerprint = fp
		replaced := fp != "" && !echCarryingFingerprints[normalizeUTLSFinger(fp)]
		if r := ECHFingerprintReplaced(&e, echCore1321); (r != "") != replaced {
			t.Errorf("ECHFingerprintReplaced(%q) = %q", fp, r)
		}
	}
	// Where ECH is not rendered the connection keeps its fingerprint, and nothing is said.
	safari := func(id string, p model.Protocol, ech *model.ECH) model.Endpoint {
		e := echTestEndpoint(id, p, ech)
		e.TLS.Fingerprint = "safari"
		return e
	}
	on := safari("on", model.ProtoTrojan, &model.ECH{Enabled: true})
	quicDNS := safari("quic-dns", model.ProtoHysteria2, &model.ECH{Enabled: true})
	off := safari("off", model.ProtoTrojan, &model.ECH{Config: testECHConfig})
	if ECHFingerprintReplaced(&on, echCore1321) != "safari" || ECHFingerprintReplaced(&on, echCoreGo23) != "" ||
		ECHFingerprintReplaced(&quicDNS, echCore1321) != "" || ECHFingerprintReplaced(&off, echCore1321) != "" {
		t.Error("ECHFingerprintReplaced must name only a rendered ECH whose fingerprint was replaced")
	}
	fpOf := func(ob map[string]any) any {
		u, _ := ob["tls"].(map[string]any)["utls"].(map[string]any)
		return u["fingerprint"]
	}
	for core, want := range map[string]string{echCore1321: "chrome", echCoreGo23: "safari"} {
		ob, err := OutboundForCore(&on, core)
		if err != nil {
			t.Fatal(err)
		}
		if fpOf(ob) != want {
			t.Errorf("core %q: fingerprint %v, want %s", core, fpOf(ob), want)
		}
	}
	if ob, err := OutboundForCore(&quicDNS, echCore1321); err != nil || fpOf(ob) != "safari" {
		t.Errorf("QUIC with the lookup dropped: fingerprint %v (%v)", fpOf(ob), err)
	}
}

// The ECH lookup goes where the DNS rules send it: the review needs the server that answers it, whether
// that server sends the hidden name in the clear, and whether it is reached through the connection the
// lookup is for (the secure default's DoH rides the main exit's group).
func TestECHLookupFor(t *testing.T) {
	nl := echTestEndpoint("nl", model.ProtoVLESS, &model.ECH{Enabled: true, QueryServerName: "example.net"})
	other := echTestEndpoint("de", model.ProtoTrojan, nil)
	prof := func(edit func(*model.Profile)) *model.Profile {
		p := &model.Profile{
			Endpoints: []model.Endpoint{nl, other},
			Groups: []model.Group{
				{ID: "grp", Name: "grp", Type: model.GroupFallback, Members: []string{"nl", "direct"}},
				{ID: "outer", Name: "outer", Type: model.GroupFallback, Members: []string{"grp", "de"}},
			},
			RoutingLists: []model.RoutingList{{ID: "mine", Name: "mine", Manual: []string{"example.net"}, Outbound: "direct", Enabled: true},
				{ID: "feed", Name: "feed", Source: "https://example.org/list.srs", Outbound: "direct", Enabled: true}},
			DNS: &model.DNSSettings{Enabled: true, Final: "dns_secure", Servers: []model.DNSServer{
				{Tag: "dns_secure", Type: "https", Server: "192.0.2.53", Detour: "grp", Enabled: true},
				{Tag: "dns_plain", Type: "udp", Server: "192.0.2.54", Enabled: true},
				{Tag: "dns_local", Type: "local", Enabled: true},
				{Tag: "dns_off", Type: "https", Server: "192.0.2.55", Enabled: false},
			}},
		}
		if edit != nil {
			edit(p)
		}
		return p
	}
	rule := func(r model.DNSRule) func(*model.Profile) {
		return func(p *model.Profile) { p.DNS.Rules = append(p.DNS.Rules, r) }
	}
	secure := ECHLookup{Name: "example.net", Server: "dns_secure", Through: "grp"}
	for _, c := range []struct {
		name string
		core string
		edit func(*model.Profile)
		want ECHLookup
	}{
		{"secure default: DoH through the group holding the connection", echCore1321, nil, secure},
		{"a 1.12 core asks for the SNI", echCore1217, nil, ECHLookup{Name: "example.com", Server: "dns_secure", Through: "grp"}},
		{"through the connection itself", echCore1321, func(p *model.Profile) { p.DNS.Servers[0].Detour = "nl" },
			ECHLookup{Name: "example.net", Server: "dns_secure", Through: "nl"}},
		{"through a group of groups", echCore1321, func(p *model.Profile) { p.DNS.Servers[0].Detour = "outer" },
			ECHLookup{Name: "example.net", Server: "dns_secure", Through: "outer"}},
		{"through another exit", echCore1321, func(p *model.Profile) { p.DNS.Servers[0].Detour = "de" },
			ECHLookup{Name: "example.net", Server: "dns_secure"}},
		{"direct", echCore1321, func(p *model.Profile) { p.DNS.Servers[0].Detour = "direct" },
			ECHLookup{Name: "example.net", Server: "dns_secure"}},
		{"a suffix rule to plain DNS", echCore1321, rule(model.DNSRule{ID: "r", DomainSuffix: []string{"net"}, Server: "dns_plain"}),
			ECHLookup{Name: "example.net", Server: "dns_plain", Clear: true}},
		{"a dotted suffix does not take the name itself", echCore1321,
			rule(model.DNSRule{ID: "r", DomainSuffix: []string{".example.net"}, Server: "dns_plain"}), secure},
		{"an A-only rule does not take HTTPS", echCore1321,
			rule(model.DNSRule{ID: "r", Domain: []string{"example.net"}, QueryType: []string{"A"}, Server: "dns_local"}), secure},
		{"an HTTPS rule takes every name", echCore1321, rule(model.DNSRule{ID: "r", QueryType: []string{"https"}, Server: "dns_local"}),
			ECHLookup{Name: "example.net", Server: "dns_local", Clear: true}},
		{"a manual list holding the name", echCore1321, rule(model.DNSRule{ID: "r", RuleSets: []string{"mine"}, Server: "dns_local"}),
			ECHLookup{Name: "example.net", Server: "dns_local", Clear: true}},
		{"a fetched list is not read", echCore1321, rule(model.DNSRule{ID: "r", RuleSets: []string{"feed"}, Server: "dns_local"}), secure},
		{"a geosite category is not read", echCore1321,
			rule(model.DNSRule{ID: "r", Domain: []string{"example.net"}, GeoSite: []string{"category-x"}, Server: "dns_local"}), secure},
		{"a disabled rule, and one to a disabled server", echCore1321, func(p *model.Profile) {
			p.DNS.Rules = []model.DNSRule{{ID: "a", Domain: []string{"example.net"}, Server: "dns_local", Disabled: true},
				{ID: "b", Domain: []string{"example.net"}, Server: "dns_off"}}
		}, secure},
		{"rejected", echCore1321, rule(model.DNSRule{ID: "r", Domain: []string{"EXAMPLE.net."}, Server: "reject"}),
			ECHLookup{Name: "example.net", Server: "reject"}},
		{"no final: the first server", echCore1321, func(p *model.Profile) { p.DNS.Final = "" }, secure},
		{"final disabled: the first server left", echCore1321, func(p *model.Profile) { p.DNS.Final = "dns_off"; p.DNS.Servers[0].Enabled = false },
			ECHLookup{Name: "example.net", Server: "dns_plain", Clear: true}},
		{"no DNS plane: the system resolver", echCore1321, func(p *model.Profile) { p.DNS = nil }, ECHLookup{Name: "example.net", Clear: true}},
		{"DNS switched off", echCore1321, func(p *model.Profile) { p.DNS.Enabled = false }, ECHLookup{Name: "example.net", Clear: true}},
	} {
		got := ECHLookupFor(prof(c.edit), &nl, c.core)
		if got == nil || *got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
	static := echTestEndpoint("s", model.ProtoVLESS, &model.ECH{Enabled: true, Config: testECHConfig})
	if ECHLookupFor(prof(nil), &static, echCore1321) != nil || ECHLookupFor(prof(nil), &nl, echCoreGo23) != nil {
		t.Error("a pasted config, or a core without ECH, looks nothing up")
	}
}

// TestECHSingBoxCheck renders ECH on every TLS protocol - a pasted config and the DNS lookup, with
// and without a query server name - for the version WR_SINGBOX reports, and runs the real check on
// it. The negative controls are what the generator and model.Validate keep out: a raw base64
// config, ECH beside Reality, and (on 1.12) query_server_name, each refused by the core itself.
func TestECHSingBoxCheck(t *testing.T) {
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — set it to a sing-box binary for a real `check`")
	}
	ver := singboxVersionOf(t, bin)
	// The config this core's own keygen prints is one the model accepts (as pasted, PEM and all) and
	// the generator renders: the validator must never refuse a real server's config.
	keyOut, err := exec.Command(bin, "generate", "ech-keypair", "example.com").CombinedOutput()
	if err != nil {
		t.Fatalf("generate ech-keypair: %v\n%s", err, keyOut)
	}
	coreCfg := string(keyOut)
	if i, j := strings.Index(coreCfg, "-----BEGIN ECH CONFIGS-----"), strings.Index(coreCfg, "-----END ECH CONFIGS-----"); i >= 0 && j > i {
		coreCfg = coreCfg[i : j+len("-----END ECH CONFIGS-----")]
	} else {
		t.Fatalf("generate ech-keypair printed no ECH CONFIGS block:\n%s", keyOut)
	}
	if _, err := model.ParseECHConfigList(coreCfg); err != nil {
		t.Fatalf("the model refuses the config sing-box %s generated: %v\n%s", strings.SplitN(ver, "\n", 2)[0], err, coreCfg)
	}
	static := func() *model.ECH { return &model.ECH{Enabled: true, Config: testECHConfig} }
	ep := func(id string, p model.Protocol, e *model.ECH, edit func(*model.Endpoint)) model.Endpoint {
		x := echTestEndpoint(id, p, e)
		if edit != nil {
			edit(&x)
		}
		return x
	}
	prof := &model.Profile{
		Endpoints: []model.Endpoint{
			ep("vless-static", model.ProtoVLESS, static(), nil),
			ep("vless-core-keygen", model.ProtoVLESS, &model.ECH{Enabled: true, Config: model.CanonicalECHConfig(coreCfg)}, nil),
			ep("vless-dns", model.ProtoVLESS, &model.ECH{Enabled: true}, nil),
			ep("vless-qsn", model.ProtoVLESS, &model.ECH{Enabled: true, QueryServerName: "example.net"}, nil),
			ep("vless-utls-frag", model.ProtoVLESS, static(), func(e *model.Endpoint) {
				e.TLS.Fingerprint, e.TLS.Fragment, e.TLS.RecordFragment = "chrome", true, true
			}),
			// A link's fingerprint that cannot carry ECH, rendered as chrome.
			ep("vless-safari", model.ProtoVLESS, static(), func(e *model.Endpoint) { e.TLS.Fingerprint = "safari" }),
			ep("vmess-grpc", model.ProtoVMess, static(), func(e *model.Endpoint) {
				e.Params["security"] = "auto"
				e.Transport = &model.Transport{Type: "grpc", ServiceName: "s"}
			}),
			ep("trojan-ws", model.ProtoTrojan, &model.ECH{Enabled: true, QueryServerName: "example.net"}, func(e *model.Endpoint) {
				e.Transport = &model.Transport{Type: "ws", Path: "/p"}
			}),
			ep("anytls-static", model.ProtoAnyTLS, static(), nil),
			ep("anytls-dns", model.ProtoAnyTLS, &model.ECH{Enabled: true}, nil),
			ep("hy2-static", model.ProtoHysteria2, static(), nil),
			ep("tuic-static", model.ProtoTUIC, static(), nil),
			ep("https-static", model.ProtoHTTP, static(), nil),
			// A Reality link's config, kept switched off: the outbound must carry Reality and no ECH.
			ep("reality-kept", model.ProtoVLESS, &model.ECH{Config: testECHConfig}, func(e *model.Endpoint) {
				e.TLS.Type, e.TLS.PublicKey = "reality", "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"
			}),
		},
		Rules: []model.Rule{{ID: "def", Default: true, Outbound: "vless-static"}},
	}
	res, err := Generate(prof, Options{MixedPort: 7890, CoreVersion: ver, CacheFile: filepath.Join(t.TempDir(), "cache.db")})
	if err != nil {
		t.Fatalf("generate for %s: %v", strings.SplitN(ver, "\n", 2)[0], err)
	}
	for _, e := range prof.Endpoints {
		ech := echOutbound(t, res.Config, e.ID)
		if (ech == nil) != (e.ID == "reality-kept") {
			t.Errorf("%s: ech = %v", e.ID, ech)
		}
	}
	if q := echOutbound(t, res.Config, "vless-qsn")["query_server_name"]; (q != nil) != (coreMinor(ver) >= 13) {
		t.Errorf("sing-box %s: query_server_name = %v", strings.SplitN(ver, "\n", 2)[0], q)
	}
	echCheck(t, bin, "ech.json", res.Config, true)

	// The negative controls: hand-built outbounds the core itself refuses.
	raw := func(tls map[string]any) map[string]any {
		return map[string]any{"outbounds": []map[string]any{{"type": "vless", "tag": "x", "server": "192.0.2.17",
			"server_port": 443, "uuid": "00000000-0000-4000-8000-000000000017", "tls": tls}}}
	}
	tls := func(extra map[string]any) map[string]any {
		m := map[string]any{"enabled": true, "server_name": "example.com"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	echCheck(t, bin, "raw-b64.json", raw(tls(map[string]any{"ech": map[string]any{"enabled": true, "config": testECHConfig}})), false)
	echCheck(t, bin, "reality.json", raw(tls(map[string]any{
		"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
		"reality": map[string]any{"enabled": true, "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0"},
		"ech":     map[string]any{"enabled": true, "config": testECHPEMLines},
	})), false)
	// query_server_name: refused by 1.12 (hence the gate), accepted from 1.13.
	echCheck(t, bin, "qsn.json", raw(tls(map[string]any{"ech": map[string]any{"enabled": true, "query_server_name": "example.net"}})),
		coreMinor(ver) >= echQueryNameMinMinor)
}

func echCheck(t *testing.T, bin, name string, cfg map[string]any, wantOK bool) {
	t.Helper()
	data, _ := json.MarshalIndent(cfg, "", "  ")
	f := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", f).CombinedOutput()
	switch {
	case wantOK && err != nil:
		t.Fatalf("sing-box check rejected %s: %v\n%s\n%s", name, err, out, data)
	case !wantOK && err == nil:
		t.Fatalf("sing-box check accepted %s, which the generator keeps out:\n%s", name, data)
	case wantOK && strings.Contains(string(out), "deprecated"):
		t.Fatalf("sing-box warned about a deprecated field in %s:\n%s", name, out)
	}
}
