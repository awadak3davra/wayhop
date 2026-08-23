package generator

import (
	"encoding/json"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

func mustParse(t *testing.T, link string) model.Endpoint {
	t.Helper()
	e, err := importer.Parse(link)
	if err != nil {
		t.Fatalf("import %q: %v", link, err)
	}
	return *e
}

func TestGenerateMixedProfile(t *testing.T) {
	vless := mustParse(t, "vless://uuid-1@1.1.1.1:443?security=reality&sni=www.microsoft.com&pbk="+generatorTestPBK+"&sid=ab&flow=xtls-rprx-vision#VLESS")
	hy2 := mustParse(t, "hysteria2://pw@2.2.2.2:443?sni=bing.com&obfs=salamander&obfs-password=zz#HY2")
	awg := mustParse(t, "[Interface]\nPrivateKey=k==\nJc=4\nJmin=40\nJmax=70\nS1=0\nS2=0\nH1=1\nH2=2\nH3=3\nH4=4\n[Peer]\nPublicKey=p==\nEndpoint=3.3.3.3:51820\nAllowedIPs=0.0.0.0/0")

	p := &model.Profile{
		Endpoints: []model.Endpoint{vless, hy2, awg},
		Groups: []model.Group{{
			ID: "main", Name: "Main failover", Type: model.GroupURLTest,
			Members: []string{vless.ID, hy2.ID, awg.ID},
			Test:    &model.Health{URL: "http://cp.cloudflare.com/generate_204", Interval: 60, Tolerance: 50},
		}},
		Rules: []model.Rule{
			{ID: "ru-direct", GeoSite: []string{"category-gov-ru"}, Outbound: model.OutboundDirect},
			{ID: "def", Default: true, Outbound: "main"},
		},
	}

	res, err := Generate(p, Options{MixedPort: 7890, ClashAddr: "127.0.0.1:9090", ClashSecret: "s3cret", TunEnabled: true})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	// Must serialize to valid JSON.
	raw, err := json.Marshal(res.Config)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundtrip map[string]any
	if err := json.Unmarshal(raw, &roundtrip); err != nil {
		t.Fatalf("invalid JSON produced: %v", err)
	}

	// AmneziaWG must become a plugin chained over SOCKS, not a sing-box outbound.
	if len(res.Plugins) != 1 || res.Plugins[0].Endpoint.Protocol != model.ProtoAmneziaWG {
		t.Fatalf("expected 1 amneziawg plugin, got %+v", res.Plugins)
	}

	obs := res.Config["outbounds"].([]map[string]any)
	types := map[string]int{}
	tags := map[string]string{}
	for _, o := range obs {
		types[o["type"].(string)]++
		if tag, ok := o["tag"].(string); ok {
			tags[tag] = o["type"].(string)
		}
	}
	// sing-box >=1.12 no longer has a `block` outbound (it's a route action now).
	for _, want := range []string{"vless", "hysteria2", "urltest", "direct"} {
		if types[want] == 0 {
			t.Fatalf("missing outbound type %q in %v", want, types)
		}
	}
	if types["block"] != 0 {
		t.Fatalf("block outbound should no longer be emitted, got %v", types)
	}
	// AmneziaWG egresses via a direct outbound bound to its kernel interface.
	if tags[awg.ID] != "direct" {
		t.Fatalf("awg outbound should be direct, got %q", tags[awg.ID])
	}

	// Reality + flow must survive into the vless outbound.
	var vlessOB map[string]any
	for _, o := range obs {
		if o["tag"] == vless.ID {
			vlessOB = o
		}
	}
	if vlessOB == nil {
		t.Fatal("vless outbound missing")
	}
	if vlessOB["flow"] != "xtls-rprx-vision" {
		t.Fatalf("flow lost: %v", vlessOB["flow"])
	}
	tls := vlessOB["tls"].(map[string]any)
	if tls["reality"] == nil || tls["server_name"] != "www.microsoft.com" {
		t.Fatalf("reality/sni lost: %v", tls)
	}

	// Route: default → group "main", the endpoint-IP bypass (rules[0]), plus the geosite rule.
	route := res.Config["route"].(map[string]any)
	if route["final"] != "main" {
		t.Fatalf("route.final = %v, want main", route["final"])
	}
	rules, ok := route["rules"].([]map[string]any)
	if !ok || len(rules) != 3 {
		t.Fatalf("expected 3 route rules (sniff + endpoint bypass + geosite), got %v", route["rules"])
	}
	if rules[0]["action"] != "sniff" {
		t.Fatalf("rules[0] should be sniff (TUN mode): %v", rules[0])
	}
	if rules[1]["outbound"] != "direct" || rules[1]["ip_cidr"] == nil {
		t.Fatalf("rules[1] should be the endpoint-IP bypass: %v", rules[1])
	}
}

func TestGenerateRejectsBadProfile(t *testing.T) {
	p := &model.Profile{
		Groups: []model.Group{{ID: "g", Name: "g", Type: model.GroupSelector, Members: []string{"nope"}}},
	}
	if _, err := Generate(p, Options{}); err == nil {
		t.Fatal("expected validation error for unresolved member")
	}
}
