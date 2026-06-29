package generator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"velinx/internal/model"
)

// generator_vlessReality builds a VLESS-Reality sing-box endpoint.
func generator_vlessReality() model.Endpoint {
	return model.Endpoint{
		ID:       "vless-reality",
		Name:     "VLESS Reality",
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoVLESS,
		Server:   "1.1.1.1",
		Port:     443,
		Params:   map[string]any{"uuid": "uuid-1", "flow": "xtls-rprx-vision"},
		TLS: &model.TLS{
			Enabled:   true,
			Type:      "reality",
			SNI:       "www.microsoft.com",
			PublicKey: generatorTestPBK,
			ShortID:   "ab",
		},
		Enabled: true,
	}
}

// generator_hysteria2 builds a Hysteria2 sing-box endpoint with obfs.
func generator_hysteria2() model.Endpoint {
	return model.Endpoint{
		ID:       "hy2",
		Name:     "HY2",
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoHysteria2,
		Server:   "2.2.2.2",
		Port:     8443,
		Params: map[string]any{
			"password":      "pw",
			"obfs":          "salamander",
			"obfs_password": "zz",
		},
		TLS:     &model.TLS{Enabled: true, SNI: "bing.com"},
		Enabled: true,
	}
}

// generator_amneziaWG builds an AmneziaWG endpoint (non-sing-box engine plugin).
func generator_amneziaWG() model.Endpoint {
	return model.Endpoint{
		ID:       "awg",
		Name:     "AmneziaWG",
		Engine:   model.EngineAmneziaWG,
		Protocol: model.ProtoAmneziaWG,
		Server:   "3.3.3.3",
		Port:     51820,
		Params: map[string]any{
			"private_key":     "k==",
			"peer_public_key": "p==",
			"jc":              4,
		},
		Enabled: true,
	}
}

// generator_olcRTC builds an olcRTC endpoint (non-sing-box engine plugin).
func generator_olcRTC() model.Endpoint {
	return model.Endpoint{
		ID:       "olc",
		Name:     "olcRTC telemost",
		Engine:   model.EngineOlcRTC,
		Protocol: model.ProtoOlcRTC,
		Server:   "telemost.yandex.ru",
		Port:     443,
		Params:   map[string]any{"provider": "telemost", "room": "abc"},
		Enabled:  true,
	}
}

// generator_outboundsByTag indexes outbounds by their "tag".
func generator_outboundsByTag(t *testing.T, res *Result) map[string]map[string]any {
	t.Helper()
	obs, ok := res.Config["outbounds"].([]map[string]any)
	if !ok {
		t.Fatalf("outbounds not []map[string]any: %T", res.Config["outbounds"])
	}
	byTag := map[string]map[string]any{}
	for _, o := range obs {
		tag, _ := o["tag"].(string)
		byTag[tag] = o
	}
	return byTag
}

// generator_typeCounts counts outbounds by "type".
func generator_typeCounts(t *testing.T, res *Result) map[string]int {
	t.Helper()
	obs, ok := res.Config["outbounds"].([]map[string]any)
	if !ok {
		t.Fatalf("outbounds not []map[string]any: %T", res.Config["outbounds"])
	}
	counts := map[string]int{}
	for _, o := range obs {
		counts[o["type"].(string)]++
	}
	return counts
}

// generator_marshalRoundtrip asserts the config marshals to valid JSON, also
// writes it under t.TempDir() so a file-backed read confirms it is well-formed.
func generator_marshalRoundtrip(t *testing.T, res *Result) {
	t.Helper()
	raw, err := json.Marshal(res.Config)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	back, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read temp config: %v", err)
	}
	var roundtrip map[string]any
	if err := json.Unmarshal(back, &roundtrip); err != nil {
		t.Fatalf("invalid JSON produced: %v", err)
	}
}

// TestGenerateFullPluginProfile exercises a profile mixing two sing-box
// endpoints (VLESS-Reality, Hysteria2) with two plugin-engine endpoints
// (AmneziaWG, olcRTC), a urltest group, a selector group, and a rule.
func TestGenerateFullPluginProfile(t *testing.T) {
	vless := generator_vlessReality()
	hy2 := generator_hysteria2()
	awg := generator_amneziaWG()
	olc := generator_olcRTC()

	p := &model.Profile{
		Endpoints: []model.Endpoint{vless, hy2, awg, olc},
		Groups: []model.Group{
			{
				ID: "auto", Name: "Auto", Type: model.GroupURLTest,
				Members: []string{vless.ID, hy2.ID},
				Test:    &model.Health{URL: "http://example.com/gen204", Interval: 30, Tolerance: 80},
			},
			{
				ID: "manual", Name: "Manual", Type: model.GroupSelector,
				Members: []string{awg.ID, olc.ID},
			},
		},
		Rules: []model.Rule{
			{ID: "gov-direct", GeoSite: []string{"category-gov-ru"}, Outbound: model.OutboundDirect},
			{ID: "def", Default: true, Outbound: "auto"},
		},
	}

	res, err := Generate(p, Options{
		MixedPort: 7890, ClashAddr: "127.0.0.1:9090", ClashSecret: "s3cret", TunEnabled: true,
	})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	generator_marshalRoundtrip(t, res)

	// --- Plugins: AmneziaWG + olcRTC, NOT sing-box outbounds. ---
	if len(res.Plugins) != 2 {
		t.Fatalf("expected 2 plugins, got %d: %+v", len(res.Plugins), res.Plugins)
	}
	// Order follows endpoint order: awg first (17900), olc second (17901).
	if res.Plugins[0].Endpoint.ID != awg.ID || res.Plugins[1].Endpoint.ID != olc.ID {
		t.Fatalf("plugin order: got %q,%q want %q,%q",
			res.Plugins[0].Endpoint.ID, res.Plugins[1].Endpoint.ID, awg.ID, olc.ID)
	}
	if res.Plugins[0].Endpoint.Protocol != model.ProtoAmneziaWG {
		t.Fatalf("plugin[0] protocol = %q, want amneziawg", res.Plugins[0].Endpoint.Protocol)
	}
	if res.Plugins[1].Endpoint.Protocol != model.ProtoOlcRTC {
		t.Fatalf("plugin[1] protocol = %q, want olcrtc", res.Plugins[1].Endpoint.Protocol)
	}
	// AmneziaWG egresses via bind_interface (no SOCKS port); olcRTC keeps its port.
	if res.Plugins[0].SOCKSPort != 0 {
		t.Fatalf("amneziawg plugin should have no SOCKS port, got %d", res.Plugins[0].SOCKSPort)
	}
	if res.Plugins[1].SOCKSPort != basePluginPort+1 {
		t.Fatalf("olcrtc plugin port = %d, want %d", res.Plugins[1].SOCKSPort, basePluginPort+1)
	}

	byTag := generator_outboundsByTag(t, res)

	// AmneziaWG egresses via a direct outbound bound to its kernel interface.
	awgOb, ok := byTag[awg.ID]
	if !ok || awgOb["type"] != "direct" {
		t.Fatalf("amneziawg outbound = %v, want direct", awgOb)
	}
	if bi, _ := awgOb["bind_interface"].(string); bi == "" {
		t.Fatalf("amneziawg outbound missing bind_interface: %v", awgOb)
	}
	// olcRTC is chained over a local SOCKS outbound at its plugin port.
	olcOb, ok := byTag[olc.ID]
	if !ok || olcOb["type"] != "socks" || olcOb["server"] != "127.0.0.1" ||
		olcOb["server_port"] != res.Plugins[1].SOCKSPort || olcOb["version"] != "5" {
		t.Fatalf("olcrtc chained outbound = %v, want socks @127.0.0.1:%d", olcOb, res.Plugins[1].SOCKSPort)
	}

	// --- Outbound type counts. ---
	counts := generator_typeCounts(t, res)
	// Two `direct` outbounds now: the builtin one + AmneziaWG's bind_interface egress.
	// sing-box >=1.12 dropped `block`.
	if counts["direct"] != 2 || counts["block"] != 0 {
		t.Fatalf("builtin outbounds wrong: direct=%d block=%d", counts["direct"], counts["block"])
	}
	if counts["vless"] != 1 {
		t.Fatalf("vless count = %d, want 1", counts["vless"])
	}
	if counts["hysteria2"] != 1 {
		t.Fatalf("hysteria2 count = %d, want 1", counts["hysteria2"])
	}
	// One chained socks outbound (olcRTC); AmneziaWG egresses via bind_interface.
	if counts["socks"] != 1 {
		t.Fatalf("socks count = %d, want 1", counts["socks"])
	}
	if counts["urltest"] != 1 {
		t.Fatalf("urltest count = %d, want 1", counts["urltest"])
	}
	if counts["selector"] != 1 {
		t.Fatalf("selector count = %d, want 1", counts["selector"])
	}
	// No native plugin-protocol outbound types must leak in.
	if counts["amneziawg"] != 0 || counts["wireguard"] != 0 || counts["olcrtc"] != 0 {
		t.Fatalf("plugin protocols leaked as sing-box outbounds: %v", counts)
	}
	// Total outbounds: direct, vless, hy2, 2 socks, 2 groups = 7 (no `block` in sing-box >=1.12).
	obs := res.Config["outbounds"].([]map[string]any)
	if len(obs) != 7 {
		t.Fatalf("outbound count = %d, want 7 (%v)", len(obs), counts)
	}

	// --- VLESS-Reality fields survive. ---
	vlessOB := byTag[vless.ID]
	if vlessOB == nil {
		t.Fatal("vless outbound missing")
	}
	if vlessOB["type"] != "vless" {
		t.Fatalf("vless type = %v", vlessOB["type"])
	}
	if vlessOB["uuid"] != "uuid-1" {
		t.Fatalf("vless uuid = %v", vlessOB["uuid"])
	}
	if vlessOB["flow"] != "xtls-rprx-vision" {
		t.Fatalf("vless flow = %v", vlessOB["flow"])
	}
	if vlessOB["server"] != "1.1.1.1" || vlessOB["server_port"] != 443 {
		t.Fatalf("vless server/port = %v:%v", vlessOB["server"], vlessOB["server_port"])
	}
	vtls, ok := vlessOB["tls"].(map[string]any)
	if !ok {
		t.Fatalf("vless tls missing/typed wrong: %T", vlessOB["tls"])
	}
	if vtls["server_name"] != "www.microsoft.com" {
		t.Fatalf("vless sni = %v", vtls["server_name"])
	}
	reality, ok := vtls["reality"].(map[string]any)
	if !ok {
		t.Fatalf("vless reality block missing: %v", vtls)
	}
	if reality["public_key"] != generatorTestPBK || reality["short_id"] != "ab" {
		t.Fatalf("reality keys lost: %v", reality)
	}

	// --- Hysteria2 fields survive, incl. obfs. ---
	hy2OB := byTag[hy2.ID]
	if hy2OB == nil {
		t.Fatal("hysteria2 outbound missing")
	}
	if hy2OB["type"] != "hysteria2" || hy2OB["password"] != "pw" {
		t.Fatalf("hy2 type/password wrong: %v / %v", hy2OB["type"], hy2OB["password"])
	}
	obfs, ok := hy2OB["obfs"].(map[string]any)
	if !ok {
		t.Fatalf("hy2 obfs missing: %T", hy2OB["obfs"])
	}
	if obfs["type"] != "salamander" || obfs["password"] != "zz" {
		t.Fatalf("hy2 obfs wrong: %v", obfs)
	}

	// --- urltest group reflects custom Health knobs. ---
	auto := byTag["auto"]
	if auto == nil || auto["type"] != "urltest" {
		t.Fatalf("auto group missing/wrong type: %v", auto)
	}
	if auto["url"] != "http://example.com/gen204" {
		t.Fatalf("urltest url = %v", auto["url"])
	}
	if auto["interval"] != "30s" {
		t.Fatalf("urltest interval = %v, want 30s", auto["interval"])
	}
	if auto["tolerance"] != 80 {
		t.Fatalf("urltest tolerance = %v, want 80", auto["tolerance"])
	}
	autoMembers, ok := auto["outbounds"].([]string)
	if !ok || len(autoMembers) != 2 || autoMembers[0] != vless.ID || autoMembers[1] != hy2.ID {
		t.Fatalf("urltest members = %v", auto["outbounds"])
	}

	// --- selector group. ---
	manual := byTag["manual"]
	if manual == nil || manual["type"] != "selector" {
		t.Fatalf("manual group missing/wrong type: %v", manual)
	}
	if _, hasURL := manual["url"]; hasURL {
		t.Fatalf("selector should not carry a url field: %v", manual)
	}
	manMembers, ok := manual["outbounds"].([]string)
	if !ok || len(manMembers) != 2 || manMembers[0] != awg.ID || manMembers[1] != olc.ID {
		t.Fatalf("selector members = %v", manual["outbounds"])
	}

	// --- Inbounds: mixed always; tun when enabled. ---
	inbounds, ok := res.Config["inbounds"].([]map[string]any)
	if !ok {
		t.Fatalf("inbounds typed wrong: %T", res.Config["inbounds"])
	}
	var mixed, tun map[string]any
	for _, in := range inbounds {
		switch in["type"] {
		case "mixed":
			mixed = in
		case "tun":
			tun = in
		}
	}
	if mixed == nil {
		t.Fatal("mixed inbound missing")
	}
	if mixed["listen_port"] != 7890 || mixed["listen"] != "127.0.0.1" {
		t.Fatalf("mixed inbound wrong: %v", mixed)
	}
	if tun == nil {
		t.Fatal("tun inbound missing despite TunEnabled")
	}

	// --- Clash API present. ---
	exp, ok := res.Config["experimental"].(map[string]any)
	if !ok {
		t.Fatalf("experimental missing: %T", res.Config["experimental"])
	}
	clash, ok := exp["clash_api"].(map[string]any)
	if !ok {
		t.Fatalf("clash_api missing: %v", exp)
	}
	if clash["external_controller"] != "127.0.0.1:9090" || clash["secret"] != "s3cret" {
		t.Fatalf("clash_api fields wrong: %v", clash)
	}

	// --- Route: rule + default → final. ---
	route, ok := res.Config["route"].(map[string]any)
	if !ok {
		t.Fatalf("route typed wrong: %T", res.Config["route"])
	}
	if route["final"] != "auto" {
		t.Fatalf("route.final = %v, want auto", route["final"])
	}
	rules, ok := route["rules"].([]map[string]any)
	if !ok || len(rules) != 3 {
		t.Fatalf("expected 3 route rules (sniff + endpoint bypass + geosite), got %v", route["rules"])
	}
	// rules[0] = sniff (TUN); rules[1] = the endpoint-IP bypass; rules[2] = the geosite rule.
	if rules[0]["action"] != "sniff" {
		t.Fatalf("rules[0] should be sniff: %v", rules[0])
	}
	if rules[1]["outbound"] != model.OutboundDirect || rules[1]["ip_cidr"] == nil {
		t.Fatalf("rules[1] should be the endpoint-IP bypass: %v", rules[1])
	}
	if rules[2]["outbound"] != model.OutboundDirect {
		t.Fatalf("rule outbound = %v, want direct", rules[2]["outbound"])
	}
	// geosite is no longer an inline matcher (sing-box 1.12 removed the database) —
	// it becomes a remote rule-set reference.
	if _, has := rules[2]["geosite"]; has {
		t.Fatalf("rule must not carry inline geosite: %v", rules[2]["geosite"])
	}
	rs, ok := rules[2]["rule_set"].([]string)
	if !ok || len(rs) != 1 || rs[0] != "geosite-category-gov-ru" {
		t.Fatalf("rule.rule_set = %v, want [geosite-category-gov-ru]", rules[2]["rule_set"])
	}

	// --- log block. ---
	if _, ok := res.Config["log"].(map[string]any); !ok {
		t.Fatalf("log block missing: %T", res.Config["log"])
	}
}

// TestGenerateEmptyProfile checks the floor: only builtin outbounds, mixed
// inbound, a direct-final route, log block, and no clash/tun by default.
func TestGenerateEmptyProfile(t *testing.T) {
	res, err := Generate(&model.Profile{}, Options{MixedPort: 1080})
	if err != nil {
		t.Fatalf("generate empty: %v", err)
	}
	generator_marshalRoundtrip(t, res)

	if len(res.Plugins) != 0 {
		t.Fatalf("expected no plugins, got %+v", res.Plugins)
	}

	obs, ok := res.Config["outbounds"].([]map[string]any)
	if !ok {
		t.Fatalf("outbounds typed wrong: %T", res.Config["outbounds"])
	}
	if len(obs) != 1 {
		t.Fatalf("empty profile outbounds = %d, want 1 (direct only; block is a route action in sing-box >=1.12)", len(obs))
	}
	counts := generator_typeCounts(t, res)
	if counts["direct"] != 1 || counts["block"] != 0 {
		t.Fatalf("builtin outbounds wrong: %v", counts)
	}

	inbounds, ok := res.Config["inbounds"].([]map[string]any)
	if !ok || len(inbounds) != 1 || inbounds[0]["type"] != "mixed" {
		t.Fatalf("empty profile inbounds = %v", res.Config["inbounds"])
	}
	if inbounds[0]["listen_port"] != 1080 {
		t.Fatalf("mixed listen_port = %v, want 1080", inbounds[0]["listen_port"])
	}

	route, ok := res.Config["route"].(map[string]any)
	if !ok {
		t.Fatalf("route typed wrong: %T", res.Config["route"])
	}
	if route["final"] != model.OutboundDirect {
		t.Fatalf("empty route.final = %v, want direct", route["final"])
	}
	if _, hasRules := route["rules"]; hasRules {
		t.Fatalf("empty profile should have no route rules: %v", route["rules"])
	}

	// No clash API and no tun inbound when options are zero.
	if _, hasExp := res.Config["experimental"]; hasExp {
		t.Fatalf("experimental should be absent without ClashAddr: %v", res.Config["experimental"])
	}
	for _, in := range inbounds {
		if in["type"] == "tun" {
			t.Fatal("tun inbound present despite TunEnabled=false")
		}
	}
	if _, ok := res.Config["log"].(map[string]any); !ok {
		t.Fatal("log block missing on empty profile")
	}
}

// TestGenerateGroupMissingMember confirms Generate runs Validate first and
// rejects a group referencing an unknown member.
func TestGenerateGroupMissingMember(t *testing.T) {
	vless := generator_vlessReality()
	p := &model.Profile{
		Endpoints: []model.Endpoint{vless},
		Groups: []model.Group{{
			ID: "grp", Name: "Group", Type: model.GroupSelector,
			Members: []string{vless.ID, "ghost-endpoint"},
		}},
	}
	res, err := Generate(p, Options{MixedPort: 7890})
	if err == nil {
		t.Fatalf("expected validation error for missing member, got config: %+v", res)
	}
	if res != nil {
		t.Fatalf("expected nil result on error, got %+v", res)
	}
}

// TestGenerateSkipsDisabledEndpoint confirms a disabled plugin endpoint
// produces neither a Plugin record nor a chained outbound.
func TestGenerateSkipsDisabledEndpoint(t *testing.T) {
	vless := generator_vlessReality()
	awg := generator_amneziaWG()
	awg.Enabled = false

	p := &model.Profile{Endpoints: []model.Endpoint{vless, awg}}
	res, err := Generate(p, Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(res.Plugins) != 0 {
		t.Fatalf("disabled plugin endpoint should yield no plugins, got %+v", res.Plugins)
	}
	byTag := generator_outboundsByTag(t, res)
	if _, ok := byTag[awg.ID]; ok {
		t.Fatalf("disabled endpoint %q must not produce an outbound", awg.ID)
	}
	if _, ok := byTag[vless.ID]; !ok {
		t.Fatalf("enabled vless endpoint %q missing its outbound", vless.ID)
	}
}
