package generator

import (
	"testing"

	"wayhop/internal/model"
)

// TestRuleSetFormat: the format is inferred from the URL extension, but a ?query /
// #fragment must be stripped first — a "list.json?token=X" is a JSON source, and
// mis-tagging it binary makes sing-box fail to parse the downloaded list. An
// explicit Format always wins.
func TestRuleSetFormat(t *testing.T) {
	cases := []struct {
		source, format, want string
	}{
		{"https://x/list.srs", "", "binary"},
		{"https://x/list.json", "", "source"},
		{"https://x/list.json?token=abc", "", "source"}, // was mis-detected as binary
		{"https://x/list.json#frag", "", "source"},
		{"https://x/list.srs?v=2", "", "binary"},
		{"https://x/dynamic?fmt=json", "", "binary"},          // no .json before the query → binary default
		{"https://x/list.json?token=abc", "binary", "binary"}, // explicit override wins
	}
	for _, c := range cases {
		got := ruleSetFormat(&model.RoutingList{Source: c.source, Format: c.format})
		if got != c.want {
			t.Errorf("ruleSetFormat(source=%q, format=%q) = %q, want %q", c.source, c.format, got, c.want)
		}
	}
}

// Routing lists must become route.rule_set entries (remote URL via download_detour,
// or inline manual) + referencing rules (reject lists before route lists), with
// cache_file enabled. Disabled lists are skipped.
func TestRoutingListsGenerateRuleSets(t *testing.T) {
	nl := generator_singBoxEndpoint("nl", model.ProtoVLESS, map[string]any{"uuid": "u"})
	p := &model.Profile{
		Endpoints: []model.Endpoint{nl},
		Rules:     []model.Rule{{ID: "d", Default: true, Outbound: model.OutboundDirect}},
		RoutingLists: []model.RoutingList{
			{ID: "ru", Name: "RU", Source: "https://x/ru.srs", Outbound: "nl", DownloadVia: model.OutboundDirect, RefreshHours: 12, Enabled: true},
			{ID: "ads", Name: "Ads", Manual: []string{"ads.example.com", "1.2.3.0/24", "9.9.9.9"}, Outbound: model.OutboundBlock, Enabled: true},
			{ID: "off", Name: "Off", Source: "https://x/off.srs", Outbound: "nl", Enabled: false},
		},
	}
	res, err := Generate(p, Options{MixedPort: 7890, ClashAddr: "127.0.0.1:9090", CacheFile: "/tmp/c.db"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	route := res.Config["route"].(map[string]any)
	sets := route["rule_set"].([]map[string]any)
	if len(sets) != 2 {
		t.Fatalf("rule_set count = %d, want 2 (disabled skipped)", len(sets))
	}
	var remote, inline map[string]any
	for _, s := range sets {
		switch s["type"] {
		case "remote":
			remote = s
		case "inline":
			inline = s
		}
	}
	if remote == nil || remote["url"] != "https://x/ru.srs" || remote["download_detour"] != "direct" ||
		remote["format"] != "binary" || remote["update_interval"] != "12h" {
		t.Fatalf("remote rule_set wrong: %v", remote)
	}
	if inline == nil {
		t.Fatal("inline (manual) rule_set missing")
	}
	m := inline["rules"].([]map[string]any)[0]
	if len(m["domain_suffix"].([]string)) != 1 {
		t.Fatalf("manual domains: %v", m["domain_suffix"])
	}
	if ips := m["ip_cidr"].([]string); len(ips) != 2 || ips[1] != "9.9.9.9/32" { // bare IP normalised to /32
		t.Fatalf("manual ip_cidr: %v", ips)
	}

	rules := route["rules"].([]map[string]any)
	rejectIdx, routeIdx := -1, -1
	for i, r := range rules {
		if r["action"] == "reject" {
			rejectIdx = i
		}
		if r["action"] == "route" && r["outbound"] == "nl" {
			routeIdx = i
		}
	}
	if rejectIdx == -1 || routeIdx == -1 || rejectIdx > routeIdx {
		t.Fatalf("want reject(ads) before route(ru): reject@%d route@%d rules=%v", rejectIdx, routeIdx, rules)
	}

	exp := res.Config["experimental"].(map[string]any)
	if cf, ok := exp["cache_file"].(map[string]any); !ok || cf["enabled"] != true || cf["path"] != "/tmp/c.db" {
		t.Fatalf("cache_file not enabled with path: %v", exp)
	}
}

// With a block-by-default posture, the terminal catch-all reject must come AFTER
// the routing-list rules — otherwise it shadows them (first-match wins) and the
// "route only the listed traffic, block everything else" whitelist breaks.
func TestRoutingListsBeforeBlockDefault(t *testing.T) {
	nl := generator_singBoxEndpoint("nl", model.ProtoVLESS, map[string]any{"uuid": "u"})
	p := &model.Profile{
		Endpoints: []model.Endpoint{nl},
		Rules:     []model.Rule{{ID: "d", Default: true, Outbound: model.OutboundBlock}},
		RoutingLists: []model.RoutingList{
			{ID: "allow", Name: "Allow", Manual: []string{"openai.com"}, Outbound: "nl", Enabled: true},
		},
	}
	res, err := Generate(p, Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	route := res.Config["route"].(map[string]any)
	if route["final"] != model.OutboundDirect {
		t.Fatalf("final = %v, want direct (a block default is a terminal rule, not final)", route["final"])
	}
	rules := route["rules"].([]map[string]any)
	listIdx, blockIdx := -1, -1
	for i, r := range rules {
		if _, ok := r["rule_set"]; ok && r["action"] == "route" {
			listIdx = i
		}
		if _, hasRS := r["rule_set"]; !hasRS {
			if _, hasNet := r["network"]; hasNet && r["action"] == "reject" {
				blockIdx = i
			}
		}
	}
	if listIdx == -1 || blockIdx == -1 || listIdx > blockIdx {
		t.Fatalf("want list route rule before block-all reject: list@%d block@%d rules=%v", listIdx, blockIdx, rules)
	}
}

// No routing lists -> no rule_set key, no cache_file.
func TestNoRoutingListsNoRuleSet(t *testing.T) {
	nl := generator_singBoxEndpoint("nl", model.ProtoVLESS, map[string]any{"uuid": "u"})
	res, err := Generate(&model.Profile{Endpoints: []model.Endpoint{nl}}, Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, ok := res.Config["route"].(map[string]any)["rule_set"]; ok {
		t.Fatal("rule_set should be absent with no routing lists")
	}
}

// TestRuleMatchDropsBlankEntries: ruleMatch must drop blank matcher entries. An
// empty domain_suffix "" matches EVERY host (every domain ends with ""), so a
// mixed matcher like domain_suffix:["real.com",""] would silently become match-all
// and leak all traffic to the rule's outbound; an all-blank slice yields no key.
func TestRuleMatchDropsBlankEntries(t *testing.T) {
	rm := ruleMatch(&model.Rule{
		DomainSuffix: []string{"real.com", "", " "},
		Domain:       []string{"x.com"},
		IPCIDR:       []string{""},
	})
	if ds, _ := rm["domain_suffix"].([]string); len(ds) != 1 || ds[0] != "real.com" {
		t.Fatalf("domain_suffix must drop blanks → [real.com], got %v", rm["domain_suffix"])
	}
	if d, _ := rm["domain"].([]string); len(d) != 1 || d[0] != "x.com" {
		t.Fatalf("domain should be [x.com], got %v", rm["domain"])
	}
	if _, ok := rm["ip_cidr"]; ok {
		t.Fatalf("an all-blank ip_cidr must be omitted entirely, got %v", rm["ip_cidr"])
	}
}
