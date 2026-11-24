package generator

import (
	"testing"

	"wayhop/internal/model"
)

// TestSingboxConsumableSource locks which remote sources sing-box can actually load. Getting this
// wrong is catastrophic rather than cosmetic: a non-loadable rule-set aborts the ENTIRE core at
// startup ("unknown version: NN" when ASCII is read as a binary header), so the daemon never runs.
func TestSingboxConsumableSource(t *testing.T) {
	cases := []struct {
		name, src, format string
		want              bool
	}{
		{"compiled srs", "https://example.test/list.srs", "", true},
		{"rule-set json", "https://example.test/list.json", "", true},
		{"srs with query", "https://example.test/list.srs?v=2", "", true},
		// The extension is read as the model and the panel read it (model.RuleSetURLKind), whatever
		// its case: read here case-sensitively, a list both of them call a rule set was left out of
		// the core with no word said, and matched nothing.
		{"upper-case srs", "https://example.test/LIST.SRS", "", true},
		{"mixed-case json with query", "https://example.test/list.Json?token=x", "", true},
		{"upper-case text list", "https://example.test/domains.TXT", "", false},
		// Real-world plain-text lists that MUST be skipped (these bricked a live router).
		{"v2fly text list, no extension", "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/anthropic", "", false},
		{"itdoginfo .lst", "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/news.lst", "", false},
		{"plain .txt", "https://example.test/domains.txt", "", false},
		{"bare path", "https://example.test/Categories/geoblock", "", false},
		// An explicit Format is the user overriding the guess — trust it either way.
		{"explicit binary wins", "https://example.test/whatever", "binary", true},
		{"explicit source wins", "https://example.test/whatever", "source", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rl := &model.RoutingList{Source: c.src, Format: c.format}
			if got := singboxConsumableSource(rl); got != c.want {
				t.Errorf("singboxConsumableSource(%q, format=%q) = %v, want %v", c.src, c.format, got, c.want)
			}
		})
	}
}

// TestRoutingFrom_SkipsUnloadableSource: a text-list source produces NO remote rule_set (so the core
// still starts), while a .srs source in the same profile is still emitted.
func TestRoutingFrom_SkipsUnloadableSource(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{ID: "vps", Name: "vps", Engine: model.EngineSingBox,
			Protocol: model.ProtoTrojan, Server: "203.0.113.9", Port: 443, Enabled: true,
			Params: map[string]any{"password": "x"}}},
		RoutingLists: []model.RoutingList{
			{ID: "textlist", Name: "text", Enabled: true, Outbound: "vps",
				Source: "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/anthropic"},
			{ID: "srslist", Name: "srs", Enabled: true, Outbound: "vps",
				Source: "https://example.test/good.srs"},
		},
	}
	sets, _ := routingFrom(p, false, "")

	var haveText, haveSRS bool
	for _, s := range sets {
		switch s["tag"] {
		case "rs-textlist":
			haveText = true
		case "rs-srslist":
			haveSRS = true
		}
	}
	if haveText {
		t.Error("a plain-text list source must NOT become a sing-box rule_set (it aborts the whole core)")
	}
	if !haveSRS {
		t.Error("a .srs source must still be emitted")
	}
}

// A text-list source WITH manual entries still contributes its manual inline set — skipping the
// remote set must not silently drop the whole list.
func TestRoutingFrom_TextSourceKeepsManualEntries(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{ID: "vps", Name: "vps", Engine: model.EngineSingBox,
			Protocol: model.ProtoTrojan, Server: "203.0.113.9", Port: 443, Enabled: true,
			Params: map[string]any{"password": "x"}}},
		RoutingLists: []model.RoutingList{{
			ID: "mixed", Name: "mixed", Enabled: true, Outbound: "vps",
			Source: "https://example.test/list.lst",
			Manual: []string{"example.com"},
		}},
	}
	sets, rules := routingFrom(p, false, "")
	var haveManual bool
	for _, s := range sets {
		if s["tag"] == "rsm-mixed" {
			haveManual = true
		}
		if s["tag"] == "rs-mixed" {
			t.Error("text source must be skipped")
		}
	}
	if !haveManual {
		t.Error("manual entries must still produce an inline rule_set")
	}
	if len(rules) == 0 {
		t.Error("the list should still route via its manual entries")
	}
}

// A typed entry with a "/" that is not an IP prefix is no name either (no name holds one). It
// was emitted as a domain suffix; it is left out, as the kernel plane leaves it out.
func TestSplitDomainsIPsLeavesOutASlashEntryThatIsNoPrefix(t *testing.T) {
	domains, ips := splitDomainsIPs([]string{"example.com", "10.0.0.0/99", "192.0.2.0/24", "example.org/path", "192.0.2.7"})
	if len(domains) != 1 || domains[0] != "example.com" {
		t.Errorf("domains = %v, want only example.com", domains)
	}
	if len(ips) != 2 || ips[0] != "192.0.2.0/24" || ips[1] != "192.0.2.7/32" {
		t.Errorf("ips = %v, want the prefix and the address", ips)
	}
	p := &model.Profile{RoutingLists: []model.RoutingList{{ID: "r", Enabled: true, Outbound: "direct", Manual: []string{"10.0.0.0/99"}}}}
	if sets, rules := routingFrom(p, false, ""); len(sets) != 0 || len(rules) != 0 {
		t.Errorf("a list of one unreadable entry gave sets=%v rules=%v, want none", sets, rules)
	}
}
