package server

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"wayhop/internal/cidrfeed"
	"wayhop/internal/keenetic"
)

// A router's list or a pasted ip.list may carry the default route, the LAN or loopback. None of them
// may reach the offered list: one such line, once an exit is picked, is a full tunnel or the LAN sent
// into it. Each is reported with its reason; an ordinary network stays.
func TestRoutingImportScreensPrefixesNoListShouldCarry(t *testing.T) {
	ans := keeneticImportAnswer([]keenetic.FQDNGroup{{Name: "domain-list0", Description: "IP_List",
		CIDRs: []string{"0.0.0.0/0", "::/0", "0.0.0.0/1", "10.0.0.0/8", "192.168.77.1/32",
			"fd00::/8", "100.64.1.0/24", "127.0.0.1/32", "fe80::1/128", "224.0.0.0/4", "203.0.113.0/24"}}}, false)
	g := ans.Groups[0]
	want := map[string]string{
		"0.0.0.0/0": routingImportSkipTooBroad, "::/0": routingImportSkipTooBroad,
		"0.0.0.0/1":  routingImportSkipTooBroad,
		"10.0.0.0/8": routingImportSkipPrivate, "192.168.77.1/32": routingImportSkipPrivate,
		"fd00::/8": routingImportSkipPrivate, "100.64.1.0/24": routingImportSkipPrivate,
		"127.0.0.1/32": routingImportSkipNotRoutable, "fe80::1/128": routingImportSkipNotRoutable,
		"224.0.0.0/4": routingImportSkipNotRoutable,
	}
	got := map[string]string{}
	for _, s := range g.Skipped {
		got[s.Entry] = s.Reason
	}
	for entry, reason := range want {
		if got[entry] != reason {
			t.Errorf("%s skipped as %q, want %q", entry, got[entry], reason)
		}
	}
	if g.Suggested == nil || strings.Join(g.Suggested.Manual, ",") != "203.0.113.0/24" || g.SkippedTotal != len(want) {
		t.Errorf("offered %+v (skipped %d), want only 203.0.113.0/24", g.Suggested, g.SkippedTotal)
	}
}

// QA-111, on the importer's side: the IPv4 default route written as IPv6 (::ffff:0.0.0.0/96) passed
// the screen as an ordinary IPv6 /96, and the kernel plane files it as 0.0.0.0/0. A v4-mapped prefix
// is judged as the IPv4 prefix it stands for.
func TestRoutingImportJudgesV4MappedPrefixesAsIPv4(t *testing.T) {
	ans := keeneticImportAnswer([]keenetic.FQDNGroup{{Name: "domain-list0", Description: "IP_List",
		CIDRs: []string{"::ffff:0.0.0.0/96", "::ffff:192.0.2.0/99", "::ffff:10.0.0.0/104", "203.0.113.0/24"}}}, false)
	g := ans.Groups[0]
	got := map[string]string{}
	for _, s := range g.Skipped {
		got[s.Entry] = s.Reason
	}
	want := map[string]string{
		"::ffff:0.0.0.0/96": routingImportSkipTooBroad, "::ffff:192.0.2.0/99": routingImportSkipTooBroad,
		"::ffff:10.0.0.0/104": routingImportSkipPrivate,
	}
	for entry, reason := range want {
		if got[entry] != reason {
			t.Errorf("%s skipped as %q, want %q", entry, got[entry], reason)
		}
	}
	if g.Suggested == nil || strings.Join(g.Suggested.Manual, ",") != "203.0.113.0/24" {
		t.Errorf("offered %+v, want only 203.0.113.0/24", g.Suggested)
	}
}

// A pasted country list keeps its aggregates. ipdeny's us-aggregated.zone, the kind of ip.list a
// HydraRoute user pastes, carries /6 and /7 aggregates; the screen first refused every prefix shorter
// than an IPv4 /8, and the offered list lost a quarter of a billion addresses. The importer and a
// fetched feed share one rule (cidrfeed.TooBroad), which refuses a share of the whole space, not a
// country's blocks. Spelled from documentation addresses at the lengths such a list carries.
func TestRoutingImportKeepsCountryAggregates(t *testing.T) {
	aggregates := []string{"198.51.100.0/6", "203.0.113.0/7", "2001:db8::/12"}
	ans := keeneticImportAnswer([]keenetic.FQDNGroup{{Name: "domain-list0", Description: "IP_List",
		CIDRs: append([]string{"0.0.0.0/1", "::/0"}, aggregates...)}}, false)
	g := ans.Groups[0]
	if g.SkippedTotal != 2 || g.Suggested == nil || len(g.Suggested.Manual) != len(aggregates) {
		t.Fatalf("skipped %+v, offered %+v; want the /1 and ::/0 refused and the aggregates offered", g.Skipped, g.Suggested)
	}
}

// The answer stays proportionate to what it reports, and a list larger than the resolver may hold is
// refused like a feed of that size.
func TestRoutingImportBoundsSkipsAndListSize(t *testing.T) {
	payload, _ := json.Marshal(map[string]string{"text": strings.Repeat("a,", 1000) + "example.com/HydraRoute\n"})
	ans := decodeRoutingImport(t, postHydraRoute(&Server{}, string(payload)))
	if len(ans.Groups) != 1 {
		t.Fatalf("groups = %d", len(ans.Groups))
	}
	if g := ans.Groups[0]; len(g.Skipped) != routingImportMaxSkips || g.SkippedTotal != 1000 {
		t.Errorf("skipped listed %d of %d, want %d of 1000", len(g.Skipped), g.SkippedTotal, routingImportMaxSkips)
	}

	names := make([]string, cidrfeed.MaxDomains+1)
	for i := range names {
		names[i] = fmt.Sprintf("n%d.example.com", i)
	}
	if s, why := suggestRoutingList("Huge", names, nil); s != nil || !strings.Contains(why, "split the list") {
		t.Errorf("an oversize list was offered (%v): %q", s != nil, why)
	}
}
