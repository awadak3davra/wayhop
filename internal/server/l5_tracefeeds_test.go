package server

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestTraceEvaluatesFetchedFeeds (L5): the trace must answer with what it has.
//
// "Where does a domain go?" read only a list's INLINE entries, so any list backed by a feed fell
// into "may also match (can't check statically) — remote rule-set — contents not loaded here".
// Measured on a live Keenetic tracing teamviewer.com: four CIDR-feed lists hedged that way
// while `ipset test` answered each one outright (NOT in set), because the very prefixes the trace
// called unloaded were sitting in the profile — 15887 of them for cidr-antifilter alone — and in the
// kernel sets built from them. The answer was available and withheld.
//
// Both directions matter: a hedge that hides a real MATCH sends the user looking for a rule that is
// right there, and a hedge over a real NON-match leaves the question unanswered.
func TestTraceEvaluatesFetchedFeeds(t *testing.T) {
	profile := &model.Profile{RoutingLists: []model.RoutingList{
		{ID: "cidr-feed", Outbound: "grp", Enabled: true,
			CIDRSource: "https://example.com/c.txt", CIDRCache: []string{"203.0.113.0/24", "198.51.100.0/24"}},
		{ID: "name-feed", Outbound: "grp", Enabled: true,
			DomainSource: "https://example.com/n.txt", DomainCache: []string{"blocked.example"}},
		{ID: "ruleset", Outbound: "grp", Enabled: true, Source: "https://example.com/x.srs"},
		{ID: "never-fetched", Outbound: "grp", Enabled: true, CIDRSource: "https://example.com/empty.txt"},
	}}

	// An address INSIDE a fetched prefix is a match, named as one.
	cands, uneval := traceCandidates("whatever.example", []string{"203.0.113.7"}, profile, nil)
	if !hasCandidate(cands, "cidr-feed") {
		t.Errorf("an IP inside a fetched prefix must match its list: %+v", cands)
	}
	if hasCandidate(uneval, "cidr-feed") {
		t.Errorf("and must not ALSO be hedged: %+v", uneval)
	}

	// An address outside every fetched prefix is a decided NON-match: neither matched nor hedged.
	cands, uneval = traceCandidates("whatever.example", []string{"192.0.2.92"}, profile, nil)
	if hasCandidate(cands, "cidr-feed") {
		t.Errorf("an IP outside every prefix must not match: %+v", cands)
	}
	if hasCandidate(uneval, "cidr-feed") {
		t.Errorf("a fetched feed must not be hedged — its contents are loaded: %+v", uneval)
	}

	// A fetched NAME feed is evaluated the same way, by suffix, exactly as dnsmasq matches it.
	cands, _ = traceCandidates("sub.blocked.example", nil, profile, nil)
	if !hasCandidate(cands, "name-feed") {
		t.Errorf("a name feed must match its own subdomains: %+v", cands)
	}

	// The one shape that genuinely cannot be read here keeps its hedge — and says why accurately.
	_, uneval = traceCandidates("whatever.example", []string{"192.0.2.92"}, profile, nil)
	if !hasCandidate(uneval, "ruleset") {
		t.Errorf("a binary rule-set must still be hedged: %+v", uneval)
	}
	for _, c := range uneval {
		if c.ID == "ruleset" && !strings.Contains(c.Why, "sing-box artifact") {
			t.Errorf("the hedge must name the real reason, got %q", c.Why)
		}
	}

	// A feed configured but never fetched holds nothing: silence would read as "does not match".
	if !hasCandidate(uneval, "never-fetched") {
		t.Errorf("an unfetched feed must say so rather than read as a non-match: %+v", uneval)
	}
	for _, c := range uneval {
		if c.ID == "never-fetched" && !strings.Contains(c.Why, "never been fetched") {
			t.Errorf("and must name that reason, got %q", c.Why)
		}
	}
}

func hasCandidate(list []traceCandidate, id string) bool {
	for _, c := range list {
		if c.ID == id {
			return true
		}
	}
	return false
}
