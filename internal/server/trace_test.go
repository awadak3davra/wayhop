package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"wakeroute/internal/clash"
	"wakeroute/internal/model"
	"wakeroute/internal/pbr"
)

// TestClashTraceMatches: sniffed connections to the domain (exact or subdomain Host) at IPs the
// conntrack pass didn't cover are returned with the chain exit; already-seen dsts, other domains,
// and host-less rows are skipped.
func TestClashTraceMatches(t *testing.T) {
	conns := []clash.Conn{
		{Chains: []string{"ru-awg1", "ru-group"}, Upload: 10, Download: 90, Metadata: clash.ConnMeta{Host: "www.youtube.com", DestinationIP: "142.250.9.9", DestinationPort: "443"}},
		{Chains: []string{"direct"}, Metadata: clash.ConnMeta{Host: "youtube.com", DestinationIP: "1.2.3.4", DestinationPort: "443"}},
		{Metadata: clash.ConnMeta{Host: "example.com", DestinationIP: "5.5.5.5"}},     // other domain → skip
		{Metadata: clash.ConnMeta{Host: "youtube.com", DestinationIP: "142.250.1.1"}}, // already seen → skip
		{Metadata: clash.ConnMeta{Host: "", DestinationIP: "6.6.6.6"}},                // no host → skip
	}
	seen := map[string]bool{"142.250.1.1": true} // conntrack already covered this IP
	got := clashTraceMatches("youtube.com", conns, seen)
	if len(got) != 2 {
		t.Fatalf("want 2 sniffed matches at new IPs, got %d: %+v", len(got), got)
	}
	if got[0].Dst != "142.250.9.9" || got[0].Domain != "www.youtube.com" || got[0].Exit != "ru-awg1→ru-group" || got[0].Dport != 443 {
		t.Errorf("got[0] = %+v, want 142.250.9.9 / www.youtube.com / ru-awg1→ru-group / 443", got[0])
	}
	if got[1].Dst != "1.2.3.4" || got[1].Domain != "youtube.com" {
		t.Errorf("got[1] = %+v, want 1.2.3.4 / youtube.com", got[1])
	}
	for _, c := range got {
		if c.Dst == "142.250.1.1" || c.Dst == "5.5.5.5" || c.Dst == "6.6.6.6" {
			t.Errorf("an excluded dst leaked: %+v", c)
		}
	}
}

func TestValidTraceDomain(t *testing.T) {
	ok := []string{"youtube.com", "sub.example.co.uk", "8.8.8.8", "2606:4700:4700::1111", "a-b_c.test"}
	bad := []string{"", "has space.com", "a;b.com", "a|b", "x'y", string(make([]byte, 254))}
	for _, d := range ok {
		if !validTraceDomain(d) {
			t.Errorf("%q should be valid", d)
		}
	}
	for _, d := range bad {
		if validTraceDomain(d) {
			t.Errorf("%q should be invalid", d)
		}
	}
}

// TestTraceConnections: only conns to the resolved IPs are reported, each with its resolved exit,
// tallied per exit; an empty match sets the guidance note.
func TestTraceConnections(t *testing.T) {
	markExit := func(m uint32) string {
		if m == 0 {
			return "direct"
		}
		return "tunnel-ru"
	}
	ips := []string{"142.250.1.1", "142.250.1.2"}
	conns := []Conn{
		{Src: "192.168.1.50", Dst: "142.250.1.1", Dport: 443, Mark: 5, UpBytes: 10, DownBytes: 90},
		{Src: "192.168.1.51", Dst: "142.250.1.2", Dport: 443, Mark: 5, UpBytes: 1, DownBytes: 2},
		{Src: "192.168.1.52", Dst: "1.2.3.4", Dport: 443, Mark: 0, UpBytes: 5, DownBytes: 5}, // other IP → excluded
	}
	res := traceConnections("youtube.com", ips, conns, markExit)
	if len(res.Connections) != 2 {
		t.Fatalf("want 2 matched conns, got %d: %+v", len(res.Connections), res.Connections)
	}
	if res.Exits["tunnel-ru"] != 2 || res.Note != "" {
		t.Errorf("want 2 via tunnel-ru and no note, got exits=%v note=%q", res.Exits, res.Note)
	}
	for _, c := range res.Connections {
		if c.Dst == "1.2.3.4" {
			t.Error("a non-matching dest leaked into the trace")
		}
		if c.Exit != "tunnel-ru" {
			t.Errorf("exit = %q, want tunnel-ru", c.Exit)
		}
	}
	// No match → guidance note.
	empty := traceConnections("idle.example", ips, []Conn{{Dst: "9.9.9.9"}}, markExit)
	if len(empty.Connections) != 0 || empty.Note == "" {
		t.Errorf("no-match should set a note, got %+v", empty)
	}
}

// TestTraceCandidates: rules / inline lists / kernel zones that reference the domain or its IPs are
// listed; disabled + non-matching rules are skipped; geo + remote-list matchers are counted as
// unevaluated.
func TestTraceCandidates(t *testing.T) {
	p := &model.Profile{
		Rules: []model.Rule{
			{ID: "yt", DomainSuffix: []string{"youtube.com"}, Outbound: "tunnel-a"},
			{ID: "ipr", IPCIDR: []string{"142.250.0.0/16"}, Outbound: "tunnel-b"},
			{ID: "geo", GeoSite: []string{"google"}, Outbound: "tunnel-c"},                    // unevaluated
			{ID: "off", DomainSuffix: []string{"youtube.com"}, Outbound: "x", Disabled: true}, // skipped
			{ID: "nomatch", DomainSuffix: []string{"example.org"}, Outbound: "x"},
		},
		RoutingLists: []model.RoutingList{
			{ID: "inlist", Manual: []string{"youtube.com", "10.0.0.0/8"}, Outbound: "tunnel-d", Enabled: true},
			{ID: "remote", Source: "https://x/y.srs", Outbound: "tunnel-e", Enabled: true}, // unevaluated
		},
	}
	plan := &pbr.Plan{Zones: []pbr.Zone{{Name: "z1", EgressTag: "tunnel-z", V4: []string{"142.250.0.0/16"}}}}
	cands, uneval := traceCandidates("www.youtube.com", []string{"142.250.1.1"}, p, plan)
	got := map[string]bool{}
	for _, c := range cands {
		got[c.Kind+":"+c.ID] = true
	}
	for _, want := range []string{"rule:yt", "rule:ipr", "list:inlist", "kernel-zone:z1"} {
		if !got[want] {
			t.Errorf("missing candidate %q; got %+v", want, cands)
		}
	}
	if got["rule:off"] || got["rule:nomatch"] {
		t.Errorf("a disabled/non-matching rule was listed: %+v", cands)
	}
	if len(cands) != 4 {
		t.Errorf("want 4 candidates, got %d: %+v", len(cands), cands)
	}
	if uneval != 2 {
		t.Errorf("want unevaluated=2 (geo rule + remote list), got %d", uneval)
	}
}

// TestHandleTrace_BadDomain: a malformed domain is rejected with 400.
func TestHandleTrace_BadDomain(t *testing.T) {
	s, _ := sharehandlers_server(t)
	req := httptest.NewRequest(http.MethodGet, "/api/diagnostics/trace?domain=bad%20domain", nil)
	w := httptest.NewRecorder()
	s.handleTrace(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a bad domain", w.Code)
	}
}
