package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/clash"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// TestClashTraceMatches: sniffed connections to the domain (exact or subdomain Host) at IPs the
// conntrack pass didn't cover are returned with the chain exit; already-seen dsts, other domains,
// and host-less rows are skipped.
func TestClashTraceMatches(t *testing.T) {
	conns := []clash.Conn{
		{Chains: []string{"tunnel-a", "ru-group"}, Upload: 10, Download: 90, Metadata: clash.ConnMeta{Host: "www.youtube.com", DestinationIP: "142.250.9.9", DestinationPort: "443"}},
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
	if got[0].Dst != "142.250.9.9" || got[0].Domain != "www.youtube.com" || got[0].Exit != "tunnel-a→ru-group" || got[0].Dport != 443 {
		t.Errorf("got[0] = %+v, want 142.250.9.9 / www.youtube.com / tunnel-a→ru-group / 443", got[0])
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
		{Src: "192.168.77.50", Dst: "142.250.1.1", Dport: 443, Mark: 5, UpBytes: 10, DownBytes: 90},
		{Src: "192.168.77.51", Dst: "142.250.1.2", Dport: 443, Mark: 5, UpBytes: 1, DownBytes: 2},
		{Src: "192.168.77.52", Dst: "1.2.3.4", Dport: 443, Mark: 0, UpBytes: 5, DownBytes: 5}, // other IP → excluded
	}
	res := traceConnections("youtube.com", ips, conns, traceLabels{markExit: markExit})
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
	empty := traceConnections("idle.example", ips, []Conn{{Dst: "9.9.9.9"}}, traceLabels{markExit: markExit})
	if len(empty.Connections) != 0 || empty.Note == "" {
		t.Errorf("no-match should set a note, got %+v", empty)
	}
}

// TestTraceExitAttribution (polish 2, live on OpenWrt: a site routed by a rule-set to a tunnel
// read "direct"): a LAN flow the core terminates (its reply comes from the router at the redirect
// port) takes the core's chain for that client ip:port, or "core" when the core does not report it,
// never its mark's "direct"; a kernel-routed flow (fast mode's resolver-fed names, a pinned flow:
// DNAT to itself, so the reply source is the destination) takes its mark's egress; the router's own
// leg takes the egress of the device its source address is on.
func TestTraceExitAttribution(t *testing.T) {
	plan := &pbr.Plan{Mask: 0x00ff0000, Egresses: []pbr.Egress{
		{Tag: "direct", Kind: pbr.EgressWAN, Mark: 0x00010000, Table: 254},
		{Tag: "awg2", Kind: pbr.EgressInterface, Iface: "awg2", Mark: 0x00020000, Table: 151},
		{Tag: "awg-eu", Kind: pbr.EgressInterface, Iface: "awg-eu", Mark: 0x00030000, Table: 152},
	}}
	core := []clash.Conn{
		{Chains: []string{"awg-eu"}, Metadata: clash.ConnMeta{SourceIP: "192.168.77.50", SourcePort: "51000", DestinationIP: "198.51.100.80", DestinationPort: "443"}},
		{Chains: []string{"vless-nl", "grp-proxy"}, Metadata: clash.ConnMeta{SourceIP: "2001:db8::50", SourcePort: "40000", DestinationIP: "2001:db8:ffff::1", DestinationPort: "443"}},
	}
	labels := traceLabels{
		markExit:   markExitResolverFrom(plan, nil),
		localIface: localIfaceFrom(map[string]string{"192.168.77.1": "br-lan", "10.77.0.30": "awg-eu", "203.0.113.7": "wan", "10.0.2.2": "awg2"}),
		coreRoute:  coreRoutes(core),
		ifaceExit:  ifaceExits(plan),
	}
	ips := []string{"198.51.100.80", "2001:db8:ffff::1"}
	conns := []Conn{
		// Redirected into the core (auto_redirect), routed by its rule-set to awg-eu; mark says WAN.
		{Src: "192.168.77.50", Sport: 51000, Dst: "198.51.100.80", Dport: 443, ReplySrc: "127.0.0.1", Mark: 0x00010000},
		// Redirected, the reply from the LAN address; the core no longer lists it.
		{Src: "192.168.77.51", Sport: 52000, Dst: "198.51.100.80", Dport: 443, ReplySrc: "192.168.77.1"},
		// Redirected IPv6, conntrack's full spelling.
		{Src: "2001:0db8:0000:0000:0000:0000:0000:0050", Sport: 40000, Dst: "2001:0db8:ffff:0000:0000:0000:0000:0001", Dport: 443, ReplySrc: "::1"},
		// Fast mode: a resolver-fed name marked into awg2, pinned past the core (reply src = dst).
		{Src: "192.168.77.52", Sport: 53000, Dst: "198.51.100.80", Dport: 443, ReplySrc: "198.51.100.80", Mark: 0x00020000},
		// A pinned flow nothing marked: the provider.
		{Src: "192.168.77.53", Sport: 54000, Dst: "198.51.100.80", Dport: 443, ReplySrc: "198.51.100.80"},
		// The router's own legs: bound to the tunnel, and on the WAN.
		{Src: "10.77.0.30", Sport: 41000, Dst: "198.51.100.80", Dport: 443, ReplySrc: "198.51.100.80", Mark: 0x2024},
		{Src: "203.0.113.7", Sport: 42000, Dst: "198.51.100.80", Dport: 443, ReplySrc: "198.51.100.80", Mark: 0x2024},
	}
	res := traceConnections("listed.example", ips, conns, labels)
	want := []string{"awg-eu", "core", "vless-nl→grp-proxy", "awg2", "direct", "awg-eu", "direct"}
	if len(res.Connections) != len(want) {
		t.Fatalf("connections %+v", res.Connections)
	}
	for i, w := range want {
		if res.Connections[i].Exit != w {
			t.Errorf("row %d: exit %q, want %q", i, res.Connections[i].Exit, w)
		}
	}
	if res.Exits["awg-eu"] != 2 || res.Exits["direct"] != 2 || res.Exits["core"] != 1 {
		t.Errorf("exits %v", res.Exits)
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
	// unevaluated is now the NAMED geo/remote rules+lists (not a bare count), so the trace can say
	// WHICH rule/list might also match and why.
	unevGot := map[string]string{}
	for _, u := range uneval {
		unevGot[u.Kind+":"+u.ID] = u.Why
	}
	if len(uneval) != 2 {
		t.Errorf("want 2 unevaluated (geo rule + remote list), got %d: %+v", len(uneval), uneval)
	}
	if w := unevGot["rule:geo"]; !strings.Contains(w, "geosite") || !strings.Contains(w, "google") {
		t.Errorf("geo rule should be named with its geosite category, got %q", w)
	}
	if _, ok := unevGot["list:remote"]; !ok {
		t.Errorf("remote list should be named as unevaluated, got %+v", uneval)
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

// TestTraceExitHunt2: a UDP flow the core's TUN carries (its connmark is the redirect
// input mark, the reply from the far side) takes the core's route; a redirect to the router's own DNS
// (reply from the router on the same port) is the router's, and never asks the core.
func TestTraceExitHunt2(t *testing.T) {
	plan := &pbr.Plan{Mask: 0x00ff0000, Egresses: []pbr.Egress{{Tag: "direct", Kind: pbr.EgressWAN, Mark: 0x00010000, Table: 254}}}
	asked := 0
	labels := traceLabels{
		markExit:   markExitResolverFrom(plan, nil),
		localIface: localIfaceFrom(map[string]string{"192.168.77.1": "br-lan"}),
		mask:       plan.Mask, coreMark: 0x2023,
		coreFetch: func() map[string]string {
			asked++
			return coreRoutes([]clash.Conn{{Chains: []string{"vless-nl"}, Metadata: clash.ConnMeta{SourceIP: "192.168.77.5", SourcePort: "40000"}}})
		},
	}
	dns := Conn{Proto: "udp", Src: "192.168.77.5", Sport: 51000, Dst: "198.51.100.53", Dport: 53, ReplySrc: "192.168.77.1", ReplySport: 53}
	if got := labels.exitOf(&dns); got != traceExitRouter || asked != 0 {
		t.Errorf("DNS redirect: %q (core asked %d)", got, asked)
	}
	quic := Conn{Proto: "udp", Src: "192.168.77.5", Sport: 40000, Dst: "198.51.100.9", Dport: 443, ReplySrc: "198.51.100.9", ReplySport: 443, Mark: 0x2023}
	if got := labels.exitOf(&quic); got != "vless-nl" {
		t.Errorf("core-carried UDP: %q", got)
	}
	tcp := Conn{Proto: "tcp", Src: "192.168.77.6", Sport: 40001, Dst: "198.51.100.9", Dport: 443, ReplySrc: "127.0.0.1", ReplySport: 7890}
	if got := labels.exitOf(&tcp); got != traceExitCore {
		t.Errorf("core-redirected TCP the core no longer lists: %q", got)
	}
}

// TestParseConntrackReplySport: the reply tuple's source port is read (the DNS-redirect test above
// needs it).
func TestParseConntrackReplySport(t *testing.T) {
	c := parseConntrack("ipv4 2 udp 17 30 src=192.168.77.5 dst=198.51.100.53 sport=51000 dport=53 packets=1 bytes=60 " +
		"src=192.168.77.1 dst=192.168.77.5 sport=53 dport=51000 packets=1 bytes=90 mark=0 zone=0 use=2\n")
	if len(c) != 1 || c[0].Sport != 51000 || c[0].ReplySport != 53 || c[0].ReplySrc != "192.168.77.1" {
		t.Fatalf("parsed %+v", c)
	}
}
