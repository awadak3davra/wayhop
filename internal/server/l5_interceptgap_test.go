package server

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

func igList(id, name string, enabled bool, manual ...string) model.RoutingList {
	return model.RoutingList{ID: id, Name: name, Enabled: enabled, Manual: manual}
}

// TestDomainRoutedLists: only entries the kernel CANNOT match by itself count. An address or a
// prefix is matched directly and needs no resolver, so a list made of those keeps working whatever
// DNS the client uses — counting it here would raise a warning about a list that has no dependency.
func TestDomainRoutedLists(t *testing.T) {
	p := model.Profile{RoutingLists: []model.RoutingList{
		igList("a", "GitHub", true, "github.com", "203.0.113.0/24"),
		igList("b", "Telegram", true, "91.108.4.0/22", "149.154.160.0/20"),
		igList("c", "IPv6 prefixes", true, "2001:db8::/32"),
		igList("d", "Single host", true, "203.0.113.7"),
		igList("e", "Disabled domains", false, "example.com"),
		igList("f", "", true, "  "),
		igList("g", "Named by id fallback", true, "cdn.example.net"),
	}}
	got := domainRoutedLists(p)
	want := map[string]bool{"GitHub": true, "Named by id fallback": true}
	if len(got) != len(want) {
		t.Fatalf("got %v, want exactly %d list(s): %v", got, len(want), want)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("%q was counted as domain-routed; it has nothing a resolver must answer", g)
		}
	}
}

// TestInterceptGapVerdict: the warning exists to stop a pass being reported for a promise the
// router cannot keep. It must fire ONLY when both halves are true, and its remedy must name the
// setting rather than restating the problem.
func TestInterceptGapVerdict(t *testing.T) {
	cases := []struct {
		name      string
		lists     []string
		intercept bool
		warn      bool
	}{
		{"domain lists, door open", []string{"GitHub"}, false, true},
		{"domain lists, door shut", []string{"GitHub"}, true, false},
		{"no domain lists, door open", nil, false, false},
		{"no domain lists, door shut", nil, true, false},
	}
	for _, c := range cases {
		st, sum, fix := interceptGapVerdict(c.lists, c.intercept)
		if c.warn && st != "warn" {
			t.Errorf("%s: status %q, want warn — this is the case that reported pass on a live router", c.name, st)
			continue
		}
		if !c.warn && st != "" {
			t.Errorf("%s: raised %q with nothing at stake", c.name, sum)
			continue
		}
		if !c.warn {
			continue
		}
		if !strings.Contains(strings.ToLower(fix), "interception") {
			t.Errorf("%s: the remedy does not name the setting that closes the gap: %q", c.name, fix)
		}
		// The summary has to say WHY, not just that something is off: "route by domain" is the fact
		// that makes the missing interception matter.
		if !strings.Contains(sum, "domain") {
			t.Errorf("%s: summary does not say the lists route by domain: %q", c.name, sum)
		}
	}
}

// TestInterceptGapPluralisation guards the counter this sentence carries.
func TestInterceptGapPluralisation(t *testing.T) {
	_, one, _ := interceptGapVerdict([]string{"A"}, false)
	_, two, _ := interceptGapVerdict([]string{"A", "B"}, false)
	// The verb travels with the count. A first cut read "1 list route by domain", which a mutation
	// surfaced; pinning the whole phrase keeps subject and verb from drifting apart again.
	if !strings.HasPrefix(one, "1 routing list matches by domain") {
		t.Errorf("singular reads %q", one)
	}
	if !strings.HasPrefix(two, "2 routing lists match by domain") {
		t.Errorf("plural reads %q", two)
	}
}

// TestRouterOwnV6IsNotAClient: the router's own encrypted resolver reaching AdGuard or Google is the
// configured behaviour. It was reported as "1 client may be bypassing the router's DNS" because
// conntrack writes IPv6 expanded and net.InterfaceAddrs reports it compressed, so the two spellings
// of ONE address never matched. The row named the router itself, which is the worst kind of finding:
// an operator would go looking for a device that does not exist.
func TestRouterOwnV6IsNotAClient(t *testing.T) {
	const compressed = "2001:db8:3::a21:24be"
	const expanded = "2001:0db8:0003:0000:0000:0000:0a21:24be"
	mine := map[string]bool{compressed: true, "192.168.50.1": true}
	conns := []Conn{
		{Src: expanded, Dst: "94.140.14.14", Dport: 443},       // the router's own DoH, expanded form
		{Src: "192.168.50.1", Dst: "8.8.8.8", Dport: 443},      // the router again, v4
		{Src: "192.168.0.77", Dst: "94.140.14.14", Dport: 443}, // a real LAN client
	}
	found, clients := detectDoHClients(conns, nil, mine)
	if clients != 1 {
		t.Fatalf("counted %d client(s) %v, want only the LAN device — the router is not bypassing itself", clients, found)
	}
	for _, f := range found {
		if strings.Contains(f, "2001:") || strings.Contains(f, "192.168.50.1 ") {
			t.Errorf("the router's own address was reported as a client: %q", f)
		}
	}

	// And the fix must not blind the check: the same router with a genuine bypassing client still
	// reports it, in canonical form.
	if len(found) != 1 || !strings.Contains(found[0], "192.168.0.77") {
		t.Errorf("the real client was lost: %v", found)
	}
}

// TestInterceptReadFromAppliedNotSaved: the two halves of this row come from two different states on
// purpose. What the operator PROMISED (domain lists) is read from the saved profile, because that is
// the page they are looking at; whether the promise is ENFORCED is read from what was applied,
// because a setting nobody applied enforces nothing. Measured on a live Keenetic: saved
// dns.intercept was true, the kernel carried no redirect, and reading both halves from the saved
// profile reported a clean row over a wide open door.
//
// It goes through interceptGapRow rather than interceptGapVerdict deliberately: the verdict function
// takes the answer as an argument and so cannot witness WHICH state the caller consulted. A first
// version of this gate called it directly and stayed green when the fix was reverted.
//
// What it does NOT cover, stated rather than implied: the nil-record branch of dnsInterceptApplied.
// This harness always yields a baseline whose Desired is present, so flipping that branch's return
// changes nothing here — it is a defensive default, not the behaviour under test.
func TestInterceptReadFromAppliedNotSaved(t *testing.T) {
	s, _ := sharehandlers_server(t)
	saved := model.Profile{
		DNS: &model.DNSSettings{Enabled: true, Intercept: true},
		RoutingLists: []model.RoutingList{{
			ID: "g", Name: "GitHub", Enabled: true, Outbound: "direct", Manual: []string{"github.com"},
		}},
	}
	if err := s.store.Replace(saved); err != nil {
		t.Fatalf("store.Replace: %v", err)
	}
	// The saved profile on its own claims the door is shut.
	if !dnsInterceptOn(s.store.Profile()) {
		t.Fatal("fixture does not model the router that was measured")
	}
	// Nothing has been applied, so nothing enforces it. The row must say so.
	st, sum, fix := s.interceptGapRow()
	if st != "warn" {
		t.Fatalf("nothing applied yet, yet the row reads %q — that is the clean row over an open door", st)
	}
	if !strings.Contains(sum, "does not answer clients' DNS") {
		t.Errorf("summary does not name the missing enforcement: %q", sum)
	}
	if !strings.Contains(strings.ToLower(fix), "interception") {
		t.Errorf("remedy does not name the setting: %q", fix)
	}
	// A profile with no domain lists has nothing at stake, applied or not.
	if err := s.store.Replace(model.Profile{DNS: saved.DNS}); err != nil {
		t.Fatalf("store.Replace: %v", err)
	}
	if st2, sum2, _ := s.interceptGapRow(); st2 != "" {
		t.Errorf("warned with no domain list to protect: %q", sum2)
	}
}
