package dnscheck

import "testing"

// A row of https-dns-proxy, as read on a test router.
func proxyRow(address, dev string, tunnel bool) Upstream {
	return Upstream{Address: address, Port: 5053, Kind: "doh", LeavesBy: dev, ViaTunnel: tunnel}
}

func warningFor(warnings []Warning, id string) *Warning {
	for i := range warnings {
		if warnings[i].ID == id {
			return &warnings[i]
		}
	}
	return nil
}

func TestLevelOfReadsTheRouteOfALocalProxy(t *testing.T) {
	cases := []struct {
		name string
		rows []Upstream
		want Level
	}{
		{"every row in a tunnel", []Upstream{proxyRow("https://1.1.1.1/dns-query", "awg2", true), proxyRow("https://9.9.9.9/dns-query", "awg2", true)}, LevelTunnelEncrypted},
		{"one row on the provider's line", []Upstream{proxyRow("https://1.1.1.1/dns-query", "awg2", true), proxyRow("https://8.8.8.8/dns-query", "eth3", false)}, LevelProviderEncrypted},
		{"first row on the provider's line", []Upstream{proxyRow("https://8.8.8.8/dns-query", "eth3", false), proxyRow("https://1.1.1.1/dns-query", "awg2", true)}, LevelProviderEncrypted},
	}
	for _, c := range cases {
		// The detour belongs to sing-box, which these proxies do not go through.
		in := AdviseInput{Path: PathReport{Upstreams: c.rows}, EncryptedDetour: "direct"}
		if got := LevelOf(in); got != c.want {
			t.Errorf("%s: LevelOf = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestLevelOfLocalRowStillFollowsTheDetour(t *testing.T) {
	in := AdviseInput{Path: PathReport{Upstreams: []Upstream{{Address: "127.0.0.1", Port: 5353, Kind: "local"}}}, EncryptedDetour: "tunnel-a"}
	if got := LevelOf(in); got != LevelTunnelEncrypted {
		t.Fatalf("LevelOf = %q", got)
	}
	in.EncryptedDetour = "direct"
	if got := LevelOf(in); got != LevelProviderEncrypted {
		t.Fatalf("LevelOf = %q", got)
	}
}

func TestAdviseMergesLastResortRows(t *testing.T) {
	in := AdviseInput{Path: PathReport{
		Measured: true,
		Upstreams: []Upstream{
			{Address: "127.0.0.1", Port: 5353, Kind: "local"},
			{Address: "1.1.1.1", Kind: "plain", LastResort: true},
			{Address: "8.8.8.8", Kind: "plain", LastResort: true},
		},
		Flows: []Flow{
			{Kind: PathWAN, Server: "1.1.1.1", Port: 53, Flows: 2},
			{Kind: PathWAN, Server: "8.8.8.8", Port: 53, Flows: 3},
		},
	}}
	warnings, _ := Advise(in)
	n := 0
	for _, w := range warnings {
		if w.ID == WarnPlainLastResort {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d last-resort warnings, want one", n)
	}
	w := warningFor(warnings, WarnPlainLastResort)
	if len(w.Facts) != 2 || w.Facts[0] != "1.1.1.1, 8.8.8.8" || w.Facts[1] != "5" {
		t.Fatalf("facts = %q", w.Facts)
	}
}

func TestAdviseProfileWarningsOnlyWhereTheyApply(t *testing.T) {
	// A profile with encrypted servers that does not answer clients, behind proxies that encrypt anyway:
	// neither warning has anything to tell.
	in := AdviseInput{
		Path:             PathReport{Upstreams: []Upstream{proxyRow("https://1.1.1.1/dns-query", "awg2", true)}},
		ProfileEncrypted: true,
		EncryptedDetour:  "direct",
	}
	warnings, _ := Advise(in)
	if warningFor(warnings, WarnEncryptedDirect) != nil {
		t.Fatal("encrypted_direct on a profile that answers nobody")
	}
	if warningFor(warnings, WarnProfileNotServed) != nil {
		t.Fatal("profile_not_served where clients are already encrypted")
	}

	in.Path.Upstreams = []Upstream{{Address: "1.1.1.1", Kind: "plain"}}
	warnings, _ = Advise(in)
	if warningFor(warnings, WarnProfileNotServed) == nil {
		t.Fatal("no profile_not_served at a plain level")
	}

	in.ProfileServes = true
	warnings, _ = Advise(in)
	if warningFor(warnings, WarnEncryptedDirect) == nil {
		t.Fatal("no encrypted_direct on a profile that answers clients")
	}
}

func TestAdviseOffersNoChainWithoutAnEditor(t *testing.T) {
	in := AdviseInput{
		Path: PathReport{Upstreams: []Upstream{
			{Address: "127.0.0.1", Port: 5353, Kind: "local"},
			{Address: "1.1.1.1", Kind: "plain", LastResort: true},
		}},
	}
	_, withEditor := Advise(in)
	found := false
	for _, o := range withEditor {
		found = found || o.ID == OptRemoveLastResort
	}
	if !found {
		t.Fatal("the fixture should offer remove_last_resort where the chain can be edited")
	}
	in.ChainLocked = true
	_, locked := Advise(in)
	for _, o := range locked {
		if o.Action.Kind == "chain" {
			t.Fatalf("option %q opens a chain editor this platform does not have", o.ID)
		}
	}
}
