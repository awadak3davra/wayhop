package dnscheck

import "testing"

// The router's own lookups stay on the provider's line on purpose, and one of them can land in the test
// lookup's window. That must not read as "the provider sees everything".
func TestOwnLookupInTheWindowDoesNotPutTheHouseholdOnTheProvidersLine(t *testing.T) {
	chain := []Upstream{
		{Address: "1.1.1.1", Iface: "nwg1", Kind: "plain", ViaTunnel: true},
		{Address: "1.0.0.1", Kind: "plain", LastResort: true},
	}
	own := Flow{Iface: "eth3", Kind: PathWAN, Server: "1.1.1.1", Port: 53, FromCanary: true}
	test := Flow{Iface: "nwg1", Kind: PathTunnel, Server: "1.1.1.1", Port: 53, FromCanary: true}
	in := AdviseInput{Path: PathReport{Measured: true, Upstreams: chain, Flows: []Flow{own, test}}}
	if got := LevelOf(in); got != LevelTunnelPlain {
		t.Errorf("level = %s", got)
	}
}

// A later row answering at the same moment only took what an earlier row failed.
func TestTheEarliestRowThatTookTheTestLookupDecides(t *testing.T) {
	chain := []Upstream{
		{Address: "1.1.1.1", Iface: "nwg1", Kind: "plain", ViaTunnel: true},
		{Address: "1.0.0.1", Kind: "plain", LastResort: true},
	}
	in := AdviseInput{Path: PathReport{Measured: true, Upstreams: chain, Flows: []Flow{
		{Iface: "eth3", Kind: PathWAN, Server: "1.0.0.1", Port: 53, FromCanary: true},
		{Iface: "nwg1", Kind: PathTunnel, Server: "1.1.1.1", Port: 53, FromCanary: true},
	}}}
	if got := LevelOf(in); got != LevelTunnelPlain {
		t.Errorf("level = %s", got)
	}
	// Only the last resort took it: every tunnel row failed, and that is what the household gets.
	in.Path.Flows = in.Path.Flows[:1]
	if got := LevelOf(in); got != LevelProviderPlain {
		t.Errorf("level = %s", got)
	}
}

// Measured, but the test lookup showed nowhere: the settings are still better than "unknown".
func TestNoTestFlowFallsBackToTheChain(t *testing.T) {
	for _, tc := range []struct {
		first Upstream
		want  Level
	}{
		{Upstream{Address: "1.1.1.1", Iface: "nwg1", Kind: "plain", ViaTunnel: true}, LevelTunnelPlain},
		{Upstream{Address: "1.1.1.1", Kind: "plain"}, LevelProviderPlain},
	} {
		in := AdviseInput{Path: PathReport{Measured: true, Upstreams: []Upstream{tc.first}}}
		if got := LevelOf(in); got != tc.want {
			t.Errorf("%+v: level = %s, want %s", tc.first, got, tc.want)
		}
	}
}

func TestAChainIsNeverProposedThroughTheRoutersOwnListener(t *testing.T) {
	bad := func(address string, path Path, v Verdict) ResolverResult {
		return ResolverResult{Address: address, Path: path, Verdict: v}
	}
	fin := Path{Iface: "nwg1", Kind: PathTunnel}
	home := Path{Kind: PathRouter}
	in := AdviseInput{
		Path:       PathReport{Measured: true, Upstreams: []Upstream{{Address: "1.1.1.1", Kind: "plain"}}},
		TunnelVia:  []string{"fin"},
		ViaByIface: map[string]string{"nwg1": "fin"},
		Resolvers: []ResolverResult{
			bad("1.1.1.1", fin, VerdictForged), bad("8.8.8.8", fin, VerdictUnreachable), bad("9.9.9.9", fin, VerdictUnreachable),
			bad("127.0.0.1", home, VerdictUnknownOperator),
		},
	}
	_, options := Advise(in)
	for _, o := range options {
		for _, row := range o.Action.Rows {
			if row.Address == "127.0.0.1" {
				t.Errorf("%s proposes the router itself: %+v", o.ID, o.Action.Rows)
			}
		}
	}
}

func TestAPlainChainWithNoTestFlowIsNotCalledMeasured(t *testing.T) {
	plain := []Upstream{{Address: "1.1.1.1", Kind: "plain"}}
	p := SettleMeasured(PathReport{Measured: true, SampleSec: 10, Upstreams: plain})
	if p.Measured || p.SampleSec != 0 {
		t.Errorf("an empty table stayed measured: %+v", p)
	}
	withFlow := PathReport{Measured: true, Upstreams: plain, Flows: []Flow{{Server: "1.1.1.1", Port: 53, FromCanary: true}}}
	if !SettleMeasured(withFlow).Measured {
		t.Error("a seen test lookup lost its measurement")
	}
	// A local first row has no port 53 flow when it works, so the silence is the good news there.
	local := PathReport{Measured: true, Upstreams: []Upstream{{Address: "127.0.0.1", Port: 5353, Kind: "local"}}}
	if !SettleMeasured(local).Measured {
		t.Error("an encrypted first row lost its measurement")
	}
}

// Seen in the lab: the router's own lookups share an address with a fallback row.
func TestAFirstRowThatAnswersIsNotOutvotedByFlowsToALaterRow(t *testing.T) {
	chain := []Upstream{{Address: "127.0.0.1", Port: 5353, Kind: "local"}, {Address: "1.1.1.1", Kind: "plain", LastResort: true}}
	own := Flow{Iface: "eth3", Kind: PathWAN, Server: "1.1.1.1", Port: 53, FromCanary: true}
	in := AdviseInput{EncryptedDetour: "main", Path: PathReport{Measured: true, FirstRowAnswered: true, Upstreams: chain, Flows: []Flow{own}, OwnResolvConf: []string{"1.1.1.1"}}}
	if got := LevelOf(in); got != LevelTunnelEncrypted {
		t.Errorf("answering first row: level = %s", got)
	}
	// The same flows with the first row silent: the lookups really are falling through.
	in.Path.FirstRowAnswered = false
	if got := LevelOf(in); got != LevelProviderPlain {
		t.Errorf("silent first row: level = %s", got)
	}
	// An answering first row that forwards in plaintext to somewhere else is still found out.
	in.Path.FirstRowAnswered = true
	in.Path.Flows = []Flow{{Iface: "eth3", Kind: PathWAN, Server: "203.0.113.53", Port: 53, FromCanary: true}}
	if got := LevelOf(in); got != LevelProviderPlain {
		t.Errorf("plaintext forwarder behind the first row: level = %s", got)
	}
}
