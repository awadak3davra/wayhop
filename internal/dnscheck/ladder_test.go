package dnscheck

import (
	"reflect"
	"strconv"
	"testing"
)

func TestLevelOf(t *testing.T) {
	wanFlow := Flow{Kind: PathWAN, Port: 53, FromCanary: true, Server: "1.1.1.1"}
	tunnelFlow := Flow{Kind: PathTunnel, Port: 53, FromCanary: true, Server: "1.1.1.1", Iface: "nwg1"}
	tests := []struct {
		name string
		in   AdviseInput
		want Level
	}{
		{name: "canary on provider", in: AdviseInput{Path: PathReport{Measured: true, Flows: []Flow{wanFlow}}}, want: LevelProviderPlain},
		{name: "canary on tunnel", in: AdviseInput{Path: PathReport{Measured: true, Flows: []Flow{tunnelFlow}}}, want: LevelTunnelPlain},
		{name: "encrypted in group", in: AdviseInput{Path: PathReport{Measured: true, Upstreams: []Upstream{{Kind: "doh"}}}, EncryptedDetour: "main"}, want: LevelTunnelEncrypted},
		{name: "encrypted direct", in: AdviseInput{Path: PathReport{Measured: true, Upstreams: []Upstream{{Kind: "local"}}}, EncryptedDetour: "direct"}, want: LevelProviderEncrypted},
		{name: "unmeasured tunnel config", in: AdviseInput{Path: PathReport{Upstreams: []Upstream{{Kind: "plain", ViaTunnel: true, Iface: "nwg1"}}}}, want: LevelTunnelPlain},
		{name: "unmeasured provider config", in: AdviseInput{Path: PathReport{Upstreams: []Upstream{{Kind: "plain", Address: "1.1.1.1"}}}}, want: LevelProviderPlain},
		{name: "nothing to read", in: AdviseInput{}, want: LevelUnknown},
		{name: "local first row is dead", in: AdviseInput{Path: PathReport{Measured: true, Upstreams: []Upstream{{Kind: "local", Address: "127.0.0.1"}, {Kind: "plain", Address: "1.1.1.1", Iface: "nwg1", ViaTunnel: true}}, Flows: []Flow{tunnelFlow}}, EncryptedDetour: "main"}, want: LevelTunnelPlain},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LevelOf(tt.in); got != tt.want {
				t.Fatalf("LevelOf() = %s, want %s", got, tt.want)
			}
		})
	}
}

func warningWithID(warnings []Warning, id string) (Warning, bool) {
	for _, w := range warnings {
		if w.ID == id {
			return w, true
		}
	}
	return Warning{}, false
}

func optionWithID(options []Option, id string) (Option, bool) {
	for _, o := range options {
		if o.ID == id {
			return o, true
		}
	}
	return Option{}, false
}

func TestAdviseWarnings(t *testing.T) {
	provider := AdviseInput{Path: PathReport{Measured: true, Upstreams: []Upstream{{Address: "1.1.1.1", Kind: "plain"}}, Flows: []Flow{
		{Kind: PathWAN, Server: "1.1.1.1", Port: 53, Flows: 2, FromCanary: true},
		{Kind: PathWAN, Server: "8.8.8.8", Port: 53, Flows: 3},
	}}}
	tunnel := AdviseInput{Path: PathReport{Measured: true, Upstreams: []Upstream{{Address: "1.1.1.1", Kind: "plain", Iface: "nwg1", ViaTunnel: true}}, Flows: []Flow{{Kind: PathTunnel, Iface: "nwg1", Server: "1.1.1.1", Port: 53, Flows: 1, FromCanary: true}}}}
	tests := []struct {
		name, id string
		severity Severity
		facts    []string
		in       AdviseInput
	}{
		{name: "path intercepted", id: WarnPathIntercepted, severity: SeverityCritical, facts: []string{"eth3"}, in: AdviseInput{Interception: []Interception{{Intercepted: true, Path: Path{Kind: PathWAN, Iface: "eth3"}}}}},
		{name: "resolver forged", id: WarnResolverForged, severity: SeverityCritical, facts: []string{"8.8.8.8", "eth3"}, in: AdviseInput{Path: PathReport{Upstreams: []Upstream{{Address: "8.8.8.8", Kind: "plain"}}}, Resolvers: []ResolverResult{{Address: "8.8.8.8", Verdict: VerdictForged, Path: Path{Kind: PathWAN, Iface: "eth3"}}}}},
		{name: "plain on provider", id: WarnPlainOnProvider, severity: SeverityCritical, facts: []string{"1.1.1.1", "5"}, in: provider},
		{name: "plain last resort", id: WarnPlainLastResort, severity: SeverityWarn, facts: []string{"1.0.0.1", "2"}, in: AdviseInput{Path: PathReport{Upstreams: []Upstream{{Address: "1.1.1.1", Kind: "plain", Iface: "nwg1", ViaTunnel: true}, {Address: "1.0.0.1", Kind: "plain", LastResort: true}}, Flows: []Flow{{Kind: PathWAN, Server: "1.0.0.1", Port: 53, Flows: 2}}}}},
		{name: "clients bypass", id: WarnClientsBypass, severity: SeverityWarn, facts: []string{"br0"}, in: AdviseInput{BypassGaps: []string{"br0"}}},
		{name: "intercept off", id: WarnClientsBypass, severity: SeverityWarn, in: AdviseInput{}},
		{name: "encrypted escape", id: WarnEncryptedEscape, severity: SeverityWarn, in: func() AdviseInput { in := tunnel; in.EncryptedEscape = true; return in }()},
		{name: "ipv6 gap", id: WarnIPv6Gap, severity: SeverityWarn, facts: []string{"br0"}, in: AdviseInput{IPv6Gaps: []string{"br0"}}},
		{name: "single path", id: WarnSinglePath, severity: SeverityWarn, facts: []string{"nwg1"}, in: tunnel},
		{name: "encrypted direct", id: WarnEncryptedDirect, severity: SeverityWarn, in: AdviseInput{ProfileEncrypted: true, ProfileServes: true, EncryptedDetour: "direct"}},
		{name: "profile not served", id: WarnProfileNotServed, severity: SeverityInfo, in: AdviseInput{ProfileEncrypted: true, Path: PathReport{Upstreams: []Upstream{{Address: "1.1.1.1", Kind: "plain"}}}}},
		{name: "own lookups plain", id: WarnOwnLookupsPlain, severity: SeverityInfo, facts: []string{"1.1.1.1", "8.8.8.8"}, in: AdviseInput{Path: PathReport{OwnResolvConf: []string{"1.1.1.1", "8.8.8.8"}}}},
		{name: "not measured", id: WarnNotMeasured, severity: SeverityInfo, in: AdviseInput{InterceptOn: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings, _ := Advise(tt.in)
			got, ok := warningWithID(warnings, tt.id)
			if !ok {
				t.Fatalf("warning %s absent from %#v", tt.id, warnings)
			}
			if got.Severity != tt.severity || !reflect.DeepEqual(got.Facts, tt.facts) {
				t.Fatalf("warning = %#v, want severity %s facts %#v", got, tt.severity, tt.facts)
			}
		})
	}
}

func TestAdviseOptions(t *testing.T) {
	forged := AdviseInput{
		Path: PathReport{Upstreams: []Upstream{{Address: "8.8.8.8", Kind: "plain"}}},
		Resolvers: []ResolverResult{
			{Address: "8.8.8.8", Verdict: VerdictForged, Path: Path{Kind: PathWAN, Iface: "eth3"}},
			{Address: "1.1.1.1", Verdict: VerdictGenuine, Path: Path{Kind: PathWAN, Iface: "eth3"}},
		},
	}
	provider := AdviseInput{Path: PathReport{Measured: true, Upstreams: []Upstream{{Address: "1.1.1.1", Kind: "plain"}}, Flows: []Flow{{Kind: PathWAN, Server: "1.1.1.1", Port: 53, Flows: 1, FromCanary: true}}}, TunnelVia: []string{"vpn1", "vpn2"}}
	tunnel := AdviseInput{Path: PathReport{Measured: true, Upstreams: []Upstream{{Address: "1.1.1.1", Kind: "plain", Iface: "nwg1", ViaTunnel: true}}, Flows: []Flow{{Kind: PathTunnel, Iface: "nwg1", Server: "1.1.1.1", Port: 53, Flows: 1, FromCanary: true}}}, TunnelVia: []string{"vpn1", "vpn2"}, ViaByIface: map[string]string{"nwg1": "vpn1"}}
	tests := []struct {
		name, id string
		in       AdviseInput
		check    func(*testing.T, Option)
	}{
		{name: "replace resolver", id: OptReplaceResolver, in: forged, check: func(t *testing.T, o Option) {
			if len(o.Action.Rows) != 1 || o.Action.Rows[0].Address != "1.1.1.1" {
				t.Fatalf("replacement rows = %#v", o.Action.Rows)
			}
		}},
		{name: "chain into tunnels", id: OptChainIntoTunnels, in: provider, check: func(t *testing.T, o Option) {
			if o.Gives != LevelTunnelPlain || len(o.Action.Rows) != 2 || o.Action.Rows[0].Via == o.Action.Rows[1].Via {
				t.Fatalf("tunnel option = %#v", o)
			}
		}},
		{name: "add second tunnel", id: OptAddSecondTunnel, in: tunnel, check: func(t *testing.T, o Option) {
			if len(o.Action.Rows) != 2 || o.Action.Rows[1].Via != "vpn2" {
				t.Fatalf("second tunnel rows = %#v", o.Action.Rows)
			}
		}},
		{name: "intercept on", id: OptInterceptOn, in: AdviseInput{}, check: sectionCheck("dns-toggles")},
		{name: "encrypted upstream", id: OptEncryptedUpstream, in: func() AdviseInput {
			in := tunnel
			in.Encrypted = []EncryptedResult{{Path: Path{Kind: PathTunnel, Iface: "nwg1"}, Proto: "doh", Status: StatusPass}}
			return in
		}(), check: func(t *testing.T, o Option) {
			if o.Gives != LevelTunnelEncrypted || o.Action.Target != "dns-fast" {
				t.Fatalf("encrypted option = %#v", o)
			}
		}},
		{name: "encrypted in tunnel", id: OptEncryptedInTunnel, in: AdviseInput{ProfileEncrypted: true, ProfileServes: true, EncryptedDetour: "direct", TunnelVia: []string{"vpn1"}}, check: sectionCheck("dns-fast")},
		{name: "block encrypted escape", id: OptBlockEncrypted, in: func() AdviseInput { in := tunnel; in.EncryptedEscape = true; return in }(), check: sectionCheck("dns-toggles")},
		{name: "remove last resort", id: OptRemoveLastResort, in: AdviseInput{Path: PathReport{Upstreams: []Upstream{{Address: "1.1.1.1", Kind: "plain", Iface: "nwg1", ViaTunnel: true}, {Address: "1.0.0.1", Kind: "plain", LastResort: true}}}, TunnelVia: []string{"vpn1"}, ViaByIface: map[string]string{"nwg1": "vpn1"}}, check: func(t *testing.T, o Option) {
			if len(o.Action.Rows) != 1 || o.Action.Rows[0].Address != "1.1.1.1" {
				t.Fatalf("remaining rows = %#v", o.Action.Rows)
			}
		}},
		{name: "remove last resort keeps loopback proxy", id: OptRemoveLastResort, in: AdviseInput{Path: PathReport{Upstreams: []Upstream{{Address: "https://dns.google/dns-query", Kind: "doh", Port: 5053, Iface: "nwg1", ViaTunnel: true}, {Address: "1.0.0.1", Kind: "plain", LastResort: true}}}, TunnelVia: []string{"vpn1"}, ViaByIface: map[string]string{"nwg1": "vpn1"}}, check: func(t *testing.T, o Option) {
			if len(o.Action.Rows) != 1 || o.Action.Rows[0].Address != "127.0.0.1" || o.Action.Rows[0].Port != 5053 {
				t.Fatalf("remaining rows = %#v", o.Action.Rows)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, options := Advise(tt.in)
			got, ok := optionWithID(options, tt.id)
			if !ok {
				t.Fatalf("option %s absent from %#v", tt.id, options)
			}
			tt.check(t, got)
			recommended := 0
			for i, option := range options {
				if option.Recommended {
					recommended++
					if i != 0 {
						t.Errorf("recommended option is not first: %#v", options)
					}
				}
			}
			if recommended != 1 {
				t.Errorf("got %d recommended options, want exactly one", recommended)
			}
		})
	}
}

func sectionCheck(target string) func(*testing.T, Option) {
	return func(t *testing.T, o Option) {
		t.Helper()
		if o.Action.Kind != "section" || o.Action.Target != target {
			t.Fatalf("action = %#v, want section %s", o.Action, target)
		}
	}
}

func TestAdviseNeverProposesBadResolver(t *testing.T) {
	in := AdviseInput{
		Path:      PathReport{Measured: true, Upstreams: []Upstream{{Address: "1.1.1.1", Kind: "plain"}}, Flows: []Flow{{Kind: PathWAN, Server: "1.1.1.1", Port: 53, Flows: 1, FromCanary: true}}},
		TunnelVia: []string{"vpn1"},
	}
	for i, address := range []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"} {
		verdict := VerdictUnreachable
		if i == 1 {
			verdict = VerdictForged
		}
		if i == 2 {
			verdict = VerdictGenuine
		}
		in.Resolvers = append(in.Resolvers, ResolverResult{Address: address, Verdict: verdict, Path: Path{Kind: PathTunnel, Iface: "vpn1"}})
	}
	_, options := Advise(in)
	option, ok := optionWithID(options, OptChainIntoTunnels)
	if !ok || len(option.Action.Rows) != 1 || option.Action.Rows[0].Address != "9.9.9.9" {
		t.Fatalf("options propose an unreachable or forged resolver: %#v", options)
	}
}

func TestAdviseDoesNotOfferTunnelOptionsWithoutTunnels(t *testing.T) {
	in := AdviseInput{Path: PathReport{Measured: true, Upstreams: []Upstream{{Address: "1.1.1.1", Kind: "plain"}}, Flows: []Flow{{Kind: PathWAN, Server: "1.1.1.1", Port: 53, Flows: 1, FromCanary: true}}}, Encrypted: []EncryptedResult{{Path: Path{Kind: PathTunnel}, Proto: "dot", Status: StatusPass}}}
	_, options := Advise(in)
	for _, id := range []string{OptChainIntoTunnels, OptEncryptedUpstream, OptEncryptedInTunnel, OptAddSecondTunnel} {
		if _, ok := optionWithID(options, id); ok {
			t.Errorf("option %s offered without TunnelVia", id)
		}
	}
}

func TestWarningOrder(t *testing.T) {
	warnings, _ := Advise(AdviseInput{Interception: []Interception{{Intercepted: true, Path: Path{Iface: "eth3"}}}, IPv6Gaps: []string{"br0"}})
	if len(warnings) < 3 || warnings[0].ID != WarnPathIntercepted || warnings[1].ID != WarnClientsBypass || warnings[2].ID != WarnIPv6Gap {
		t.Fatalf("warning order = %#v", warnings)
	}
	for i, w := range warnings {
		if w.ID == WarnNotMeasured && w.Severity != SeverityInfo {
			t.Errorf("warning %d (%s) has wrong severity", i, w.ID)
		}
	}
}

func TestPlainLastResortCountsOnlyItsPort(t *testing.T) {
	in := AdviseInput{Path: PathReport{Upstreams: []Upstream{{Address: "1.1.1.1", Kind: "plain", ViaTunnel: true}, {Address: "1.0.0.1", Kind: "plain", LastResort: true}}, Flows: []Flow{{Kind: PathWAN, Server: "1.0.0.1", Port: 853, Flows: 9}}}}
	warnings, _ := Advise(in)
	w, _ := warningWithID(warnings, WarnPlainLastResort)
	if !reflect.DeepEqual(w.Facts, []string{"1.0.0.1", strconv.Itoa(0)}) {
		t.Fatalf("last-resort facts = %#v", w.Facts)
	}
}

func TestAdviseDoesNotOfferFixIPv6(t *testing.T) {
	_, options := Advise(AdviseInput{IPv6Gaps: []string{"br0"}})
	for _, o := range options {
		if o.ID == OptFixIPv6 {
			t.Fatalf("Advise must not offer fix_ipv6: %#v", options)
		}
	}
}

func TestCanaryLevelBelievesPlainFlowWhenFirstRowEncrypted(t *testing.T) {
	p := PathReport{
		Measured: true,
		Upstreams: []Upstream{
			{Address: "127.0.0.1", Kind: "local", Port: 5353},
		},
		OwnResolvConf: []string{"192.0.2.1"},
		Flows: []Flow{
			{Kind: PathWAN, Server: "192.0.2.1", Port: 53, FromCanary: true, Flows: 1},
			{Kind: PathWAN, Server: "8.8.8.8", Port: 53, FromCanary: true, Flows: 1},
		},
	}
	level, ok := canaryLevel(p)
	if !ok || level != LevelProviderPlain {
		t.Fatalf("got level=%v, ok=%v, want LevelProviderPlain", level, ok)
	}

	pOnlyOwn := PathReport{
		Measured: true,
		Upstreams: []Upstream{
			{Address: "127.0.0.1", Kind: "local", Port: 5353},
		},
		OwnResolvConf: []string{"192.0.2.1"},
		Flows: []Flow{
			{Kind: PathWAN, Server: "192.0.2.1", Port: 53, FromCanary: true, Flows: 1},
		},
	}
	if _, ok := canaryLevel(pOnlyOwn); ok {
		t.Fatalf("flow in OwnResolvConf must be skipped")
	}
}

func TestResultOnUpstreamNon53Port(t *testing.T) {
	u := Upstream{Address: "1.1.1.1", Port: 5053}
	r := ResolverResult{Address: "1.1.1.1", Path: Path{Kind: PathWAN}}
	if resultOnUpstream(r, u) {
		t.Fatalf("row on port 5053 cannot be judged by a probe on 53")
	}
}

func TestViaForUpstreamUnknownBindingKeepsIface(t *testing.T) {
	in := AdviseInput{
		Path: PathReport{
			Upstreams: []Upstream{
				{Address: "1.1.1.1", Kind: "plain", Iface: "custom0", ViaTunnel: true},
			},
		},
		TunnelVia: []string{"vpn1"},
	}
	rows := existingRows(in, true)
	if len(rows) != 1 || rows[0].Via != "" || rows[0].Iface != "custom0" {
		t.Fatalf("expected Via empty and Iface custom0, got %#v", rows)
	}
}

func TestSingleUsablePathCountsDistinctInterfaces(t *testing.T) {
	inTwoOnSame := AdviseInput{
		Path: PathReport{
			Upstreams: []Upstream{
				{Address: "1.1.1.1", Kind: "plain", Iface: "nwg1", ViaTunnel: true},
				{Address: "1.0.0.1", Kind: "plain", Iface: "nwg1", ViaTunnel: true},
			},
		},
	}
	single, iface := singleUsablePath(inTwoOnSame)
	if !single || iface != "nwg1" {
		t.Fatalf("two rows on nwg1 should be single usable path 'nwg1', got single=%v, iface=%q", single, iface)
	}

	inOneAndEmpty := AdviseInput{
		Path: PathReport{
			Upstreams: []Upstream{
				{Address: "1.1.1.1", Kind: "plain", Iface: "nwg1", ViaTunnel: true},
				{Address: "1.0.0.1", Kind: "plain", LastResort: true},
			},
		},
	}
	single, _ = singleUsablePath(inOneAndEmpty)
	if single {
		t.Fatalf("one row on nwg1 and one row with no interface must not be single usable path")
	}
}

func TestLevelOfFallbackFromConfig(t *testing.T) {
	inPrivate := AdviseInput{
		Path: PathReport{
			Upstreams: []Upstream{
				{Address: "192.168.77.1", Kind: "plain"},
			},
		},
	}
	if got := LevelOf(inPrivate); got != LevelProviderPlain {
		t.Fatalf("private address on br*-free chain should be LevelProviderPlain, got %v", got)
	}

	inLoopback := AdviseInput{
		Path: PathReport{
			Upstreams: []Upstream{
				{Address: "127.0.0.1", Kind: "plain"},
			},
		},
	}
	if got := LevelOf(inLoopback); got != LevelUnknown {
		t.Fatalf("loopback plain address should be LevelUnknown, got %v", got)
	}

	inBrChain := AdviseInput{
		Path: PathReport{
			Upstreams: []Upstream{
				{Address: "192.168.77.1", Kind: "plain"},
				{Address: "10.0.0.1", Kind: "plain", Iface: "br0"},
			},
		},
	}
	if got := LevelOf(inBrChain); got != LevelUnknown {
		t.Fatalf("chain with br0 interface should be LevelUnknown, got %v", got)
	}
}
