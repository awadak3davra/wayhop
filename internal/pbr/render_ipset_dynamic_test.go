package pbr

import (
	"reflect"
	"strings"
	"testing"
)

func dynamicDomainTestPlan() *Plan {
	return &Plan{
		Mask: 0x00ff0000,
		Zones: []Zone{
			{Name: "list_alpha", V4: []string{"192.0.2.0/24"}, Domains: []string{"alpha.example"}, Mark: 0x00020000},
			{Name: "list_beta", Domains: []string{"beta.example"}, Mark: 0x00030000},
		},
	}
}

func TestDynamicDomainRestoreGolden(t *testing.T) {
	pl := dynamicDomainTestPlan()
	io := IpsetOptions{DynamicDomainSets: true}
	want := "create wr_list_alpha_4 hash:net family inet hashsize 1024 maxelem 131072 timeout 86400 -exist\n" +
		"add wr_list_alpha_4 192.0.2.0/24 timeout 0 -exist\n" +
		"create wr_list_alpha_6 hash:net family inet6 hashsize 1024 maxelem 131072 timeout 86400 -exist\n" +
		"create wd_list_alpha_4 hash:ip family inet hashsize 1024 maxelem 131072 timeout 21600 -exist\n" +
		"create wd_list_alpha_6 hash:ip family inet6 hashsize 1024 maxelem 131072 timeout 21600 -exist\n" +
		"create wr_list_beta_4 hash:net family inet hashsize 1024 maxelem 131072 timeout 86400 -exist\n" +
		"create wr_list_beta_6 hash:net family inet6 hashsize 1024 maxelem 131072 timeout 86400 -exist\n" +
		"create wd_list_beta_4 hash:ip family inet hashsize 1024 maxelem 131072 timeout 21600 -exist\n" +
		"create wd_list_beta_6 hash:ip family inet6 hashsize 1024 maxelem 131072 timeout 21600 -exist\n"
	if got := pl.RenderIpsetRestore(io); got != want {
		t.Fatalf("restore =\n%s\nwant\n%s", got, want)
	}
	wantNames := []string{
		"wr_list_alpha_4", "wr_list_alpha_6", "wd_list_alpha_4", "wd_list_alpha_6",
		"wr_list_beta_4", "wr_list_beta_6", "wd_list_beta_4", "wd_list_beta_6",
	}
	if got := pl.IpsetNames(io); !reflect.DeepEqual(got, wantNames) {
		t.Fatalf("set names = %v, want %v", got, wantNames)
	}
	if got := len(io.DynamicSetName(strings.Repeat("x", 80), "6")); got != 31 {
		t.Fatalf("long dynamic set name has %d bytes, want 31", got)
	}
}

func TestDynamicDomainMarkGoldenAndPrecedence(t *testing.T) {
	pl := dynamicDomainTestPlan()
	io := IpsetOptions{DynamicDomainSets: true}
	script := pl.RenderIptablesScript(io)
	want := "-A WR_PREROUTING -j CONNMARK --restore-mark --nfmask 0x00ff0000 --ctmask 0x00ff0000\n" +
		"-A WR_PREROUTING -m set --match-set wr_list_alpha_4 dst -j MARK --set-xmark 0x00020000/0x00ff0000\n" +
		"-A WR_PREROUTING -m set --match-set wd_list_alpha_4 dst -j MARK --set-xmark 0x00020000/0x00ff0000\n" +
		"-A WR_PREROUTING -m set --match-set wd_list_alpha_4 dst -m conntrack --ctstate NEW -j SET --add-set wd_list_alpha_4 dst --exist --timeout 21600\n" +
		"-A WR_PREROUTING -m set --match-set wr_list_beta_4 dst -j MARK --set-xmark 0x00030000/0x00ff0000\n" +
		"-A WR_PREROUTING -m set --match-set wd_list_beta_4 dst -j MARK --set-xmark 0x00030000/0x00ff0000\n" +
		"-A WR_PREROUTING -m set --match-set wd_list_beta_4 dst -m conntrack --ctstate NEW -j SET --add-set wd_list_beta_4 dst --exist --timeout 21600\n" +
		"-A WR_PREROUTING -j CONNMARK --save-mark --nfmask 0x00ff0000 --ctmask 0x00ff0000\n" +
		"-A WR_PREROUTING -j CONNMARK --restore-mark --nfmask 0x00ff0000 --ctmask 0x00ff0000\n" +
		"-A WR_PREROUTING -m set --match-set wr_list_alpha_6 dst -j MARK --set-xmark 0x00020000/0x00ff0000\n" +
		"-A WR_PREROUTING -m set --match-set wd_list_alpha_6 dst -j MARK --set-xmark 0x00020000/0x00ff0000\n" +
		"-A WR_PREROUTING -m set --match-set wd_list_alpha_6 dst -m conntrack --ctstate NEW -j SET --add-set wd_list_alpha_6 dst --exist --timeout 21600\n" +
		"-A WR_PREROUTING -m set --match-set wr_list_beta_6 dst -j MARK --set-xmark 0x00030000/0x00ff0000\n" +
		"-A WR_PREROUTING -m set --match-set wd_list_beta_6 dst -j MARK --set-xmark 0x00030000/0x00ff0000\n" +
		"-A WR_PREROUTING -m set --match-set wd_list_beta_6 dst -m conntrack --ctstate NEW -j SET --add-set wd_list_beta_6 dst --exist --timeout 21600\n" +
		"-A WR_PREROUTING -j CONNMARK --save-mark --nfmask 0x00ff0000 --ctmask 0x00ff0000\n"
	got := mangleRestoreRules(script)
	if got != want {
		t.Fatalf("mangle rules =\n%s\nwant\n%s", got, want)
	}

	withoutDynamic := func(s string) string {
		var lines []string
		for _, line := range strings.Split(s, "\n") {
			if line != "" && !strings.Contains(line, "wd_") {
				lines = append(lines, line)
			}
		}
		return strings.Join(lines, "\n")
	}
	if dynamic, legacy := withoutDynamic(got), withoutDynamic(mangleRestoreRules(pl.RenderIptablesScript(IpsetOptions{}))); dynamic != legacy {
		t.Fatalf("dynamic rules changed legacy precedence:\n%s\nlegacy:\n%s", dynamic, legacy)
	}
}

func TestDynamicDomainScopedMarkAndRefresh(t *testing.T) {
	pl := &Plan{Mask: 0x00ff0000, Zones: []Zone{{
		Name: "list_scoped", Domains: []string{"scoped.example"}, Mark: 0x00020000,
		SrcScoped: true, SrcMAC: []string{"aa:bb:cc:dd:ee:ff"},
	}}}
	rules := mangleRestoreRules(pl.RenderIptablesScript(IpsetOptions{DynamicDomainSets: true}))
	mustContain(t, rules, "-m mac --mac-source aa:bb:cc:dd:ee:ff -m set --match-set wd_list_scoped_4 dst -j MARK")
	if got := strings.Count(rules, "-j SET --add-set wd_list_scoped_4 "); got != 1 {
		t.Fatalf("v4 refresh rules = %d, want 1:\n%s", got, rules)
	}
	if got := strings.Count(rules, "-j SET --add-set wd_list_scoped_6 "); got != 1 {
		t.Fatalf("v6 refresh rules = %d, want 1:\n%s", got, rules)
	}
}

func TestDynamicDomainDnsmasqAndTeardown(t *testing.T) {
	pl := dynamicDomainTestPlan()
	io := IpsetOptions{DynamicDomainSets: true}
	conf := pl.DnsmasqIpsetConfig(io, 1024)
	mustContain(t, conf, "ipset=/alpha.example/wd_list_alpha_4,wd_list_alpha_6\n")
	mustContain(t, conf, "ipset=/beta.example/wd_list_beta_4,wd_list_beta_6\n")
	if strings.Contains(conf, "/wr_") {
		t.Fatalf("dnsmasq still targets static sets:\n%s", conf)
	}

	teardown := pl.RenderTeardownScript(Options{}, io)
	for _, name := range pl.IpsetNames(io) {
		mustContain(t, teardown, "ipset destroy "+name+" 2>/dev/null || true\n")
	}
	next := pl.RenderKeeneticScript(Options{}, io)
	if retired := RetireProgram(teardown, next, pl.IpsetNames(io)); strings.Contains(retired, "ipset destroy wd_") {
		t.Fatalf("reapply destroys carried dynamic sets:\n%s", retired)
	}
	legacy := pl.RenderKeeneticScript(Options{}, IpsetOptions{})
	retired := RetireProgram(teardown, legacy, pl.IpsetNames(IpsetOptions{}))
	mustContain(t, retired, "ipset destroy wd_list_alpha_4")
	mustContain(t, retired, "ipset destroy wd_list_beta_6")
}

func TestDynamicDomainKillSwitchReadsBothGenerations(t *testing.T) {
	pl := dynamicDomainTestPlan()
	pl.Egresses = []Egress{{Tag: "vpn", Kind: EgressInterface, FailClosed: true}}
	for i := range pl.Zones {
		pl.Zones[i].EgressTag = "vpn"
	}
	bs := pl.KillSwitchBackstop(IpsetOptions{DynamicDomainSets: true})
	want4 := []string{"wd_list_alpha_4", "wd_list_beta_4", "wr_list_alpha_4", "wr_list_beta_4"}
	want6 := []string{"wd_list_alpha_6", "wd_list_beta_6", "wr_list_alpha_6", "wr_list_beta_6"}
	if !reflect.DeepEqual(bs.Sets4, want4) || !reflect.DeepEqual(bs.Sets6, want6) {
		t.Fatalf("kill-switch sets = %v / %v, want %v / %v", bs.Sets4, bs.Sets6, want4, want6)
	}
	// The fail-closed pins stay exactly as in the legacy snippet.
	pins := func(conf string) string {
		return conf[strings.Index(conf, "# Kill switch"):]
	}
	dyn := pl.DnsmasqIpsetConfig(IpsetOptions{DynamicDomainSets: true, KillSwitchDNS: "127.0.0.1#5353"}, 1024)
	legacy := pl.DnsmasqIpsetConfig(IpsetOptions{KillSwitchDNS: "127.0.0.1#5353"}, 1024)
	mustContain(t, dyn, "server=/alpha.example/beta.example/127.0.0.1#5353\n")
	if pins(dyn) != pins(legacy) {
		t.Fatalf("fail-closed pins changed:\n%s\nlegacy:\n%s", dyn, legacy)
	}
}

func TestDynamicDomainHandoffMatchesResolverSets(t *testing.T) {
	pl := dynamicDomainTestPlan()
	pl.Egresses = []Egress{{Tag: "a", Kind: EgressInterface}, {Tag: "b", Kind: EgressInterface}}
	pl.Zones[0].EgressTag, pl.Zones[1].EgressTag = "a", "b"
	// alpha (names + a prefix) is the domain zone, beta the stronger one: both have names.
	specs := strings.Join(pl.handoffChainSpecs(IpsetOptions{DynamicDomainSets: true}.withDefaultsCopy()), "\n")
	for _, pair := range [][2]string{
		{"wr_list_alpha_4", "wr_list_beta_4"}, {"wr_list_alpha_4", "wd_list_beta_4"},
		{"wd_list_alpha_4", "wr_list_beta_4"}, {"wd_list_alpha_4", "wd_list_beta_4"},
	} {
		mustContain(t, specs, "-m set --match-set "+pair[0]+" dst -m set --match-set "+pair[1]+" dst ")
	}
	out := strings.Join(pl.handoffOutputSpecs(IpsetOptions{DynamicDomainSets: true}.withDefaultsCopy()), "\n")
	mustContain(t, out, "-m set --match-set wd_list_beta_4 dst -j MARK")
	legacy := IpsetOptions{}.withDefaultsCopy()
	if got := strings.Join(pl.handoffChainSpecs(legacy), "\n"); strings.Contains(got, "wd_") || strings.Count(got, "\n") != 0 {
		t.Fatalf("legacy hand-off changed:\n%s", got)
	}
}

func TestDynamicSetsBeyondWAN(t *testing.T) {
	pl := dynamicDomainTestPlan()
	pl.Egresses = []Egress{{Tag: "wan", Kind: EgressWAN}, {Tag: "vpn", Kind: EgressInterface}}
	pl.Zones[0].EgressTag, pl.Zones[1].EgressTag = "wan", "vpn"
	if names, _ := pl.DynamicSets(IpsetOptions{}); names != nil {
		t.Fatalf("legacy plane has dynamic sets: %v", names)
	}
	names, beyond := pl.DynamicSets(IpsetOptions{DynamicDomainSets: true})
	want := []string{"wd_list_alpha_4", "wd_list_alpha_6", "wd_list_beta_4", "wd_list_beta_6"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("names = %v", names)
	}
	if beyond["wd_list_alpha_4"] || !beyond["wd_list_beta_4"] || !beyond["wd_list_beta_6"] {
		t.Fatalf("beyond = %v", beyond)
	}
}

func (io IpsetOptions) withDefaultsCopy() IpsetOptions {
	io.withDefaults()
	return io
}

func TestDynamicDomainOptionLeavesLegacyBytesUnchanged(t *testing.T) {
	pl := dynamicDomainTestPlan()
	plain, explicit := IpsetOptions{}, IpsetOptions{DynamicDomainSets: false}
	if pl.RenderIpsetRestore(plain) != pl.RenderIpsetRestore(explicit) ||
		pl.RenderIptablesScript(plain) != pl.RenderIptablesScript(explicit) ||
		pl.DnsmasqIpsetConfig(plain, 1024) != pl.DnsmasqIpsetConfig(explicit, 1024) ||
		pl.RenderTeardownScript(Options{}, plain) != pl.RenderTeardownScript(Options{}, explicit) {
		t.Fatal("the zero dynamic option changed legacy output")
	}
}

// HUNT-K #10/#11: the fast policy file answers a canary of its own; the legacy file is unchanged.
func TestDynamicDomainCanary(t *testing.T) {
	pl := dynamicDomainTestPlan()
	mustContain(t, pl.DnsmasqIpsetConfig(IpsetOptions{DynamicDomainSets: true}, 1024), "address=/"+FastCanaryName+"/"+FastCanaryAddr+"\n")
	if strings.Contains(pl.DnsmasqIpsetConfig(IpsetOptions{}, 1024), FastCanaryName) {
		t.Fatal("the legacy file carries the canary")
	}
}
