package pbr

import (
	"errors"
	"strings"
	"testing"
)

// fakeRun answers commands with recorded output. The replies are an ORDERED slice rather than a
// map: with a map, two keys matching the same command line would be picked between at random and
// the test would fail once every few hundred runs, which is the kind of flake that gets re-run
// rather than diagnosed.
type fakeRun struct{ replies []reply }

type reply struct {
	match string // substring of "name args"
	out   string
	err   error
}

func (f fakeRun) Run(stdin, name string, args ...string) (string, error) {
	line := strings.TrimSpace(name + " " + strings.Join(args, " "))
	for _, r := range f.replies {
		if strings.Contains(line, r.match) {
			return r.out, r.err
		}
	}
	return "", errors.New("not found: " + line)
}

var errExit = errors.New("exit status 2")

// dnsmasqStock is the real banner from OpenWrt 21.02.7, options line included — the two live in one
// output, which is why "no-ipset" is findable at all.
const dnsmasqStock = "Dnsmasq version 2.85  Copyright (c) 2000-2021 Simon Kelley\n" +
	"Compile time options: IPv6 GNU-getopt no-DBus no-UBus no-i18n no-IDN DHCP DHCPv6 " +
	"no-Lua TFTP no-conntrack no-ipset auth cryptohash DNSSEC no-ID loop-detect inotify dumpfile\n"

// stockRouter is a stock fw3-era OpenWrt as it would answer on real hardware: no ipset, no CONNMARK
// extension, a dnsmasq built no-ipset — but a WORKING IPv6 mangle table, because kmod-ip6tables
// ships in the image. (A container answers rc=3 there, but that is the host kernel refusing a module
// built for another one, and encoding it here would make a harness limitation look like firmware.)
func stockRouter() fakeRun {
	return fakeRun{replies: []reply{
		{match: "nft --version", err: errors.New("not found")},
		{match: "ipset --version", err: errors.New("not found")},
		{match: "-m set", out: `iptables v1.8.7 (legacy): Set wayhop_probe_nosuch doesn't exist.`, err: errExit},
		{match: "CONNMARK", out: `iptables v1.8.7 (legacy): unknown option "--restore-mark"`, err: errExit},
		{match: "ip6tables", out: "-P PREROUTING ACCEPT\n"},
		{match: "dnsmasq", out: dnsmasqStock},
		{match: "cat /etc/firewall.user", out: "# Put your custom iptables rules here\n"},
		{match: "uci show firewall", out: "firewall.@include[0]=include\nfirewall.@include[0].path='/etc/firewall.user'\n"},
	}}
}

func TestProbeFw3_StockRouterIsReadCorrectly(t *testing.T) {
	f := ProbeFw3(stockRouter())

	if f.HasIpsetBinary {
		t.Error("ipset reported present on a host where the command does not exist")
	}
	// The trap this probe exists for: the set-match check FAILS on a working host, because the set
	// is missing rather than the match. Reading "did it exit non-zero" would call it absent.
	if !f.HasIptablesSet {
		t.Error("a working `set` match was reported absent because its probe exited non-zero")
	}
	if f.HasConnmark {
		t.Error("CONNMARK reported present on a build that answers `unknown option`")
	}
	if !f.HasIP6Mangle {
		t.Error("IPv6 mangle reported absent although ip6tables answered")
	}
	if f.DnsmasqHasIpset {
		t.Error("a dnsmasq built no-ipset was reported as ipset-capable")
	}
	if f.DnsmasqVersion != "2.85" {
		t.Errorf("dnsmasq version read as %q, want 2.85", f.DnsmasqVersion)
	}
	if !f.FirewallUser || !f.IncludeWired {
		t.Errorf("firewall.user state misread: exists=%v wired=%v", f.FirewallUser, f.IncludeWired)
	}

	// And the whole point: this host must not be called ready.
	if Fw3Ready(f) {
		t.Fatal("a stock router was called ready for the ipset datapath")
	}
	if !strings.Contains(strings.Join(strs(Fw3Prerequisites(f)), "\n"), "iptables-mod-conntrack-extra") {
		t.Error("the CONNMARK requirement did not survive the round trip from probe to prerequisite")
	}
}

// A host with everything installed answers the two extension probes differently, and both answers
// are still failures — `-C` reports "no such rule" because we never installed one.
func TestProbeFw3_EquippedRouterReadsAsReady(t *testing.T) {
	r := stockRouter()
	r.replies = append([]reply{
		{match: "ipset --version", out: "ipset v7.6, protocol version: 7\n"},
		{match: "CONNMARK", out: "iptables: No chain/target/match by that name.", err: errors.New("exit status 1")},
		{match: "dnsmasq", out: strings.Replace(dnsmasqStock, "no-ipset", "ipset", 1)},
	}, r.replies...)

	f := ProbeFw3(r)
	if !f.HasIpsetBinary || !f.HasConnmark || !f.DnsmasqHasIpset {
		t.Fatalf("an equipped host read as ipset=%v connmark=%v dnsmasq=%v", f.HasIpsetBinary, f.HasConnmark, f.DnsmasqHasIpset)
	}
	if !Fw3Ready(f) {
		t.Errorf("an equipped host was refused: %v", strs(Fw3Prerequisites(f)))
	}
}

// An absent dnsmasq produces no output, and no output does not contain "no-ipset". Without the
// banner guard the probe would report full ipset support for a dnsmasq that is not installed —
// a check answering confidently about a subject that is not there.
func TestProbeFw3_AbsentDnsmasqIsNotCalledCapable(t *testing.T) {
	r := stockRouter()
	r.replies = append([]reply{{match: "dnsmasq", err: errors.New("not found")}}, r.replies...)

	f := ProbeFw3(r)
	if f.DnsmasqHasIpset {
		t.Fatal("a dnsmasq that is not installed was reported as ipset-capable")
	}
	if f.DnsmasqVersion != "" {
		t.Errorf("a version was invented for an absent dnsmasq: %q", f.DnsmasqVersion)
	}
}

// Anything the probe does not recognise must read as absent. A false "present" ships a datapath
// that is applied and quietly wrong; a false "absent" only asks for an install that is already done.
func TestProbeFw3_UnrecognisedAnswersFailClosed(t *testing.T) {
	r := stockRouter()
	r.replies = append([]reply{
		{match: "-m set", out: "iptables: something nobody has seen before", err: errExit},
		{match: "CONNMARK", out: "iptables: something nobody has seen before", err: errExit},
	}, r.replies...)

	f := ProbeFw3(r)
	if f.HasIptablesSet || f.HasConnmark {
		t.Fatalf("an unreadable answer became a positive one: set=%v connmark=%v", f.HasIptablesSet, f.HasConnmark)
	}
}

func TestFw3Era_FollowsTheNftBinary(t *testing.T) {
	if !Fw3Era(stockRouter()) {
		t.Error("a host with no nft was not recognised as fw3-era")
	}
	fw4 := stockRouter()
	fw4.replies = append([]reply{{match: "nft --version", out: "nftables v1.0.9 (Old Doc Yak)\n"}}, fw4.replies...)
	if Fw3Era(fw4) {
		t.Error("a host with nftables was called fw3-era; the iptables datapath is the wrong plane there")
	}
}
