package pbr

import (
	"strings"
	"testing"
)

// stockFw3 is what openwrt/rootfs:x86-64-21.02.7 and :x86-64-19.07.10 actually ship, read from
// `opkg list-installed` in a container (119 and 117 packages respectively — a non-zero denominator
// matters here, because an opkg that cannot take its lock reports every package as absent and the
// result looks like a measurement).
//
// Absent on both: ipset, and iptables-mod-conntrack-extra — so `-j CONNMARK --restore-mark` gets
// `unknown option`, a userspace-extension miss rather than a kernel one. PRESENT on both:
// kmod-ip6tables, so IPv6 mangle is not a stock gap; the container cannot exercise it only because
// modules built for the image's kernel will not load against the host's, which is a property of the
// harness and must not be recorded as a property of the firmware. /etc/firewall.user ships wired as
// firewall.@include[0] on both.
func stockFw3() Fw3Facts {
	return Fw3Facts{
		HasIpsetBinary:  false,
		HasIptablesSet:  false,
		HasConnmark:     false,
		HasIP6Mangle:    true,
		DnsmasqHasIpset: false,
		FirewallUser:    true,
		IncludeWired:    true,
		DnsmasqVersion:  "2.85",
	}
}

func readyFw3() Fw3Facts {
	return Fw3Facts{
		HasIpsetBinary: true, HasIptablesSet: true, HasConnmark: true, HasIP6Mangle: true,
		DnsmasqHasIpset: true, FirewallUser: true, IncludeWired: true,
	}
}

// The claim this file exists to prevent: that the Keenetic datapath can simply be pointed at an
// fw3-era OpenWrt. On a stock image it cannot, and the failure is silent — rules that match an empty
// set and a dnsmasq that ignores it.
func TestFw3Prerequisites_StockImageIsNotReady(t *testing.T) {
	reqs := Fw3Prerequisites(stockFw3())
	if len(reqs) == 0 {
		t.Fatal("a stock fw3 image was reported ready; it has neither ipset nor an ipset-capable dnsmasq")
	}
	if Fw3Ready(stockFw3()) {
		t.Error("Fw3Ready agreed with a state that cannot carry traffic")
	}
	joined := strings.Join(strs(reqs), "\n")
	for _, want := range []string{"ipset", "dnsmasq-full", "iptables-mod-conntrack-extra"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the package that supplies the missing piece is not named (%s):\n%s", want, joined)
		}
	}
	// An earlier version named iptables-mod-ipset, which exists on neither 19.07 nor 21.02 — the
	// operator would have been sent to run an install that opkg refuses with "Unknown package".
	if strings.Contains(joined, "iptables-mod-ipset") {
		t.Errorf("a package that does not exist in any fw3-era feed is being recommended:\n%s", joined)
	}
	// Each requirement has to say what goes wrong, or the operator cannot judge whether to install.
	for _, r := range reqs {
		if r.Why == "" {
			t.Errorf("requirement %q does not say what breaks without it", r.What)
		}
	}
}

func TestFw3Prerequisites_ReadyHostIsSilent(t *testing.T) {
	if reqs := Fw3Prerequisites(readyFw3()); len(reqs) != 0 {
		t.Fatalf("a host with everything present reported %d requirement(s): %v", len(reqs), strs(reqs))
	}
	if !Fw3Ready(readyFw3()) {
		t.Error("Fw3Ready refused a host that has everything")
	}
}

// The failure this check was added for. Everything is installed except the CONNMARK extension: the
// chain builds, the sets fill, the MARK rules apply, and anything that asks "are the rules there"
// says yes. But the mark is never written to the connection, so it survives only on packets that
// match a destination set themselves. A host in this state must not be called ready.
func TestFw3Prerequisites_MissingConnmarkBlocks(t *testing.T) {
	f := readyFw3()
	f.HasConnmark = false

	if Fw3Ready(f) {
		t.Fatal("a host with no CONNMARK target was called ready; it would mark the first packets of a flow and route the rest out the wrong path")
	}
	reqs := Fw3Prerequisites(f)
	if len(reqs) != 1 {
		t.Fatalf("expected exactly the CONNMARK requirement, got: %v", strs(reqs))
	}
	if reqs[0].Package != "iptables-mod-conntrack-extra" {
		t.Errorf("CONNMARK blamed on %q; it is supplied by iptables-mod-conntrack-extra on both 19.07 and 21.02", reqs[0].Package)
	}
	// The reason has to say the mark is lost, not merely that a module is absent — the operator's
	// decision to install hinges on knowing traffic is misrouted, not that a checkbox is unticked.
	if !strings.Contains(reqs[0].Why, "mark") {
		t.Errorf("the reason does not explain that the mark is lost: %q", reqs[0].Why)
	}
}

// The counterpart: a missing IPv6 mangle table costs IPv6 MSS clamping and nothing else. Refusing
// to route IPv4 over it would be a self-inflicted outage, so it must be reported without blocking.
func TestFw3Prerequisites_MissingIP6MangleReportsButDoesNotBlock(t *testing.T) {
	f := readyFw3()
	f.HasIP6Mangle = false

	reqs := Fw3Prerequisites(f)
	if len(reqs) != 1 {
		t.Fatalf("expected exactly the IPv6 requirement, got: %v", strs(reqs))
	}
	if reqs[0].Blocking {
		t.Error("a missing IPv6 mangle table was treated as blocking; IPv4 routing does not depend on it")
	}
	if !Fw3Ready(f) {
		t.Error("Fw3Ready refused a host that can route IPv4 perfectly well")
	}
	if !strings.Contains(reqs[0].Why, "IPv4") {
		t.Errorf("the reason should say IPv4 is unaffected, or the operator cannot judge the risk: %q", reqs[0].Why)
	}
}

// Blockers have to come first: an operator reading a list top-down should not install the optional
// IPv6 module before the one without which nothing routes.
func TestFw3Prerequisites_BlockersAreListedFirst(t *testing.T) {
	// A stock image alone would give an all-blocking list, and an ordering check over a list with
	// nothing to mis-order passes without examining anything. Take the IPv6 module away too, so
	// there is genuinely something that could come out in the wrong place.
	f := stockFw3()
	f.HasIP6Mangle = false
	reqs := Fw3Prerequisites(f)

	var blocking, optional int
	for _, r := range reqs {
		if r.Blocking {
			blocking++
		} else {
			optional++
		}
	}
	if blocking == 0 || optional == 0 {
		t.Fatalf("this orders nothing: %d blocking, %d optional", blocking, optional)
	}

	seenNonBlocking := false
	for _, r := range reqs {
		if !r.Blocking {
			seenNonBlocking = true
			continue
		}
		if seenNonBlocking {
			t.Fatalf("a blocking requirement (%q) is listed after an optional one:\n%s",
				r.What, strings.Join(strs(reqs), "\n"))
		}
	}
}

// The subtler of the two: the file exists, so a naive check passes, but nothing includes it — the
// rules would be written and then dropped by the next fw3 reload. That is the failure that works
// until somebody else touches the firewall, which is the worst kind to ship.
func TestFw3Prerequisites_UnwiredIncludeIsReported(t *testing.T) {
	f := readyFw3()
	f.IncludeWired = false
	reqs := Fw3Prerequisites(f)
	if len(reqs) != 1 {
		t.Fatalf("expected exactly the include problem, got: %v", strs(reqs))
	}
	// The reason must name the reboot. Saying "a reload drops them" was the earlier wording and it
	// was measurably false — fw3 leaves foreign chains alone through reload, restart and even stop.
	// An operator told the wrong failure mode looks for the wrong evidence.
	if !strings.Contains(reqs[0].Why, "reboot") {
		t.Errorf("the reason should explain that the rules are lost at reboot: %q", reqs[0].Why)
	}
	if strings.Contains(reqs[0].Why, "reload") {
		t.Errorf("the reason still blames fw3 reload, which was measured not to drop them: %q", reqs[0].Why)
	}
	// It is a configuration matter, not a package — suggesting one would send the operator to install
	// something that is already there.
	if reqs[0].Package != "" {
		t.Errorf("an unwired include was blamed on a missing package %q", reqs[0].Package)
	}
}

// Replacing the whole of /etc/firewall.user would discard whatever the operator keeps there, which on
// a router is often the one rule their setup depends on.
func TestMergeFirewallUser_KeepsWhatIsNotOurs(t *testing.T) {
	existing := "# my own rules\niptables -I INPUT -p tcp --dport 2222 -j ACCEPT\n"
	block := RenderFirewallUser("iptables -t mangle -A PREROUTING -j MARK --set-mark 0x20000")

	out := MergeFirewallUser(existing, block)
	if !strings.Contains(out, "--dport 2222") {
		t.Fatal("the operator's own rule was discarded")
	}
	if !strings.Contains(out, "--set-mark 0x20000") {
		t.Fatal("our block is missing")
	}

	// Re-merging must REPLACE our block, not stack a second one.
	again := MergeFirewallUser(out, RenderFirewallUser("iptables -t mangle -A PREROUTING -j MARK --set-mark 0x30000"))
	if n := strings.Count(again, fw3MarkerBegin); n != 1 {
		t.Fatalf("re-merging produced %d WayHop blocks; a reload would then apply both", n)
	}
	if strings.Contains(again, "0x20000") {
		t.Error("the previous block survived alongside the new one")
	}
	if !strings.Contains(again, "--dport 2222") {
		t.Error("the operator's rule was lost on the second merge")
	}
}

// A file whose end marker was lost to a hand-edit must not end up with two begin markers, or the
// next merge cannot tell where our block starts.
func TestMergeFirewallUser_SurvivesATruncatedBlock(t *testing.T) {
	broken := "# theirs\n" + fw3MarkerBegin + "\niptables -A INPUT -j DROP\n" // no end marker
	out := MergeFirewallUser(broken, RenderFirewallUser("iptables -t mangle -A PREROUTING -j MARK --set-mark 0x20000"))
	if n := strings.Count(out, fw3MarkerBegin); n != 1 {
		t.Fatalf("expected one begin marker, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "# theirs") {
		t.Error("content before the broken block was discarded")
	}
}

func TestRenderFirewallUser_IsMarkedAndSaysItIsRegenerated(t *testing.T) {
	out := RenderFirewallUser("iptables -A FORWARD -j ACCEPT")
	if !strings.HasPrefix(out, fw3MarkerBegin) || !strings.Contains(out, fw3MarkerEnd) {
		t.Fatal("the block is not delimited by markers, so a merge cannot find it again")
	}
	if !strings.Contains(out, "regenerated") {
		t.Error("the block does not warn that edits inside it are lost")
	}
}

func strs(rs []Fw3Requirement) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.String())
	}
	return out
}
