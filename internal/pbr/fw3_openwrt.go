package pbr

import (
	"fmt"
	"sort"
	"strings"
)

// fw3_openwrt.go carries the ipset/iptables datapath (written for KeeneticOS in render_ipset.go)
// onto hosts where nftables is absent and RenderNft has nothing to apply to.
//
// READ THIS BEFORE EXTENDING IT. That description fits KeeneticOS, whose firmware ships no nftables
// and cannot be given any. It does NOT fit fw3-era OpenWrt, which was the original motivation for
// this file and turned out not to need it: `opkg install nftables` succeeds from both the 19.07.10
// and 21.02.7 feeds (EOL and still serving), and the nft it installs, 0.9.2 and 0.9.6 respectively,
// loads WayHop's rendered `table inet wayhop_pbr` unchanged, chains and sets intact. kmod-nft-core
// is in both feeds, so the kernel half is a package too. The remedy the capability evaluator
// already prints for those routers is therefore correct and sufficient, and Evaluate now names the
// exact command.
//
// What is measured and what is not: the load was exercised in a container, so it proves the
// USERSPACE nft of those releases accepts our syntax. The kernel half rests on kmod-nft-core being
// in the feed, not on that load, because a container runs the host's kernel.
//
// So this file's live purpose is Keenetic-shaped hosts. It is kept, tested and correct for that;
// what it should not become is a second OpenWrt datapath maintained in parallel with the nft one.
//
// The rule SYNTAX ports unmodified, and that is not a guess: RenderIpsetRestore and
// RenderIptablesScript were run inside openwrt/rootfs:x86-64-21.02.7 against iptables 1.8.7 and
// ipset 7.6 — both MAJOR versions ahead of the Keenetic stack they were written for (iptables
// 1.4.21, kernel 4.9). The sets came out with the right membership, the bypass RETURN landed ahead
// of the MARK rules, the marks carried the expected 0xff0000 mask, and re-running left the rule
// count unchanged. So no per-release rendering is needed.
//
// What does NOT port is the assumption that the kernel has the pieces the script uses. The rendered
// script needs FOUR capabilities, not one, and a stock fw3-era image has only two of them:
//
//	-m set --match-set          the ipset match      (kmod-ipt-ipset, pulled in by `ipset`)
//	-j CONNMARK --save/restore  mark persistence     (iptables-mod-conntrack-extra)
//	-j MARK / -j TCPMSS         base iptables        (always present)
//	ip6tables -t mangle         IPv6 MSS clamping    (kmod-ip6tables)
//
// The CONNMARK pair is the dangerous one. Those two commands failing is invisible: every other rule
// in the script still applies, so the chain looks right and traffic is still marked — but the mark
// is never written to the conntrack entry and never restored, so only packets that themselves match
// a destination set stay marked. Everything else in the flow falls back to the main table. That is a
// datapath which is present, plausible on inspection, and quietly wrong for most of a connection.
//
// (There is no `iptables-mod-ipset` package on either release — an earlier version of this file
// named one. The `set` match ships in the base `iptables` package; only the kernel module is
// separate.)
//
// Two more things are NOT the same, and both were measured in those containers rather than assumed:
//
//  1. A stock fw3-era OpenWrt cannot run this datapath at all. `ipset` is not in the image, and the
//     base dnsmasq is built with `no-ipset`, so `ipset=` in a dnsmasq config is not understood.
//     Keenetic ships both. Applying the Keenetic renderer there would install rules that match an
//     empty world and a dnsmasq that ignores the sets — a datapath that is present, silent, and
//     wrong, which is worse than one that refuses.
//
//  2. Re-assertion is needed for a different reason than on Keenetic, and an earlier version of
//     this comment had it wrong. The claim was that fw3 flushes our rules on every reload the way
//     NDM does. It does not. Measured on 21.02 against an fw3 building a real 45-chain ruleset:
//     `fw3 reload`, `restart`, `stop` and `start` all left WR_PREROUTING and its PREROUTING jump
//     untouched — and `stop` is not a no-op, it removed all 45 of fw3's own chains in the same
//     breath. fw3 only tears down what it created.
//
//     What our rules do NOT survive is a reboot: iptables comes up empty and nothing re-applies
//     them. /etc/firewall.user is the supported answer to that, and it is already registered as
//     `firewall.@include[0].path='/etc/firewall.user'` on both releases.
//
//     One operational detail, also measured: includes run on `fw3 start`/`restart`, NOT on
//     `fw3 reload` — a rule added to firewall.user stayed absent across two reloads and appeared
//     on the first restart. Anything that expects the include to have run must not call reload.

// Fw3Facts is what the host reports about its ipset datapath. Passed in rather than probed so this
// stays pure, and so a caller cannot forget to gather one of them and get a cheerful answer.
type Fw3Facts struct {
	HasIpsetBinary  bool   // `ipset` on PATH
	HasIptablesSet  bool   // `iptables -m set` loads
	HasConnmark     bool   // `iptables -j CONNMARK` loads
	HasIP6Mangle    bool   // `ip6tables -t mangle -S` succeeds
	DnsmasqHasIpset bool   // dnsmasq built WITHOUT the no-ipset option
	FirewallUser    bool   // /etc/firewall.user exists
	IncludeWired    bool   // firewall config has an include pointing at it
	DnsmasqVersion  string // for the message only
}

// Fw3Requirement is one thing missing before the datapath can work, and what supplies it.
type Fw3Requirement struct {
	What    string // the missing capability, in the operator's terms
	Package string // the package that provides it; "" when it is a configuration matter
	Why     string // what silently goes wrong without it
	// Blocking distinguishes "the routing will be wrong" from "one thing is degraded". Both are
	// worth telling the operator about, but only a blocker should stop an apply — refusing to
	// route IPv4 because IPv6 MSS clamping is unavailable would be its own kind of wrong.
	Blocking bool
}

func (r Fw3Requirement) String() string {
	if r.Package != "" {
		return fmt.Sprintf("%s — install %s (%s)", r.What, r.Package, r.Why)
	}
	return fmt.Sprintf("%s (%s)", r.What, r.Why)
}

// Fw3Prerequisites reports everything that must be true before the ipset datapath can carry traffic
// on this host, in a stable order.
//
// It reports rather than repairs. Installing packages is a device-mutating step with its own
// pre-flight (platform.BuildInstallPlan weighs free space and kmod/kernel matching), and folding it
// in here would put an unattended install behind a function that reads like a query.
func Fw3Prerequisites(f Fw3Facts) []Fw3Requirement {
	var out []Fw3Requirement

	if !f.HasIpsetBinary {
		out = append(out, Fw3Requirement{
			What:     "the ipset tool is not installed",
			Package:  "ipset",
			Why:      "the sets that hold the routed prefixes cannot be created, so every rule matches nothing",
			Blocking: true,
		})
	}
	if !f.HasIptablesSet {
		out = append(out, Fw3Requirement{
			What: "iptables has no `set` match",
			// Not iptables-mod-ipset — no such package exists on 19.07 or 21.02. The match itself
			// is in the base iptables package; what can be missing is the kernel module, and that
			// arrives as a dependency of `ipset`.
			Package:  "kmod-ipt-ipset",
			Why:      "the marking rules cannot reference a set, so nothing is ever marked and traffic takes the default route",
			Blocking: true,
		})
	}
	if !f.HasConnmark {
		out = append(out, Fw3Requirement{
			What:    "iptables has no CONNMARK target",
			Package: "iptables-mod-conntrack-extra",
			// This is the one worth spelling out. Losing CONNMARK does not make the datapath fail
			// visibly: the chain builds, the MARK rules apply, and a check that only looks for
			// "are the rules there" passes. The mark just never survives past the packets that
			// match a destination set themselves.
			Why:      "the mark is never saved to the connection or restored, so only packets that match a destination set stay marked and the rest of each flow falls back to the default route",
			Blocking: true,
		})
	}
	if !f.HasIP6Mangle {
		out = append(out, Fw3Requirement{
			What:    "ip6tables has no mangle table",
			Package: "kmod-ip6tables",
			Why:     "IPv6 MSS clamping cannot be installed, so large IPv6 packets through a tunnel can black-hole; IPv4 routing is unaffected",
		})
	}
	if !f.DnsmasqHasIpset {
		what := "dnsmasq was built without ipset support"
		if f.DnsmasqVersion != "" {
			what += " (" + f.DnsmasqVersion + ")"
		}
		out = append(out, Fw3Requirement{
			What:    what,
			Package: "dnsmasq-full",
			Why:     "domain-based routing fills its sets from DNS answers; without it the sets stay empty and only literal-IP rules work",
			// Blocking because the ipset plane exists FOR domain lists — the whole reason this
			// datapath is preferred over pre-resolving is that dnsmasq fills the sets at query
			// time. Without that it is an expensive way to route a handful of literal CIDRs.
			Blocking: true,
		})
	}
	if !f.FirewallUser {
		out = append(out, Fw3Requirement{
			What:     "/etc/firewall.user is missing",
			Why:      "the rules would be lost at the next reboot, since iptables comes up empty and this file is the supported place to put them back",
			Blocking: true,
		})
	} else if !f.IncludeWired {
		out = append(out, Fw3Requirement{
			What: "/etc/firewall.user exists but the firewall config does not include it",
			// Not "the next reload drops them" — measurement showed fw3 leaves foreign chains
			// alone. The failure is slower and easier to misattribute: routing works for weeks
			// and is simply gone after a power cut.
			Why:      "the rules would work until the next reboot and then silently not come back, which is easy to blame on the tunnel rather than on routing",
			Blocking: true,
		})
	}
	// Blockers first, and within each group the ones an install can fix — that is the order the
	// operator has to act in.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Blocking != out[j].Blocking {
			return out[i].Blocking
		}
		return out[i].Package != "" && out[j].Package == ""
	})
	return out
}

// Fw3Ready reports whether the datapath can be applied at all. A non-blocking requirement (IPv6 MSS
// clamping) is still reported by Fw3Prerequisites but does not hold up IPv4 routing.
func Fw3Ready(f Fw3Facts) bool {
	for _, r := range Fw3Prerequisites(f) {
		if r.Blocking {
			return false
		}
	}
	return true
}

// RenderFirewallUser wraps a rendered iptables script so fw3 re-applies it at boot.
//
// The body is expected to be idempotent — RenderIptablesScript already is, because the Keenetic hook
// re-runs it too — so being invoked again on an already-configured system restores what is missing
// rather than doubling what is there. Verified on 21.02: after deleting the chain and its jump by
// hand, one `fw3 restart` brought the whole datapath back, and repeated restarts left the rule count
// unchanged. The markers let a later version replace only its own block instead of overwriting a
// file the operator may also be using.
func RenderFirewallUser(body string) string {
	var b strings.Builder
	b.WriteString(fw3MarkerBegin + "\n")
	b.WriteString("# Written by WayHop. fw3 flushes its chains on every reload; this include puts the\n")
	b.WriteString("# policy-routing rules back. Everything between the markers is regenerated — edits\n")
	b.WriteString("# here are lost. Anything outside them is left alone.\n")
	b.WriteString(strings.TrimRight(body, "\n"))
	b.WriteString("\n" + fw3MarkerEnd + "\n")
	return b.String()
}

const (
	fw3MarkerBegin = "### WAYHOP-PBR BEGIN"
	fw3MarkerEnd   = "### WAYHOP-PBR END"
)

// MergeFirewallUser puts block into an existing /etc/firewall.user, replacing a previous WayHop block
// and leaving everything else untouched. Returns the new file contents.
//
// Replacing the whole file would be simpler and would silently discard whatever the operator had put
// there — which on a router is often the one rule that makes their setup work.
func MergeFirewallUser(existing, block string) string {
	begin := strings.Index(existing, fw3MarkerBegin)
	if begin < 0 {
		if strings.TrimSpace(existing) == "" {
			return block
		}
		return strings.TrimRight(existing, "\n") + "\n\n" + block
	}
	end := strings.Index(existing[begin:], fw3MarkerEnd)
	if end < 0 {
		// A begin marker with no end: the file was truncated or hand-edited. Appending a second
		// block would leave two begins and make the next merge ambiguous, so replace from the marker
		// to the end and say nothing was kept after it — there is nothing trustworthy to keep.
		return strings.TrimRight(existing[:begin], "\n") + "\n\n" + block
	}
	tail := existing[begin+end+len(fw3MarkerEnd):]
	head := strings.TrimRight(existing[:begin], "\n")
	out := block
	if head != "" {
		out = head + "\n\n" + block
	}
	if t := strings.TrimLeft(tail, "\n"); t != "" {
		out = strings.TrimRight(out, "\n") + "\n\n" + t
	}
	return out
}
