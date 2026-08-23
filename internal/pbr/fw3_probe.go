package pbr

import "strings"

// fw3_probe.go reads a host's ipset-datapath capabilities so Fw3Prerequisites has something real to
// judge. Everything here is READ-ONLY: `iptables -C` asks whether a rule exists and installs
// nothing, so a router can be interrogated without being changed.
//
// The alternative — insert a probe rule and delete it again — would be a mutation on a live router
// for the sake of a question, and a crash between the two halves would leave it behind.
//
// The answers are read from iptables' own wording, and the wording was measured rather than
// recalled, on iptables 1.8.3 (OpenWrt 19.07.10) and 1.8.7 (21.02.7), which agree exactly:
//
//	extension missing        rc 2  iptables v1.8.7: unknown option "--restore-mark"
//	extension fine, no rule  rc 1  iptables: No chain/target/match by that name.
//	set match fine, no set   rc 2  iptables v1.8.7: Set wayhop_probe_nosuch doesn't exist.
//
// Note the third line: a working `set` match reports failure too, because the SET is missing rather
// than the match. Keying on "did it fail" would call a perfectly good match absent.
//
// Every probe reports present only on recognised positive evidence and treats anything unfamiliar
// as absent. That is deliberate: an unreadable answer must not become a cheerful one, because the
// consequence of a false "present" is a datapath that is applied and quietly wrong, while a false
// "absent" only asks the operator to install something they already have.

// probeSetName is a set that cannot exist, so the match probe can never accidentally match a real
// rule. Within ipset's 31-character limit.
const probeSetName = "wayhop_probe_nosuch"

// Fw3Era reports whether this host's firewall plane is fw3/iptables rather than fw4/nftables.
//
// Checked separately from Fw3Facts on purpose: on an fw4 host the ipset datapath is not merely
// unready, it is the wrong plane entirely, and folding that into a readiness answer would let a
// caller read "nothing is missing" as "go ahead".
func Fw3Era(run Runner) bool {
	_, err := run.Run("", "nft", "--version")
	return err != nil
}

// ProbeFw3 gathers Fw3Facts from a live host. Read-only.
func ProbeFw3(run Runner) Fw3Facts {
	var f Fw3Facts

	_, err := run.Run("", "ipset", "--version")
	f.HasIpsetBinary = err == nil

	f.HasIptablesSet = probeSetMatch(run)
	f.HasConnmark = probeConnmark(run)

	_, err = run.Run("", "ip6tables", "-t", "mangle", "-S")
	f.HasIP6Mangle = err == nil

	ver, _ := run.Run("", "dnsmasq", "--version")
	// An absent dnsmasq produces no output, and "no output" does not contain "no-ipset" — so a
	// naive negated Contains would report full ipset support for a dnsmasq that is not installed.
	// Require the banner before believing either answer.
	if strings.Contains(ver, "Dnsmasq version") {
		f.DnsmasqVersion = dnsmasqVersion(ver)
		f.DnsmasqHasIpset = !strings.Contains(ver, "no-ipset")
	}

	_, err = run.Run("", "cat", "/etc/firewall.user")
	f.FirewallUser = err == nil

	if out, err := run.Run("", "uci", "show", "firewall"); err == nil {
		f.IncludeWired = strings.Contains(out, "/etc/firewall.user")
	}
	return f
}

// probeSetMatch reports whether iptables can use `-m set`.
func probeSetMatch(run Runner) bool {
	out, err := run.Run("", "iptables", "-t", "mangle", "-C", "PREROUTING",
		"-m", "set", "--match-set", probeSetName, "dst", "-j", "RETURN")
	if err == nil {
		return true // the rule somehow exists, so the match certainly loads
	}
	// "Set … doesn't exist" means the match loaded and got as far as asking the kernel for the set.
	// "No chain/target/match by that name" is how -C says the rule is simply not there; PREROUTING
	// always exists in mangle, so it cannot be the chain that is missing.
	return strings.Contains(out, "doesn't exist") ||
		strings.Contains(out, "No chain/target/match by that name")
}

// probeConnmark reports whether iptables has the CONNMARK target — the capability whose absence is
// otherwise invisible, since every other rule in the rendered script still applies without it.
func probeConnmark(run Runner) bool {
	out, err := run.Run("", "iptables", "-t", "mangle", "-C", "PREROUTING",
		"-j", "CONNMARK", "--restore-mark", "--nfmask", "0xff0000", "--ctmask", "0xff0000")
	if err == nil {
		return true
	}
	if strings.Contains(out, "unknown option") || strings.Contains(out, "Couldn't load") {
		return false
	}
	return strings.Contains(out, "No chain/target/match by that name")
}

// dnsmasqVersion pulls "2.85" out of "Dnsmasq version 2.85  Copyright …", for the message only.
func dnsmasqVersion(banner string) string {
	fields := strings.Fields(banner)
	for i, w := range fields {
		if w == "version" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}
