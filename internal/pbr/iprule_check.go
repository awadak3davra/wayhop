package pbr

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// MissingIPRules names the `ip rule add` lines of a rendered shell program that the kernel's rule
// dumps (`ip rule` and `ip -6 rule` output) do not carry.
//
// The program runs under `sh -s`, whose exit status is that of its last command, so a refused
// `ip rule add` in the middle was invisible to the Apply: the marks were set, no rule read
// them, and the traffic left by the WAN while the panel said verified. Reading the rules back is the
// only check that does not depend on how the program reports.
//
// Lines the program runs best-effort (`|| true`) are not judged. v6Known is false when the v6 dump
// could not be read at all; the v6 rules are then left unjudged, as the v6 sets are.
func MissingIPRules(script, v4Dump, v6Dump string, v6Known bool) []string {
	v4 := parseRuleDump(v4Dump)
	v6 := parseRuleDump(v6Dump)
	var out []string
	for _, line := range strings.Split(script, "\n") {
		line = strings.TrimSpace(line)
		var rest string
		var dump []ipRuleKey
		switch {
		case strings.HasPrefix(line, "ip rule add "):
			rest, dump = strings.TrimPrefix(line, "ip rule add "), v4
		case strings.HasPrefix(line, "ip -6 rule add "):
			if !v6Known {
				continue
			}
			rest, dump = strings.TrimPrefix(line, "ip -6 rule add "), v6
		default:
			continue
		}
		if strings.Contains(rest, "||") {
			continue
		}
		want, ok := parseRuleSpec(strings.Fields(rest))
		if !ok {
			continue
		}
		found := false
		for _, have := range dump {
			if have == want {
				found = true
				break
			}
		}
		if !found {
			out = append(out, line)
		}
	}
	return out
}

// ipRuleKey is the part of a rule both the program and the kernel's dump state.
type ipRuleKey struct {
	pref           int
	fwmark, fwmask uint64
	to             string
	iif            string
	action         string // "lookup <table>" or "blackhole"
}

// parseRuleSpec reads the arguments of `ip rule add`.
func parseRuleSpec(f []string) (ipRuleKey, bool) {
	var k ipRuleKey
	k.pref = -1
	for i := 0; i < len(f); i++ {
		next := func() string {
			if i+1 < len(f) {
				i++
				return f[i]
			}
			return ""
		}
		switch f[i] {
		case "priority", "pref", "preference":
			n, err := strconv.Atoi(next())
			if err != nil {
				return k, false
			}
			k.pref = n
		case "fwmark":
			mark, mask, ok := parseMarkMask(next())
			if !ok {
				return k, false
			}
			k.fwmark, k.fwmask = mark, mask
		case "to":
			k.to = canonicalPrefix(next())
		case "iif", "dev":
			k.iif = next()
		case "table", "lookup":
			k.action = "lookup " + canonicalTable(next())
		case "blackhole":
			k.action = "blackhole"
		case "type":
			// "type blackhole", the only form BusyBox ip 1.37 accepts for the rule type.
			if next() != "blackhole" {
				return k, false
			}
			k.action = "blackhole"
		default:
			return k, false // a selector this check does not model: do not judge the line
		}
	}
	return k, k.pref >= 0 && k.action != ""
}

// parseRuleDump reads `ip rule` output into keys.
func parseRuleDump(dump string) []ipRuleKey {
	var out []ipRuleKey
	for _, line := range strings.Split(dump, "\n") {
		rl, ok := parseRuleLine(line)
		if !ok {
			continue
		}
		k := ipRuleKey{pref: rl.pref, fwmark: rl.fwmark, fwmask: rl.fwmask}
		if rl.fwmark != 0 && rl.fwmask == 0 {
			k.fwmask = 0xffffffff // `ip` omits a full mask
		}
		if rl.toCIDR != "" {
			k.to = canonicalPrefix(rl.toCIDR)
		}
		k.iif = rl.iif
		// BusyBox ip on KeeneticOS prints a blackhole rule as "lookup unspec blackhole", so the rule
		// type is read before the table.
		switch {
		case strings.Contains(" "+rl.original+" ", " blackhole "):
			k.action = "blackhole"
		case rl.lookup != "":
			k.action = "lookup " + canonicalTable(rl.lookup)
		}
		out = append(out, k)
	}
	return out
}

func parseMarkMask(s string) (mark, mask uint64, ok bool) {
	m, k, hasMask := strings.Cut(s, "/")
	mark, err := strconv.ParseUint(m, 0, 32)
	if err != nil {
		return 0, 0, false
	}
	mask = 0xffffffff
	if hasMask {
		if mask, err = strconv.ParseUint(k, 0, 32); err != nil {
			return 0, 0, false
		}
	}
	return mark, mask, true
}

// canonicalPrefix makes "192.0.2.7" and "192.0.2.7/32" the same key; `ip` prints a host rule bare.
func canonicalPrefix(s string) string {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked().String()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()).String()
	}
	return s
}

// canonicalTable maps the reserved table names `ip` prints to their numbers.
func canonicalTable(s string) string {
	switch s {
	case "main":
		return "254"
	case "local":
		return "255"
	case "default":
		return "253"
	}
	return s
}

// IpsetRestoreRemovals returns the `ipset restore` stream that deletes every entry the previous
// stream added and the target's no longer does.
//
// Restore streams only add (`-exist`), so re-running a narrower list left the dropped CIDRs in the
// set and their traffic kept taking the tunnel. A set the target no longer creates at all
// has its rules changed too and goes with the old plane's teardown; its entries are listed here as
// well, which is harmless: a delete of a missing entry is ignored under `-exist`.
//
// Only this one step is narrowed, never the whole set: flushing a resolver-filled set would send
// the listed domains out the WAN until each client looked them up again.
func IpsetRestoreRemovals(previous, target string) string {
	keep := map[string]bool{}
	for _, e := range restoreAdds(target) {
		keep[e] = true
	}
	var b strings.Builder
	seen := map[string]bool{}
	for _, e := range restoreAdds(previous) {
		if keep[e] || seen[e] {
			continue
		}
		seen[e] = true
		fmt.Fprintf(&b, "del %s -exist\n", e)
	}
	return b.String()
}

// restoreAdds lists "<set> <entry>" for every add line of a restore stream.
func restoreAdds(stream string) []string {
	var out []string
	for _, line := range strings.Split(stream, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "add" {
			out = append(out, f[1]+" "+f[2])
		}
	}
	return out
}
