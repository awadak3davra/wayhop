package pbr

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// guard_source.go is the operator's own source routing as the kill-switch guard sees it.
//
// The guard knows a kill-switched destination's own tunnels and takes every other device for the
// provider. That is not true of a segment the operator routes by source: a rule of the router's own,
// `from 192.168.33.0/24 lookup 160` with `default dev awg1` in table 160, sends everything that
// segment asks for into one tunnel, ahead of WayHop's marks. For that segment the tunnel is the way
// out the operator chose, and a kill-switched address reached by it has not left by the provider.
//
// So the guard is told each such rule as a (source, device) pair, and a packet that a kill switch
// would drop is let through when it comes from that source and leaves by that device. The pair is
// only ever told for a device that is a tunnel and is not on the provider's side (the daemon judges
// it, killswitchsource.go): the kill switch's first promise, never by the provider's device, is kept
// by the rule's own `oifname`. Block lists are not opened: what the operator blocks is dropped for
// every segment.

// GuardSource is one source rule of the router's own and the device its table leaves by.
type GuardSource struct {
	// Src is the rule's `from` prefix. The zero prefix for a rule that selects by input device.
	Src netip.Prefix
	// Iif is the rule's `iif` device, when it selects by one.
	Iif string
	// Dev is the device of the default route in the table the rule looks up.
	Dev string
}

// SourceRule is one `ip rule` line that selects by source alone and looks up a table of its own.
type SourceRule struct {
	Line  string
	Pref  int
	Src   netip.Prefix // zero for `from all`
	Iif   string
	Table string // as `ip rule` prints it: a number or a name
}

// SourceRules reads the rules of an `ip rule show` dump that route a segment by its source: a `from
// <prefix>` or an `iif <device>`, no mark, no destination, and a lookup of a table that is not one
// of the kernel's three.
//
//	30:	from 192.168.33.0/24 lookup 160
//	31:	from all iif br-guest lookup 161
//
// Left out: rules with a fwmark (WayHop's own, the core's), with `to`, `not`, a port, a protocol, a
// uid range or an output device; `iif lo` (the router's own packets are not forwarded); rules that
// are not a lookup (goto, unreachable, blackhole, nop).
func SourceRules(dump string) []SourceRule {
	var out []SourceRule
	for _, line := range strings.Split(dump, "\n") {
		rl, ok := parseRuleLine(line)
		if !ok || rl.lookup == "" || rl.fwmark != 0 || rl.fwmask != 0 || rl.toCIDR != "" {
			continue
		}
		switch rl.lookup {
		case "local", "main", "default", "0", "253", "254", "255":
			continue
		}
		f := strings.Fields(line)
		r := SourceRule{Line: strings.Join(f, " "), Pref: rl.pref, Table: rl.lookup}
		plain := true
		for i := 1; i < len(f) && plain; i++ {
			switch f[i] {
			case "from":
				if i+1 >= len(f) {
					plain = false
					break
				}
				if f[i+1] != "all" {
					p, err := parseRulePrefix(f[i+1])
					if err != nil {
						plain = false
						break
					}
					r.Src = p
				}
				i++
			case "iif":
				if i+1 >= len(f) {
					plain = false
					break
				}
				r.Iif = f[i+1]
				i++
			case "lookup":
				i++
			case "not", "fwmark", "to", "oif", "ipproto", "sport", "dport", "uidrange", "tos", "dsfield", "tun_id",
				"goto", "nop", "unreachable", "blackhole", "prohibit", "suppress_prefixlength", "suppress_ifgroup", "l3mdev":
				plain = false
			}
		}
		if !plain || r.Iif == "lo" || !r.Src.IsValid() && r.Iif == "" {
			continue
		}
		out = append(out, r)
	}
	return out
}

// parseRulePrefix reads a rule's `from` value: a prefix, or an address standing for itself.
func parseRulePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("rule source %q: %w", s, err)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// TableDefaultDevices reads `ip [-6] route show table all` for the device of every table's default
// route, by table as the dump names it. A table with default routes by more than one device lists
// them all; a blackhole or unreachable default has no device and is not listed.
//
//	default dev awg1 table 160 scope link
//	default via 10.8.0.1 dev tun0 table vpn proto static
func TableDefaultDevices(dump string) map[string][]string {
	out := map[string][]string{}
	for _, line := range strings.Split(dump, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != "default" {
			continue
		}
		dev, table := "", ""
		for i := 1; i+1 < len(f); i++ {
			switch f[i] {
			case "dev":
				dev = f[i+1]
			case "table":
				table = f[i+1]
			}
		}
		if dev == "" || table == "" {
			continue
		}
		out[table] = sortedUnique(append(out[table], dev))
	}
	return out
}

// GuardedList is one kill-switched address zone as Review names it: what it was compiled from, the
// devices it may leave by, and the sources it is limited to (none: every source).
type GuardedList struct {
	Zone    string
	Origin  ZoneOrigin
	Devices []string
	// Src is the zone's source prefixes, and SrcNegate says they are the ones it does NOT cover.
	Src       []netip.Prefix
	SrcNegate bool
}

// GuardedLists is the kill-switched zones the guard holds to their tunnels (block lists are not
// among them).
func (pl *Plan) GuardedLists() []GuardedList {
	var out []GuardedList
	for _, g := range pl.guardedZones() {
		if len(g.allow) == 0 {
			continue
		}
		l := GuardedList{Zone: g.zone.Name, Origin: g.zone.origin, Devices: append([]string(nil), g.allow...), SrcNegate: g.zone.SrcNegate}
		for _, c := range append(append([]string(nil), g.zone.SrcV4...), g.zone.SrcV6...) {
			if p, err := parseRulePrefix(c); err == nil {
				l.Src = append(l.Src, p)
			}
		}
		out = append(out, l)
	}
	return out
}

// sourceAccepts renders the accepts for the operator's source routing: the segment's packets by the
// device its own rule routes it to, and the answers coming back by that device. away is the devices
// known to be the provider's; a pair that names one is not rendered, whoever told it.
func sourceAccepts(src []GuardSource, away []string) []string {
	not := map[string]bool{}
	for _, d := range away {
		not[d] = true
	}
	var out []string
	for _, s := range src {
		if !guardDevName(s.Dev) || not[s.Dev] {
			continue
		}
		switch {
		case s.Src.IsValid():
			fam := "ip"
			if s.Src.Addr().Is6() {
				fam = "ip6"
			}
			p := s.Src.Masked().String()
			out = append(out,
				fmt.Sprintf("%s saddr %s oifname %q accept", fam, p, s.Dev),
				fmt.Sprintf("iifname %q %s daddr %s accept", s.Dev, fam, p))
		case guardDevName(s.Iif) && s.Iif != s.Dev:
			out = append(out,
				fmt.Sprintf("iifname %q oifname %q accept", s.Iif, s.Dev),
				fmt.Sprintf("iifname %q oifname %q accept", s.Dev, s.Iif))
		}
	}
	sort.Strings(out)
	return sortedUnique(out)
}
