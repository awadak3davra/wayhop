package importer

import (
	"strings"

	"wayhop/internal/cidrfeed"
)

// hydraroute.go reads the two routing files of HydraRoute Neo, a Keenetic add-on that routes by DNS
// answers, so a router moving to WayHop keeps its lists. Format as its README states it
// (Ground-Zerro/HydraRoute, Neo/README.md):
//
//	domain.conf                              ip.list
//	## YouTube                               ##Google CDN
//	youtube.com,googlevideo.com/HydraRoute   /HydraRoute
//	geosite:google,youtu.be/nwg0             192.0.2.0/24
//	                                         geoip:ru
//	                                         (a blank line ends the block)
//	                                         #/nwg0       <- a block switched off
//
// The name after "/" is a Keenetic policy or a system interface; WayHop routes by its own exits, so
// that name is carried as context and the operator picks the exit. A domain matches itself and its
// subdomains there, as a routing-list domain does here. Nothing is dropped silently: what cannot be
// carried is reported per line with the reason.

// HydraRoute file formats, as ParseHydraRoute recognised the paste.
const (
	HydraFormatDomains = "domain.conf"
	HydraFormatIPs     = "ip.list"
)

// Reasons an entry is not carried.
const (
	// HydraSkipInvalid is neither a usable domain nor an address or prefix, or a line that is no rule.
	HydraSkipInvalid = "invalid"
	// HydraSkipGeosite is a geosite:TAG. HydraRoute expands it from a v2ray .dat file; WayHop has none.
	HydraSkipGeosite = "geosite"
	// HydraSkipGeoIP is ip.list's geoip:TAG, for the same reason.
	HydraSkipGeoIP = "geoip"
	// HydraSkipLeadingDot is ".example.com". The README says HydraRoute matches no name with it, so
	// carrying it would start routing traffic that was never routed.
	HydraSkipLeadingDot = "leading_dot"
	// HydraSkipDisabled is an entry of an ip.list block switched off with "#/".
	HydraSkipDisabled = "disabled"
)

// HydraSkip is one entry that was not carried.
type HydraSkip struct {
	Line   int    // 1-based line of the paste
	Entry  string // as written
	Reason string // a HydraSkip* constant
}

// HydraTarget is every rule of one target, merged: one WayHop routing list has one exit.
type HydraTarget struct {
	Target       string   // the policy or interface after "/"
	Descriptions []string // the distinct "##" descriptions of its rules, in order
	Domains      []string
	CIDRs        []string
	Skipped      []HydraSkip
}

// HydraRoute is a parsed paste.
type HydraRoute struct {
	Format  string
	Targets []HydraTarget // in the order each target first appears
	Skipped []HydraSkip   // lines that belong to no target
}

// ParseHydraRoute reads a pasted domain.conf or ip.list. The two are told apart by their first rule:
// ip.list opens a block with "/target" (or "#/target"), and a domain.conf line never starts with one.
func ParseHydraRoute(text string) HydraRoute {
	lines := strings.Split(strings.TrimPrefix(text, "\uFEFF"), "\n")
	b := hydraBuilder{index: map[string]int{}}
	b.out.Format = hydraFormat(lines)
	if b.out.Format == HydraFormatIPs {
		b.parseIPList(lines)
	} else {
		b.parseDomainConf(lines)
	}
	return b.out
}

func hydraFormat(lines []string) string {
	for _, raw := range lines {
		t := strings.TrimSpace(raw)
		if t == "" || (strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "#/")) {
			continue
		}
		if _, isCIDR := cidrfeed.NormalizeCIDR(t); isCIDR || strings.HasPrefix(t, "/") || strings.HasPrefix(t, "#/") {
			return HydraFormatIPs
		}
		return HydraFormatDomains
	}
	return HydraFormatDomains
}

type hydraBuilder struct {
	out   HydraRoute
	index map[string]int    // target -> position in out.Targets
	seen  []map[string]bool // per target: entries already carried
}

func (b *hydraBuilder) target(name string) int {
	if i, ok := b.index[name]; ok {
		return i
	}
	b.index[name] = len(b.out.Targets)
	b.out.Targets = append(b.out.Targets, HydraTarget{Target: name})
	b.seen = append(b.seen, map[string]bool{})
	return len(b.out.Targets) - 1
}

func (b *hydraBuilder) describe(i int, desc []string) {
	if len(desc) == 0 {
		return
	}
	d := strings.Join(desc, " ")
	for _, have := range b.out.Targets[i].Descriptions {
		if have == d {
			return
		}
	}
	b.out.Targets[i].Descriptions = append(b.out.Targets[i].Descriptions, d)
}

func (b *hydraBuilder) skip(i, line int, entry, reason string) {
	s := HydraSkip{Line: line, Entry: entry, Reason: reason}
	if i < 0 {
		b.out.Skipped = append(b.out.Skipped, s)
		return
	}
	b.out.Targets[i].Skipped = append(b.out.Targets[i].Skipped, s)
}

func (b *hydraBuilder) add(i int, entry string, cidr bool) {
	if b.seen[i][entry] {
		return
	}
	b.seen[i][entry] = true
	if cidr {
		b.out.Targets[i].CIDRs = append(b.out.Targets[i].CIDRs, entry)
	} else {
		b.out.Targets[i].Domains = append(b.out.Targets[i].Domains, entry)
	}
}

// hydraDescription is the text of a "##" line, or false for any other line.
func hydraDescription(t string) (string, bool) {
	if !strings.HasPrefix(t, "##") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimLeft(t, "#")), true
}

// parseDomainConf reads `dom1,dom2,geosite:tag/Target` rules. The "##" lines directly above a rule
// are its description; a blank line or any other line in between detaches them.
func (b *hydraBuilder) parseDomainConf(lines []string) {
	var desc []string
	for n, raw := range lines {
		line := n + 1
		t := strings.TrimSpace(raw)
		if d, ok := hydraDescription(t); ok {
			if d != "" {
				desc = append(desc, d)
			}
			continue
		}
		pending := desc
		desc = nil
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		// The target follows the LAST "/": a prefix pasted among the names ("example.com,192.0.2.0/24/nwg0")
		// otherwise made "24/nwg0" the target. It is one policy or interface name, so a line with
		// anything after it ("youtube.com/HydraRoute # video") names none and is reported, not guessed.
		cut := strings.LastIndex(t, "/")
		ok := cut >= 0
		names, target := t, ""
		if ok {
			names, target = t[:cut], strings.TrimSpace(t[cut+1:])
		}
		// A bare prefix ("192.0.2.0/24") would otherwise read as names "192.0.2.0" for a target "24".
		if _, isCIDR := cidrfeed.NormalizeCIDR(t); isCIDR || !ok || target == "" || strings.ContainsAny(target, " \t#") ||
			strings.TrimSpace(names) == "" {
			b.skip(-1, line, t, HydraSkipInvalid)
			continue
		}
		i := b.target(target)
		b.describe(i, pending)
		for _, e := range strings.Split(names, ",") {
			e = strings.TrimSpace(e)
			switch {
			case e == "":
			case strings.HasPrefix(strings.ToLower(e), "geosite:"):
				b.skip(i, line, e, HydraSkipGeosite)
			case strings.HasPrefix(e, "."):
				b.skip(i, line, e, HydraSkipLeadingDot)
			default:
				name := strings.ToLower(strings.TrimSuffix(e, "."))
				if !cidrfeed.ValidDomain(name) {
					b.skip(i, line, e, HydraSkipInvalid)
					continue
				}
				b.add(i, name, false)
			}
		}
	}
}

// parseIPList reads `/Target` blocks of prefixes. "#/Target" opens a block HydraRoute ignores, so its
// entries are reported as disabled rather than imported; a blank line ends a block.
func (b *hydraBuilder) parseIPList(lines []string) {
	var desc []string
	cur, disabled := -1, false
	for n, raw := range lines {
		line := n + 1
		t := strings.TrimSpace(raw)
		if d, ok := hydraDescription(t); ok {
			if d != "" {
				desc = append(desc, d)
			}
			continue
		}
		pending := desc
		desc = nil
		switch {
		case t == "":
			cur, disabled = -1, false
		case strings.HasPrefix(t, "/") || strings.HasPrefix(t, "#/"):
			disabled = t[0] == '#'
			target := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(t, "#"), "/"))
			if target == "" {
				cur = -1
				b.skip(-1, line, t, HydraSkipInvalid)
				continue
			}
			cur = b.target(target)
			if !disabled {
				b.describe(cur, pending)
			}
		case strings.HasPrefix(t, "#"):
		case cur < 0:
			b.skip(-1, line, t, HydraSkipInvalid)
		case disabled:
			b.skip(cur, line, t, HydraSkipDisabled)
		case strings.HasPrefix(strings.ToLower(t), "geoip:"):
			b.skip(cur, line, t, HydraSkipGeoIP)
		default:
			cidr, ok := cidrfeed.NormalizeCIDR(t)
			if !ok {
				b.skip(cur, line, t, HydraSkipInvalid)
				continue
			}
			b.add(cur, cidr, true)
		}
	}
}
