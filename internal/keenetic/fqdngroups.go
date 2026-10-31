package keenetic

import (
	"strconv"
	"strings"

	"wayhop/internal/cidrfeed"
)

// fqdngroups.go reads KeeneticOS's own routing lists, the `object-group fqdn` blocks of a
// `show running-config`, so a router that already routes by them can carry them into WayHop. Pure
// parser; the ndmc read that feeds it lives in the server, and nothing here writes NDM.
//
// The shape, read from a live router (its prefixes swapped for documentation ones):
//
//	object-group fqdn domain-list7
//	    description Telegram
//	    include 192.0.2.0/23
//	    include 198.51.100.0/22
//	!
//	dns-proxy
//	    route object-group domain-list8 PPPoE0 auto reject
//
// A group mixes names and IPv4 prefixes freely (on that router: Google 169 names, Telegram 5 names
// and 29 prefixes, IP_List 178 prefixes and nothing else). The group itself says nothing about where
// its traffic goes; that is the `route object-group` line under the top-level `dns-proxy` block.

// FQDNGroup is one `object-group fqdn` block.
type FQDNGroup struct {
	Name        string // NDM name, e.g. "domain-list7"
	Description string // decoded `description`; "" when the group has none
	Domains     []string
	CIDRs       []string // masked prefixes; a bare address becomes /32 or /128
	// Excludes are the `exclude` lines as written. A WayHop routing list has no exclusion, so they are
	// reported for the operator to see and never folded into Domains.
	Excludes []string
	// Skipped are the `include` values that are neither a usable name nor an address or prefix.
	Skipped []string
	// Route is the interface `dns-proxy` routes this group by ("PPPoE0"), "" when NDM routes it nowhere.
	Route string
}

// ParseFQDNGroups reads every `object-group fqdn` block of a running-config, in the order NDM printed
// them, each with the interface its `dns-proxy` route names.
func ParseFQDNGroups(runningConfig string) []FQDNGroup {
	var groups []FQDNGroup
	routes := map[string]string{}
	var cur *FQDNGroup
	seen := map[string]bool{}
	inDNSProxy := false
	flush := func() {
		if cur != nil {
			groups = append(groups, *cur)
			cur = nil
		}
	}
	for _, raw := range strings.Split(runningConfig, "\n") {
		line := strings.TrimRight(raw, "\r")
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		// A block opens at column 0 and its body is indented, so any unindented line (the "!" that
		// NDM prints between blocks included) ends the one before it.
		if line[0] != ' ' && line[0] != '\t' {
			flush()
			inDNSProxy = t == "dns-proxy"
			if name, ok := strings.CutPrefix(t, "object-group fqdn "); ok {
				cur = &FQDNGroup{Name: ndmUnquote(name)}
				seen = map[string]bool{}
			}
			continue
		}
		switch {
		case cur != nil:
			// NDM separates with one space; a hand-edited or pasted config may use a tab, and a line read
			// with the wrong separator vanished from both the entries and the skipped ones.
			keyword, arg := t, ""
			if i := strings.IndexAny(t, " \t"); i >= 0 {
				keyword, arg = t[:i], strings.TrimSpace(t[i+1:])
			}
			arg = ndmUnquote(arg)
			switch keyword {
			case "description":
				cur.Description = arg
			case "include":
				cur.addInclude(arg, seen)
			case "exclude":
				if arg != "" {
					cur.Excludes = append(cur.Excludes, arg)
				}
			default:
				// A directive this reader does not know is said, not dropped: the import promises that
				// nothing in a group goes missing silently.
				cur.Skipped = append(cur.Skipped, t)
			}
		case inDNSProxy:
			// route object-group <group> <interface> [auto] [reject]
			f := strings.Fields(t)
			if len(f) >= 4 && f[0] == "route" && f[1] == "object-group" {
				if _, dup := routes[f[2]]; !dup {
					routes[f[2]] = f[3]
				}
			}
		}
	}
	flush()
	for i := range groups {
		groups[i].Route = routes[groups[i].Name]
	}
	return groups
}

// addInclude files one `include` value as a prefix, an address, or a name, and anything else as
// skipped. A repeat of something already filed is dropped.
func (g *FQDNGroup) addInclude(v string, seen map[string]bool) {
	if v == "" {
		return
	}
	// The same two tests a fed list passes, so an imported group carries one spelling per network
	// ("192.0.2.7" is "192.0.2.7/32") and no name the resolver plane would drop.
	if cidr, ok := cidrfeed.NormalizeCIDR(v); ok {
		if !seen[cidr] {
			seen[cidr] = true
			g.CIDRs = append(g.CIDRs, cidr)
		}
		return
	}
	name := strings.ToLower(strings.TrimSuffix(v, "."))
	if !cidrfeed.ValidDomain(name) {
		g.Skipped = append(g.Skipped, v)
		return
	}
	if !seen[name] {
		seen[name] = true
		g.Domains = append(g.Domains, name)
	}
}

// ndmUnquote reads one string argument the way `show running-config` prints it. A plain word is
// returned as is. A quoted one has its quotes removed and its escapes decoded: measured on a live
// router, NDM prints every non-ASCII byte as \xHH (`description "\xd0\x9c\xd0\xb0..."` is the UTF-8
// of "Ма..."). An escaped backslash or quote is read the same C way; any other backslash is kept as
// written rather than guessed at. Bytes that do not form UTF-8 become U+FFFD, so a broken
// description can still be shown.
func ndmUnquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return s
	}
	in := s[1 : len(s)-1]
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		c := in[i]
		if c != '\\' || i+1 == len(in) {
			out = append(out, c)
			continue
		}
		switch next := in[i+1]; {
		case next == 'x' && i+3 < len(in):
			if b, err := strconv.ParseUint(in[i+2:i+4], 16, 8); err == nil {
				out = append(out, byte(b))
				i += 3
				continue
			}
			out = append(out, c)
		case next == '\\' || next == '"':
			out = append(out, next)
			i++
		default:
			out = append(out, c)
		}
	}
	return strings.ToValidUTF8(string(out), "\uFFFD")
}
