package dnscheck

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

// ConnFlow is the original direction of one connection-table entry. Replied records whether the
// reverse direction carried packets; an unanswered flow still proves where the lookup was sent.
type ConnFlow struct {
	Proto   string
	Src     string
	Dst     string
	Sport   int
	Dport   int
	Replied bool
}

type connFlowKey struct {
	proto        string
	src, dst     string
	sport, dport int
}

func (f ConnFlow) key() connFlowKey {
	return connFlowKey{proto: f.Proto, src: f.Src, dst: f.Dst, sport: f.Sport, dport: f.Dport}
}

// ParseConntrack reads both /proc/net/nf_conntrack and conntrack -L lines. Only the original
// direction's DNS destinations are returned; the reverse tuple is used solely to detect a reply.
func ParseConntrack(text string) []ConnFlow {
	var out []ConnFlow
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		proto := ""
		switch {
		case fields[0] == "udp" || fields[0] == "tcp":
			proto = fields[0]
		case len(fields) > 2 && (fields[0] == "ipv4" || fields[0] == "ipv6") &&
			(fields[2] == "udp" || fields[2] == "tcp"):
			proto = fields[2]
		default:
			continue
		}

		var f ConnFlow
		f.Proto = proto
		direction := 0
		unreplied, assured := false, false
		replyPackets, sawReplyPackets := 0, false
		valid := true
		for _, tok := range fields {
			switch tok {
			case "[UNREPLIED]":
				unreplied = true
			case "[ASSURED]":
				assured = true
			}
			key, value, ok := strings.Cut(tok, "=")
			if !ok {
				continue
			}
			switch key {
			case "src":
				direction++
				if direction == 1 {
					f.Src = canonicalIP(value)
					valid = valid && f.Src != ""
				}
			case "dst":
				if direction == 1 {
					f.Dst = canonicalIP(value)
					valid = valid && f.Dst != ""
				}
			case "sport":
				if direction == 1 {
					n, err := strconv.Atoi(value)
					valid = valid && err == nil && n > 0 && n <= 65535
					f.Sport = n
				}
			case "dport":
				if direction == 1 {
					n, err := strconv.Atoi(value)
					valid = valid && err == nil
					f.Dport = n
				}
			case "packets":
				if direction >= 2 {
					n, err := strconv.Atoi(value)
					if err == nil {
						replyPackets += n
						sawReplyPackets = true
					}
				}
			}
		}
		if !valid || f.Src == "" || f.Dst == "" || f.Sport == 0 || (f.Dport != 53 && f.Dport != 853) {
			continue
		}
		// Old conntrack tools may omit reverse packet counters. A reverse tuple without UNREPLIED (or
		// ASSURED) is still evidence of a reply there; explicit zero counters are not.
		f.Replied = !unreplied && (replyPackets > 0 || assured || (direction >= 2 && !sawReplyPackets))
		out = append(out, f)
	}
	return out
}

func canonicalIP(s string) string {
	if i := strings.LastIndexByte(s, '%'); i >= 0 {
		s = s[:i]
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	return ip.String()
}

// DiffFlows returns entries in after whose protocol and four-tuple were not present in before.
func DiffFlows(before, after []ConnFlow) []ConnFlow {
	old := make(map[connFlowKey]bool, len(before))
	for _, f := range before {
		old[f.key()] = true
	}
	seen := map[connFlowKey]bool{}
	var out []ConnFlow
	for _, f := range after {
		key := f.key()
		if old[key] || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// SummarizeFlows keeps the router's own lookups and groups them by egress and resolver. addressListing
// is ip -o addr output: a client's source is not made a router lookup merely by passing through NAT.
func SummarizeFlows(flows []ConnFlow, addressListing string, tunnels map[string]bool, canary []ConnFlow) []Flow {
	own := routerAddresses(addressListing)
	canaryKeys := make(map[connFlowKey]bool, len(canary))
	for _, f := range canary {
		canaryKeys[f.key()] = true
	}
	type aggregate struct {
		flow     Flow
		seenKeys map[connFlowKey]bool
	}
	groups := map[string]*aggregate{}
	for _, f := range flows {
		iface, ok := own[f.Src]
		if !ok {
			continue
		}
		if iface == "lo" {
			continue // the router asking its own listener is not a way out
		}
		kind := PathWAN
		if tunnels[iface] {
			kind = PathTunnel
		} else if strings.HasPrefix(iface, "br") {
			if ip := net.ParseIP(f.Dst); ip != nil && ip.IsPrivate() {
				kind = PathRouter
			}
		}
		key := strings.Join([]string{iface, string(kind), f.Dst, strconv.Itoa(f.Dport), f.Proto}, "\x00")
		g := groups[key]
		if g == nil {
			g = &aggregate{flow: Flow{
				Iface: iface, Kind: kind, Server: f.Dst, Port: f.Dport, Proto: f.Proto,
			}, seenKeys: map[connFlowKey]bool{}}
			groups[key] = g
		}
		flowKey := f.key()
		if !g.seenKeys[flowKey] {
			g.seenKeys[flowKey] = true
			g.flow.Flows++
			if f.Replied {
				g.flow.Replied++
			}
		}
		g.flow.FromCanary = g.flow.FromCanary || canaryKeys[flowKey]
	}
	out := make([]Flow, 0, len(groups))
	for _, g := range groups {
		out = append(out, g.flow)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Iface != b.Iface {
			return a.Iface < b.Iface
		}
		if a.Server != b.Server {
			return a.Server < b.Server
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Proto < b.Proto
	})
	return out
}

func routerAddresses(out string) map[string]string {
	addrs := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		iface := strings.TrimSuffix(fields[1], ":")
		if i := strings.IndexByte(iface, '@'); i >= 0 {
			iface = iface[:i]
		}
		for i := 2; i+1 < len(fields); i++ {
			if fields[i] != "inet" && fields[i] != "inet6" {
				continue
			}
			addr := fields[i+1]
			if j := strings.IndexByte(addr, '/'); j >= 0 {
				addr = addr[:j]
			}
			if ip := canonicalIP(addr); ip != "" && iface != "" {
				addrs[ip] = iface
			}
		}
	}
	return addrs
}
