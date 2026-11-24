package server

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"wayhop/internal/clash"
	"wayhop/internal/generator"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// traceConn is one live connection to a traced domain's IP, with the egress it actually took.
// Domain is the sniffed SNI/host when the connection was found via the clash view (vs only by IP).
type traceConn struct {
	Dst       string `json:"dst"`
	Domain    string `json:"domain,omitempty"`
	Exit      string `json:"exit,omitempty"`
	Dport     int    `json:"dport"`
	UpBytes   int64  `json:"up_bytes"`
	DownBytes int64  `json:"down_bytes"`
	State     string `json:"state,omitempty"`
}

// traceCandidate is a configured rule / list / kernel-zone that references the traced domain or
// one of its IPs. NOT a definitive verdict: cross-plane precedence is mode-dependent, so this lists
// what COULD route the domain (top-to-bottom on the sing-box plane; a kernel carve-out takes a
// matching IP first in fast/hybrid). The live Connections are the ground truth.
type traceCandidate struct {
	Kind     string `json:"kind"` // rule | list | kernel-zone
	ID       string `json:"id"`
	Why      string `json:"why"`
	Outbound string `json:"outbound"`
}

// traceResult is the per-domain explain: the domain's current IPs, the live connections to them
// and the exit each took (ground truth, from the connection table — no prediction, so it can't lie
// about the real exit), plus the configured candidates that reference the domain/IPs.
type traceResult struct {
	Domain       string           `json:"domain"`
	IPs          []string         `json:"ips"`
	Connections  []traceConn      `json:"connections"`
	Exits        map[string]int   `json:"exits"` // exit tag -> connection count
	Configured   []traceCandidate `json:"configured,omitempty"`
	Unevaluated  []traceCandidate `json:"unevaluated,omitempty"` // geo/remote-set rules/lists that MAY also match (can't be checked statically)
	ResolveError string           `json:"resolve_error,omitempty"`
	Note         string           `json:"note,omitempty"`
}

// validTraceDomain accepts a hostname or IP literal (the chars net.LookupHost needs); it is a
// syscall, not a shell, so this only screens out garbage/abuse, not injection.
func validTraceDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	for _, r := range d {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_', r == ':':
		default:
			return false
		}
	}
	return true
}

// traceExitCore labels a flow the core terminated whose route the core did not report (its API is
// down, or the flow closed between the two reads). Never "direct": the core decided where it went.
const traceExitCore = "core"

// traceExitRouter labels a flow the router itself answered (a redirect to its own DNS).
const traceExitRouter = "router"

// traceLabels is what tells a conntrack row's real exit.
//   - markExit: a flow the kernel routes (not redirected: a plain or pinned flow) leaves by its mark's
//     egress; this covers fast mode's resolver-fed names (their mark is saved to the connmark like a
//     static list's) and hybrid's kernel carve-outs.
//   - localIface: the router's own addresses (loopback included) and the device each is on. A LAN
//     flow whose reply comes from one of them was redirected into the core (auto_redirect: the reply
//     source is 127.0.0.1 or the LAN address, at the core's redirect port), so its mark says nothing:
//     the core chose the outbound. A flow whose SOURCE is the router's is the router's own leg (the
//     core's outbound socket bound to a tunnel, a probe): it leaves by the device that owns its source
//     address.
//   - coreRoute: the core's outbound chain per client "ip:port" (its /connections), for the flows it
//     terminates. nil when the core is not running or not asked. coreFetch, when set, fills it on
//     the first row that needs it, so a table with no such row never asks the core.
//   - ifaceExit: the egress tag that owns a device ("" none: the provider's side).
type traceLabels struct {
	markExit   func(uint32) string
	localIface func(addr string) (iface string, local bool)
	coreRoute  map[string]string
	coreFetch  func() map[string]string
	ifaceExit  map[string]string
	// routed is the large lists' tables (fast mode): an unmarked flow to one of their addresses
	// left by that list's egress (fastdns_routed.go).
	routed *routedIndex
	// mask and coreMark tell a flow the core's TUN carries: its connmark outside the plan's mask is
	// the auto_redirect input mark (UDP and ICMP, whose reply still comes from the far side).
	mask, coreMark uint32
}

// exitOf is the exit a conntrack row took.
func (l *traceLabels) exitOf(c *Conn) string {
	if l.localIface != nil {
		if c.ReplySrc != "" && c.ReplySrc != c.Dst {
			if _, local := l.localIface(c.ReplySrc); local && c.ReplySport != 0 && c.ReplySport == c.Dport {
				// Redirected to the router on the same port: its own service (the DNS redirect to
				// dnsmasq on :53), not the core, whose redirect port differs.
				return traceExitRouter
			}
			if _, local := l.localIface(c.ReplySrc); local {
				if l.coreRoute == nil && l.coreFetch != nil {
					l.coreRoute, l.coreFetch = l.coreFetch(), nil
				}
				if route := l.coreRoute[flowKey(c.Src, strconv.Itoa(c.Sport))]; route != "" {
					return route
				}
				return traceExitCore
			}
		}
		if iface, local := l.localIface(c.Src); local {
			if tag := l.ifaceExit[iface]; tag != "" {
				return tag
			}
			return model.OutboundDirect
		}
	}
	// The core's TUN carries it (UDP): its route, as for a redirected flow.
	if l.coreMark != 0 && c.Mark&^l.mask == l.coreMark {
		if l.coreRoute == nil && l.coreFetch != nil {
			l.coreRoute, l.coreFetch = l.coreFetch(), nil
		}
		if route := l.coreRoute[flowKey(c.Src, strconv.Itoa(c.Sport))]; route != "" {
			return route
		}
		return traceExitCore
	}
	if tag := l.routed.lookup(c.Dst, c.Mark); tag != "" {
		return tag
	}
	return l.markExit(c.Mark)
}

// connLabels is the exit attribution the trace and the Dashboard share (traceLabels): the installed
// plan's marks and devices, the router's addresses read now, and the core's routes from coreFetch
// (nil: none), asked only when a row the core terminated needs them.
func (s *Server) connLabels(coreFetch func() map[string]string) traceLabels {
	plan := s.installedKernelPlan()
	_, remote, _ := s.planRemote(plan)
	labels := traceLabels{markExit: s.markExitResolver(), localIface: localIfaceFrom(routerAddrIfaces()),
		coreFetch: coreFetch, ifaceExit: ifaceExits(plan), routed: newRoutedIndex(plan, remote),
		coreMark: generator.AutoRedirectInputMark}
	if plan != nil {
		labels.mask = plan.Mask
	}
	return labels
}

// coreRoutes indexes the core's connections by client "ip:port", each with its chain as the trace
// prints it (outbound first, then the groups that chose it).
func coreRoutes(conns []clash.Conn) map[string]string {
	out := make(map[string]string, len(conns))
	for i := range conns {
		m := conns[i].Metadata
		if m.SourceIP == "" || m.SourcePort == "" || len(conns[i].Chains) == 0 {
			continue
		}
		out[flowKey(m.SourceIP, m.SourcePort)] = strings.Join(conns[i].Chains, "→")
	}
	return out
}

// flowKey is a client "ip:port" in one spelling: conntrack's proc file writes IPv6 in full, the
// core compressed.
func flowKey(ip, port string) string {
	return net.JoinHostPort(canonIP(ip), port)
}

// ifaceExits maps each kernel device of the plan's tunnel egresses to the egress's tag.
func ifaceExits(plan *pbr.Plan) map[string]string {
	out := map[string]string{}
	if plan == nil {
		return out
	}
	for _, e := range plan.Egresses {
		if e.Kind != pbr.EgressInterface {
			continue
		}
		for _, d := range e.Devices() {
			if _, ok := out[d]; !ok {
				out[d] = e.Tag
			}
		}
	}
	return out
}

// routerAddrIfaces is the router's own addresses by device, read when a trace needs them. A variable for
// tests.
var routerAddrIfaces = func() map[string]string {
	out := map[string]string{}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				out[p.Addr().Unmap().String()] = ifc.Name
			}
		}
	}
	return out
}

// localIfaceFrom answers traceLabels.localIface from an address -> device map; loopback is always
// the router's.
func localIfaceFrom(addrs map[string]string) func(string) (string, bool) {
	return func(addr string) (string, bool) {
		a, err := netip.ParseAddr(addr)
		if err != nil {
			return "", false
		}
		a = a.Unmap()
		if a.IsLoopback() {
			return "lo", true
		}
		iface, ok := addrs[a.String()]
		return iface, ok
	}
}

// traceConnections matches conntrack rows against the domain's resolved IPs and reports each with
// its exit (traceLabels) + a per-exit tally. Pure (deps passed in) for unit-testing. A device using
// its own DNS may have connected to different IPs than the router resolves now — hence the note when
// nothing matches.
func traceConnections(domain string, ips []string, conns []Conn, labels traceLabels) traceResult {
	ipset := make(map[string]bool, len(ips))
	for _, ip := range ips {
		ipset[canonIP(ip)] = true
	}
	res := traceResult{Domain: domain, IPs: ips, Exits: map[string]int{}}
	for i := range conns {
		c := &conns[i]
		if !ipset[canonIP(c.Dst)] {
			continue
		}
		exit := labels.exitOf(c)
		res.Connections = append(res.Connections, traceConn{Dst: c.Dst, Exit: exit, Dport: c.Dport, UpBytes: c.UpBytes, DownBytes: c.DownBytes, State: c.State})
		res.Exits[exit]++
	}
	if len(res.Connections) == 0 {
		res.Note = "no active connection to this domain's current IPs — open it on a device and trace again to see its live exit (a device using its own DNS/DoH may resolve to different IPs; see the DNS-bypass check)"
	}
	return res
}

// parseAddrs parses resolved IP strings into netip.Addr, dropping any that don't parse.
func parseAddrs(ipStrs []string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ipStrs))
	for _, s := range ipStrs {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a)
		}
	}
	return out
}

// ipInCIDRs returns the first CIDR/IP entry that covers any of ips (or "" if none). Each entry may
// be a prefix ("10.0.0.0/8") or a bare IP ("1.2.3.4").
func ipInCIDRs(ips []netip.Addr, entries []string) string {
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if pfx, err := netip.ParsePrefix(e); err == nil {
			for _, ip := range ips {
				if pfx.Contains(ip) {
					return e
				}
			}
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil {
			for _, ip := range ips {
				if ip == a {
					return e
				}
			}
		}
	}
	return ""
}

// matchDomainIP returns a human "why" if the domain matches any exact/suffix pattern or any IP
// falls in any of the cidr entries; "" otherwise. domain_suffix uses a raw suffix match, mirroring
// sing-box.
func matchDomainIP(domain string, ips []netip.Addr, exact, suffix, cidrs []string) string {
	for _, d := range exact {
		if d = strings.TrimSpace(d); d != "" && domain == d {
			return "domain " + d
		}
	}
	for _, sfx := range suffix {
		if sfx = strings.TrimSpace(sfx); sfx != "" && strings.HasSuffix(domain, sfx) {
			return "domain_suffix " + sfx
		}
	}
	if c := ipInCIDRs(ips, cidrs); c != "" {
		return "ip ∈ " + c
	}
	return ""
}

// splitInline classifies a routing list's Manual entries into domains vs CIDR/IP literals.
func splitInline(manual []string) (domains, cidrs []string) {
	for _, e := range manual {
		t := strings.TrimSpace(e)
		if t == "" {
			continue
		}
		if _, err := netip.ParsePrefix(t); err == nil {
			cidrs = append(cidrs, t)
		} else if _, err := netip.ParseAddr(t); err == nil {
			cidrs = append(cidrs, t)
		} else {
			domains = append(domains, t)
		}
	}
	return
}

// traceCandidates lists the configured rules / inline lists / kernel zones that reference the
// domain or its IPs, plus a count of geo/remote matchers it could not evaluate here. Pure (model
// + compiled plan passed in) for unit-testing. plan is nil in tun/mixed (no kernel plane).
func traceCandidates(domain string, ipStrs []string, p *model.Profile, plan *pbr.Plan) (cands, uneval []traceCandidate) {
	ips := parseAddrs(ipStrs)
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Disabled || r.Default {
			continue
		}
		if why := matchDomainIP(domain, ips, r.Domain, r.DomainSuffix, r.IPCIDR); why != "" {
			cands = append(cands, traceCandidate{Kind: "rule", ID: r.ID, Why: why, Outbound: r.Outbound})
		} else if len(r.GeoSite) > 0 || len(r.GeoIP) > 0 {
			// A geo matcher needs the on-router dataset — NAME it (with its categories + where it'd
			// route) rather than a bare count, so the trace says WHICH rule might also match.
			uneval = append(uneval, traceCandidate{Kind: "rule", ID: r.ID, Why: geoMatcherWhy(r), Outbound: r.Outbound})
		}
	}
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if !rl.Enabled {
			continue
		}
		// The FETCHED feeds count as list contents, because they are: CIDRCache and DomainCache are
		// what the refresher wrote and what Apply turns into ipset members. Reading only Manual sent
		// every feed-backed list into "may also match (can't check statically)" — on the operator's
		// router that was four lists hedged over an address the kernel could answer for outright,
		// `ipset test` saying NOT in set for each. A trace that hedges what it can decide is the
		// question the user came with, returned unanswered.
		domains, cidrs := splitInline(rl.Manual)
		domains = append(domains, rl.DomainCache...)
		cidrs = append(cidrs, rl.CIDRCache...)
		if why := matchDomainIP(domain, ips, domains, domains, cidrs); why != "" {
			cands = append(cands, traceCandidate{Kind: "list", ID: rl.ID, Why: why, Outbound: rl.Outbound})
		} else if rl.Source != "" {
			// A .srs rule-set is the one list shape whose contents genuinely are not parsed here: it
			// is a binary sing-box artifact, not prefixes this process ever reads. A CIDR or name feed
			// no longer belongs in this branch — its cache was just evaluated above, and calling it a
			// "rule-set" named the wrong thing as well as claiming the wrong reason.
			uneval = append(uneval, traceCandidate{Kind: "list", ID: rl.ID,
				Why: "remote rule-set — its contents are a sing-box artifact, not read here", Outbound: rl.Outbound})
		} else if (rl.CIDRSource != "" && len(rl.CIDRCache) == 0) || (rl.DomainSource != "" && len(rl.DomainCache) == 0) {
			// A feed configured but never fetched holds nothing, so silence here would read as "does
			// not match" when the truth is "nothing has been downloaded yet".
			uneval = append(uneval, traceCandidate{Kind: "list", ID: rl.ID,
				Why: "feed has never been fetched — nothing to match against yet", Outbound: rl.Outbound})
		}
	}
	if plan != nil {
		for _, z := range plan.Zones {
			entries := append(append(append(append([]string{}, z.V4...), z.V6...), z.RouteV4...), z.RouteV6...)
			if c := ipInCIDRs(ips, entries); c != "" {
				cands = append(cands, traceCandidate{Kind: "kernel-zone", ID: z.Name, Why: "ip ∈ " + c, Outbound: z.EgressTag})
			}
		}
	}
	return cands, uneval
}

// geoMatcherWhy names a rule's geo matchers (its geosite/geoip categories) — the reason the trace
// can't confirm the match statically (the dataset isn't loaded here). Actionable: the user sees
// exactly which geo categories would route this rule and where.
func geoMatcherWhy(r *model.Rule) string {
	var parts []string
	if len(r.GeoSite) > 0 {
		parts = append(parts, "geosite: "+strings.Join(r.GeoSite, ", "))
	}
	if len(r.GeoIP) > 0 {
		parts = append(parts, "geoip: "+strings.Join(r.GeoIP, ", "))
	}
	return strings.Join(parts, "; ") + " — needs the on-router dataset"
}

// clashTraceMatches finds connections sing-box saw to the traced domain (by sniffed Host, so it
// catches IPs the router didn't resolve now — CDN rotation, or a client that resolved itself) and
// returns those whose dst IP isn't already covered by the conntrack pass. The exit is the clash
// chain (sing-box's own outbound path). seenDsts is updated so a repeated dst is reported once.
// Pure for unit-testing.
func clashTraceMatches(domain string, conns []clash.Conn, seenDsts map[string]bool) []traceConn {
	var out []traceConn
	for i := range conns {
		c := &conns[i]
		h := c.Metadata.Host
		if h == "" || (h != domain && !strings.HasSuffix(h, "."+domain)) {
			continue
		}
		dst := c.Metadata.DestinationIP
		if dst == "" || seenDsts[dst] {
			continue
		}
		seenDsts[dst] = true
		dport, _ := strconv.Atoi(c.Metadata.DestinationPort)
		out = append(out, traceConn{
			Dst: dst, Domain: h, Exit: strings.Join(c.Chains, "→"),
			Dport: dport, UpBytes: c.Upload, DownBytes: c.Download,
		})
	}
	return out
}

// handleTrace explains where traffic to a domain actually goes: resolve it (router's resolver),
// then show the live connections to those IPs and the exit each took. Read-only. The accurate
// half of the per-domain trace; a static "which rule should match" prediction is future work.
// GET /api/diagnostics/trace?domain=<host>.
func (s *Server) handleTrace(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if !validTraceDomain(domain) {
		writeErr(w, http.StatusBadRequest, "a valid domain is required")
		return
	}
	writeJSON(w, http.StatusOK, s.traceDomain(r.Context(), domain))
}

// traceLookupHost resolves a traced domain with the router's resolver. A variable so the speed
// test's route (speedRoute traces its site) can be tested without a live lookup.
var traceLookupHost = net.DefaultResolver.LookupHost

// traceDomain is the trace itself, shared by the Diagnostics page and the Telegram bot's /route.
// The caller has validated domain.
func (s *Server) traceDomain(parent context.Context, domain string) traceResult {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	res := traceResult{Domain: domain, Exits: map[string]int{}}
	ips, err := traceLookupHost(ctx, domain)
	switch {
	case err != nil:
		res.ResolveError = err.Error()
		res.Note = "the router could not resolve this domain (check its spelling, or the router's DNS)"
	default:
		res.IPs = ips
		// The core's view first: the route of every flow it terminates (a LAN flow redirected into
		// it carries no mark that says where it went), and the sniffed connections below.
		var core []clash.Conn
		coreOK := false
		if s.clash != nil {
			cctx, ccancel := context.WithTimeout(parent, 4*time.Second)
			if cs, cerr := s.clash.Connections(cctx); cerr == nil {
				core, coreOK = cs.Connections, true
			}
			ccancel()
		}
		if data, ferr := os.ReadFile("/proc/net/nf_conntrack"); ferr == nil {
			labels := s.connLabels(nil)
			labels.coreRoute = coreRoutes(core)
			live := traceConnections(domain, ips, parseConntrack(string(data)), labels)
			res.Connections, res.Exits, res.Note = live.Connections, live.Exits, live.Note
		} else {
			res.Note = "connection table unavailable (non-Linux?) — resolution + configured rules shown only"
		}
		// Augment with connections sing-box sniffed to this domain at IPs the resolved set missed
		// (CDN rotation / a client resolving itself). Best-effort: tun/hybrid only, clash-failure-safe.
		if coreOK {
			seen := make(map[string]bool, len(res.Connections))
			for _, c := range res.Connections {
				seen[c.Dst] = true
			}
			for _, e := range clashTraceMatches(domain, core, seen) {
				res.Connections = append(res.Connections, e)
				res.Exits[e.Exit]++
			}
		}
		if len(res.Connections) > 0 {
			res.Note = "" // found live connections (via conntrack and/or sniffed) — clear the no-match hint
		}
	}
	// Configured candidates (rules / inline lists / kernel zones) that reference the domain or its
	// IPs — computed even on a resolve error, since a domain rule can match without an IP.
	profile := s.store.Profile()
	_, plan := s.genOptionsWithPlan(&profile, s.config())
	res.Configured, res.Unevaluated = traceCandidates(domain, ips, &profile, plan)
	return res
}
