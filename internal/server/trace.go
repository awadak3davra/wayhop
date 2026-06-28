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

	"wakeroute/internal/clash"
	"wakeroute/internal/model"
	"wakeroute/internal/pbr"
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
	Unevaluated  int              `json:"unevaluated,omitempty"` // geo/remote matchers that may also match
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

// traceConnections matches conntrack rows against the domain's resolved IPs and reports each with
// its resolved exit + a per-exit tally. Pure (deps passed in) for unit-testing. A device using its
// own DNS may have connected to different IPs than the router resolves now — hence the note when
// nothing matches.
func traceConnections(domain string, ips []string, conns []Conn, markExit func(uint32) string) traceResult {
	ipset := make(map[string]bool, len(ips))
	for _, ip := range ips {
		ipset[ip] = true
	}
	res := traceResult{Domain: domain, IPs: ips, Exits: map[string]int{}}
	for i := range conns {
		c := &conns[i]
		if !ipset[c.Dst] {
			continue
		}
		exit := markExit(c.Mark)
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
func traceCandidates(domain string, ipStrs []string, p *model.Profile, plan *pbr.Plan) ([]traceCandidate, int) {
	ips := parseAddrs(ipStrs)
	var cands []traceCandidate
	unevaluated := 0
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.Disabled || r.Default {
			continue
		}
		if why := matchDomainIP(domain, ips, r.Domain, r.DomainSuffix, r.IPCIDR); why != "" {
			cands = append(cands, traceCandidate{Kind: "rule", ID: r.ID, Why: why, Outbound: r.Outbound})
		} else if len(r.GeoSite) > 0 || len(r.GeoIP) > 0 {
			unevaluated++ // a geo matcher needs the dataset — can't evaluate here
		}
	}
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if !rl.Enabled {
			continue
		}
		domains, cidrs := splitInline(rl.Manual)
		if why := matchDomainIP(domain, ips, domains, domains, cidrs); why != "" {
			cands = append(cands, traceCandidate{Kind: "list", ID: rl.ID, Why: why, Outbound: rl.Outbound})
		} else if rl.Source != "" || rl.CIDRSource != "" {
			unevaluated++ // a remote rule-set's contents aren't loaded here
		}
	}
	if plan != nil {
		for _, z := range plan.Zones {
			entries := append(append([]string{}, z.V4...), z.V6...)
			if c := ipInCIDRs(ips, entries); c != "" {
				cands = append(cands, traceCandidate{Kind: "kernel-zone", ID: z.Name, Why: "ip ∈ " + c, Outbound: z.EgressTag})
			}
		}
	}
	return cands, unevaluated
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
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	res := traceResult{Domain: domain, Exits: map[string]int{}}
	ips, err := net.DefaultResolver.LookupHost(ctx, domain)
	switch {
	case err != nil:
		res.ResolveError = err.Error()
		res.Note = "the router could not resolve this domain (check its spelling, or the router's DNS)"
	default:
		res.IPs = ips
		if data, ferr := os.ReadFile("/proc/net/nf_conntrack"); ferr == nil {
			live := traceConnections(domain, ips, parseConntrack(string(data)), s.markExitResolver())
			res.Connections, res.Exits, res.Note = live.Connections, live.Exits, live.Note
		} else {
			res.Note = "connection table unavailable (non-Linux?) — resolution + configured rules shown only"
		}
		// Augment with connections sing-box sniffed to this domain at IPs the resolved set missed
		// (CDN rotation / a client resolving itself). Best-effort: tun/hybrid only, clash-failure-safe.
		if s.clash != nil {
			cctx, ccancel := context.WithTimeout(r.Context(), 4*time.Second)
			if cs, cerr := s.clash.Connections(cctx); cerr == nil {
				seen := make(map[string]bool, len(res.Connections))
				for _, c := range res.Connections {
					seen[c.Dst] = true
				}
				for _, e := range clashTraceMatches(domain, cs.Connections, seen) {
					res.Connections = append(res.Connections, e)
					res.Exits[e.Exit]++
				}
			}
			ccancel()
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
	writeJSON(w, http.StatusOK, res)
}
