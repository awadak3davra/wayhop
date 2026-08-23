package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"

	"wayhop/internal/model"
)

// dohResolvers maps the IP of a well-known public DNS-over-HTTPS / DNS-over-TLS resolver to its
// provider. A LAN client opening a :443 (DoH) or :853 (DoT) connection to one of these is almost
// certainly resolving names itself instead of through the router — so the router never sees the
// query and a domain-based routing rule can't fire for that client (the dominant "it doesn't
// work" root cause). Keys are canonical (net.IP.String()) so v6 forms compare regardless of how
// conntrack prints them.
//
// It is NOT exhaustive and cannot be. Anycast providers rotate, and the gap is wider than the
// obvious one: stock Firefox's default DoH host, mozilla.cloudflare-dns.com, resolves to Cloudflare
// anycast addresses (measured 2026-08: 172.64.41.4, 162.159.61.4) — Cloudflare, and not one of the
// 1.1.1.1 entries below. That is why the pass wording states its scope and why a :853 connection
// counts without appearing here at all: on the one port where the protocol is unambiguous, this list
// is not the evidence.
var dohResolvers = map[string]string{
	"1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "1.1.1.2": "Cloudflare", "1.0.0.2": "Cloudflare",
	"2606:4700:4700::1111": "Cloudflare", "2606:4700:4700::1001": "Cloudflare",
	"8.8.8.8": "Google", "8.8.4.4": "Google",
	"2001:4860:4860::8888": "Google", "2001:4860:4860::8844": "Google",
	"9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "9.9.9.11": "Quad9",
	"2620:fe::fe": "Quad9", "2620:fe::9": "Quad9",
	"94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
	"2a10:50c0::ad1:ff": "AdGuard", "2a10:50c0::ad2:ff": "AdGuard",
	"208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
}

// detectDoHClients scans the connection table for LAN clients talking to a known public DoH/DoT
// resolver (on :443 or :853) and returns one human line per (client, provider), deduped and in
// first-seen order, with the DHCP hostname when known. Pure (conns + leases passed in) for tests.
// mine is the set of addresses the ROUTER itself holds. A flow that starts at one of them is the
// router's own traffic, not a client's, and the difference is the whole claim: this row is titled
// "LAN clients use the router's DNS".
//
// Measured on a live AX3000T before this existed. WayHop's own secure default resolves over
// DoH to 1.1.1.1, riding the tunnel — so conntrack carried `src=10.0.0.30 dst=1.1.1.1 dport=443`, and
// 10.0.0.30 is the router's address on its own awg0 device. The check reported the ROUTER as a LAN
// client bypassing the router, and the row's fix text told the operator to disable DoH on that device
// or block the resolver in Routing: advice that, followed, breaks the router's own encrypted DNS.
// Returns one line per (client, resolver) PAIR — the evidence the operator needs — plus the number
// of distinct CLIENTS, which is a different number and the one the summary sentence claims.
// Measured on a live Keenetic: one phone talking to both Google and AdGuard produced two
// lines, and the row said "2 client(s) may be bypassing the router's DNS", with the same address
// printed twice in the detail directly underneath. A count of devices is what an operator acts on —
// it decides how many gadgets they go and reconfigure.
func detectDoHClients(conns []Conn, leases map[string]string, mine map[string]bool) ([]string, int) {
	type key struct{ client, provider string }
	seen := map[key]bool{}
	var order []key
	for _, c := range conns {
		// Canonicalise the SOURCE for exactly the reason the destination is canonicalised below, and
		// this half was missing: conntrack writes IPv6 expanded (2001:0db8:0003:0000:...:0a21:24be)
		// while net.InterfaceAddrs reports it compressed (2001:db8:3::a21:24be), so the string lookup
		// never matched and the router's own address was not recognised as its own. Measured on the
		// operator's Keenetic: the row read "1 client may be bypassing the router's DNS (DoH/DoT)"
		// and named the router, whose encrypted resolver reaching AdGuard and Google is the
		// configured behaviour, not a bypass. A false positive here is worse than a miss: it is the
		// row an operator would act on by hunting a device that does not exist.
		src := c.Src
		if ip := net.ParseIP(src); ip != nil {
			src = ip.String()
		}
		if mine[src] {
			continue // the router talking to its own upstream resolver is not a client bypassing it
		}
		if c.Dport != 443 && c.Dport != 853 {
			continue
		}
		dst := c.Dst
		if ip := net.ParseIP(dst); ip != nil {
			dst = ip.String() // canonicalise so v6 forms match the map keys
		}
		prov, known := dohResolvers[dst]
		if !known {
			// Port 853 is IANA-assigned to DNS-over-TLS: the port IS the evidence, whoever the peer
			// is. Requiring a list hit on top of it threw away the one signal here that does not
			// depend on a hand-written map being complete — a client on NextDNS, ControlD, Mullvad,
			// dns.sb or a self-hosted resolver was dropped and the row reported a clean result.
			//
			// :443 keeps needing the list, and that asymmetry is deliberate: DoH is indistinguishable
			// from ordinary HTTPS by port alone, so flagging every unlisted HTTPS peer would flag the
			// whole web and the row would mean nothing.
			if c.Dport != 853 {
				continue
			}
			prov = "unknown resolver " + dst
		}
		k := key{client: src, provider: prov}
		if !seen[k] {
			seen[k] = true
			order = append(order, k)
		}
	}
	out := make([]string, 0, len(order))
	clients := map[string]bool{}
	for _, k := range order {
		clients[k.client] = true
		label := k.client
		if name := leases[k.client]; name != "" {
			label = name + " (" + k.client + ")"
		}
		out = append(out, label+" → "+k.provider)
	}
	return out, len(clients)
}

// routerAddrs is every address this router holds, canonicalised the way conntrack prints them.
//
// Read from the interfaces rather than from configuration: the address that produced the false
// positive was on an `awg0` device the panel created at Apply, not something anybody had written down,
// and a list of "the addresses we think we have" would have missed exactly that one. A failure here
// returns an empty set, which is the pre-fix behaviour — noisier, never quieter.
func routerAddrs() map[string]bool {
	out := map[string]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		switch v := a.(type) {
		case *net.IPNet:
			out[v.IP.String()] = true
		case *net.IPAddr:
			out[v.IP.String()] = true
		}
	}
	return out
}

// dnsBypassPassSummary is the sentence a clean result prints. It is a function rather than a literal
// buried in a branch so its wording can be asserted: this row is the operator's evidence that
// domain-based routing reaches every client, and a negative result here means only "nothing matched
// what this check can see".
func dnsBypassPassSummary() string {
	return fmt.Sprintf("no DoT (:853) connection, and no client talking to one of the %d known public "+
		"DoH addresses — a DoH endpoint outside that list cannot be detected this way", len(dohResolvers))
}

// dnsBypassCheck is a Diagnostics-battery probe: it flags LAN clients seen using their own public
// DoH/DoT resolver, which silently bypasses the router's DNS so domain-based rules never apply to
// them. Read-only; degrades to a warn off-Linux (no conntrack table).
func (s *Server) dnsBypassCheck(_ context.Context) healthRow {
	row := healthRow{ID: "dns-bypass", Label: "LAN clients use the router's DNS"}
	data, err := os.ReadFile("/proc/net/nf_conntrack")
	if err != nil {
		row.Status, row.Summary = "na", "this host has no connection table to read"
		return row
	}
	found, clients := detectDoHClients(parseConntrack(string(data)), readLeases(), routerAddrs())
	if len(found) == 0 {
		// Catching nobody is not the same as nobody being able to. If the profile routes domains and
		// the door is open, say so instead of passing on a promise this router cannot keep.
		//
		// The lists come from what is SAVED (that is what the operator sees on the Routing page), but
		// whether the door is shut comes from what was APPLIED. A first cut read both from the saved
		// profile and reported a clean row on a router whose saved dns.intercept was true while the
		// kernel carried no redirect at all — the setting had never been applied. Reading the promise
		// from one state and the enforcement from another is the whole point: a saved intention is
		// not a closed door.
		if st, sum, fx := s.interceptGapRow(); st != "" {
			row.Status, row.Summary, row.Fix = st, sum, fx
			return row
		}
		row.Status, row.Summary = "pass", dnsBypassPassSummary()
		return row
	}
	row.Status = "warn"
	row.Summary = fmt.Sprintf("%s may be bypassing the router's DNS (DoH/DoT)", countWordClients(clients))
	row.Detail = strings.Join(found, "; ")
	row.Fix = "those clients resolve names themselves over encrypted DNS, so domain-based routing rules won't apply to them — disable DoH on the device, or block public DoH resolvers in Routing"
	return row
}

// dohResolver is one curated public DoH/DoT resolver with a ready-to-block host CIDR — the
// enforcement companion to dns-bypass detection: the UI can offer a one-click "block public DoH"
// routing-list from these (a block list drops the IPs on both kernel planes, forcing clients back
// to the router's DNS). Same curated list as the detection, so the two never drift.
type dohResolver struct {
	IP       string `json:"ip"`
	CIDR     string `json:"cidr"` // /32 or /128, ready to drop into a block routing-list
	Provider string `json:"provider"`
}

// dohResolverList returns the curated resolvers sorted by provider then IP, each with a host CIDR.
// Pure for unit-testing.
func dohResolverList() []dohResolver {
	out := make([]dohResolver, 0, len(dohResolvers))
	for ip, prov := range dohResolvers {
		cidr := ip + "/32"
		if p := net.ParseIP(ip); p != nil && p.To4() == nil {
			cidr = ip + "/128"
		}
		out = append(out, dohResolver{IP: ip, CIDR: cidr, Provider: prov})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Provider != out[j].Provider {
			return out[i].Provider < out[j].Provider
		}
		return out[i].IP < out[j].IP
	})
	return out
}

// handleDoHResolvers serves the curated public DoH/DoT resolver list so the UI can build a
// one-click "block public DoH" routing-list. Read-only. GET /api/dns/doh-resolvers.
func (s *Server) handleDoHResolvers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"resolvers": dohResolverList()})
}

// countWordClients keeps the singular honest — "1 client(s)" next to one address is the kind of
// detail that makes a reader doubt the number.
func countWordClients(n int) string {
	if n == 1 {
		return "1 client"
	}
	return fmt.Sprintf("%d clients", n)
}

// --- domain lists depend on the router answering DNS -------------------------------------------
//
// A routing list entry that is a DOMAIN cannot be matched by the kernel, which only sees addresses.
// It works by the router resolving the name for the client and putting the ANSWER into the kernel
// set. So the list holds exactly as long as the client asks this router. If the client resolves
// elsewhere it gets a different address for the same name — measured on a live network:
// one download host answered a different address to each of two resolvers, and
// only the second was in the set. The first leaves through the ordinary path with nothing on screen
// saying so, which is how a file download fails while the site it came from works.
//
// The check above catches a client only if it is talking to one of the curated public DoH addresses.
// That is a narrow net, and it returned "pass" on a router where interception was off entirely and
// every client was free to bypass — a pass for a promise the router had no way to keep. The state of
// the door is a fact the daemon owns, so it is reported rather than inferred from who walked through.

// domainRoutedLists names the enabled routing lists that route at least one DOMAIN. Entries that
// parse as an address or a prefix need no DNS and are not counted. Pure for unit-testing.
func domainRoutedLists(p model.Profile) []string {
	var out []string
	for _, l := range p.RoutingLists {
		if !l.Enabled {
			continue
		}
		for _, e := range l.Manual {
			e = strings.TrimSpace(e)
			if e == "" {
				continue
			}
			if net.ParseIP(e) != nil {
				continue
			}
			if _, _, err := net.ParseCIDR(e); err == nil {
				continue
			}
			name := l.Name
			if name == "" {
				name = l.ID
			}
			out = append(out, name)
			break
		}
	}
	return out
}

// interceptGapVerdict is the verdict for a router whose DNS was NOT caught being bypassed. It is a
// warn only when the profile actually promises domain routing AND interception is off: with no
// domain lists there is nothing to keep, and with interception on the promise is enforced rather
// than trusted. Pure for unit-testing.
func interceptGapVerdict(domainLists []string, interceptOn bool) (status, summary, fix string) {
	if len(domainLists) == 0 || interceptOn {
		return "", "", ""
	}
	return "warn",
		fmt.Sprintf("%s by domain, but this router does not answer clients' DNS", listsMatchPhrase(len(domainLists))),
		"those lists match addresses this router resolved; a client that asks a different resolver gets a different " +
			"address for the same name and its traffic leaves the ordinary way. Turn on DNS interception so every " +
			"client is answered here, or accept that these lists cover only the clients that ask this router."
}

// interceptGapRow is the seam where the two states meet, and it exists as a seam because the choice
// of state IS the behaviour: a gate that calls interceptGapVerdict with its own boolean cannot tell
// whether the caller read the saved profile or the applied one, and the first version of this fix
// passed such a gate while reading the wrong one.
func (s *Server) interceptGapRow() (status, summary, fix string) {
	return interceptGapVerdict(domainRoutedLists(s.store.Profile()), s.dnsInterceptApplied())
}

// dnsInterceptOn reports whether a profile asks for clients' plain DNS to be answered by this router
// whatever server they addressed. Pure: it describes an intention, not what the kernel carries.
func dnsInterceptOn(p model.Profile) bool {
	return p.DNS != nil && p.DNS.Enabled && p.DNS.Intercept
}

// dnsInterceptApplied is the same question asked of the state that is actually in force. Nothing
// applied yet means nothing is enforcing it, which is the honest answer rather than the optimistic
// one.
func (s *Server) dnsInterceptApplied() bool {
	base := s.appliedBaseline()
	// Desired is nil on a record that knows what was installed but not what was asked for. That is
	// not evidence of interception, so it reads as "not enforced" like every other unknown here.
	if base == nil || base.Desired == nil {
		return false
	}
	return dnsInterceptOn(base.Desired.Profile)
}

// listsMatchPhrase carries the subject AND its verb, because the count changes both: "1 list route
// by domain" is the kind of sentence that makes a reader distrust the number in front of it.
func listsMatchPhrase(n int) string {
	if n == 1 {
		return "1 routing list matches"
	}
	return fmt.Sprintf("%d routing lists match", n)
}
