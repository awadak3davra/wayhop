package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
)

// dohResolvers maps the IP of a well-known public DNS-over-HTTPS / DNS-over-TLS resolver to its
// provider. A LAN client opening a :443 (DoH) or :853 (DoT) connection to one of these is almost
// certainly resolving names itself instead of through the router — so the router never sees the
// query and a domain-based routing rule can't fire for that client (the dominant "it doesn't
// work" root cause). Keys are canonical (net.IP.String()) so v6 forms compare regardless of how
// conntrack prints them. Not exhaustive (anycast providers like NextDNS rotate) — best-effort.
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
func detectDoHClients(conns []Conn, leases map[string]string) []string {
	type key struct{ client, provider string }
	seen := map[key]bool{}
	var order []key
	for _, c := range conns {
		if c.Dport != 443 && c.Dport != 853 {
			continue
		}
		dst := c.Dst
		if ip := net.ParseIP(dst); ip != nil {
			dst = ip.String() // canonicalise so v6 forms match the map keys
		}
		prov, ok := dohResolvers[dst]
		if !ok {
			continue
		}
		k := key{client: c.Src, provider: prov}
		if !seen[k] {
			seen[k] = true
			order = append(order, k)
		}
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		label := k.client
		if name := leases[k.client]; name != "" {
			label = name + " (" + k.client + ")"
		}
		out = append(out, label+" → "+k.provider)
	}
	return out
}

// dnsBypassCheck is a Diagnostics-battery probe: it flags LAN clients seen using their own public
// DoH/DoT resolver, which silently bypasses the router's DNS so domain-based rules never apply to
// them. Read-only; degrades to a warn off-Linux (no conntrack table).
func (s *Server) dnsBypassCheck(_ context.Context) healthRow {
	row := healthRow{ID: "dns-bypass", Label: "LAN clients use the router's DNS"}
	data, err := os.ReadFile("/proc/net/nf_conntrack")
	if err != nil {
		row.Status, row.Summary = "warn", "can't read the connection table (non-Linux?)"
		return row
	}
	found := detectDoHClients(parseConntrack(string(data)), readLeases())
	if len(found) == 0 {
		row.Status, row.Summary = "pass", "no client seen using a public DoH/DoT resolver"
		return row
	}
	row.Status = "warn"
	row.Summary = fmt.Sprintf("%d client(s) may be bypassing the router's DNS (DoH/DoT)", len(found))
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
