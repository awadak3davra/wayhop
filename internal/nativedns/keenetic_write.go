package nativedns

import (
	"fmt"
	"strings"
)

// RenderDnsmasqD renders a NativeDNS into the Keenetic dnsmasq.d upstream file content that recreates
// the resolver chain — the generalization of the manual Tier-3 edit. `server=` lines are emitted in
// NativeDNS order (strict-order preserves that order as the fallback chain): a plain resolver writes
// its address directly, a DoH resolver writes a loopback ref `server=127.0.0.1#PORT` to a local
// https-dns-proxy (the proxy side is set up separately), a local resolver is skipped (dnsmasq IS the
// device resolver). strict-order/no-resolv directives are emitted when set. Returns the FILE CONTENT
// only — writing it and restarting dnsmasq is a separate, user-gated step (KeeneticApplyCmds). Pure;
// the inverse of ReadDnsmasqD for the plaintext chain.
func RenderDnsmasqD(nd NativeDNS) string {
	var b strings.Builder
	b.WriteString("# WayHop-managed DNS upstreams. Tier order: VPN-encrypted -> WAN -> geo-fallback.\n")
	b.WriteString("# strict-order => tunnel primaries are tried first; the geo-fallback only when they are down.\n")
	if nd.StrictOrder {
		b.WriteString("strict-order\n")
	}
	if nd.NoResolv {
		b.WriteString("no-resolv\n")
	}
	port := 5053
	for _, r := range nd.Resolvers {
		switch r.Kind {
		case KindDoH:
			b.WriteString(fmt.Sprintf("server=127.0.0.1#%d\n", port))
			port++
		case KindLocal:
			// dnsmasq is the device resolver — nothing to forward.
		default: // plain (dot degrades to a plain forward best-effort)
			b.WriteString("server=" + serverRef(r) + "\n")
		}
	}
	return b.String()
}

// KeeneticApplyCmds are the user-gated device steps to activate a rendered dnsmasq.d file: back it up,
// (write the content — done by the caller), then restart dnsmasq. Kept separate from RenderDnsmasqD so
// the content can be previewed before the device write. NOT run by the improvement loop.
func KeeneticApplyCmds(path string) []string {
	return []string{
		"cp -p " + path + " " + path + ".bak-wayhop",
		"# (caller writes the rendered content to " + path + ")",
		"/opt/etc/init.d/S56dnsmasq restart",
	}
}
