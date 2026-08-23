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
	// The header described strict order whatever the setting, and this file is read on the router with
	// no panel beside it: someone finding it in /opt/etc/dnsmasq.d would take "tunnel primaries are
	// tried first" for how their router behaves. Without the directive dnsmasq asks every upstream at
	// once and keeps the first reply - which can be the plaintext WAN one while an encrypted tunnel
	// resolver is up, the opposite of what the tier order promises. So the header describes the file
	// it is actually in.
	if nd.StrictOrder {
		b.WriteString("# strict-order => tunnel primaries are tried first; the geo-fallback only when they are down.\n")
		b.WriteString("strict-order\n")
	} else {
		b.WriteString("# Order below is configuration order only: with no strict-order directive dnsmasq asks\n")
		b.WriteString("# every upstream at once and keeps the first reply, which may be the WAN one even while\n")
		b.WriteString("# a tunnel resolver is up.\n")
	}
	if nd.NoResolv {
		b.WriteString("no-resolv\n")
	}
	// Loopback-port bookkeeping. An ADOPTED DoH resolver carries its real https-dns-proxy port in
	// Port (ReadDnsmasqD sets it); a KindLocal forward carries its own port. A NEW DoH added in the
	// UI has no port yet (Port==0) and is assigned a synthetic loopback port from a counter starting
	// at 5053 — which must dodge EVERY already-claimed port, else two `server=127.0.0.1#PORT` lines
	// would target the same port and silently forward one query to the wrong proxy/resolver. So
	// pre-collect all explicit loopback ports (KindLocal + adopted DoH) up front — either emission
	// order can collide.
	used := map[int]bool{}
	for _, r := range nd.Resolvers {
		if (r.Kind == KindLocal || r.Kind == KindDoH) && r.Port != 0 {
			used[r.Port] = true
		}
	}
	port := 5053
	for _, r := range nd.Resolvers {
		switch r.Kind {
		case KindDoH:
			// Adopted DoH: re-emit the captured proxy port verbatim so the loopback ref still targets
			// the SAME running https-dns-proxy. New DoH (Port==0): synthesize the next free port for a
			// to-be-provisioned proxy.
			p := r.Port
			if p == 0 {
				for used[port] {
					port++
				}
				p = port
				port++
			}
			b.WriteString(fmt.Sprintf("server=127.0.0.1#%d\n", p))
		case KindLocal:
			// A loopback FORWARD the reader produced (server=127.0.0.1#PORT to a local resolver, or a
			// DoH proxy whose argv wasn't captured) MUST round-trip — dropping it silently deletes that
			// DNS upstream on an adopt→edit→write-back. Only a portless KindLocal means "dnsmasq itself
			// is the resolver, nothing to forward".
			if r.Port != 0 {
				b.WriteString(fmt.Sprintf("server=127.0.0.1#%d\n", r.Port))
			}
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
		// Snapshot the PRISTINE original only once: guard with `[ -f ….bak-wayhop ]` so a
		// second apply (adopt → edit → re-apply) does not overwrite the good backup with the
		// already-WayHop-modified file and lose the true original. Mirrors StageSingboxConfig's
		// "re-staging keeps the FIRST snapshot" rule; .bak-wayhop is the only restore artifact.
		"[ -f " + path + ".bak-wayhop ] || cp -p " + path + " " + path + ".bak-wayhop",
		"# (caller writes the rendered content to " + path + ")",
		"/opt/etc/init.d/S56dnsmasq restart",
	}
}
