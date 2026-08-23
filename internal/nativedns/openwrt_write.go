package nativedns

import (
	"errors"
	"fmt"
	"strings"
)

// RenderUCI renders a NativeDNS into the uci command PLAN that reconfigures the OpenWrt DNS stack:
// clear the existing https-dns-proxy instances, add one per DoH resolver (sequential loopback ports
// from 5053), point dnsmasq at those proxies (+ any plain non-fallback upstreams), set noresolv, and
// register the plaintext resolvers as doh_backup_server (the geo-fallback tier). It returns the plan
// ONLY — applying it (see UCICommitCmds: uci commit + service restart) is a separate, user-gated,
// device-mutating step. Pure; the inverse of ReadUCI.
func RenderUCI(nd NativeDNS) []string {
	var cmds []string

	// 1) Rebuild https-dns-proxy from the DoH resolvers, in order.
	cmds = append(cmds, "while uci -q delete https-dns-proxy.@https-dns-proxy[0]; do :; done")
	port := 5053
	var proxyRefs []string
	for _, r := range nd.Resolvers {
		if r.Kind != KindDoH {
			continue
		}
		cmds = append(cmds,
			"uci add https-dns-proxy https-dns-proxy",
			fmt.Sprintf("uci set https-dns-proxy.@https-dns-proxy[-1].resolver_url='%s'", r.Address),
			"uci set https-dns-proxy.@https-dns-proxy[-1].listen_addr='127.0.0.1'",
			fmt.Sprintf("uci set https-dns-proxy.@https-dns-proxy[-1].listen_port='%d'", port),
		)
		proxyRefs = append(proxyRefs, fmt.Sprintf("127.0.0.1#%d", port))
		port++
	}

	// 2) dnsmasq: noresolv + server list (proxy refs + plain non-fallback upstreams) + doh_backup_server
	// (the plaintext geo-fallback tier).
	cmds = append(cmds, uciSetBool("dhcp.@dnsmasq[0].noresolv", nd.NoResolv))
	// Written for the same reason it is now read: without it the tier order below is decoration,
	// because dnsmasq queries every upstream at once and answers with whichever replies first - which
	// can be the plaintext WAN one while an encrypted tunnel resolver is up.
	cmds = append(cmds, uciSetBool("dhcp.@dnsmasq[0].strictorder", nd.StrictOrder))
	cmds = append(cmds, "uci -q delete dhcp.@dnsmasq[0].server")
	servers := append([]string{}, proxyRefs...)
	var backups []string
	for _, r := range nd.Resolvers {
		switch r.Kind {
		case KindPlain:
			if r.Tier == TierFallback {
				// A plain fallback resolver normally lands in doh_backup_server (the geo-fallback tier a
				// DoH proxy consults). Route it to the LIVE dnsmasq `server` list instead when either:
				//   - it carries a non-standard #port — doh_backup_server can't round-trip a port, so it
				//     would be silently dropped (a query then hits :53 and fails); or
				//   - there is NO DoH proxy to consume doh_backup_server — leaving it only in the backup
				//     tier would strand dnsmasq with no upstream at all (noresolv also blocks ISP DNS),
				//     killing resolution outright.
				// serverRef preserves the #port, and ReadUCI round-trips a `server` entry back to a plain
				// TierFallback resolver, so the adopt->render->read loop stays stable.
				if r.Port != 0 || len(proxyRefs) == 0 {
					servers = append(servers, serverRef(r))
				} else {
					backups = append(backups, r.Address)
				}
			} else {
				servers = append(servers, serverRef(r)) // e.g. a private VPS-DoT-over-tunnel upstream
			}
		case KindLocal:
			// dnsmasq IS the device resolver — nothing to add.
		}
	}
	for _, s := range servers {
		cmds = append(cmds, fmt.Sprintf("uci add_list dhcp.@dnsmasq[0].server='%s'", s))
	}
	cmds = append(cmds, "uci -q delete dhcp.@dnsmasq[0].doh_backup_server")
	for _, b := range backups {
		cmds = append(cmds, fmt.Sprintf("uci add_list dhcp.@dnsmasq[0].doh_backup_server='%s'", b))
	}
	return cmds
}

// UCICommitCmds are the final commit + service restarts — kept SEPARATE from RenderUCI so a caller can
// preview the plan before running the device-mutating part. NOT run by the improvement loop.
func UCICommitCmds() []string {
	return []string{
		"uci commit https-dns-proxy",
		"uci commit dhcp",
		"/etc/init.d/https-dns-proxy restart",
		"/etc/init.d/dnsmasq restart",
	}
}

// ValidateForWrite rejects a NativeDNS that would render an unusable config (empty address, a DoH
// resolver without an https:// URL). Checked before any write so a bad plane can't be applied.
func ValidateForWrite(nd NativeDNS) error {
	if len(nd.Resolvers) == 0 {
		return errors.New("no resolvers to write")
	}
	for i, r := range nd.Resolvers {
		if strings.TrimSpace(r.Address) == "" {
			return fmt.Errorf("resolver %d: empty address", i)
		}
		// A display-only redacted address must never be written back: RenderUCI would interpolate the
		// masked placeholder into resolver_url and break DoH resolution. The real URL is kept on the
		// device, not in the client-posted (redacted) plane — reject rather than corrupt the config.
		if strings.Contains(r.Address, RedactionMark) {
			return fmt.Errorf("resolver %d: address is redacted (display-only); native write-back of a token-bearing DoH resolver is not yet supported — the real URL stays on the device", i)
		}
		// RenderUCI interpolates r.Address into single-quoted `uci set …='%s'` commands
		// with no escaping, so a quote/newline/control char would produce a malformed (or,
		// if pasted into a device shell, injected) command. A DNS resolver address — an IP,
		// hostname, or https:// URL — never legitimately contains whitespace, a quote, a
		// backtick, a backslash, or a control character, so reject them at this single choke
		// point rather than escaping each of the several interpolation sites.
		if bad := strings.IndexFunc(r.Address, func(c rune) bool {
			return c <= ' ' || c == '\'' || c == '"' || c == '`' || c == '\\' || c == 0x7f
		}); bad >= 0 {
			return fmt.Errorf("resolver %d: address %q contains whitespace or a shell/uci control character", i, r.Address)
		}
		if r.Kind == KindDoH && !strings.HasPrefix(r.Address, "https://") {
			return fmt.Errorf("resolver %d: DoH address must be an https:// URL, got %q", i, r.Address)
		}
	}
	return nil
}

func uciSetBool(key string, v bool) string {
	if v {
		return fmt.Sprintf("uci set %s='1'", key)
	}
	return fmt.Sprintf("uci -q delete %s", key)
}

func serverRef(r NativeResolver) string {
	if r.Port > 0 {
		return fmt.Sprintf("%s#%d", r.Address, r.Port)
	}
	return r.Address
}
