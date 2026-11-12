package nativedns

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// RenderUCI renders a NativeDNS into the uci command PLAN that reconfigures the OpenWrt DNS stack:
// one https-dns-proxy instance per DoH resolver, dnsmasq pointed at those proxies (+ any plain
// non-fallback upstreams), noresolv and strictorder, and the plaintext resolvers registered as
// doh_backup_server (the geo-fallback tier). It returns the plan ONLY — applying it (see
// UCICommitCmds: uci commit + service restart) is a separate, user-gated, device-mutating step.
// Pure; the inverse of ReadUCI.
//
// It changes what the plane names and leaves everything else in both configs as it is (QA-116). The
// plan used to delete the whole dnsmasq server list and every https-dns-proxy section and rebuild
// them from the plane. ReadUCI models neither split-DNS entries ("/domain/ip") nor any instance
// option besides resolver_url and listen_port, so a user who ran the previewed commands lost their
// split-DNS entries, every bootstrap_dns and every other per-instance option, and the preview did not
// say so. Now:
//   - A DoH resolver adopted from instance N (Source "https-dns-proxy[N]") updates instance N in
//     place: its resolver_url, plus listen_port when the plane gives it no port and listen_addr when
//     it has none either. dnsmasq is pointed at the address and port the instance listens on. Any
//     other DoH resolver gets a new instance on 127.0.0.1 and a port no resolver in the plane uses.
//   - List values are removed one by one with del_list, the way the https-dns-proxy package edits
//     the same lists: the values the plane adopted from that list, and the values it is about to add
//     (so they move into the plane's order rather than appear twice).
//
// A value or an instance the plane does not name stays where it is, which also means a resolver
// dropped from an edited plane is not removed from the router.
func RenderUCI(nd NativeDNS) []string {
	var cmds []string

	// 1) https-dns-proxy: one instance per DoH resolver, in order. Ports any resolver in the plane
	// already uses are never handed to a new instance.
	avoid := map[int]bool{}
	for _, r := range nd.Resolvers {
		if validPort(r.Port) {
			avoid[r.Port] = true
		}
	}
	next := 5053
	freePort := func() int {
		for avoid[next] {
			next++
		}
		avoid[next] = true
		return next
	}
	claimed := map[int]bool{}
	var proxyRefs []string
	for _, r := range nd.Resolvers {
		if r.Kind != KindDoH {
			continue
		}
		sect := "https-dns-proxy.@https-dns-proxy[-1]"
		port := 0
		listenAddr, hasAddr := "", false
		if idx, ok := proxyInstance(r.Source); ok && !claimed[idx] {
			claimed[idx] = true
			sect = fmt.Sprintf("https-dns-proxy.@https-dns-proxy[%d]", idx)
			if validPort(r.Port) {
				port = r.Port // it already listens there; its listen options are left alone
			}
			// An adopted instance keeps the address it listens on, and dnsmasq is pointed there.
			listenAddr, hasAddr = r.ListenAddr, r.ListenAddr != ""
		} else {
			cmds = append(cmds, "uci add https-dns-proxy https-dns-proxy")
		}
		cmds = append(cmds, fmt.Sprintf("uci set %s.resolver_url='%s'", sect, r.Address))
		if port == 0 {
			port = freePort()
			if !hasAddr {
				listenAddr = "127.0.0.1"
				cmds = append(cmds, fmt.Sprintf("uci set %s.listen_addr='%s'", sect, listenAddr))
			}
			cmds = append(cmds, fmt.Sprintf("uci set %s.listen_port='%d'", sect, port))
		}
		proxyRefs = append(proxyRefs, fmt.Sprintf("%s#%d", dohRefHost(listenAddr), port))
	}

	// 2) dnsmasq: noresolv + server list (proxy refs + plain non-fallback upstreams) + doh_backup_server
	// (the plaintext geo-fallback tier).
	cmds = append(cmds, uciSetBool("dhcp.@dnsmasq[0].noresolv", nd.NoResolv))
	// Written for the same reason it is now read: without it the tier order below is decoration,
	// because dnsmasq queries every upstream at once and answers with whichever replies first - which
	// can be the plaintext WAN one while an encrypted tunnel resolver is up.
	cmds = append(cmds, uciSetBool("dhcp.@dnsmasq[0].strictorder", nd.StrictOrder))
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
	// Remove only what this plane manages: what it adopted from each list, and what it is about to
	// add. Split-DNS entries, the https-dns-proxy package's own entries and anything else ReadUCI
	// skipped stay in place.
	seen := map[string]bool{}
	delList := func(opt, v string) {
		c := fmt.Sprintf("uci -q del_list dhcp.@dnsmasq[0].%s='%s'", opt, v)
		if !seen[c] {
			seen[c] = true
			cmds = append(cmds, c)
		}
	}
	for _, r := range nd.Resolvers {
		switch r.Source {
		case "dnsmasq.server":
			delList("server", serverRef(r))
		case "dnsmasq.doh_backup_server":
			delList("doh_backup_server", r.Address)
		}
	}
	for _, s := range servers {
		delList("server", s)
	}
	for _, b := range backups {
		delList("doh_backup_server", b)
	}
	for _, s := range servers {
		cmds = append(cmds, fmt.Sprintf("uci add_list dhcp.@dnsmasq[0].server='%s'", s))
	}
	for _, b := range backups {
		cmds = append(cmds, fmt.Sprintf("uci add_list dhcp.@dnsmasq[0].doh_backup_server='%s'", b))
	}
	return cmds
}

// proxyInstance reads the https-dns-proxy section index out of a resolver's Source tag
// ("https-dns-proxy[2]" → 2). The tag comes back from the client, so only the exact form ReadUCI
// writes is accepted, and the index is re-formatted from the integer, never copied into a command.
func proxyInstance(source string) (int, bool) {
	digits, ok := strings.CutPrefix(source, "https-dns-proxy[")
	if !ok {
		return 0, false
	}
	if digits, ok = strings.CutSuffix(digits, "]"); !ok {
		return 0, false
	}
	n, err := strconv.Atoi(digits)
	if err != nil || n < 0 || strconv.Itoa(n) != digits {
		return 0, false
	}
	return n, true
}

func validPort(p int) bool { return p > 0 && p <= 65535 }

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
		// The binding is written after `@` in a config line, so it gets the same treatment as the address.
		if r.Iface != "" && !ValidIfaceName(r.Iface) {
			return fmt.Errorf("resolver %d: %q is not an interface name", i, r.Iface)
		}
		// listen_addr comes back from the client too and RenderUCI writes it into dnsmasq's server list.
		if r.ListenAddr != "" && net.ParseIP(r.ListenAddr) == nil {
			return fmt.Errorf("resolver %d: listen_addr %q is not an IP address", i, r.ListenAddr)
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

// serverRef writes a resolver as a dnsmasq server entry. The port goes before a binding the address
// carries ("IP@wan" with port 53 is "IP#53@wan"), the inverse of splitServerRef.
func serverRef(r NativeResolver) string {
	addr, bind := r.Address, ""
	if i := strings.IndexByte(addr, '@'); i >= 0 {
		addr, bind = addr[:i], addr[i:]
	}
	if r.Iface != "" {
		bind = "@" + r.Iface
	}
	if r.Port > 0 {
		return fmt.Sprintf("%s#%d%s", addr, r.Port, bind)
	}
	return addr + bind
}
