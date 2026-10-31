package nativedns

import (
	"fmt"
	"strconv"
	"strings"
)

// ReadUCI parses `uci show https-dns-proxy` + `uci show dhcp` into a NativeDNS. Each https-dns-proxy
// instance becomes a DoH resolver (its resolver_url) in index order; dnsmasq's noresolv, its plain
// upstreams, and the doh_backup_server plaintext fallbacks (the geo-allowed last-resort tier) round it
// out. Tolerant: unknown lines are ignored, split-DNS "/domain/upstream" entries and dnsmasq's
// references to the DoH proxies are skipped (the proxies are already captured), so a firmware quirk
// can't break adoption. What it skips is not WayHop's to manage: RenderUCI leaves it on the router.
// Pure — the caller supplies the two `uci show` outputs.
func ReadUCI(httpsDNSProxy, dhcp string) NativeDNS {
	nd := NativeDNS{Platform: "openwrt"}

	// 1) https-dns-proxy instances → DoH resolvers, in index order.
	type inst struct{ url, addr, port string }
	byIdx := map[int]*inst{}
	maxIdx := -1
	globalAddr := "" // the package's own default for instances without listen_addr (newer releases)
	for _, ln := range strings.Split(httpsDNSProxy, "\n") {
		key, vals := parseUCILine(ln)
		if key == "" || len(vals) == 0 {
			continue
		}
		if key == "https-dns-proxy.config.listen_addr" {
			globalAddr = strings.TrimSpace(vals[0])
			continue
		}
		idx, field, ok := uciSectionIndex(key)
		if !ok {
			continue
		}
		if byIdx[idx] == nil {
			byIdx[idx] = &inst{}
		}
		if idx > maxIdx {
			maxIdx = idx
		}
		switch field {
		case "resolver_url":
			byIdx[idx].url = vals[0]
		case "listen_addr":
			byIdx[idx].addr = strings.TrimSpace(vals[0])
		case "listen_port":
			byIdx[idx].port = strings.TrimSpace(vals[0])
		}
	}
	dohRefs := map[string]bool{} // "host#port" of each proxy, as dnsmasq refers to it
	for i := 0; i <= maxIdx; i++ {
		in := byIdx[i]
		if in == nil || strings.TrimSpace(in.url) == "" {
			continue
		}
		// Port and ListenAddr are where the instance listens. RenderUCI updates this instance in place
		// and points dnsmasq there, so the write-back neither moves the proxies nor recreates their
		// sections (which cost every option it does not model, QA-116). Without listen_port the package
		// starts the instance on its counter: 5053, plus one for each instance started before it, so
		// 5053+N for @https-dns-proxy[N] (net/https-dns-proxy init script, 21.02 to master).
		addr := in.addr
		if addr == "" {
			addr = globalAddr
		}
		port := atoiSafe(in.port)
		if in.port == "" {
			port = 5053 + i
		}
		nd.Resolvers = append(nd.Resolvers, NativeResolver{
			Kind: KindDoH, Address: in.url, Port: port, Tier: TierHidden,
			Source: fmt.Sprintf("https-dns-proxy[%d]", i), ListenAddr: addr,
		})
		dohRefs[dohRefHost(addr)+"#"+strconv.Itoa(port)] = true
	}

	// 2) dnsmasq: noresolv + plain fallbacks + any plain upstream not pointing at a captured DoH proxy,
	// from the first dnsmasq section only. That is the section RenderUCI writes (@dnsmasq[0]), and the
	// plane holds one forwarder: one server order, one noresolv, one strictorder. A second instance
	// (another port or interface) has its own; merged into the plane, the write-back copied them onto
	// the first instance. Writing each value back to the section it came from would need a section on
	// every resolver and per-section switches, and a tier order across two forwarders means nothing,
	// so the other sections are left as they are, both ways. uci show prints a named first section by
	// name and an anonymous one as @dnsmasq[0]; a dump without section lines still names it so.
	main := ""
	for _, ln := range strings.Split(dhcp, "\n") {
		key, vals := parseUCILine(ln)
		parts := strings.SplitN(key, ".", 3)
		if len(parts) < 2 {
			continue
		}
		if len(parts) == 2 {
			if main == "" && len(vals) > 0 && vals[0] == "dnsmasq" {
				main = parts[1]
			}
			continue
		}
		if parts[1] != main && parts[1] != "@dnsmasq[0]" {
			continue
		}
		switch parts[2] {
		case "noresolv":
			if len(vals) > 0 && vals[0] == "1" {
				nd.NoResolv = true
			}
		// strictorder is dnsmasq's strict-order under uci. It was read on Keenetic and not here, so an
		// OpenWrt router that had it on adopted as StrictOrder:false - the panel showed no pill, and
		// RenderUCI then wrote the router back WITHOUT it, quietly turning "try the tunnel resolver
		// first" into "ask every upstream at once and keep the first reply". A round trip must not
		// lose a setting it is capable of carrying.
		case "strictorder":
			if len(vals) > 0 && vals[0] == "1" {
				nd.StrictOrder = true
			}
		case "doh_backup_server":
			for _, v := range vals {
				if ip := strings.TrimSpace(v); ip != "" {
					nd.Resolvers = append(nd.Resolvers, NativeResolver{
						Kind: KindPlain, Address: ip, Tier: TierFallback, Source: "dnsmasq.doh_backup_server",
					})
				}
			}
		case "server":
			for _, v := range vals {
				v = strings.TrimSpace(v)
				if v == "" || strings.HasPrefix(v, "/") { // split-DNS "/domain/upstream" is routing, not a resolver
					continue
				}
				host, port := splitServerRef(v)
				if dohRefs[host+"#"+port] { // dnsmasq's ref to a DoH proxy already captured
					continue
				}
				nd.Resolvers = append(nd.Resolvers, NativeResolver{
					Kind: KindPlain, Address: host, Port: atoiSafe(port),
					Tier: tierForKind(KindPlain), Source: "dnsmasq.server",
				})
			}
		}
	}
	return nd
}

// parseUCILine splits a `uci show` line into its key and quoted value list. A bare (unquoted) RHS
// returns a single value; a non key=value line returns "".
func parseUCILine(line string) (string, []string) {
	line = strings.TrimSpace(line)
	eq := strings.IndexByte(line, '=')
	if eq < 0 {
		return "", nil
	}
	key := strings.TrimSpace(line[:eq])
	rhs := strings.TrimSpace(line[eq+1:])
	if rhs == "" {
		return key, nil
	}
	if rhs[0] != '\'' {
		return key, []string{strings.Trim(rhs, "'")}
	}
	var vals []string
	for {
		i := strings.IndexByte(rhs, '\'')
		if i < 0 {
			break
		}
		j := strings.IndexByte(rhs[i+1:], '\'')
		if j < 0 {
			break
		}
		vals = append(vals, rhs[i+1:i+1+j])
		rhs = rhs[i+1+j+1:]
	}
	return key, vals
}

// uciSectionIndex extracts the [N] index and trailing field from a key like
// "https-dns-proxy.@https-dns-proxy[0].resolver_url" → (0, "resolver_url", true).
func uciSectionIndex(key string) (int, string, bool) {
	lb := strings.IndexByte(key, '[')
	if lb < 0 {
		return 0, "", false
	}
	rb := strings.IndexByte(key[lb:], ']')
	if rb < 0 {
		return 0, "", false
	}
	rb += lb
	idx, err := strconv.Atoi(key[lb+1 : rb])
	if err != nil {
		return 0, "", false
	}
	field := ""
	if rb+1 < len(key) && key[rb+1] == '.' {
		field = key[rb+2:]
	}
	return idx, field, true
}

// splitServerRef splits a dnsmasq server ref "IP#PORT" into host + port ("" if none). A binding
// (`@interface`, `@source[#port]`) follows the server's port in dnsmasq's syntax; it stays on the host
// ("IP@wan" for "IP#53@wan") so serverRef can put the port back in front of it.
func splitServerRef(v string) (string, string) {
	addr, bind := v, ""
	if j := strings.IndexByte(v, '@'); j >= 0 {
		addr, bind = v[:j], v[j:]
	}
	if i := strings.IndexByte(addr, '#'); i >= 0 {
		return addr[:i] + bind, addr[i+1:]
	}
	return v, ""
}

// dohRefHost is the address dnsmasq reaches an https-dns-proxy instance on, written the way the
// package writes its own dnsmasq entry: a wildcard bind is reached on the loopback of its family, and
// an instance with no listen_addr listens on 127.0.0.1.
func dohRefHost(listenAddr string) string {
	switch listenAddr = strings.TrimSpace(listenAddr); listenAddr {
	case "", "0.0.0.0", "::ffff:0.0.0.0":
		return "127.0.0.1"
	case "::":
		return "::1"
	}
	return listenAddr
}

func atoiSafe(s string) int { n, _ := strconv.Atoi(s); return n }
