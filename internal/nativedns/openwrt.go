package nativedns

import (
	"fmt"
	"strconv"
	"strings"
)

// ReadUCI parses `uci show https-dns-proxy` + `uci show dhcp` into a NativeDNS. Each https-dns-proxy
// instance becomes a DoH resolver (its resolver_url) in index order; dnsmasq's noresolv, its plain
// upstreams, and the doh_backup_server plaintext fallbacks (the geo-allowed last-resort tier) round it
// out. Tolerant: unknown lines are ignored, split-DNS "/domain/upstream" entries and the loopback
// references to the DoH proxies are skipped (the proxies are already captured), so a firmware quirk
// can't break adoption. Pure — the caller supplies the two `uci show` outputs.
func ReadUCI(httpsDNSProxy, dhcp string) NativeDNS {
	nd := NativeDNS{Platform: "openwrt"}

	// 1) https-dns-proxy instances → DoH resolvers, in index order.
	type inst struct{ url, port string }
	byIdx := map[int]*inst{}
	maxIdx := -1
	for _, ln := range strings.Split(httpsDNSProxy, "\n") {
		key, vals := parseUCILine(ln)
		if key == "" || len(vals) == 0 {
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
		case "listen_port":
			byIdx[idx].port = vals[0]
		}
	}
	dohPorts := map[string]bool{}
	for i := 0; i <= maxIdx; i++ {
		in := byIdx[i]
		if in == nil || strings.TrimSpace(in.url) == "" {
			continue
		}
		nd.Resolvers = append(nd.Resolvers, NativeResolver{
			Kind: KindDoH, Address: in.url, Tier: TierHidden,
			Source: fmt.Sprintf("https-dns-proxy[%d]", i),
		})
		if in.port != "" {
			dohPorts[in.port] = true
		}
	}

	// 2) dnsmasq (dhcp.@dnsmasq[0]): noresolv + plain fallbacks + any plain upstream not pointing at a
	// captured DoH proxy.
	for _, ln := range strings.Split(dhcp, "\n") {
		key, vals := parseUCILine(ln)
		if key == "" {
			continue
		}
		field := uciField(key)
		switch field {
		case "noresolv":
			if len(vals) > 0 && vals[0] == "1" {
				nd.NoResolv = true
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
				if host == "127.0.0.1" && dohPorts[port] { // loopback ref to a DoH proxy already captured
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

// uciField returns the last dotted segment of a key (the option name).
func uciField(key string) string {
	if i := strings.LastIndexByte(key, '.'); i >= 0 {
		return key[i+1:]
	}
	return key
}

// splitServerRef splits a dnsmasq server ref "IP#PORT" into host + port ("" if none).
func splitServerRef(v string) (string, string) {
	if i := strings.IndexByte(v, '#'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

func atoiSafe(s string) int { n, _ := strconv.Atoi(s); return n }
