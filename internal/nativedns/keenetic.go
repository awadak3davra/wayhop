package nativedns

import (
	"net"
	"strings"
)

// ReadDnsmasqD parses a Keenetic dnsmasq.d upstream config (+ the optional running https-dns-proxy
// argv) into a NativeDNS. dnsmasq `server=` lines are the ordered upstream chain: a private/mesh IP
// (10./172.16-31./192.168.) is the encrypted-VPS-over-tunnel primary (Tier-1, ViaTunnel), a public IP
// is the plaintext geo-allowed last resort (Tier-3), and a `127.0.0.1#PORT` ref resolves to the local
// DoH proxy listening on that port (Tier-1 DoH) when the proxy argv is supplied. `strict-order` and
// `no-resolv` are adopted; split-DNS `server=/domain/…` and comments are skipped. Pure + tolerant.
func ReadDnsmasqD(dnsmasqConf, httpsDNSProxyArgs string) NativeDNS {
	nd := NativeDNS{Platform: "keenetic"}
	dohByPort := parseHTTPSDNSProxyPorts(httpsDNSProxyArgs) // listen-port -> resolver_url

	for _, ln := range strings.Split(dnsmasqConf, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		switch {
		case ln == "strict-order":
			nd.StrictOrder = true
		case ln == "no-resolv":
			nd.NoResolv = true
		case strings.HasPrefix(ln, "server="):
			v := strings.TrimSpace(strings.TrimPrefix(ln, "server="))
			if v == "" || strings.HasPrefix(v, "/") { // split-DNS "server=/domain/upstream" is routing
				continue
			}
			host, port := splitServerRef(v)
			if host == "127.0.0.1" {
				if url, ok := dohByPort[port]; ok { // a local DoH proxy on that port
					nd.Resolvers = append(nd.Resolvers, NativeResolver{
						Kind: KindDoH, Address: url, Tier: TierHidden, Source: "https-dns-proxy:" + port,
					})
				} else {
					nd.Resolvers = append(nd.Resolvers, NativeResolver{
						Kind: KindLocal, Address: host, Port: atoiSafe(port), Tier: TierWANEnc, Source: "dnsmasq.d server",
					})
				}
				continue
			}
			private := isPrivateIP(host)
			tier := TierFallback
			if private {
				tier = TierHidden // encrypted VPS resolver reached over the mesh/tunnel
			}
			nd.Resolvers = append(nd.Resolvers, NativeResolver{
				Kind: KindPlain, Address: host, Port: atoiSafe(port), ViaTunnel: private,
				Tier: tier, Source: "dnsmasq.d server",
			})
		}
	}
	return nd
}

// parseHTTPSDNSProxyPorts extracts the listen-port → first resolver_url mapping from a single
// https-dns-proxy argv (e.g. `-d -a 127.0.0.1 -p 5053 -b 1.1.1.1 -r https://1.1.1.1/dns-query`).
func parseHTTPSDNSProxyPorts(args string) map[string]string {
	m := map[string]string{}
	toks := strings.Fields(args)
	port, url := "", ""
	for i := 0; i < len(toks); i++ {
		switch toks[i] {
		case "-p":
			if i+1 < len(toks) {
				port = toks[i+1]
				i++
			}
		case "-r":
			if i+1 < len(toks) && url == "" {
				url = toks[i+1]
				i++
			}
		}
	}
	if port != "" && url != "" {
		m[port] = url
	}
	return m
}

// isPrivateIP reports whether host is an RFC1918/ULA/loopback/link-local literal — the heuristic that a
// dnsmasq forward to it rides the mesh/tunnel rather than the raw WAN.
func isPrivateIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
