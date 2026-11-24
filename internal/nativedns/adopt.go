package nativedns

import "net"

// Runner executes a device command and returns its combined output. Injectable so the adopt logic is
// pure and testable: on a real router the server passes an exec-backed runner; tests pass a fake that
// returns captured fixtures.
type Runner func(name string, args ...string) (string, error)

// AdoptOpenWrt reads the live OpenWrt DNS stack (`uci show https-dns-proxy` + `uci show dhcp`) into a
// NativeDNS.
//
// https-dns-proxy is an OPTIONAL package. On a stock OpenWrt that never installed it,
// `uci show https-dns-proxy` exits non-zero with "Entry not found" — the COMMON case, not an error.
// Treating that as fatal would make the whole native-DNS view report unavailable on most OpenWrt
// routers even though the dnsmasq/dhcp half is present and perfectly adoptable. So the DoH-proxy read is best-effort and only the dhcp read is load-bearing.
func AdoptOpenWrt(run Runner) (NativeDNS, error) {
	hp, _ := run("uci", "show", "https-dns-proxy")
	dh, err := run("uci", "show", "dhcp")
	if err != nil {
		return NativeDNS{}, err // dnsmasq/dhcp IS the DNS plane here — without it there is nothing to adopt
	}
	nd := ReadUCI(hp, dh)
	nd.Resolvers = append(nd.Resolvers, resolvFileResolvers(dh, nd, run)...)
	return nd, nil
}

// resolvFileResolvers are the WAN's servers dnsmasq forwards to from its resolv file, which it reads
// unless noresolv is set. A stock OpenWrt names no server at all and forwards only to these, so without
// them the DNS page would say "No upstreams detected" about a router that resolves every name (on
// OpenWrt the resolv file is resolv.conf.auto).
func resolvFileResolvers(dhcp string, nd NativeDNS, run Runner) []NativeResolver {
	if nd.NoResolv {
		return nil
	}
	known := map[string]bool{}
	for _, r := range nd.Resolvers {
		known[r.Address] = true
	}
	read := resolvFileReader(run)
	var out []NativeResolver
	dnsmasqForwardersUCI(dhcp, func(file string) []string {
		ns := read(file)
		for _, a := range ns {
			if ip := net.ParseIP(a); ip == nil || ip.IsLoopback() || known[a] {
				continue
			}
			known[a] = true
			out = append(out, NativeResolver{Kind: KindPlain, Address: a, Tier: tierForKind(KindPlain), Source: "dnsmasq.resolvfile"})
		}
		return ns
	})
	return out
}

// AdoptKeenetic reads the live Keenetic DNS stack (the dnsmasq.d upstreams + the running
// https-dns-proxy argv) into a NativeDNS. Both reads are BEST-EFFORT: the Entware DNS stack is
// optional, so a box with no matching dnsmasq.d/*.conf must yield an empty-but-valid plane, NOT a
// hard error. On busybox an unmatched glob is passed to cat literally, so cat exits non-zero — the
// old `if err != nil { return }` turned that into a 500 on GET /api/dns/native for every stock
// Keenetic without the opkg dnsmasq confs. Ignoring the error (like the ps read below, and matching
// the unknown-platform empty-plane default) degrades gracefully; a genuinely dead transport simply
// yields the same empty plane rather than a user-facing error on an optional feature.
func AdoptKeenetic(run Runner) (NativeDNS, error) {
	// The MAIN config first, then the conf-dir — which is the order dnsmasq itself reads them in on
	// Entware, where /opt/etc/dnsmasq.conf ends with conf-dir=/opt/etc/dnsmasq.d,*.conf.
	//
	// Reading only the conf-dir would miss the upstreams entirely. On Keenetic the main config
	// typically carries no-resolv, strict-order and the server= lines, while the one file in
	// dnsmasq.d is WayHop's own policy file with zero server= lines. The "Router's native DNS" card
	// would then say "No upstreams detected" about a resolver that forwards every LAN lookup to
	// plaintext servers, and the write-back preview would describe a plane with neither strict-order
	// nor no-resolv — the opposite of the router's actual configuration, in the two directives that
	// decide how upstreams are consulted.
	// The sentinel between the two reads is what lets the parser tag each upstream with the file it
	// really came from. A blob of concatenated text cannot say, and would label every resolver
	// "dnsmasq.d server" — including the ones that live in the MAIN config, which is exactly the
	// distinction that matters: an upstream there comes before anything in the conf-dir, so a chain
	// written only into the conf-dir lands behind it. ChainHost.Apply moves those lines aside for that
	// reason.
	conf, _ := run("sh", "-c", keeneticDnsmasqRead)
	ps, _ := run("sh", "-c", "ps 2>/dev/null | grep '[h]ttps-dns-proxy'")
	return ReadDnsmasqD(conf, ps), nil
}

// Adopt dispatches to the platform reader. An unknown platform yields an empty (but valid) plane.
func Adopt(run Runner, platform string) (NativeDNS, error) {
	switch platform {
	case "openwrt":
		return AdoptOpenWrt(run)
	case "keenetic":
		return AdoptKeenetic(run)
	}
	return NativeDNS{Platform: platform}, nil
}
