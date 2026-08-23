package nativedns

// Runner executes a device command and returns its combined output. Injectable so the adopt logic is
// pure and testable: on a real router the server passes an exec-backed runner; tests pass a fake that
// returns captured fixtures.
type Runner func(name string, args ...string) (string, error)

// AdoptOpenWrt reads the live OpenWrt DNS stack (`uci show https-dns-proxy` + `uci show dhcp`) into a
// NativeDNS.
//
// https-dns-proxy is an OPTIONAL package. On a stock OpenWrt that never installed it,
// `uci show https-dns-proxy` exits non-zero with "Entry not found" — the COMMON case, not an error.
// Treating that as fatal made the whole native-DNS view report unavailable on most OpenWrt routers
// even though the dnsmasq/dhcp half was present and perfectly adoptable (observed on a real
// OpenWrt 24.10.4). So the DoH-proxy read is best-effort and only the dhcp read is load-bearing.
func AdoptOpenWrt(run Runner) (NativeDNS, error) {
	hp, _ := run("uci", "show", "https-dns-proxy")
	dh, err := run("uci", "show", "dhcp")
	if err != nil {
		return NativeDNS{}, err // dnsmasq/dhcp IS the DNS plane here — without it there is nothing to adopt
	}
	return ReadUCI(hp, dh), nil
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
	// Reading only the conf-dir missed the upstreams entirely. Measured on a live Keenetic:
	// dnsmasq is running and owns :53, its main config carries no-resolv, strict-order,
	// server=1.1.1.1 and server=8.8.8.8, and the one file in dnsmasq.d is WayHop's own policy file
	// with zero server= lines. So the "Router's native DNS" card said "No upstreams detected" about a
	// resolver that forwards every LAN lookup to two plaintext servers, and the write-back preview
	// would have described a plane with neither strict-order nor no-resolv — the opposite of the
	// router's actual configuration, in the two directives that decide how upstreams are consulted.
	// The sentinel between the two reads is what lets the parser tag each upstream with the file it
	// really came from. A blob of concatenated text cannot say, and every resolver was labelled
	// "dnsmasq.d server" — including the ones that live in the MAIN config, which is exactly the
	// distinction that matters: the write-back writes 00-upstream.conf inside the conf-dir and
	// leaves the main config untouched, so those upstreams are added beside the originals, not
	// replacing them.
	conf, _ := run("sh", "-c",
		"cat /opt/etc/dnsmasq.conf 2>/dev/null; echo '"+DnsmasqDirSentinel+"'; cat /opt/etc/dnsmasq.d/*.conf 2>/dev/null")
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
