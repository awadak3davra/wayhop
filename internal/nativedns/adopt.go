package nativedns

// Runner executes a device command and returns its combined output. Injectable so the adopt logic is
// pure and testable: on a real router the server passes an exec-backed runner; tests pass a fake that
// returns captured fixtures.
type Runner func(name string, args ...string) (string, error)

// AdoptOpenWrt reads the live OpenWrt DNS stack (`uci show https-dns-proxy` + `uci show dhcp`) into a
// NativeDNS.
func AdoptOpenWrt(run Runner) (NativeDNS, error) {
	hp, err := run("uci", "show", "https-dns-proxy")
	if err != nil {
		return NativeDNS{}, err
	}
	dh, err := run("uci", "show", "dhcp")
	if err != nil {
		return NativeDNS{}, err
	}
	return ReadUCI(hp, dh), nil
}

// AdoptKeenetic reads the live Keenetic DNS stack (the dnsmasq.d upstreams + the running
// https-dns-proxy argv) into a NativeDNS.
func AdoptKeenetic(run Runner) (NativeDNS, error) {
	conf, err := run("sh", "-c", "cat /opt/etc/dnsmasq.d/*.conf 2>/dev/null")
	if err != nil {
		return NativeDNS{}, err
	}
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
