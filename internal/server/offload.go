package server

import (
	"os"
	"os/exec"
	"strings"
)

// probeOffloadDevices discovers the netdevs Phase-1b flow-offload should attach to: the
// WAN uplink (the default route's `dev`) plus the LAN bridge (br-lan, if present). Used
// only when config.Offload is set WITHOUT an explicit OffloadDevices list. Best-effort —
// it returns whatever it finds (possibly empty, in which case pbr.Compile skips offload
// and warns) and never errors. On a non-Linux/no-`ip` host (e.g. the test machine) the
// exec simply fails and this returns nil, so an accidental call is harmless.
func probeOffloadDevices() []string {
	var devs []string
	if out, err := exec.Command("ip", "-o", "route", "show", "default").Output(); err == nil {
		if d := parseDefaultRouteDev(string(out)); d != "" {
			devs = append(devs, d)
		}
	}
	// LAN bridge(s): enumerate REAL bridge devices rather than assuming OpenWrt's br-lan — Keenetic's
	// bridge is br0, and multi-bridge setups exist. awg*/wg* tunnel devices are never bridges, so they
	// are naturally excluded (carve-out traffic must not be offloaded — it would lose its per-packet PBR).
	for _, b := range probeBridges() {
		devs = appendUniqueStr(devs, b)
	}
	return devs
}

// probeBridges returns the router's bridge interface names (best-effort). Prefers `ip -o link show
// type bridge`; falls back to scanning /sys/class/net/*/bridge. Empty off-Linux / on error.
func probeBridges() []string {
	if out, err := exec.Command("ip", "-o", "link", "show", "type", "bridge").Output(); err == nil {
		if bs := parseBridgeLinks(string(out)); len(bs) > 0 {
			return bs
		}
	}
	var out []string
	if ents, err := os.ReadDir("/sys/class/net"); err == nil {
		for _, e := range ents {
			if _, err := os.Stat("/sys/class/net/" + e.Name() + "/bridge"); err == nil {
				out = append(out, e.Name())
			}
		}
	}
	return out
}

// parseBridgeLinks extracts interface names from `ip -o link show type bridge` output. Pure, so it is
// unit-tested without the host. Each line begins "<idx>: <name>: <flags> ..." (a name may carry an
// "@parent" suffix for a sub-interface — stripped, though bridges themselves never have one).
func parseBridgeLinks(out string) []string {
	var names []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name := strings.TrimSuffix(f[1], ":")
		if i := strings.IndexByte(name, '@'); i >= 0 {
			name = name[:i]
		}
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

// parseDefaultRouteDev extracts the first default route's `dev <name>` from the output of
// `ip -o route show default` (e.g. "default via 192.168.1.254 dev wan src 192.168.1.70").
// Pure, so it is unit-tested without touching the host. Returns "" if no dev is found.
func parseDefaultRouteDev(out string) string {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		for i := 0; i+1 < len(fields); i++ {
			if fields[i] == "dev" {
				return fields[i+1]
			}
		}
	}
	return ""
}

func appendUniqueStr(ss []string, s string) []string {
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}
