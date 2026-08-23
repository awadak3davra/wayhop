package keenetic

import (
	"net"
	"strconv"
	"strings"
)

// preflight.go reads the LIVE device state the cutover needs but the static model can't carry
// (see the red-team's bypass + adopt holes). Pure parsers here; the RCI/file reads that feed
// them happen at deploy pre-flight.

// WGInterface is one AmneziaWG/WireGuard interface from `show running-config`: its NDM name,
// description, and peer endpoint (the server the tunnel dials).
type WGInterface struct {
	Iface    string // "Wireguard0"
	Name     string // `description` (e.g. "WG_A")
	Endpoint string // peer endpoint host — IP or hostname
	Port     string // peer endpoint port
}

// GlobalPriorities reads every interface's `ip global` priority out of a `show running-config`,
// keyed by NDM interface name ("Wireguard0", "GigabitEthernet1").
//
// This number is KeeneticOS's own ordering of the internet-facing connections, and it is what picks
// the default route — which makes it the native way to say "send everything through this tunnel",
// with no static default route to install and no anti-loop bypass to get right: NDM keeps the
// tunnel's own peer traffic on the underlying WAN by itself.
//
// HIGHER wins. Measured on the live router: the WAN sits at 54610 and holds 0.0.0.0/0 while five
// tunnels sit at 2730-32766 and do not. (WireguardOpts.Metric documents this field as "lower =
// preferred", which does not match the device; that comment is about the route metric era.)
func GlobalPriorities(runningConfig string) map[string]int {
	out := map[string]int{}
	cur := ""
	for _, line := range strings.Split(runningConfig, "\n") {
		// An interface block opens at column 0; everything belonging to it is indented, so a nested
		// "interface" word inside a peer block cannot be mistaken for a new block here.
		if strings.HasPrefix(line, "interface ") {
			cur = strings.TrimSpace(strings.TrimPrefix(line, "interface "))
			continue
		}
		if cur == "" {
			continue
		}
		t := strings.TrimSpace(line)
		if line == "!" {
			cur = ""
			continue
		}
		if !strings.HasPrefix(t, "ip global ") {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(t, "ip global "))); err == nil {
			out[cur] = n
		}
	}
	return out
}

// parseWireguardEndpoints extracts the live AmneziaWG/WireGuard interfaces + their peer
// endpoints from a KeeneticOS `show running-config`. Pre-flight uses this to (1) build the
// REAL adopt map from interfaces that actually exist (keen-pbr references nwg3/wgtest but
// only Wireguard0/1/2/5 are live — that stale tag must be reconciled, not assumed) and (2)
// seed the anti-loop bypass with the peer endpoint IPs (adopted External endpoints carry no
// model Server, so the bypass cannot come from the model).
func parseWireguardEndpoints(runningConfig string) []WGInterface {
	var out []WGInterface
	var cur *WGInterface
	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}
	for _, line := range strings.Split(runningConfig, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "interface Wireguard"):
			flush()
			cur = &WGInterface{Iface: strings.TrimSpace(strings.TrimPrefix(t, "interface "))}
		case cur != nil && strings.HasPrefix(t, "description "):
			cur.Name = strings.TrimSpace(strings.TrimPrefix(t, "description "))
		case cur != nil && strings.HasPrefix(t, "endpoint "):
			cur.Endpoint, cur.Port = splitEndpoint(strings.TrimSpace(strings.TrimPrefix(t, "endpoint ")))
		case line == "!": // a TOP-LEVEL "!" (no indentation) closes the interface; the indented "    !" closes only the peer
			flush()
		}
	}
	flush()
	return out
}

// splitEndpoint splits "host:port" / "[v6]:port" via net.SplitHostPort; a bare host (no port)
// is returned as-is.
func splitEndpoint(ep string) (host, port string) {
	if h, p, err := net.SplitHostPort(ep); err == nil {
		return h, p
	}
	return ep, ""
}

// BypassHosts returns the peer endpoint hosts that must egress via ISP (anti-loop), skipping
// the management interface (Wireguard2 / nwg2, which the live S89 explicitly never touches).
func BypassHosts(ifaces []WGInterface, mgmtIface string) []string {
	var out []string
	for _, w := range ifaces {
		if w.Iface == mgmtIface || w.Endpoint == "" {
			continue
		}
		out = append(out, w.Endpoint)
	}
	return out
}

// OccupiedWireguardInterfaces returns the exact NDM interface identities present in one captured
// running-config. It is used only as allocation evidence; it grants no ownership authority.
func OccupiedWireguardInterfaces(runningConfig string) map[string]bool {
	occupied := make(map[string]bool)
	for _, iface := range parseWireguardEndpoints(runningConfig) {
		if strings.HasPrefix(iface.Iface, "Wireguard") {
			occupied[iface.Iface] = true
		}
	}
	return occupied
}
