package netvpn

import (
	"context"
	"os/exec"
	"strings"
)

// KeeneticOS has no `wg`/`awg` CLI; the runtime is owned by NDM (the management daemon)
// and inspected via `ndmc -c "show interface"`. That command prints a flat, per-interface
// block of indented "key: value" lines, e.g.:
//
//	interface-name: Wireguard0
//	    description: ND_VPS
//	    type: Wireguard
//	    link: up
//	    connected: yes
//	    state: up
//	interface-name: GigabitEthernet1
//	    type: Port
//	    ...
//
// Unlike `wg show all dump`, NDM does NOT expose per-peer endpoints, public keys, or
// transfer counters here — only the interface's identity/state — so discovered NDM tunnels
// carry no Peers and no PublicKey. This is purely a "which native tunnels exist" signal that
// lets Velinx treat a Keenetic Wireguard/AmneziaWG interface as an egress.

// parseNDMInterfaces parses `ndmc -c "show interface"` output, returning one DiscoveredVPN
// per interface whose NDM type is "Wireguard" (KeeneticOS labels both plain WireGuard and
// AmneziaWG tunnels as "Wireguard" — the type carries AmneziaWG obfuscation params, so we
// classify them as "amneziawg"). Pure (no I/O) so it is unit-tested with captured samples.
//
// The kernel interface name is derived from the NDM name: "Wireguard0" → "nwg0"
// (lowercase + "wireguard"→"nwg"), matching the device's kernel iface naming (nwgN).
// Non-Wireguard interfaces are ignored. Peers/PublicKey stay empty (NDM does not list them).
func parseNDMInterfaces(out string) []DiscoveredVPN {
	type ndmIface struct {
		name string // NDM interface-name, e.g. "Wireguard0"
		typ  string // NDM type, e.g. "Wireguard"
		desc string // NDM description, e.g. "ND_VPS"
	}
	var ifaces []ndmIface
	cur := -1
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		key, val, ok := splitNDMKV(trimmed)
		if !ok {
			continue
		}
		switch key {
		case "interface-name":
			ifaces = append(ifaces, ndmIface{name: val})
			cur = len(ifaces) - 1
		case "type":
			if cur >= 0 {
				ifaces[cur].typ = val
			}
		case "description":
			if cur >= 0 {
				ifaces[cur].desc = val
			}
		}
	}

	var res []DiscoveredVPN
	for _, in := range ifaces {
		if !strings.EqualFold(in.typ, "Wireguard") {
			continue
		}
		res = append(res, DiscoveredVPN{
			Iface: ndmKernelIface(in.name),
			// KeeneticOS "Wireguard" interfaces carry AmneziaWG params; classify as
			// amneziawg (plain "wireguard" would also be acceptable).
			Type: "amneziawg",
			// NDM "description:" is a user-set label, e.g. "ND_VPS" ("" if absent).
			Name: in.desc,
			// PublicKey + Peers intentionally empty: `show interface` does not expose them.
		})
	}
	return res
}

// splitNDMKV splits a trimmed "key: value" NDM line on the first ": ". A bare "key:" with no
// value (ok==true, val=="") is accepted; lines without a colon are rejected (ok==false).
func splitNDMKV(s string) (key, val string, ok bool) {
	i := strings.Index(s, ":")
	if i < 0 {
		return "", "", false
	}
	if key = strings.TrimSpace(s[:i]); key == "" {
		return "", "", false
	}
	return key, strings.TrimSpace(s[i+1:]), true
}

// ndmKernelIface maps an NDM interface name to its kernel name: "Wireguard0" → "nwg0".
func ndmKernelIface(ndmName string) string {
	return strings.ReplaceAll(strings.ToLower(ndmName), "wireguard", "nwg")
}

// DiscoverNDM probes a KeeneticOS host for native tunnels via `ndmc -c "show interface"`.
// Best-effort: a missing ndmc (non-Keenetic host) or any error simply yields nil.
func DiscoverNDM(ctx context.Context) []DiscoveredVPN {
	out, err := exec.CommandContext(ctx, "ndmc", "-c", "show interface").Output()
	if err != nil {
		return nil
	}
	return parseNDMInterfaces(string(out))
}
