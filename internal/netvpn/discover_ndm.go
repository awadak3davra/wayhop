package netvpn

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// KeeneticOS has no `wg`/`awg` CLI; the runtime is owned by NDM (the management daemon)
// and inspected via `ndmc -c "show interface"`. That command prints a flat, per-interface
// block of indented "key: value" lines, e.g.:
//
//	interface-name: Wireguard0
//	    description: WG_A
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
// lets WayHop treat a Keenetic Wireguard/AmneziaWG interface as an egress.

// parseNDMInterfaces parses `ndmc -c "show interface"` output, returning one DiscoveredVPN
// per interface whose NDM type is "Wireguard" (KeeneticOS labels both plain WireGuard and
// AmneziaWG tunnels as "Wireguard" — the type carries AmneziaWG obfuscation params, so we
// classify them as "amneziawg"). Pure (no I/O) so it is unit-tested with captured samples.
//
// It builds on ParseNDMInterfaceStatus rather than re-tokenizing the same text, so the two NDM
// readers cannot drift, and it carries that reader's admin/link Up verdict into ndmUp — without
// it every NDM-discovered tunnel would report a permanent Active()==false (NDM lists no peers).
//
// The kernel interface name is derived from the NDM name: "Wireguard0" → "nwg0"
// (lowercase + "wireguard"→"nwg"), matching the device's kernel iface naming (nwgN).
// Non-Wireguard interfaces are ignored. Peers/PublicKey stay empty (NDM does not list them).
func parseNDMInterfaces(out string) []DiscoveredVPN {
	var res []DiscoveredVPN
	for _, st := range ParseNDMInterfaceStatus(out) {
		if !strings.EqualFold(st.Type, "Wireguard") {
			continue
		}
		up := st.Up
		res = append(res, DiscoveredVPN{
			Iface: ndmKernelIface(st.Name),
			// Capture the raw NDM name verbatim: it is the authoritative handle for the
			// managed-toggle/state path and is NOT recoverable from the derived kernel name
			// when the tunnel was created by hand with an arbitrary NDM name.
			NDMName: st.Name,
			// KeeneticOS "Wireguard" interfaces carry AmneziaWG params; classify as
			// amneziawg (plain "wireguard" would also be acceptable).
			Type: "amneziawg",
			// NDM "description:" is a user-set label, e.g. "WG_A" ("" if absent).
			Name: st.Description,
			// The NDM admin/link verdict is the ONLY liveness signal here (no peers/handshakes),
			// so Active() reads it instead of reporting a permanent false.
			ndmUp: &up,
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
// It distinguishes two very different "no result" cases: a MISSING ndmc means this is not a
// KeeneticOS host (OpenWrt/dev/CI) — that yields (nil, nil), a normal empty result. But an ndmc
// that EXISTS and FAILS (non-zero exit, killed by ctx, etc.) yields a non-nil error, so a caller
// can tell "no tunnels configured" apart from "discovery itself broke" — the exact silent-nil that
// once hid a live KeeneticOS discovery failure behind an empty list.
func DiscoverNDM(ctx context.Context) ([]DiscoveredVPN, error) {
	out, err := exec.CommandContext(ctx, "ndmc", "-c", "show interface").Output()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, nil // not a KeeneticOS host — no tunnels, not a failure
		}
		return nil, fmt.Errorf("ndmc show interface: %w", err)
	}
	return parseNDMInterfaces(string(out)), nil
}
