package netvpn

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// KeeneticOS has no `wg`/`awg` CLI of its own; the runtime is owned by NDM (the management daemon)
// and inspected via `ndmc -c "show interface"`. That command prints a per-interface block of
// "key: value" lines with the keys right-aligned on one colon column, and nested sub-blocks
// aligned further right (captured from KeeneticOS 5.x):
//
//	Interface, name = "Wireguard0"
//	               id: Wireguard0
//	   interface-name: Wireguard0
//	             type: Wireguard
//	      description: WG_A
//	             link: up
//	        connected: yes
//	            state: up
//	        wireguard:
//	           public-key: <the interface's own key>
//	          listen-port: 43556
//
// Unlike `wg show all dump`, the listing does NOT print peers, endpoints or transfer counters —
// only the interface's identity, its own public key and its state. Every configured tunnel is
// listed, up or down, so the listing is the router's truth about which tunnels exist.

// parseNDMInterfaces parses `ndmc -c "show interface"` output, returning one DiscoveredVPN
// per interface whose NDM type is "Wireguard" (KeeneticOS labels both plain WireGuard and
// AmneziaWG tunnels as "Wireguard" — the type carries AmneziaWG obfuscation params, so we
// classify them as "amneziawg"). Pure (no I/O) so it is unit-tested with captured samples.
//
// It builds on ParseNDMInterfaceStatus rather than re-tokenizing the same text, so the two NDM
// readers cannot drift, and it carries that reader's liveness verdict into ndmUp — without it
// every NDM-discovered tunnel would report a permanent Active()==false (NDM lists no peers).
//
// The kernel interface name is derived from the NDM name: "Wireguard0" → "nwg0"
// (lowercase + "wireguard"→"nwg"), matching the device's kernel iface naming (nwgN).
// Non-Wireguard interfaces are ignored. The interface's own public key comes from its
// `wireguard:` sub-block; it is what tells a new tunnel apart from a deleted one whose NDM slot
// (Wireguard5) it reused. Peers stay empty: the listing does not print them.
func parseNDMInterfaces(out string) []DiscoveredVPN {
	var res []DiscoveredVPN
	for _, st := range ParseNDMInterfaceStatus(out) {
		if !strings.EqualFold(st.Type, "Wireguard") {
			continue
		}
		live := ndmLive(st)
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
			Name:       st.Description,
			PublicKey:  st.PublicKey,
			ListenPort: st.ListenPort,
			Source:     SourceNDM,
			// The NDM link verdict is the ONLY liveness signal here (no peers/handshakes),
			// so Active() reads it instead of reporting a permanent false.
			ndmUp: &live,
		})
	}
	return res
}

// ndmLive is whether the tunnel carries traffic now. `state:` is the ADMIN state: a tunnel that is
// switched on but whose handshake never completes reads "state: up", "link: down", "connected: no".
// So the link pair decides whenever NDM prints it, and the admin state only stands in for it.
func ndmLive(st NDMInterfaceStatus) bool {
	if st.Connected != "" {
		return strings.EqualFold(st.Connected, "yes") && !strings.EqualFold(st.Link, "down")
	}
	return st.Up
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
	vpns, _, err := discoverNDM(ctx)
	return vpns, err
}

// discoverNDM is DiscoverNDM that also says whether ndmc exists on this host.
func discoverNDM(ctx context.Context) ([]DiscoveredVPN, bool, error) {
	out, err := exec.CommandContext(ctx, "ndmc", "-c", "show interface").Output()
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, false, nil // not a KeeneticOS host — no tunnels, not a failure
		}
		return nil, true, fmt.Errorf("ndmc show interface: %w", err)
	}
	return parseNDMInterfaces(string(out)), true, nil
}
