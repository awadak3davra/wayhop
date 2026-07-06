// Package netvpn discovers VPN tunnels that are ALREADY configured on the router
// (WireGuard / AmneziaWG) so WayHop can understand and route through them without
// re-importing keys — the OS owns the tunnel, WayHop just uses it as an egress.
//
// Discovery reads the runtime via the wg/awg CLIs (`wg show all dump`), which is the
// authoritative view of live interfaces + peers. It captures only the non-secret fields
// (interface name, the interface's own public key, listen port, and per-peer endpoint /
// allowed-IPs / handshake / transfer counters) — it deliberately drops the private key,
// the per-peer preshared key, and AmneziaWG's obfuscation magic headers, so the result is
// safe to surface in the API/UI.
package netvpn

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
)

// Peer is one remote endpoint of a discovered tunnel.
type Peer struct {
	PublicKey     string   `json:"public_key"`               // remote peer's public key (identifying, not secret)
	Endpoint      string   `json:"endpoint,omitempty"`       // host:port of the remote VPN server ("" if roaming/unset)
	AllowedIPs    []string `json:"allowed_ips,omitempty"`    // routed prefixes (0.0.0.0/0 ⇒ full tunnel)
	LastHandshake int64    `json:"last_handshake,omitempty"` // unix seconds (0 = never)
	RxBytes       int64    `json:"rx_bytes,omitempty"`
	TxBytes       int64    `json:"tx_bytes,omitempty"`
}

// DiscoveredVPN is a native tunnel found on the router.
type DiscoveredVPN struct {
	Iface string `json:"iface"` // kernel interface name (awg0, wg0, nwg1…)
	// NDMName is the KeeneticOS NDM interface name (e.g. "Wireguard5"); "" off Keenetic
	// (the wg/awg dumps carry no NDM name). The kernel Iface is DERIVED from it
	// (Wireguard0→nwg0), but a hand-named tunnel's NDM name is NOT recoverable from the
	// kernel name — so it is captured verbatim here for the native managed-toggle/state path.
	NDMName    string `json:"ndm_name,omitempty"`
	Type       string `json:"type"`           // "wireguard" | "amneziawg"
	Name       string `json:"name,omitempty"` // human-friendly label ("" if unknown; wg/awg dumps carry none, NDM "description:")
	PublicKey  string `json:"public_key"`     // this interface's own public key
	ListenPort int    `json:"listen_port,omitempty"`
	Peers      []Peer `json:"peers,omitempty"`
}

// FullTunnel reports whether any peer routes everything (a default-route exit candidate).
func (d DiscoveredVPN) FullTunnel() bool {
	for _, p := range d.Peers {
		for _, a := range p.AllowedIPs {
			if a == "0.0.0.0/0" || a == "::/0" {
				return true
			}
		}
	}
	return false
}

// Active reports whether any peer handshook within activeWindow seconds of nowUnix — a
// best-effort "this tunnel is carrying traffic now" signal (WireGuard rekeys ~every 2 min).
func (d DiscoveredVPN) Active(nowUnix int64) bool {
	for _, p := range d.Peers {
		if p.LastHandshake > 0 && nowUnix-p.LastHandshake < activeWindow {
			return true
		}
	}
	return false
}

const activeWindow = 180 // seconds; a touch over WireGuard's ~120s rekey interval

// parseWgDump parses `wg show all dump` / `awg show all dump` output into discovered
// tunnels. Pure (no I/O) so it is unit-tested with captured samples. The dump lists, per
// interface, the interface line first (private-key in field 1) then its peer lines
// (peer public-key in field 1); both start with the interface name, so the first line for
// a given interface is treated as the interface line and the rest as peers. AmneziaWG adds
// extra obfuscation columns to the interface line — harmless here, we read only fields 0/2/3.
func parseWgDump(out, typ string) []DiscoveredVPN {
	byIface := map[string]*DiscoveredVPN{}
	var order []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			continue
		}
		iface := f[0]
		d, seen := byIface[iface]
		if !seen {
			// interface line: f[0]=iface f[1]=privkey f[2]=pubkey f[3]=listen-port …
			d = &DiscoveredVPN{Iface: iface, Type: typ, PublicKey: f[2]}
			if p, err := strconv.Atoi(f[3]); err == nil {
				d.ListenPort = p
			}
			byIface[iface] = d
			order = append(order, iface)
			continue
		}
		// peer line: f[1]=pubkey f[2]=psk f[3]=endpoint f[4]=allowed-ips f[5]=handshake f[6]=rx f[7]=tx
		if len(f) < 8 {
			continue
		}
		peer := Peer{PublicKey: f[1]}
		if f[3] != "(none)" && f[3] != "" {
			peer.Endpoint = f[3]
		}
		if f[4] != "(none)" && f[4] != "" {
			peer.AllowedIPs = strings.Split(f[4], ",")
		}
		peer.LastHandshake, _ = strconv.ParseInt(f[5], 10, 64)
		peer.RxBytes, _ = strconv.ParseInt(f[6], 10, 64)
		peer.TxBytes, _ = strconv.ParseInt(f[7], 10, 64)
		d.Peers = append(d.Peers, peer)
	}
	res := make([]DiscoveredVPN, 0, len(order))
	for _, n := range order {
		res = append(res, *byIface[n])
	}
	return res
}

// Discover probes the host for native WireGuard + AmneziaWG tunnels via the wg/awg CLIs.
// Missing tools or non-router hosts simply yield no results (best-effort, never errors).
//
// On KeeneticOS the wg/awg CLIs are absent (NDM owns the runtime), so when the dumps yield
// nothing we fall back to the NDM discovery path (`ndmc -c "show interface"`). Where wg/awg
// ARE present (OpenWrt/Entware), behavior is unchanged — the fallback is never consulted.
func Discover(ctx context.Context) []DiscoveredVPN {
	var all []DiscoveredVPN
	for _, t := range []struct{ bin, typ string }{
		{"awg", "amneziawg"},
		{"wg", "wireguard"},
	} {
		out, err := exec.CommandContext(ctx, t.bin, "show", "all", "dump").Output()
		if err != nil {
			continue
		}
		all = append(all, parseWgDump(string(out), t.typ)...)
	}
	if len(all) == 0 {
		all = DiscoverNDM(ctx)
	}
	return all
}
