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
	"errors"
	"fmt"
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
	// Source says where the tunnel was seen: SourceNDM, SourceUCI or SourceRuntime.
	Source string `json:"source,omitempty"`
	// ndmUp carries the KeeneticOS admin/link verdict (InterfaceStatusUp) for tunnels discovered
	// via `ndmc show interface`, which lists NO peers/handshakes for Active() to read. nil off the
	// NDM path (wg/awg dumps carry real handshakes). Unexported and never serialized: a purely
	// internal signal that routes Active() to the correct source of truth per discovery path.
	ndmUp *bool
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

// Active reports a best-effort "this tunnel is carrying traffic now" signal. For tunnels
// discovered from a wg/awg dump it is peer-derived: any peer handshook within activeWindow
// seconds of nowUnix (WireGuard rekeys ~every 2 min). KeeneticOS tunnels come from
// `ndmc show interface`, which lists no peers/handshakes — there ndmUp holds the authoritative
// NDM admin/link verdict, so a healthy native tunnel reports active instead of the permanent
// false a peer-only check would give.
func (d DiscoveredVPN) Active(nowUnix int64) bool {
	if d.ndmUp != nil { // NDM-discovered: no peer handshakes, trust the admin/link state
		return *d.ndmUp
	}
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
			d = &DiscoveredVPN{Iface: iface, Type: typ, PublicKey: f[2], Source: SourceRuntime}
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

// Where a discovered tunnel was seen. A tunnel read from the router's CONFIGURATION (NDM on
// KeeneticOS, uci on OpenWrt) is listed whether it is up or down, so its absence from that listing
// means it was deleted. A tunnel seen only in the runtime (an awg-quick/wg-quick tunnel) vanishes
// the moment it goes down, so its absence proves nothing.
const (
	SourceNDM     = "ndm"
	SourceUCI     = "uci"
	SourceRuntime = "runtime"
)

// ConfigListed reports whether the tunnel came from a configuration listing (see SourceNDM).
func (d DiscoveredVPN) ConfigListed() bool { return d.Source == SourceNDM || d.Source == SourceUCI }

// wayhopIfacePrefix names every device WayHop creates for its own endpoints (util.AWGIface): the
// awg-quick plugin, the generator's bind_interface and the native OpenWrt writer all use it. Those
// tunnels are WayHop's, not the router's, and offering one for adoption would route an exit
// through itself.
const wayhopIfacePrefix = "wr_"

// Discovery is one full look at the router's native tunnels and how far that look reached.
type Discovery struct {
	VPNs []DiscoveredVPN
	// NDM and UCI report that the router's configuration listing was read. Only then is a tunnel
	// that is absent from it known to be deleted rather than unreadable.
	NDM, UCI bool
	// Err is non-nil when a tool that exists failed, so the result may be incomplete. Absent tools
	// are normal (each platform has only some of them) and never an error.
	Err error
}

// Discover is DiscoverAll for callers that need only the tunnels and whether the look was complete.
func Discover(ctx context.Context) ([]DiscoveredVPN, error) {
	d := DiscoverAll(ctx)
	return d.VPNs, d.Err
}

// DiscoverAll reads every source the router has and merges them:
//
//   - `awg show all dump` / `wg show all dump`: live interfaces with peers and handshakes;
//   - `ndmc -c "show interface"` (KeeneticOS): every NDM WireGuard interface, up or down;
//   - `uci -q show network` (OpenWrt): every configured wireguard/amneziawg interface, so a tunnel
//     that is down is still listed and keeps its identity.
//
// All sources are always consulted. The NDM listing used to be a fallback for an empty dump, so a
// Keenetic that also runs an Entware awg tunnel listed that one tunnel and none of the router's own,
// and nothing added or deleted in the Keenetic web UI ever reached WayHop.
func DiscoverAll(ctx context.Context) Discovery {
	var d Discovery
	var errs []error
	var runtime []DiscoveredVPN
	for _, t := range []struct{ bin, typ string }{
		{"awg", "amneziawg"},
		{"wg", "wireguard"},
	} {
		out, err := exec.CommandContext(ctx, t.bin, "show", "all", "dump").Output()
		if err != nil {
			if errors.Is(err, exec.ErrNotFound) {
				continue
			}
			// A failing dump may still have printed the interfaces it could read; keep them, but
			// the look is incomplete, so nothing may be concluded from what is absent.
			errs = append(errs, fmt.Errorf("%s show all dump: %w", t.bin, err))
		}
		runtime = append(runtime, parseWgDump(string(out), t.typ)...)
	}

	ndm, ndmFound, err := discoverNDM(ctx)
	if err != nil {
		errs = append(errs, err)
	}
	d.NDM = ndmFound && err == nil

	uci, uciFound, err := discoverUCI(ctx)
	if err != nil {
		errs = append(errs, err)
	}
	d.UCI = uciFound && err == nil

	d.VPNs = mergeDiscovered(ndm, runtime, uci)
	d.Err = errors.Join(errs...)
	return d
}

// mergeDiscovered folds the three sources into one row per interface. NDM rows come first and
// stay authoritative for identity and state; a dump row for the same interface only adds the
// peers NDM does not print. A uci row marks a live interface as configuration-backed and lends it
// a label, and stands in for an interface that is configured but not running. WayHop's own
// devices are dropped. Pure, so the merge is tested without a router.
func mergeDiscovered(ndm, runtime, uci []DiscoveredVPN) []DiscoveredVPN {
	out := make([]DiscoveredVPN, 0, len(ndm)+len(runtime)+len(uci))
	at := map[string]int{}
	add := func(v DiscoveredVPN) {
		if v.Iface == "" || strings.HasPrefix(v.Iface, wayhopIfacePrefix) {
			return
		}
		at[v.Iface] = len(out)
		out = append(out, v)
	}
	for _, v := range ndm {
		if _, dup := at[v.Iface]; !dup {
			add(v)
		}
	}
	for _, v := range runtime {
		i, seen := at[v.Iface]
		if !seen {
			add(v)
			continue
		}
		cur := &out[i]
		if cur.Source != SourceNDM {
			continue // the same interface from both dumps: the first one wins
		}
		if cur.PublicKey == "" {
			cur.PublicKey = v.PublicKey
		}
		if cur.ListenPort == 0 {
			cur.ListenPort = v.ListenPort
		}
		if len(cur.Peers) == 0 {
			cur.Peers = v.Peers
		}
	}
	for _, v := range uci {
		i, seen := at[v.Iface]
		if !seen {
			add(v)
			continue
		}
		cur := &out[i]
		if cur.Source != SourceRuntime {
			continue
		}
		cur.Source = SourceUCI
		if cur.Name == "" {
			cur.Name = v.Name
		}
		if cur.PublicKey == "" {
			cur.PublicKey = v.PublicKey
		}
	}
	return out
}
