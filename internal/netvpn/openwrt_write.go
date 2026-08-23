package netvpn

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// openwrt_write.go renders an AmneziaWG tunnel into the uci command PLAN that makes it a FIRST-CLASS
// OpenWrt interface — a `config interface` section with proto=amneziawg plus one peer section per
// peer. That is the whole point of writing uci rather than driving `awg` directly: netifd owns the
// link, LuCI shows it on the Interfaces page and can edit it, and the tunnel survives a reboot
// without WayHop being involved.
//
// Pure, like nativedns.RenderUCI: it returns commands and touches nothing. Applying them (uci commit
// + network reload) is a separate, user-gated, device-mutating step — the operator asked to be shown
// the exact commands before anything is written.
//
// The schema below is not from documentation; it was read off a live OpenWrt 25.12.2 AX3000T running
// luci-proto-amneziawg, whose /etc/config/network carries:
//
//	config interface 'awg0'
//	    option proto 'amneziawg'   option private_key '…'   list addresses '10.0.0.30/32'
//	    option mtu '1280'          option awg_jc '5'  …  option awg_i5 '0x262f…'
//	config amneziawg_awg0          # section TYPE is amneziawg_<ifname>
//	    option public_key '…'      option endpoint_host '203.0.113.10'
//	    list allowed_ips '0.0.0.0/0'   option route_allowed_ips '0'
//
// Two decisions worth stating, because both are load-bearing:
//
//   - Peer sections are written NAMED (awg0_peer1, awg0_peer2…), not anonymous. The router has one of
//     each today — awg0's peer is anonymous, awg1's is named `awg1_peer` — so luci-proto-amneziawg
//     accepts both. A writer needs the named form: an anonymous section can only be addressed by
//     index, and an index shifts when anything else is added or removed, so removal and re-apply
//     would be aimed at whatever happens to sit at that position.
//
//   - route_allowed_ips is forced to '0'. With it on, netifd installs a route per allowed-IP — and
//     for a full-tunnel peer that is a default route. WayHop's PBR is the owner of the route table
//     (nft mark → ip rule → table 151/152); a second writer would fight it, and the symptom would be
//     traffic silently taking the wrong exit. Both peers on the live router already carry '0'.
type AWGPeer struct {
	Description         string   // free text, shown in LuCI
	PublicKey           string   // remote peer's public key
	PresharedKey        string   // optional
	EndpointHost        string   // host or IP; empty ⇒ roaming peer, no endpoint written
	EndpointPort        int      // ignored when EndpointHost is empty
	AllowedIPs          []string // prefixes this peer may source/carry
	PersistentKeepalive int      // seconds; 0 ⇒ not written

	// Ref is the section name exactly as `uci show` printed it: `awg1_peer` for a named section,
	// `@amneziawg_awg0[0]` for an anonymous one. It is set only by the parser and never rendered.
	//
	// Without it, removal guesses. RemoveUCI derives `<iface>_peerN` from a COUNT, so on the
	// operator's own AX3000T — whose hand-made awg0 carries an ANONYMOUS peer — it emitted a delete
	// for `awg0_peer1`, a section that does not exist, and never touched `@amneziawg_awg0[0]`. The
	// interface would go and its peer would be left behind pointing at nothing.
	Ref string
	// PeerType is the raw section type as printed (`amneziawg_awg0`), so a peer belonging to a
	// different protocol than the one being written can be named in a message rather than guessed at.
	PeerType string

	// Disabled mirrors luci-proto-amneziawg's per-peer on/off switch — a control that does not exist
	// in luci-proto-wireguard, which this protocol was forked from, and which is therefore easy to
	// miss when reasoning from the WireGuard schema. protoSchema.PeerDisabled carries that fact now,
	// so the option is written for AmneziaWG and omitted for WireGuard rather than written blindly.
	//
	// It is written EXPLICITLY on every apply rather than left alone, because `uci set` does not
	// remove options it was not told about (measured: a staged `disabled=1` survived a later
	// `uci set proto`). Left implicit, a peer switched off in LuCI would stay off after a write that
	// intended it on, while the post-write comparison reported a perfect match — the check would be
	// telling the truth about every field it looks at and still be wrong about whether the tunnel runs.
	Disabled bool
}

// AWGInterface is one AmneziaWG tunnel as WayHop wants it to exist in /etc/config/network.
//
// Obfuscation carries the AmneziaWG knobs by their BARE name (jc, s1, s3, i1 …) exactly as the
// importer parses them; the uci option name gets the awg_ prefix at render time. Keeping the bare
// name here means the 2.x/3.x additions (s3, s4, i1..i5 — which this router uses) need no change to
// this type, and no second list of parameter names to drift out of step with importer.awgKeys.
type AWGInterface struct {
	Name        string            // uci section name AND kernel interface name (awg0)
	PrivateKey  string            // this side's private key
	Addresses   []string          // interface addresses, e.g. 10.0.0.30/32
	MTU         int               // 0 ⇒ not written, netifd decides
	Obfuscation map[string]string // bare AWG param name -> value ("jc" -> "5", "i1" -> "0x8e7a…")
	Peers       []AWGPeer

	// Proto is the native protocol this interface is written as. The ZERO VALUE IS AmneziaWG, so
	// every caller and every test written before this field existed renders exactly the bytes it
	// rendered before. See proto.go.
	Proto Proto
}

// RenderUCI returns the commands that create iface from nothing. Use RenderUCIFrom when the
// interface may already exist — see there for why the difference matters.
func RenderUCI(iface AWGInterface) []string { return RenderUCIFrom(iface, nil) }

// RenderUCIFrom returns the commands that turn cur into iface. cur is nil when the interface does
// not exist yet.
//
// Idempotence needs the list options cleared before they are rebuilt, because `uci add_list` appends
// — re-applying an unchanged tunnel would otherwise list every address twice. But the clear can only
// be issued when there is something to clear, and THAT is what cur is for.
//
// The first version emitted the delete unconditionally, on the belief that `-q` made it harmless.
// The router disagreed on the first real write: `uci -q delete` on an absent option exits 1 (measured
// — `-q` suppresses the message, not the status), the batch aborted seven commands in, and the
// applier reverted a half-written interface. Which is the machinery working, but the plan should not
// have contained a command that could not succeed.
func RenderUCIFrom(iface AWGInterface, cur *AWGInterface) []string {
	var out []string
	n := iface.Name
	// The zero Proto resolves to AmneziaWG, so a caller that never heard of this field gets exactly
	// the bytes it got before. schemaFor cannot fail for a resolved value that came from a caller
	// this package accepted — BuildPlanFor refuses an unknown protocol long before rendering.
	sc, _ := schemaFor(iface.Proto)

	out = append(out, fmt.Sprintf("uci set network.%s=interface", n))
	out = append(out, fmt.Sprintf("uci set network.%s.proto='%s'", n, string(sc.Name)))
	if iface.PrivateKey != "" {
		out = append(out, fmt.Sprintf("uci set network.%s.private_key=%s", n, q(iface.PrivateKey)))
	}
	if cur != nil && len(cur.Addresses) > 0 {
		out = append(out, fmt.Sprintf("uci -q delete network.%s.addresses", n))
	}
	for _, a := range iface.Addresses {
		out = append(out, fmt.Sprintf("uci add_list network.%s.addresses=%s", n, q(a)))
	}
	if iface.MTU > 0 {
		out = append(out, fmt.Sprintf("uci set network.%s.mtu='%d'", n, iface.MTU))
	}
	// Sorted so the plan is stable between runs — an unordered map would make the preview differ
	// from one render to the next and turn a no-op re-apply into an apparent change.
	//
	// A protocol with no obfuscation namespace gets nothing here even if the map is populated;
	// BuildPlanFor refuses that combination outright rather than dropping the parameters silently,
	// because an AmneziaWG profile quietly rendered as plain WireGuard is a tunnel whose peer will
	// not answer.
	if sc.ObfPrefix != "" {
		for _, k := range sortedKeys(iface.Obfuscation) {
			out = append(out, fmt.Sprintf("uci set network.%s.%s%s=%s", n, sc.ObfPrefix, k, q(iface.Obfuscation[k])))
		}
	}

	for i, p := range iface.Peers {
		sec := PeerSection(n, i)
		out = append(out, fmt.Sprintf("uci set network.%s=%s%s", sec, sc.PeerType, n))
		if p.Description != "" {
			out = append(out, fmt.Sprintf("uci set network.%s.description=%s", sec, q(p.Description)))
		}
		out = append(out, fmt.Sprintf("uci set network.%s.public_key=%s", sec, q(p.PublicKey)))
		if p.PresharedKey != "" {
			out = append(out, fmt.Sprintf("uci set network.%s.preshared_key=%s", sec, q(p.PresharedKey)))
		}
		if p.EndpointHost != "" {
			out = append(out, fmt.Sprintf("uci set network.%s.endpoint_host=%s", sec, q(p.EndpointHost)))
			if p.EndpointPort > 0 {
				out = append(out, fmt.Sprintf("uci set network.%s.endpoint_port='%d'", sec, p.EndpointPort))
			}
		}
		if p.PersistentKeepalive > 0 {
			out = append(out, fmt.Sprintf("uci set network.%s.persistent_keepalive='%d'", sec, p.PersistentKeepalive))
		}
		// See the type comment: netifd must not install routes for these prefixes.
		out = append(out, fmt.Sprintf("uci set network.%s.route_allowed_ips='0'", sec))
		// Always stated, never inherited — see AWGPeer.Disabled. Only where the protocol's handler
		// has the switch at all: luci-proto-wireguard does not, and writing it there would leave an
		// option nothing reads and the differ would compare on every apply forever.
		if sc.PeerDisabled {
			out = append(out, fmt.Sprintf("uci set network.%s.disabled='%s'", sec, boolOpt(p.Disabled)))
		}
		// Same rule as the addresses above: only clear a list that is actually there. A peer section
		// can be absent even when the interface exists, so the index is checked too.
		if cur != nil && i < len(cur.Peers) && len(cur.Peers[i].AllowedIPs) > 0 {
			out = append(out, fmt.Sprintf("uci -q delete network.%s.allowed_ips", sec))
		}
		for _, a := range p.AllowedIPs {
			out = append(out, fmt.Sprintf("uci add_list network.%s.allowed_ips=%s", sec, q(a)))
		}
	}
	return out
}

// RemoveUCI returns the commands that take the interface and its peers back out, deriving each peer's
// section name from a COUNT.
//
// That derivation is only correct for peers this writer created, which are named <iface>_peerN. It is
// wrong for anything else, and the operator's own router is the counter-example: awg0 there was made
// by hand and its peer is ANONYMOUS (`network.@amneziawg_awg0[0]`), so this emits a delete for
// `awg0_peer1` — a section that does not exist — and leaves the real peer behind. Prefer
// RemoveUCIRefs, which deletes the sections the parser actually found.
func RemoveUCI(name string, peerCount int) []string {
	refs := make([]string, 0, peerCount)
	for i := 0; i < peerCount; i++ {
		refs = append(refs, PeerSection(name, i))
	}
	return RemoveUCIRefs(name, refs)
}

// RemoveUCIRefs returns the commands that take the interface and the named peer sections back out.
// The refs come from the parser (AWGPeer.Ref), so both the named and the anonymous form are handled.
//
// Anonymous refs are deleted in DESCENDING index order. `uci delete network.@type[0]` renumbers
// @type[1] down to [0], so deleting upwards removes the wrong section on the second step — and on a
// router with two hand-made peers it would delete one and orphan the other while reporting success.
func RemoveUCIRefs(name string, peerRefs []string) []string {
	sorted := append([]string(nil), peerRefs...)
	sort.SliceStable(sorted, func(i, j int) bool { return anonIndex(sorted[i]) > anonIndex(sorted[j]) })
	out := make([]string, 0, len(sorted)+1)
	for _, ref := range sorted {
		if strings.TrimSpace(ref) == "" {
			continue
		}
		out = append(out, fmt.Sprintf("uci -q delete network.%s", ref))
	}
	out = append(out, fmt.Sprintf("uci -q delete network.%s", name))
	return out
}

// anonIndex is the bracket index of an anonymous section ref, or -1 for a named one. Named sections
// are unaffected by renumbering, so they sort last and their relative order is preserved.
func anonIndex(ref string) int {
	l := strings.LastIndex(ref, "[")
	r := strings.LastIndex(ref, "]")
	if l < 0 || r < l {
		return -1
	}
	n, err := strconv.Atoi(ref[l+1 : r])
	if err != nil {
		return -1
	}
	return n
}

// DeleteOptionCmds removes named options from a section. Every caller feeds it keys the parser
// actually READ off the device: `uci -q delete` on an absent option exits 1 (measured — -q suppresses
// the message, not the status) and would abort the batch, so a speculative delete is a broken plan.
func DeleteOptionCmds(section string, opts []string) []string {
	out := make([]string, 0, len(opts))
	for _, o := range opts {
		out = append(out, fmt.Sprintf("uci -q delete network.%s.%s", section, o))
	}
	return out
}

// PeerSection is the uci section name for the i-th peer of iface. One place, so the writer and the
// remover cannot disagree about what a peer is called.
func PeerSection(iface string, i int) string {
	return iface + "_peer" + strconv.Itoa(i+1)
}

// CommitCmds is the device-mutating tail, kept separate from the plan so a preview can never apply
// itself. `reload` rather than `restart`: restarting the network on a router you are connected to
// over that same network drops the session that asked for it.
func CommitCmds() []string {
	return []string{"uci commit network", "/etc/init.d/network reload"}
}

// q single-quotes a uci value. Any embedded single quote is closed, escaped and reopened — the shell
// idiom — so a description or key containing one cannot end the quoting early and have the rest of
// the value read as further shell words.
func q(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// boolOpt renders a uci flag. uci flags are the strings "0"/"1", not Go booleans, and writing
// "false" would be read back as truthy by some consumers.
func boolOpt(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
