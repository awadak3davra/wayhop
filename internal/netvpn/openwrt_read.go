package netvpn

import (
	"strconv"
	"strings"
)

// openwrt_read.go is the inverse of RenderUCI: it parses `uci show network` back into the
// AWGInterface values WayHop believes it wrote.
//
// It exists for one reason. The operator's rule is to re-verify immediately before changing
// anything and again afterwards, and neither half is possible without reading the device's own view.
// Before a write, the current section is compared against what is expected — a mismatch means
// somebody edited the tunnel in LuCI and the plan was computed against a config that no longer
// exists, so the write must stop rather than overwrite their work. After a write, the section is
// read back and compared against what was intended, because "the commands exited 0" and "the
// configuration now says what I meant" are different claims.
//
// The input format is what the device actually prints (captured from OpenWrt 25.12.2):
//
//	network.awg0=interface
//	network.awg0.proto='amneziawg'
//	network.awg0.addresses='10.0.0.30/32'
//	network.@amneziawg_awg0[0]=amneziawg_awg0
//	network.@amneziawg_awg0[0].allowed_ips='10.0.0.0/24' '10.0.1.0/28' '0.0.0.0/0'
//	network.awg1_peer=amneziawg_awg1
//
// Three shapes have to survive that: a list is several quoted tokens on ONE line; a section type is
// printed UNquoted on the right of `=`; and a peer section may be named (awg1_peer) or anonymous
// (@amneziawg_awg0[0]). The peer's owning interface comes from its section TYPE, amneziawg_<ifname>,
// which is the only thing that ties the two together in either form.

// ParseUCIShow returns every AmneziaWG interface described by the output of `uci show network`,
// keyed by interface name. Unknown options are ignored rather than rejected: a hand-added option
// that WayHop does not model is the operator's business, and refusing to read the section because of
// it would make the safety check fail exactly when someone has been editing.
func ParseUCIShow(out string) map[string]AWGInterface {
	type section struct {
		typ  string
		opts map[string][]string
	}
	secs := map[string]*section{}
	order := []string{}

	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "network.") {
			continue
		}
		eq := strings.Index(ln, "=")
		if eq < 0 {
			continue
		}
		lhs, rhs := ln[len("network."):eq], ln[eq+1:]

		// A section declaration has no option part. Splitting on the LAST dot is wrong for the
		// anonymous form, whose name contains no dot but does contain brackets; splitting on the
		// first dot is wrong for nothing here, since neither section names nor option names contain
		// one on this platform.
		name, opt := lhs, ""
		if i := strings.Index(lhs, "."); i >= 0 {
			name, opt = lhs[:i], lhs[i+1:]
		}
		s := secs[name]
		if s == nil {
			s = &section{opts: map[string][]string{}}
			secs[name] = s
			order = append(order, name)
		}
		if opt == "" {
			s.typ = strings.Trim(rhs, "'")
			continue
		}
		s.opts[opt] = splitUCIValues(rhs)
	}

	ifaces := map[string]AWGInterface{}
	for _, name := range order {
		s := secs[name]
		// An ALLOW-LIST of tunnel protocols, not "any section with peers". `proto='static'` and
		// `proto='dhcp'` must stay invisible to this package, and a section with no proto at all is
		// not an AmneziaWG tunnel just because the zero value of Proto means AmneziaWG elsewhere.
		p := Proto(first(s.opts["proto"]))
		if s.typ != "interface" || !isTunnelProto(p) {
			continue
		}
		sc, _ := schemaFor(p)
		mtu, _ := strconv.Atoi(first(s.opts["mtu"]))
		iface := AWGInterface{
			Name:        name,
			Proto:       p,
			PrivateKey:  first(s.opts["private_key"]),
			Addresses:   s.opts["addresses"],
			MTU:         mtu,
			Obfuscation: map[string]string{},
		}
		// Harvested under THIS section's own protocol namespace. On a `proto='wireguard'` section an
		// `awg_*` option is not an obfuscation parameter that happens to be there — it is a leftover
		// from a protocol this interface no longer speaks, and treating it as owned would make the
		// differ compare a value the renderer can never write.
		if sc.ObfPrefix != "" {
			for k, v := range s.opts {
				if strings.HasPrefix(k, sc.ObfPrefix) {
					iface.Obfuscation[strings.TrimPrefix(k, sc.ObfPrefix)] = first(v)
				}
			}
		}
		ifaces[name] = iface
	}

	// Peers in a second pass: a peer section can appear before its interface in the output, and
	// attaching it during the first pass would drop those.
	for _, name := range order {
		s := secs[name]
		owner, ok := peerOwner(s.typ)
		if !ok {
			continue
		}
		iface, known := ifaces[owner]
		if !known {
			continue // a peer whose interface is gone: an orphan, not our tunnel
		}
		// The peer must belong to the protocol the interface actually speaks. An `amneziawg_awg0`
		// section under an awg0 that now says `proto='wireguard'` is a leftover of the old protocol,
		// not a peer of the new one: attaching it would have the renderer rewrite it under the wrong
		// type and the differ compare a `disabled` flag the new handler does not have. Such sections
		// are reported by PeerSectionsFor so the plan can delete them by name.
		if sc, _ := schemaFor(iface.Proto); s.typ != sc.PeerType+owner {
			continue
		}
		port, _ := strconv.Atoi(first(s.opts["endpoint_port"]))
		ka, _ := strconv.Atoi(first(s.opts["persistent_keepalive"]))
		iface.Peers = append(iface.Peers, AWGPeer{
			Description:         first(s.opts["description"]),
			PublicKey:           first(s.opts["public_key"]),
			PresharedKey:        first(s.opts["preshared_key"]),
			EndpointHost:        first(s.opts["endpoint_host"]),
			EndpointPort:        port,
			PersistentKeepalive: ka,
			Disabled:            first(s.opts["disabled"]) == "1",
			AllowedIPs:          s.opts["allowed_ips"],
			Ref:                 name,
			PeerType:            s.typ,
		})
		ifaces[owner] = iface
	}
	return ifaces
}

// peerOwner returns the interface a peer section belongs to, by matching its TYPE against each known
// protocol's peer prefix.
//
// Prefix match, never a generic split on "_": WayHop's own interface names are `wr_<8 hex>`, so
// `amneziawg_wr_44284aea` has to trim exactly `amneziawg_` and keep `wr_44284aea`. Splitting on the
// last underscore would answer `amneziawg_wr`, and on the first would answer `wr_44284aea` only by
// luck of the prefix having one.
func peerOwner(typ string) (string, bool) {
	for _, sc := range protoSchemas {
		if owner := strings.TrimPrefix(typ, sc.PeerType); owner != typ && owner != "" {
			return owner, true
		}
	}
	return "", false
}

// PeerSectionsFor returns every peer section in the config that belongs to iface under ANY known
// protocol, as the refs `uci show` printed. It is how a plan finds the sections it must delete when
// an interface changes protocol, and how removal finds peers the count-based derivation never could —
// including the anonymous `@amneziawg_awg0[0]` on the operator's own router.
func PeerSectionsFor(uciNetwork, iface string) []string {
	var refs []string
	for _, ln := range strings.Split(uciNetwork, "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "network.") {
			continue
		}
		eq := strings.Index(ln, "=")
		if eq < 0 {
			continue
		}
		lhs, rhs := ln[len("network."):eq], ln[eq+1:]
		if strings.Contains(lhs, ".") {
			continue // an option line, not a section declaration
		}
		typ := strings.Trim(rhs, "'")
		if owner, ok := peerOwner(typ); ok && owner == iface {
			refs = append(refs, lhs)
		}
	}
	return refs
}

// RoutesOwnedByNetifd reports the peer sections that have route_allowed_ips enabled — the one setting
// that quietly takes the route table away from WayHop's PBR. It is reported per section rather than
// as a bool so the message can name what to fix, and it is read from the DEVICE rather than assumed
// from what was written: the point of the check is to catch the config having been changed elsewhere.
func RoutesOwnedByNetifd(out string) []string {
	var bad []string
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "network.") || !strings.Contains(ln, ".route_allowed_ips=") {
			continue
		}
		i := strings.Index(ln, ".route_allowed_ips=")
		v := strings.Trim(ln[i+len(".route_allowed_ips="):], "'")
		if v != "0" && v != "" {
			bad = append(bad, strings.TrimPrefix(ln[:i], "network."))
		}
	}
	return bad
}

// splitUCIValues splits the right-hand side into values. A list arrives as several single-quoted
// tokens on one line; a scalar as one; a section type unquoted. An embedded quote arrives as the
// four characters '\” — close, escaped quote, reopen — so the scan tracks quoting rather than
// splitting on spaces, which would cut a value containing one in half.
func splitUCIValues(rhs string) []string {
	rhs = strings.TrimSpace(rhs)
	if rhs == "" {
		return nil
	}
	if !strings.HasPrefix(rhs, "'") {
		return []string{rhs} // unquoted: a section type
	}
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(rhs); i++ {
		switch {
		case rhs[i] == '\'' && !inQuote:
			inQuote = true
		case rhs[i] == '\'' && inQuote:
			inQuote = false
			// `'\''` continues the SAME value; a space (or end) ends it. Only the two escape
			// characters \' are consumed here — the quote that follows REOPENS the value and is
			// left for the next iteration to see as an opening quote. Setting inQuote back to true
			// here instead made the loop read that reopening quote as a closing one, and the value
			// came back truncated at the first apostrophe.
			if strings.HasPrefix(rhs[i+1:], `\'`) {
				cur.WriteByte('\'')
				i += 2
				continue
			}
			if i+1 >= len(rhs) || rhs[i+1] == ' ' {
				out = append(out, cur.String())
				cur.Reset()
			}
		case inQuote:
			cur.WriteByte(rhs[i])
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}
