package netvpn

import (
	"fmt"
	"strings"
)

// openwrt_firewall.go attaches an AmneziaWG interface to a firewall zone, which is what makes the
// tunnel usable rather than merely present: without a zone, fw4 has no policy for traffic entering
// or leaving it and the interface sits there doing nothing.
//
// Zones are ANONYMOUS uci sections — the device addresses them as @zone[0], @zone[1], @zone[2] — so
// the only stable handle is the `name` option. Writing to a remembered index is the bug this file
// exists to avoid: adding or deleting any zone shifts every index after it, and a plan built
// yesterday would attach the tunnel to whichever zone happens to occupy that slot today. The live
// router illustrates the risk exactly: its zones are lan, wan and vpn at indices 0, 1, 2, and the
// tunnels are attached to the third.
//
// The index is therefore resolved at PLAN time and carried with the name it resolved to, so the
// check immediately before writing can confirm the slot still holds the zone the plan meant.

// Zone is one firewall zone as the device reports it.
type Zone struct {
	Ref      string   // uci section reference, e.g. "@zone[2]"
	Name     string   // the stable handle, e.g. "vpn"
	Networks []string // interfaces attached to it
	Devices  []string // raw devices attached to it, netifd or not (see openwrt_bind.go)
}

// ParseFirewallZones reads `uci show firewall` into the zones it declares, in device order.
func ParseFirewallZones(out string) []Zone {
	idx := map[string]*Zone{}
	var order []string
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(ln, "firewall.") {
			continue
		}
		eq := strings.Index(ln, "=")
		if eq < 0 {
			continue
		}
		lhs, rhs := ln[len("firewall."):eq], ln[eq+1:]
		// A zone reference is "@zone[N]" and an option adds ".name" / ".network" after it. The
		// bracket, not a dot, is what ends the section reference.
		close := strings.Index(lhs, "]")
		if !strings.HasPrefix(lhs, "@zone[") || close < 0 {
			continue
		}
		ref, opt := lhs[:close+1], strings.TrimPrefix(lhs[close+1:], ".")
		z := idx[ref]
		if z == nil {
			z = &Zone{Ref: ref}
			idx[ref] = z
			order = append(order, ref)
		}
		switch opt {
		case "":
			// the section declaration itself
		case "name":
			z.Name = first(splitUCIValues(rhs))
		case "network":
			z.Networks = splitUCIValues(rhs)
		case "device":
			z.Devices = splitUCIValues(rhs)
		}
	}
	out2 := make([]Zone, 0, len(order))
	for _, r := range order {
		out2 = append(out2, *idx[r])
	}
	return out2
}

// FindZone returns the zone with the given name. Found is false when it is absent, which the caller
// must treat as "cannot attach" rather than "attach to something else" — a tunnel silently landing
// in the wan zone would be forwarded by wan's policy, and on this router that policy is REJECT.
func FindZone(zones []Zone, name string) (Zone, bool) {
	for _, z := range zones {
		if z.Name == name {
			return z, true
		}
	}
	return Zone{}, false
}

// ZoneAttachCmds adds iface to the zone's network list, or returns nothing when it is already there.
// Returning nothing matters: uci add_list appends unconditionally, so a re-apply would list the same
// interface twice and fw4 would render duplicate rules for it.
func ZoneAttachCmds(z Zone, iface string) []string {
	for _, n := range z.Networks {
		if n == iface {
			return nil
		}
	}
	return []string{fmt.Sprintf("uci add_list firewall.%s.network=%s", z.Ref, q(iface))}
}

// ZoneDetachCmds removes iface from the zone, or returns nothing when it is not attached.
func ZoneDetachCmds(z Zone, iface string) []string {
	for _, n := range z.Networks {
		if n == iface {
			return []string{fmt.Sprintf("uci del_list firewall.%s.network=%s", z.Ref, q(iface))}
		}
	}
	return nil
}

// FirewallCommitCmds is the mutating tail for the firewall, kept apart from the plan for the same
// reason as CommitCmds. `reload` — a restart of fw4 drops every established connection through the
// router, including the session issuing the command.
func FirewallCommitCmds() []string {
	return []string{"uci commit firewall", "/etc/init.d/firewall reload"}
}
