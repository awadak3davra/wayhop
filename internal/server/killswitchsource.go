package server

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"sort"
	"strings"
	"time"

	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// killswitchsource.go reads the operator's own source routing for the nft guard.
//
// A router may route a whole segment by its source, ahead of WayHop's marks: on a small OpenWrt router the
// second access point's network goes out by one tunnel, `from 192.168.33.0/24 lookup 160` with
// `default dev awg1` in table 160. The guard used to know a kill-switched destination's own tunnels
// and take everything else for the provider, so that segment lost every kill-switched list whose
// tunnels did not include awg1, with WayHop healthy; and under a names hold it kept its internet only
// because awg1 happened to be one of WayHop's endpoints.
//
// The daemon reads `ip rule show` and the tables those rules look up, and tells the guard each
// (source, device) pair whose device is a way out the operator may choose for a kill-switched
// destination:
//
//   - never a device of the provider's side (ksSides.judge): a segment sent straight to the uplink by
//     source stays held for kill-switched destinations, which is what the kill switch promises;
//   - a tunnel: one WayHop runs traffic through, or an interface the network configuration declares
//     with a tunnel protocol. A LAN network used as a way out (a gateway on the LAN) is not one:
//     where its traffic goes next is not this router's to say.
//
// What is told only grows while the daemon runs, like the LAN's routes: each pair is bound to its
// device in the rule the guard renders, so a rule the operator has since removed opens nothing by
// any other device, and a table that an operator's script flips between two tunnels costs one reload
// of the guard and one write of its boot copy, not one per flip. A device that becomes the
// provider's (it gains a default route) is dropped from what is told at the next reading.

const (
	// ksSourceMax bounds the pairs the guard is told.
	ksSourceMax = 16
	// ksSourceRefresh is how old the reading of the rules may get.
	ksSourceRefresh = time.Minute
	// ksSourceReadTime bounds one reading.
	ksSourceReadTime = 5 * time.Second

	findingSourceRouted = "kill_switch.source_routed_segment"
	findingSourceHeld   = "kill_switch.source_routed_held"
	findingSourceBound  = "kill_switch.source_routed_bound"
)

// sourceBoundSummary is the Diagnostics and Review wording for pairs the bound refused.
func sourceBoundSummary(over int) string {
	return fmt.Sprintf("%d source-routing rule(s) of the router are not told to the kill switch: it remembers at most %d", over, ksSourceMax)
}

const sourceBoundDetail = "The guard remembers the router's own source-routing rules (from <network> lookup <table>) since the daemon " +
	"started, rules removed since then included. Over the bound a new rule is not told, and its network is held for kill-switched " +
	"lists (dropped, not let out by the rule's tunnel) until WayHop is restarted."

// sourceBoundFindings is the Review line for the same (empty while nothing was refused).
func (s *Server) sourceBoundFindings() []PlanFinding {
	s.ksLocal.mu.Lock()
	over := s.ksLocal.sourceOver
	s.ksLocal.mu.Unlock()
	if over == 0 {
		return nil
	}
	return []PlanFinding{{
		ID: findingSourceBound, Setting: "kill switch", Item: "source-routing rules",
		Requested: "every source-routing rule told to the kill switch", Effective: sourceBoundSummary(over),
		Severity: platform.SeverityDegraded, Reason: platform.ReasonModeConflict, Blocks: platform.BlocksNothing,
		Detail: sourceBoundDetail,
		Remedy: "Restart WayHop after removing old source-routing rules, or route those networks with fewer rules.",
	}}
}

// ksTunnelProtos are the interface protocols of the network configuration that make a device a
// tunnel: what leaves by it is carried inside another connection.
var ksTunnelProtos = map[string]bool{
	"wireguard": true, "amneziawg": true, "openvpn": true, "openconnect": true, "sstp": true,
	"vti": true, "vtiip6": true, "xfrm": true,
}

// ksSourceDump is one reading of the router's rules and of the tables' default routes.
type ksSourceDump struct {
	rules4, rules6   string
	routes4, routes6 string
}

// ksReadSourceRouting reads the rules and, when any of them routes by source, the tables. A variable
// so tests answer with a router's dump. tables is the daemon's own reader of `ip route show table
// all` (routeTableIO.read).
var ksReadSourceRouting = func(ctx context.Context, tables func(context.Context, bool) (string, error)) (ksSourceDump, error) {
	if _, err := exec.LookPath("uci"); err != nil {
		return ksSourceDump{}, fmt.Errorf("not an OpenWrt host")
	}
	ctx, cancel := context.WithTimeout(ctx, ksSourceReadTime)
	defer cancel()
	var d ksSourceDump
	var err error
	if d.rules4, d.rules6, err = openwrtRuleReader(ctx); err != nil {
		return ksSourceDump{}, err
	}
	if tables == nil {
		return d, nil
	}
	if len(pbr.SourceRules(d.rules4)) > 0 {
		if d.routes4, err = tables(ctx, false); err != nil {
			return ksSourceDump{}, fmt.Errorf("ip route show table all: %w", err)
		}
	}
	if len(pbr.SourceRules(d.rules6)) > 0 {
		d.routes6, _ = tables(ctx, true) // no IPv6 on the router is not a fault
	}
	return d, nil
}

// ksSourceRoute is one source rule of the router's own, with the device its table leaves by and
// what that device is.
type ksSourceRoute struct {
	pbr.GuardSource
	Line string
	Side ksSide
	// Tunnel says the device is a tunnel: WayHop's own, or declared with a tunnel protocol.
	Tunnel bool
}

// ok says the guard may let the segment's kill-switched traffic leave by the device.
func (r ksSourceRoute) ok() bool { return r.Side != sideProvider && r.Tunnel }

// label names the segment as the operator wrote it.
func (r ksSourceRoute) label() string {
	if r.Src.IsValid() {
		return r.Src.String()
	}
	return "the network on " + r.Iif
}

// tunnelDevice reports whether dev is a tunnel: one of WayHop's, or a device of an interface the
// network configuration declares with a tunnel protocol.
func (j ksJudge) tunnelDevice(dev string) bool {
	if j.tunnel[dev] {
		return true
	}
	for _, n := range j.sd.ifaces {
		if ksTunnelProtos[j.sd.proto[n]] && j.sd.ifaceHolds(n, dev, 0) {
			return true
		}
	}
	return false
}

// sourceRoutes sets the rules of a reading against the tables and the sides: one entry per rule and
// device of its table's default route. A rule whose table has no default route routes nothing by
// itself (the lookup falls through to the next rule) and is left out.
func sourceRoutes(d ksSourceDump, j ksJudge) []ksSourceRoute {
	var out []ksSourceRoute
	seen := map[pbr.GuardSource]bool{}
	for _, fam := range []struct{ rules, routes string }{{d.rules4, d.routes4}, {d.rules6, d.routes6}} {
		devs := pbr.TableDefaultDevices(fam.routes)
		for _, r := range pbr.SourceRules(fam.rules) {
			for _, dev := range devs[r.Table] {
				k := pbr.GuardSource{Src: r.Src, Iif: r.Iif, Dev: dev}
				if seen[k] {
					continue
				}
				seen[k] = true
				out = append(out, ksSourceRoute{GuardSource: k, Line: r.Line, Side: j.side(dev), Tunnel: j.tunnelDevice(dev)})
			}
		}
	}
	return out
}

// lessSource orders pairs for a stable program.
func lessSource(a, b pbr.GuardSource) bool {
	if a.Dev != b.Dev {
		return a.Dev < b.Dev
	}
	if a.Iif != b.Iif {
		return a.Iif < b.Iif
	}
	if c := a.Src.Addr().Compare(b.Src.Addr()); c != 0 {
		return c < 0
	}
	return a.Src.Bits() < b.Src.Bits()
}

// noteSourcesLocked takes a reading into what is remembered and returns what the guard is told now:
// every remembered pair whose device is still a tunnel off the provider's side. read is false when
// nothing was read this time. l.mu is held.
func (l *ksLocal) noteSourcesLocked(fresh []ksSourceRoute, read bool, j ksJudge) []pbr.GuardSource {
	if l.sources == nil {
		l.sources = map[pbr.GuardSource]bool{}
	}
	if read {
		sort.Slice(fresh, func(a, b int) bool { return lessSource(fresh[a].GuardSource, fresh[b].GuardSource) })
		over := 0
		for _, r := range fresh {
			switch {
			case !r.ok() || l.sources[r.GuardSource]:
			case len(l.sources) < ksSourceMax:
				l.sources[r.GuardSource] = true
			default:
				over++
			}
		}
		// A pair the bound refuses is held like a rule to the provider, and only a
		// restart forgets stale ones. Say so once in the log; Diagnostics and Review show the count.
		l.sourceOver = over
		if over > 0 && !l.sourceOverSaid {
			l.sourceOverSaid = true
			log.Printf("kill switch: %d source-routing rule(s) of the router are not told to the guard: it remembers at most %d "+
				"(rules removed since the daemon started count until a restart); their networks are held for kill-switched lists",
				over, ksSourceMax)
		}
	}
	var told []pbr.GuardSource
	for k := range l.sources {
		if j.side(k.Dev) != sideProvider && j.tunnelDevice(k.Dev) {
			told = append(told, k)
		}
	}
	sort.Slice(told, func(a, b int) bool { return lessSource(told[a], told[b]) })
	return told
}

// guardSources is the source routing the guard is told about.
func (s *Server) guardSources() []pbr.GuardSource {
	if s == nil {
		return nil
	}
	s.ksLocal.mu.Lock()
	defer s.ksLocal.mu.Unlock()
	return append([]pbr.GuardSource(nil), s.ksLocal.toldSource...)
}

// sourceRoutedFindings says what the operator's own source routing means for the kill switch:
// which kill-switched lists a source-routed segment reaches by its own tunnel
// instead of the list's, and which segment is held because its rule leads to the provider or to a
// device that is not a tunnel. held says a names hold is armed.
func sourceRoutedFindings(plan *pbr.Plan, routes []ksSourceRoute, held bool) []PlanFinding {
	if plan == nil || len(routes) == 0 {
		return nil
	}
	lists := plan.GuardedLists()
	if len(lists) == 0 && len(plan.GuardNameSets) == 0 && !held {
		return nil
	}
	owner := func(o pbr.ZoneOrigin, zone string) string {
		switch {
		case o.ID == "":
			return zone
		case o.Kind == pbr.ZoneFromRule:
			return fmt.Sprintf("the routing rule %q", o.ID)
		}
		return fmt.Sprintf("the list %q", o.ID)
	}
	names := ""
	if len(plan.GuardNameSets) > 0 {
		var ids []string
		for _, ns := range plan.GuardNameSets {
			ids = append(ids, ns.ID)
		}
		names = strings.Join(ids, ", ")
	}
	var out []PlanFinding
	for _, r := range routes {
		// The lists that cover the segment, and of them the ones whose own tunnels do not include
		// the segment's device.
		var other, all []string
		for _, l := range lists {
			if !listCoversSource(l, r) {
				continue
			}
			name := owner(l.Origin, l.Zone)
			all = append(all, name)
			mine := false
			for _, d := range l.Devices {
				mine = mine || d == r.Dev
			}
			if !mine {
				other = append(other, name+" (its tunnels: "+strings.Join(l.Devices, ", ")+")")
			}
		}
		rule := "the router's own rule \"" + r.Line + "\" sends everything from " + r.label() + " out by " + r.Dev + ", whatever WayHop's lists say"
		if r.ok() {
			if len(other) == 0 && names == "" {
				continue
			}
			detail := rule + ". For that network " + r.Dev + " is the way out you chose, so the kill switch lets it through there"
			if len(other) > 0 {
				detail += ": its traffic to " + strings.Join(other, ", ") + " leaves by " + r.Dev + ", not by the list's own tunnels, in every state"
			}
			if names != "" {
				detail += ". The addresses WayHop has noted for kill-switched names (" + names + ") leave by " + r.Dev + " from that network too"
			}
			detail += ". It never leaves by the provider: on the provider's device the kill switch drops it as for everyone else. " +
				"Block lists are dropped for that network as well"
			out = append(out, PlanFinding{
				ID: findingSourceRouted, Setting: "kill switch", Item: r.label() + " by " + r.Dev,
				Requested: "kill-switched lists by their own tunnels", Effective: r.label() + " reaches them by " + r.Dev,
				Severity: platform.SeverityDegraded, Reason: platform.ReasonModeConflict, Blocks: platform.BlocksNothing,
				Detail: detail,
				Remedy: "Nothing is required if that network is meant to leave by " + r.Dev + ". To have it follow the lists' tunnels instead, remove the " +
					"rule and route the network in WayHop (a routing rule with that source).",
			})
			continue
		}
		if len(all) == 0 && names == "" && !held {
			continue
		}
		why := "is not a tunnel WayHop can tell (not one of its own, and not an interface with a tunnel protocol in the network configuration)"
		if r.Side == sideProvider {
			why = "is the provider's side"
		}
		detail := rule + ", and " + r.Dev + " " + why + ". The kill switch does not let a kill-switched destination leave there: from that network "
		if len(all) > 0 {
			detail += strings.Join(all, ", ") + " cannot be reached"
		} else {
			detail += "the addresses of kill-switched names cannot be reached"
		}
		if held {
			detail += ", and while the names hold stands (the proxy core runs, or has just stopped) every new connection of that network " +
				"to a public address is held"
		}
		out = append(out, PlanFinding{
			ID: findingSourceHeld, Setting: "kill switch", Item: r.label() + " by " + r.Dev,
			Requested: "kill-switched lists by a tunnel", Effective: r.label() + " is held on " + r.Dev,
			Severity: platform.SeverityDegraded, Reason: platform.ReasonModeConflict, Blocks: platform.BlocksNothing,
			Detail: detail,
			Remedy: "Point the rule's table at a tunnel (an interface with a tunnel protocol, in a firewall zone apart from the uplink), or remove the " +
				"rule and route the network in WayHop. If that network must use the provider, take what it needs out of the kill-switched lists.",
		})
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Item < out[b].Item })
	return out
}

// listCoversSource reports whether a kill-switched zone can match a packet of the segment: a zone
// limited to other sources does not.
func listCoversSource(l pbr.GuardedList, r ksSourceRoute) bool {
	if len(l.Src) == 0 || !r.Src.IsValid() {
		return true
	}
	overlap := false
	for _, p := range l.Src {
		overlap = overlap || p.Overlaps(r.Src)
	}
	return overlap || l.SrcNegate
}
