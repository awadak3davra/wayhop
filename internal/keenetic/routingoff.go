package keenetic

import (
	"errors"
	"sort"
)

// Turning WayHop's routing off on KeeneticOS removes the two things a native plan routes with — its
// `ip route` commands (RouteTeardownCommands) and the `ip global` ladder that hands the default route
// to a tunnel — and keeps the interfaces themselves, so turning routing back on is one commit away.

// errNoRouterLadder: without a priority on any connection the plan did not raise, there is nothing
// the default route could be handed back to, and any number written would be a guess.
var errNoRouterLadder = errors.New("no connection the router owns carries an `ip global` priority: there is nothing to hand the default route back to")

// RoutingOffPriorities is the `ip global` each interface the plan raised has to go back to so the
// router's own connections hold the default route again.
//
// GlobalPriorityWas is not enough on its own. It records what the interface read when THIS plan was
// compiled, and a plan compiled over an earlier WayHop ladder records that ladder's raised number
// (re-raising Wireguard3 records Was=33330 — see the nativeplan reconcile tests). That is the right
// value for undoing one Apply and the wrong one for "route as if WayHop were not routing". So a
// recorded value is used only when it sits below the router's own top connection (the ceiling: the
// highest priority on any interface the plan did not raise). An interface whose record is missing or
// sits at or above the ceiling is put below every connection the router owns, in ladder order: the
// router never told us its original number, and last place is the one position that cannot take
// the default route from a connection of the router's own. An interface the running config does not
// show is left out: there is nothing to lower.
//
// observed is the running config's ladder (GlobalPriorities). Pure — no device I/O.
func RoutingOffPriorities(plan *Plan, observed map[string]int) (map[string]int, error) {
	if plan == nil || len(plan.GlobalPriority) == 0 {
		return nil, nil
	}
	ceiling, floor := 0, 0
	for iface, prio := range observed {
		if _, ours := plan.GlobalPriority[iface]; ours || prio <= 0 {
			continue
		}
		if prio > ceiling {
			ceiling = prio
		}
		if floor == 0 || prio < floor {
			floor = prio
		}
	}
	if ceiling == 0 {
		return nil, errNoRouterLadder
	}
	ifaces := make([]string, 0, len(plan.GlobalPriority))
	for iface := range plan.GlobalPriority {
		ifaces = append(ifaces, iface)
	}
	// Ladder order (highest first, ties by name) so the lowered interfaces keep their relative order.
	sort.Slice(ifaces, func(i, j int) bool {
		pi, pj := plan.GlobalPriority[ifaces[i]], plan.GlobalPriority[ifaces[j]]
		if pi != pj {
			return pi > pj
		}
		return ifaces[i] < ifaces[j]
	})
	out := make(map[string]int, len(ifaces))
	next := floor - 1
	for _, iface := range ifaces {
		if _, present := observed[iface]; !present {
			// Not in the running config (gone, or never given a priority): nothing holds a default
			// route there, and `interface X` for a name NDM does not know would create one.
			continue
		}
		if was, known := plan.GlobalPriorityWas[iface]; known && was > 0 && was < ceiling {
			out[iface] = was
			continue
		}
		if next < 1 {
			next = 1
		}
		out[iface] = next
		next--
	}
	return out, nil
}

// LadderBlocks renders an `ip global` assignment as the same NDM command blocks the plan's own
// ladder uses, sorted by interface name.
func LadderBlocks(ladder map[string]int) [][]string { return priorityBlocks(ladder) }
