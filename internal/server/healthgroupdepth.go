package server

import (
	"context"
	"fmt"
	"strings"

	"wayhop/internal/model"
)

// healthgroupdepth.go answers a question a green battery could otherwise hide: is a failover group as
// deep as it looks?
//
// The kernel plane can only fall to a member that has a real link. A group mixing a native tunnel
// with one the proxy core carries has fewer exits than names, and the difference only shows when the
// first one dies. Measured on a live AX3000T: group-failover lists tunnel-a (interface awg1) and
// proxy-member (a sing-box socks outbound at 10.0.1.2:1080), its policy table holds exactly one route
// and no blackhole, and the group carries no kill switch. So when awg1 goes down there is nothing to
// elect, the fwmark lookup falls through to main, and traffic meant for a tunnel leaves through the
// provider in the clear.
//
// The Failover card already says this. It is said again here for the reason listsInForceCheck exists:
// that card is read while choosing members, and this battery is where someone goes with "is it
// working?" — the moment the difference matters is the moment nobody is looking at the card.

// groupDepth is one group's kernel depth against the names it carries.
type groupDepth struct {
	ID, Name   string
	Electable  int
	Members    int
	KillSwitch bool
}

// shallowKernelGroups reports the groups the kernel routes whose depth is less than their membership.
// electable comes from kernelElectableMembers: capability, not health, so the answer does not flicker
// as members blink.
func shallowKernelGroups(groups []model.Group, electable map[string][]string) []groupDepth {
	var out []groupDepth
	for i := range groups {
		g := &groups[i]
		members, routed := electable[g.ID]
		if !routed {
			continue // the kernel carries none of this group's lists; nothing to be shallow about
		}
		if len(members) >= len(g.Members) {
			continue
		}
		out = append(out, groupDepth{ID: g.ID, Name: nameOrID(g.Name, g.ID),
			Electable: len(members), Members: len(g.Members), KillSwitch: g.KillSwitch})
	}
	return out
}

// groupDepthConsequence names what happens once the kernel-routable members are gone. The two
// outcomes are opposite in the way that matters, so the sentence must not average them.
func groupDepthConsequence(killSwitch bool) string {
	if killSwitch {
		return "once none of those is up, that traffic is dropped"
	}
	return "once none of those is up, that traffic leaves through the provider"
}

// groupDepthCheck is the battery row.
func (s *Server) groupDepthCheck(_ context.Context) healthRow {
	row := healthRow{ID: "group_depth", Label: "Failover groups are as deep as they look"}
	if s == nil || s.store == nil {
		row.Status, row.Summary = "na", "not checked here"
		return row
	}
	electable := s.kernelElectableMembers()
	if len(electable) == 0 {
		row.Status, row.Summary = "na", "the kernel plane routes no failover group here"
		return row
	}
	profile := s.store.Profile()
	shallow := shallowKernelGroups(profile.Groups, electable)
	if len(shallow) == 0 {
		row.Status = "pass"
		row.Summary = fmt.Sprintf("%s as deep in the kernel as %s names",
			countWordGroupsAre(len(electable)), pluralIt(len(electable)))
		return row
	}
	names := make([]string, 0, len(shallow))
	for _, g := range shallow {
		names = append(names, fmt.Sprintf("%s (%d of %d)", g.Name, g.Electable, g.Members))
	}
	row.Status = "warn"
	row.Summary = fmt.Sprintf("%s fewer exits in the kernel than %s names",
		countWordGroups(len(shallow)), pluralIt(len(shallow)))
	row.Detail = strings.Join(names, ", ") + " — only members with a kernel link can be elected; " +
		groupDepthConsequence(shallow[0].KillSwitch) + "."
	row.Fix = "Give the group a second member the kernel can route to (a native tunnel), or turn on its kill switch so the traffic is dropped rather than sent out the provider."
	return row
}

// countWordGroups keeps the singular honest, for the reason countWordLists spells out: a router that
// writes "1 groups" invites the reader to doubt the number beside it. Two forms because the two
// sentences need different verbs, and "1 group has as deep as it names" is the kind of line that
// makes a reader stop reading the number.
func countWordGroups(n int) string {
	if n == 1 {
		return "1 group has"
	}
	return fmt.Sprintf("%d groups have", n)
}

func countWordGroupsAre(n int) string {
	if n == 1 {
		return "1 group is"
	}
	return fmt.Sprintf("%d groups are", n)
}

func pluralIt(n int) string {
	if n == 1 {
		return "it"
	}
	return "they"
}
