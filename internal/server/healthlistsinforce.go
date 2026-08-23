package server

import (
	"context"
	"fmt"
	"strings"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// healthlistsinforce.go answers the question the battery never asked: are the routing lists this
// router is configured with actually carrying anything?
//
// Every other row asks a question about the ROUTER — is the clock right, is the tunnel reachable, is
// the kernel plane installed, is there disk. Each can be a truthful "pass" while the thing the
// operator actually configured does nothing. That is not hypothetical: on a live OpenWrt the
// battery reported healthy across the board while ELEVEN of fifteen routing lists were inert. Every
// answer was correct in isolation — tunnels handshaking, exit IP resolved, DNS answering, and
// "Kernel routing (PBR): active — 4 zone(s) applied", which was true of the four IP/CIDR lists. The
// other eleven are domain lists, which in "fast" mode only the proxy core can match, and in that mode
// there is no TUN, so no LAN packet ever reaches the core. Nothing compared "lists configured"
// against "lists carried", so nothing said a word.
//
// The panel does say it elsewhere: the mode selector calls fast mode "domain carve-outs OFF" and the
// apply review notes "rules use the userspace fallback". Both are seen once, on other screens, at a
// moment when the operator is choosing something rather than asking what is wrong. The battery is
// where someone goes with "is it working?", so the answer belongs here.

// listCarrier records why one list is or is not carried.
type listCarrier struct {
	ID     string
	Name   string
	Reason string // empty when the list IS in force
}

// listsInForce classifies every ENABLED list as carried or not.
//
// A list is in force when the kernel plane holds a zone for it, or when the proxy core holds it AND
// something routes LAN traffic into the core. The second half is the one that was missing: a list can
// sit in the core's config, perfectly valid, and still match nothing because no packet arrives.
//
// coreConfigKnown=false means the running core config could not be read. Then a core-carried list is
// UNKNOWN rather than broken, and is reported as neither — accusing a working list because a file
// could not be opened is the failure mode this check must not have.
func listsInForce(lists []model.RoutingList, zones map[string]bool,
	coreVisible map[string]bool, coreConfigKnown, coreSeesLANTraffic bool) (inForce, notInForce, unknown []listCarrier) {
	for i := range lists {
		rl := &lists[i]
		if !rl.Enabled {
			continue // a switched-off list is not a fault; it is a decision
		}
		entry := listCarrier{ID: rl.ID, Name: nameOrID(rl.Name, rl.ID)}
		if zones[pbr.ListZoneName(rl.ID)] {
			inForce = append(inForce, entry)
			continue
		}
		if !coreConfigKnown {
			entry.Reason = "the running proxy configuration could not be read, so this was not checked"
			unknown = append(unknown, entry)
			continue
		}
		if coreVisible[rl.ID] {
			if coreSeesLANTraffic {
				inForce = append(inForce, entry)
				continue
			}
			entry.Reason = "only the proxy core can match this list, and in this routing mode no LAN traffic reaches the core"
			notInForce = append(notInForce, entry)
			continue
		}
		entry.Reason = "neither the kernel plane nor the proxy core carries it"
		notInForce = append(notInForce, entry)
	}
	return inForce, notInForce, unknown
}

// listsInForceCheck is the battery row. It names the lists that are not carried, because "some lists
// are inert" sends the operator to compare fifteen rows by hand, which is the work this exists to do.
func (s *Server) listsInForceCheck(ctx context.Context) healthRow {
	row := healthRow{ID: "lists_in_force", Label: "Routing lists in force"}
	if s == nil || s.store == nil {
		row.Status, row.Summary = "na", "not checked here"
		return row
	}
	profile := s.store.Profile()
	enabled := 0
	for i := range profile.RoutingLists {
		if profile.RoutingLists[i].Enabled {
			enabled++
		}
	}
	if enabled == 0 {
		row.Status, row.Summary = "pass", "no routing lists are configured"
		return row
	}

	cfg := s.config()
	mode := s.routingMode(cfg)
	zones := map[string]bool{}
	if base := s.appliedBaseline(); base != nil {
		if plan := base.Materialization.kernelPlan(); plan != nil {
			for _, z := range plan.Zones {
				zones[z.Name] = true
			}
		}
	}
	coreVisible, coreConfigKnown := coreVisibleLists(cfg.SingBox.Config)
	if cfg.Demo {
		// The demo runs no sing-box, so the file this reads never exists and every list would report
		// "not checked" — leaving the warn path, the whole point of this row, as the one path the demo
		// can never show. listtraffic.go answers the same question the same way and for the same
		// reason: an enabled list is what the core would have been given.
		coreVisible, coreConfigKnown = map[string]bool{}, true
		for i := range profile.RoutingLists {
			coreVisible[profile.RoutingLists[i].ID] = profile.RoutingLists[i].Enabled
		}
	}
	// Only a TUN puts transparently-routed LAN traffic in front of the core. "mixed" is a local proxy
	// by definition and "fast" deliberately keeps the kernel fast-path, so in both the core sees only
	// what is aimed at its own port.
	coreSeesLAN := mode == "tun" || mode == "hybrid"

	in, out, unknown := listsInForce(profile.RoutingLists, zones, coreVisible, coreConfigKnown, coreSeesLAN)
	switch {
	case len(out) == 0 && len(unknown) == 0:
		row.Status = "pass"
		row.Summary = fmt.Sprintf("%s in force", countWordLists(len(in)))
		return row
	case len(out) == 0:
		row.Status = "na"
		row.Summary = fmt.Sprintf("%s in force · %d not checked here", countWordLists(len(in)), len(unknown))
		row.Detail = unknown[0].Reason
		return row
	}
	row.Status = "warn"
	row.Summary = fmt.Sprintf("%d of %d configured lists match nothing on this router", len(out), len(in)+len(out)+len(unknown))
	row.Detail = strings.Join(listCarrierNames(out, 6), ", ") + " — " + out[0].Reason
	// The remedy depends on WHY, and there is only one why worth a sentence: the core holds the list
	// but nothing feeds it. Naming the two modes that do is more use than "check your configuration".
	if strings.Contains(out[0].Reason, "no LAN traffic reaches the core") {
		row.Fix = "Switch routing mode to hybrid or tun so the core sees LAN traffic, or express these lists as IP/CIDR so the kernel can carry them in " + mode + " mode."
	} else {
		row.Fix = "Apply the configuration so the kernel plane picks these lists up, or check that their outbound still exists."
	}
	return row
}

// listCarrierNames renders at most max names, saying how many it left out rather than truncating
// silently — a list of five when there are twelve reads as "only five are affected".
func listCarrierNames(entries []listCarrier, max int) []string {
	out := make([]string, 0, max+1)
	for i, e := range entries {
		if i == max {
			out = append(out, fmt.Sprintf("and %d more", len(entries)-max))
			break
		}
		out = append(out, e.Name)
	}
	return out
}

// countWordLists keeps the singular honest: "1 lists in force" is the kind of detail that makes a
// reader doubt the number next to it.
func countWordLists(n int) string {
	if n == 1 {
		return "1 list"
	}
	return fmt.Sprintf("%d lists", n)
}
