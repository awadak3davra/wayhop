package server

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"wayhop/internal/dnscheck"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// overlapreview.go is Review's account of lists that share addresses on the KeeneticOS kernel plane
// (FIXES.md "Kill switch audit / precedence").

const (
	findingOverlap    = "routing_list.overlap"
	findingOverridden = "kill_switch.overridden"
	findingHandoff    = "routing_list.handoff"
	findingSharedCDN  = "routing_list.shared_cdn"
)

// ipCheckDomains are address-echo services apps ask to learn the address they appear from (some
// apps' VPN detection asks the first three). A list of nothing else is one whose purpose
// is to show a Russian address.
var ipCheckDomains = map[string]bool{
	"api.ipify.org": true, "checkip.amazonaws.com": true, "ifconfig.me": true, "ifconfig.co": true,
	"icanhazip.com": true, "ipinfo.io": true, "ident.me": true, "api.myip.com": true,
}

// keeneticOverlapPreflight reports which list wins each static overlap, refuses a kill-switched list
// that would lose one, names the domain lists whose own names the sing-box hand-off keeps, and warns
// about direct domain lists whose names resolve into shared CDN anycast. members reads a live set
// (nil: not available).
func keeneticOverlapPreflight(prof model.Profile, carries bool, members func(set string) []netip.Prefix) []platform.Unsupported {
	if !carries {
		return nil
	}
	plan, _, err := pbr.Compile(&prof, pbr.Options{CollectDomainZones: true, ListEgresses: true})
	if err != nil || plan == nil {
		return nil
	}
	listOf := func(zone string) string {
		if ids := listIDsOfZones(plan, []string{zone}); len(ids) == 1 {
			return ids[0]
		}
		return strings.TrimPrefix(zone, "list_")
	}
	var out []platform.Unsupported
	for _, o := range plan.Overlaps() {
		l, w := listOf(o.Loser), listOf(o.Winner)
		if o.Leaks() {
			out = append(out, platform.Unsupported{
				Setting: findingOverridden + ":" + l, Value: w, Severity: platform.SeverityPrivacy,
				Reason: fmt.Sprintf("%d address ranges of the kill-switched list %q are also in %q, which would take them past the kill switch", o.Count, l, w),
				Remedy: fmt.Sprintf("Remove the shared ranges from %q, or put it under the same kill switch.", w),
			})
			continue
		}
		out = append(out, platform.Unsupported{
			Setting: findingOverlap + ":" + l + ":" + w, Value: strconv.Itoa(o.Count), Severity: platform.SeverityDegraded,
			Reason: fmt.Sprintf("%d address ranges of %q are also in %q, which routes elsewhere; %q wins them (direct lists yield to tunnels, "+
				"tunnels to kill-switched tunnels, everything to a block; otherwise lists of names yield to lists of addresses, then by name)", o.Count, l, w, w),
			Remedy: "Nothing is required if that is the intended exit for the shared ranges; otherwise remove them from one list.",
		})
	}
	h := plan.Handoff()
	winners := map[string][]string{}
	for _, p := range h.Pairs {
		winners[p.Domain] = append(winners[p.Domain], listOf(p.Stronger))
	}
	for _, r := range h.Routes {
		x := listOf(r.Zone)
		others := strings.Join(winners[r.Zone], ", ")
		out = append(out, platform.Unsupported{
			Setting: findingHandoff + ":" + x, Value: others, Severity: platform.SeverityDegraded,
			Reason: fmt.Sprintf("the names of %q can resolve to addresses that %s also hold; those addresses follow that list, and the names of %q "+
				"are told apart from other sites on them by sing-box (SNI/Host) and keep their own exit. While the core is not running they "+
				"follow the other list too", x, others, x),
			Remedy: "Nothing is required.",
		})
	}
	cdn := dnscheck.CloudflareRanges()
	for _, z := range plan.Zones {
		if len(z.Domains) == 0 || z.SrcScoped || !zoneIsDirect(plan, z) {
			continue
		}
		x := listOf(z.Name)
		if members != nil {
			n := 0
			for _, p := range members(pbr.IpsetOptions{}.ZoneSetName(z.Name, "4")) {
				for _, c := range cdn {
					if c.Overlaps(p) {
						n++
						break
					}
				}
			}
			if n > 0 {
				out = append(out, platform.Unsupported{
					Setting: findingSharedCDN + ":" + x, Value: strconv.Itoa(n), Severity: platform.SeverityDegraded,
					Reason: fmt.Sprintf("%d of the addresses the names of %q resolved to are Cloudflare's shared anycast. A list sent direct acts on "+
						"addresses, so every other site on them would leave by the provider too; lists that route those addresses through a "+
						"tunnel keep them, and only this list's own names go direct", n, x),
					Remedy: "Send the list through a tunnel instead of direct if its names must not decide for other sites.",
				})
			}
		}
		onlyChecks := true
		for _, d := range z.Domains {
			onlyChecks = onlyChecks && ipCheckDomains[d]
		}
		if onlyChecks {
			out = append(out, platform.Unsupported{
				Setting: findingSharedCDN + ":ipcheck:" + x, Value: x, Severity: platform.SeverityDegraded,
				Reason: fmt.Sprintf("%q holds only address-check services, which apps ask to see where they connect from. Sent direct they show "+
					"the provider's address, and their shared anycast addresses pull other sites along", x),
				Remedy: "Send the list through a Russian exit (a tunnel or group with a Russian server) instead of direct: the checks still see " +
					"a Russian address, and nothing leaves by the provider.",
			})
		}
	}
	return out
}

func zoneIsDirect(plan *pbr.Plan, z pbr.Zone) bool {
	for _, e := range plan.Egresses {
		if e.Tag == z.EgressTag {
			return e.Kind == pbr.EgressWAN
		}
	}
	return false
}

// liveSetMembers reads members of the applied Keenetic plane's sets, for Review; nil off that plane.
func (s *Server) liveSetMembers() func(set string) []netip.Prefix {
	base := s.appliedBaseline()
	if base == nil || base.Materialization.Kernel.Ipset == nil {
		return nil
	}
	adapter, err := newExactKeeneticKernelAdapter(*base.Materialization.Kernel.Ipset)
	if err != nil {
		return nil
	}
	read := withDynamicMembers(ipsetMembers(adapter), base.Materialization.Kernel.Plan, base.Materialization.Kernel.Ipset.DynamicDomainSets)
	return func(set string) []netip.Prefix {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		got, err := read(ctx, set)
		if err != nil {
			return nil
		}
		return got
	}
}
