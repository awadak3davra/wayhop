package server

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// killswitchreview.go is what Review says about a kill switch on the KeeneticOS kernel plane before
// Apply: the backstop's size against its cap, the lists it cannot cover, and kill-switched names the
// router's resolver would look up by its own upstreams.

const (
	findingBackstopCap    = "kill_switch.backstop_cap"
	findingBackstopNear   = "kill_switch.backstop_near"
	findingBackstopScoped = "kill_switch.backstop_scoped"
	// findingKillSwitchIntercept: a kill-switched list of names without DNS interception that refuses
	// encrypted DNS.
	findingKillSwitchIntercept = "kill_switch.dns_intercept"
	// findingBackstopBypass: a tunnel server inside a kill-switched list.
	findingBackstopBypass = "kill_switch.backstop_bypass"
	// findingKillSwitchNeedsOpt: the kill switch lives on the Entware volume.
	findingKillSwitchNeedsOpt = "kill_switch.needs_opt"
)

// keeneticInterceptsAllDNS reports whether clients' DNS is answered by the router whatever they ask:
// plain DNS redirected, DoT and the well-known DoH endpoints refused.
func keeneticInterceptsAllDNS(prof model.Profile) bool {
	return prof.DNS != nil && prof.DNS.Enabled && prof.DNS.Intercept && prof.DNS.InterceptRejectEncrypted
}

// killSwitchBypassOverlap names the tunnel servers (the plan's bypass addresses) inside a kill-switched
// list's static prefixes.
func killSwitchBypassOverlap(plan *pbr.Plan) []string {
	bs := plan.KillSwitchBackstop(pbr.IpsetOptions{})
	cover := append(append([]netip.Prefix(nil), bs.V4...), bs.V6...)
	var out []string
	for _, c := range append(append([]string(nil), plan.BypassV4...), plan.BypassV6...) {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			a, aerr := netip.ParseAddr(c)
			if aerr != nil {
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		for _, k := range cover {
			if k.Bits() <= p.Bits() && k.Contains(p.Addr()) {
				out = append(out, p.Addr().String())
				break
			}
		}
	}
	sort.Strings(out)
	return out
}

// keeneticKillSwitchPreflight is the Keenetic kernel plane's kill switch review. carries says whether
// that plane routes the lists in this mode (keeneticKernelPlaneCarriesLists).
func keeneticKillSwitchPreflight(c config.Config, prof model.Profile, carries bool) []platform.Unsupported {
	if !carries {
		return nil
	}
	plan, _, err := pbr.Compile(&prof, pbr.Options{CollectDomainZones: true, ListEgresses: true})
	if err != nil || plan == nil {
		return nil // the compile's own error is reported by the Apply that runs it
	}
	var out []platform.Unsupported
	bs := plan.KillSwitchBackstop(pbr.IpsetOptions{})
	n, max := bs.Routes(), ksBackstopMax(c)
	mb := func(routes int) string { return fmt.Sprintf("%.1f MB", float64(routes)*ksRouteBytes/1e6) }
	switch {
	case n > max:
		out = append(out, platform.Unsupported{
			Setting: findingBackstopCap, Value: strconv.Itoa(n), Severity: platform.SeverityBlocked,
			Reason: fmt.Sprintf("the kill-switched lists need %d backstop routes after aggregation, more than the cap of %d "+
				"(about %s of router memory against %s); without its backstop the kill switch would leak while KeeneticOS rebuilds its firewall",
				n, max, mb(n), mb(max)),
			Remedy: "Make the kill-switched lists smaller, or raise kill_switch_backstop_max in config.json if the router has the memory.",
		})
	case n > max*8/10:
		out = append(out, platform.Unsupported{
			Setting: findingBackstopNear, Value: strconv.Itoa(n), Severity: platform.SeverityDegraded,
			Reason: fmt.Sprintf("the kill-switched lists need %d of the %d backstop routes the cap allows (about %s); "+
				"addresses their domain names resolve to are added only while room is left", n, max, mb(n)),
			Remedy: "Nothing is required. Raise kill_switch_backstop_max in config.json if the domain lists are large.",
		})
	}
	// The backstop is a routing table looked up by interface and mark; it cannot tell
	// devices apart (an ip rule has no MAC match, and a device's address is the DHCP server's to
	// change). A kill-switched list scoped to some devices, or carried by an access policy, therefore
	// leaks to the provider in every firewall rebuild and at boot. Under the operator's rule "no traffic
	// of a kill-switched list reaches the provider in any state" that is refused, not advised.
	// A routing rule with a source matcher (MAC, address, interface, port) is scoped the
	// same way, and is refused by its zone like a list.
	scoped := originsOfZones(plan, plan.KillSwitchScopedZones())
	for _, o := range scoped {
		// A list also fails closed by its own "block when all tunnels are down"; the text
		// names the cause the profile has, and the remedy that matches it.
		cause, off := "a kill switch", "switch the kill switch off for its group"
		item, what := o.ID, fmt.Sprintf("the list %q is", o.ID)
		remedy := "Apply the list to all devices, or " + off + "."
		if o.Kind == pbr.ZoneFromRule {
			item, what = "rule_"+o.ID, fmt.Sprintf("the routing rule %q (it matches a source device, address, interface or port) is", o.ID)
			remedy = "Route those destinations by a routing list or rule for all devices, or switch the kill switch off for the rule's group."
		} else if rl := prof.RoutingListByID(o.ID); rl != nil && !model.ListKillSwitch(&prof, *rl) {
			cause = "\"block when all tunnels are down\""
			remedy = "Apply the list to all devices, or set its \"when all tunnels are down\" to send by the provider."
		}
		out = append(out, platform.Unsupported{
			Setting: findingBackstopScoped + ":" + item, Value: o.ID, Severity: platform.SeverityBlocked,
			Reason: fmt.Sprintf("%s under %s for some devices only (or through an access policy). On KeeneticOS that hold is "+
				"enforced by a routing backstop that holds traffic by interface, not by device, so every time KeeneticOS rebuilds its firewall "+
				"(every few minutes) and while the router boots, those devices' traffic would reach the provider", what, cause),
			Remedy: remedy,
		})
	}
	// Everything the kill switch holds with comes from the Entware volume: the hook, the
	// restore files, WayHop. If /opt does not mount (a USB stick, a filesystem error after a power cut)
	// no hook runs and KeeneticOS routes everything by the provider. Only a KeeneticOS-native setting
	// could hold that.
	if bs.Active() || len(scoped) > 0 {
		out = append(out, platform.Unsupported{
			Setting: findingKillSwitchNeedsOpt, Severity: platform.SeverityDegraded,
			Reason: "the kill switch is enforced from the Entware volume (/opt). If it does not mount after a reboot, there is no kill " +
				"switch at all: the router sends the kill-switched lists' traffic and DNS by the provider until /opt is back",
			Remedy: "Keep the Entware volume healthy (internal storage rather than a USB stick where the router allows it). For a " +
				"guarantee without /opt, block the destinations in KeeneticOS itself as well.",
		})
	}
	// A list of names is marked, and backstopped, by the addresses dnsmasq put in its set.
	// A client that asks its own resolver (a hardcoded 8.8.8.8, DoT, DoH) never fills it, and that
	// traffic leaves by the provider in steady state. Interception with encrypted DNS refused closes
	// all but DoH to an arbitrary host, and a lookup inside NDM's rebuild window (the redirect is
	// rebuilt like the chain), which no rule can tell apart: said, not hidden.
	if !keeneticInterceptsAllDNS(prof) {
		for _, id := range listIDsOfZones(plan, plan.KillSwitchDomainZones()) {
			out = append(out, platform.Unsupported{
				Setting: findingKillSwitchIntercept + ":" + id, Value: id, Severity: platform.SeverityBlocked,
				Reason: fmt.Sprintf("the list %q holds domain names under a kill switch, and they are routed by the addresses the router's "+
					"resolver learns for them: a device that asks its own resolver (a fixed 8.8.8.8, DNS over TLS) never fills the list, and its "+
					"traffic to those sites leaves by the provider. With interception on and encrypted DNS refused that is closed, except for "+
					"DNS over HTTPS to a server that is not one of the well-known resolvers, and lookups made in the seconds KeeneticOS takes "+
					"to rebuild its firewall: neither can be told apart from other traffic", id),
				Remedy: "On the DNS page turn on \"Intercept clients' DNS\" with \"Refuse encrypted DNS\". Or make the list one of addresses " +
					"(CIDR) only, or switch the kill switch off.",
			})
		}
	}
	// The marking chain leaves a tunnel server unmarked (anti-loop), so with the server
	// inside a kill-switched list the backstop drops a LAN device's own connection to it.
	if over := killSwitchBypassOverlap(plan); len(over) > 0 {
		out = append(out, platform.Unsupported{
			Setting: findingBackstopBypass, Value: strings.Join(over, ", "), Severity: platform.SeverityDegraded,
			Reason: fmt.Sprintf("the tunnel server(s) %s lie inside a kill-switched list: the router itself still reaches them, but a device "+
				"on the LAN that connects to one directly (its own VPN client to the same server) is blocked by the kill switch", strings.Join(over, ", ")),
			Remedy: "Nothing is required. To let LAN devices reach that server directly, take its address out of the kill-switched list.",
		})
	}
	if servedDNSPort(c, prof) == 0 {
		for _, id := range listIDsOfZones(plan, plan.KillSwitchDomainZones()) {
			rl := prof.RoutingListByID(id)
			via := ""
			if rl != nil {
				via = rl.Outbound
			}
			out = append(out, platform.Unsupported{
				Setting: "dns_path:killswitch:" + id, Value: via, Severity: platform.SeverityPrivacy,
				Reason: fmt.Sprintf("the list %q holds domain names under a kill switch, and WayHop's DNS listener is off: the router's resolver "+
					"would look them up through its own upstreams, by the provider when those are direct", id),
				Remedy: "On the DNS page turn on the DNS plane with \"Serve clients\", so the list's names are asked of WayHop alone " +
					"and fail while the tunnel is down. Or switch the kill switch off.",
			})
		}
	}
	return out
}

// ksRouteBytes is the kernel memory one backstop route costs, as estimated in ksBackstopDefaultMax.
const ksRouteBytes = 130

// originsOfZones maps zone names back to the lists and rules they were compiled from, de-duplicated
// and sorted by kind then id. By the zone's recorded origin, not by name (a prefix match
// would name list "x" for a zone of list "x_dns", and a rule's zone would match no list at all).
func originsOfZones(plan *pbr.Plan, zones []string) []pbr.ZoneOrigin {
	seen := map[pbr.ZoneOrigin]bool{}
	var out []pbr.ZoneOrigin
	for _, z := range zones {
		if o, ok := plan.ZoneOrigin(z); ok && !seen[o] {
			seen[o] = true
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// listIDsOfZones is the routing lists among originsOfZones.
func listIDsOfZones(plan *pbr.Plan, zones []string) []string {
	var out []string
	for _, o := range originsOfZones(plan, zones) {
		if o.Kind == pbr.ZoneFromList {
			out = append(out, o.ID)
		}
	}
	return out
}
