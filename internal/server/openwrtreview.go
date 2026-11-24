package server

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/ctflush"
	"wayhop/internal/model"
	"wayhop/internal/netvpn"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// openwrtreview.go is what Review says about the nft plane from the router's own state: rules that
// are not WayHop's and read its marks or tables, tunnels the firewall does not forward to, and what
// a kill switch over names costs.

const (
	findingForeignRule    = "kernel_plane.foreign_rule"
	findingNoForward      = "kernel_plane.tunnel_not_forwarded"
	findingNamesHold      = "kill_switch.names_hold"
	findingNamesUnheld    = "kill_switch.names_unheld"
	findingOffloadNoReset = "kill_switch.offload_no_reset"
	findingGuardLarge     = "kill_switch.guard_large"
	findingResetNoModule  = "routing_list.fastest_reset_unavailable"
	openwrtReviewReadTime = 5 * time.Second
)

// openwrtRuleReader reads `ip rule show` and `ip -6 rule show`. A variable so tests answer with a
// router's dump.
var openwrtRuleReader = func(ctx context.Context) (v4, v6 string, err error) {
	ctx, cancel := context.WithTimeout(ctx, openwrtReviewReadTime)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "rule", "show").Output()
	if err != nil {
		return "", "", fmt.Errorf("ip rule show: %w", err)
	}
	out6, _ := exec.CommandContext(ctx, "ip", "-6", "rule", "show").Output() // no IPv6 on the router is not a fault
	return string(out), string(out6), nil
}

// openwrtPlaneFindings is the nft plane's review. Nothing on KeeneticOS, in the demo, or in a mode
// without a kernel plane.
func (s *Server) openwrtPlaneFindings(ctx context.Context, cfg config.Config, prof *model.Profile) []PlanFinding {
	if s == nil || prof == nil || cfg.Demo || s.detectedPlatform() != platform.OpenWrt {
		return nil
	}
	mode := s.routingMode(cfg)
	if mode != "hybrid" && mode != "fast" {
		return nil
	}
	plan, _, err := pbr.Compile(prof, s.pbrCompileOptions(cfg))
	if err != nil || plan == nil {
		return nil
	}
	var out []PlanFinding
	if v4, v6, err := openwrtRuleReader(ctx); err == nil {
		own := plan.RenderIP(pbr.Options{})
		if installed := s.installedKernelPlan(); installed != nil {
			own = append(own, installed.RenderIP(pbr.Options{})...)
		}
		out = append(out, foreignRuleFindings(v4, v6, own, plan, s.installedKernelPlan())...)
	}
	read := s.uciReader
	if read == nil {
		read = readUCI
	}
	if network, firewall, err := read(); err == nil {
		out = append(out, notForwardedFindings(plan, network, firewall)...)
		reading := ksReadLocalRoutes()
		sides, uplink := parseSides(network, firewall), s.everUplink(reading.Uplink)
		out = append(out, providerSideFindings(plan, sides, reading.Routes, uplink)...)
		// The operator's own source routing against the kill-switched lists.
		if d, err := ksReadSourceRouting(ctx, s.tableIO().read); err == nil {
			held := mode == "hybrid" && plan.GuardNames
			out = append(out, sourceRoutedFindings(plan, sourceRoutes(d, sides.judge(uplink, planTunnels(plan))), held)...)
		}
		out = append(out, s.sourceBoundFindings()...)
		if mode == "hybrid" {
			out = append(out, offloadFindings(plan, firewall)...)
		}
	}
	if mode == "fast" {
		out = append(out, offloadHWFindings(cfg, plan)...)
	}
	out = append(out, s.fastDNSReview(ctx, cfg, prof, plan)...)
	out = append(out, guardSizeFindings(plan)...)
	out = append(out, s.namesHoldFindings(cfg, plan)...)
	out = append(out, killSwitchResolverFindings(cfg, prof)...)
	out = append(out, resetUnavailableFindings(prof)...)
	return out
}

// findingOffloadHW is Review's warning about hardware flow offload in fast mode on OpenWrt.
const findingOffloadHW = "offload.hw_experimental"

// offloadHWFindings warns about hardware flow offload in fast mode on OpenWrt (requested as "hw", or
// "auto" resolved to it): on an MT7981 router (OpenWrt 25.12.6) it broke some HTTPS services
// (HTTP 000) and loaded the CPU to ~92 %, while "sw" worked but gained nothing over off. The cause is
// not established, so the hw path itself is unchanged; Review says so before the Apply. Advice only: it blocks nothing.
func offloadHWFindings(cfg config.Config, plan *pbr.Plan) []PlanFinding {
	hw := cfg.Offload == "hw" || (plan != nil && plan.Flowtable != nil && plan.Flowtable.HW)
	if !hw {
		return nil
	}
	return []PlanFinding{{
		ID: findingOffloadHW, Setting: "offload", Item: "hw", Requested: "hw", Effective: "degraded",
		Severity: platform.SeverityDegraded, Reason: platform.ReasonOperatorChoice, Blocks: platform.BlocksNothing,
		Detail: "Hardware flow offload in fast mode is experimental and known to break some sites on MT7981 routers " +
			"(measured on an MT7981 router: Instagram and Gemini stopped loading and the CPU went to ~92 %).",
		Remedy: "Set offload to sw or off.",
	}}
}

// killSwitchResolverFindings is the DNS half of a kill switch over names on OpenWrt. The lists' names
// are routed by the core, and their lookups are held to the list's tunnel by the core's DNS rules
// (the dns_path review refuses a direct server for them). That holds only for lookups the core
// answers: with "Serve clients" off the router's own resolver (dnsmasq) answers the home network and
// asks its upstreams, the provider's unless they were changed, for every name, these included.
func killSwitchResolverFindings(cfg config.Config, prof *model.Profile) []PlanFinding {
	if servedDNSPort(cfg, *prof) != 0 {
		return nil
	}
	var out []PlanFinding
	for _, rl := range prof.RoutingLists {
		if !rl.Enabled || !model.ListKillSwitch(prof, rl) {
			continue
		}
		if _, names := listEntryKinds(rl); names == 0 {
			continue
		}
		out = append(out, PlanFinding{
			ID: "dns_path:killswitch:" + rl.ID, Setting: "DNS", Item: rl.ID,
			Requested: "kill-switched names looked up through the tunnel", Effective: "looked up by the router's own resolver",
			Severity: platform.SeverityPrivacy, Reason: platform.ReasonModeConflict, Blocks: platform.BlocksNothing,
			Detail: fmt.Sprintf("the list %q holds domain names under a kill switch, and WayHop does not answer the home network's DNS: "+
				"the router's resolver looks those names up through its own upstreams, by the provider when those are the provider's", rl.ID),
			Remedy: "On the DNS page turn on the DNS plane with \"Serve clients\", so the list's names are asked of WayHop alone and " +
				"fail while the tunnel is down. Or keep the list to addresses (CIDR), or switch the kill switch off.",
		})
	}
	return out
}

// foreignRuleFindings reports the rules pbr.ForeignRules finds. own is every rule line
// WayHop installs, for the plan under review and the installed one.
func foreignRuleFindings(v4, v6 string, own []string, plans ...*pbr.Plan) []PlanFinding {
	// stops says which kill-switched list or group a rule takes the traffic of: the
	// rule wins over WayHop's own (a lower priority number) and sends that mark to its table, and
	// the kill-switch guard lets the list leave by its own tunnels only. Safe, and an outage of the
	// list for as long as the rule stands, which a warning about "another list's traffic" would not say.
	stops := func(r pbr.ForeignRule) string {
		for _, plan := range plans {
			if plan == nil || r.Mark == 0 {
				continue
			}
			for _, e := range plan.Egresses {
				if e.Mark != r.Mark || e.Table == r.Table || !(e.Kind == pbr.EgressInterface && e.FailClosed) {
					continue
				}
				owner := "the group " + e.Tag
				if id, ok := model.ListEgressID(e.Tag); ok {
					owner = "the list " + id
				}
				return fmt.Sprintf(". That mark is %s's, which is under a kill switch: the rule sends its traffic to table %d, and unless "+
					"that table leads to one of its own tunnels the kill switch drops it. While the rule stands, %s stops", owner, r.Table, owner)
			}
		}
		return ""
	}
	var out []PlanFinding
	for fam, dump := range map[string]string{"ip": v4, "ip -6": v6} {
		for _, r := range pbr.ForeignRules(dump, pbr.Options{}, own) {
			what := "looks up one of WayHop's routing tables"
			switch r.Why {
			case "mark":
				what = "matches one of WayHop's marks"
			case "mark+table":
				what = "matches one of WayHop's marks and looks up one of WayHop's routing tables"
			}
			out = append(out, PlanFinding{
				ID: findingForeignRule, Setting: "routing rule on the router", Item: fam + " rule " + strings.Join(strings.Fields(r.Line), " "),
				Requested: "WayHop's rules alone decide WayHop's marks", Effective: "another rule decides too",
				Severity: platform.SeverityDegraded, Reason: platform.ReasonModeConflict, Blocks: platform.BlocksNothing,
				Detail: fmt.Sprintf("the router has a rule WayHop did not install that %s: \"%s\". WayHop's marks (inside 0x00ff0000) and "+
					"tables (151 and up) belong to whichever list holds them now, not to the list they meant when the rule was written: "+
					"the rule can send another list's traffic through that tunnel%s", what, strings.Join(strings.Fields(r.Line), " "), stops(r)),
				Remedy: "Remove the rule and whatever adds it (a script in /usr/bin, /etc/rc.local, cron or hotplug). A group's failover is " +
					"WayHop's own job now. If the rule must stay, give it a mark outside 0x00ff0000 and a table below 151.",
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Item < out[j].Item })
	return out
}

// forwardedDevices reads which devices the firewall forwards LAN traffic to: a device (or the
// interface that owns it) in a zone that is the destination of a forwarding. `uci show` shapes:
//
//	firewall.@zone[2].name='vpn'
//	firewall.@zone[2].network='awg0' 'awg1'
//	firewall.@forwarding[1].src='lan'
//	firewall.@forwarding[1].dest='vpn'
//	network.awg2.device='awg2'            (absent for a tunnel: the interface is the device)
//
// zoned is every device some zone holds at all.
func forwardedDevices(network, firewall string) (forwarded, zoned func(string) bool) {
	deviceOf := map[string]string{} // interface -> device, where they differ
	for _, ln := range strings.Split(network, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(ln), "=")
		if !ok || !strings.HasPrefix(key, "network.") {
			continue
		}
		parts := strings.Split(key, ".")
		if len(parts) == 3 && (parts[2] == "device" || parts[2] == "ifname") {
			deviceOf[parts[1]] = strings.Trim(val, "'\"")
		}
	}
	dests := map[string]bool{}
	for _, ln := range strings.Split(firewall, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(ln), "=")
		if ok && strings.HasPrefix(key, "firewall.@forwarding[") && strings.HasSuffix(key, ".dest") {
			dests[strings.Trim(val, "'\"")] = true
		}
	}
	zones := netvpn.ParseFirewallZones(firewall)
	holds := func(z netvpn.Zone, dev string) bool {
		for _, n := range z.Networks {
			if n == dev || deviceOf[n] == dev {
				return true
			}
		}
		for _, d := range z.Devices {
			// fw4 takes a trailing + as "any device with this prefix".
			if d == dev || strings.HasSuffix(d, "+") && strings.HasPrefix(dev, strings.TrimSuffix(d, "+")) {
				return true
			}
		}
		return false
	}
	forwarded = func(dev string) bool {
		for _, z := range zones {
			if dests[z.Name] && holds(z, dev) {
				return true
			}
		}
		return false
	}
	zoned = func(dev string) bool {
		for _, z := range zones {
			if holds(z, dev) {
				return true
			}
		}
		return false
	}
	return forwarded, zoned
}

// notForwardedFindings names the tunnels a group or a fastest list may be moved to that the firewall
// does not forward LAN traffic to. The elector measures a tunnel from the router
// itself, which no forward rule judges: such a tunnel answers every handshake, can be elected on
// latency, and then drops every client packet in the firewall's forward chain.
func notForwardedFindings(plan *pbr.Plan, network, firewall string) []PlanFinding {
	if strings.TrimSpace(firewall) == "" {
		return nil
	}
	forwarded, zoned := forwardedDevices(network, firewall)
	var out []PlanFinding
	seen := map[string]bool{}
	for _, e := range plan.Egresses {
		if e.Kind != pbr.EgressInterface || len(e.Ifaces) < 2 {
			continue
		}
		for _, dev := range e.Devices() {
			if seen[dev] || forwarded(dev) {
				continue
			}
			seen[dev] = true
			state := "is in no firewall zone"
			if zoned(dev) {
				state = "is in a firewall zone nothing is forwarded to"
			}
			owner := "group " + e.Tag
			if id, ok := model.ListEgressID(e.Tag); ok {
				owner = "list " + id
			}
			out = append(out, PlanFinding{
				ID: findingNoForward, Setting: "tunnel interface", Item: dev,
				Requested: "any tunnel of " + owner, Effective: dev + " would carry nothing",
				Severity: platform.SeverityDegraded, Reason: platform.ReasonModeConflict, Blocks: platform.BlocksNothing,
				Detail: fmt.Sprintf("the tunnel interface %s %s. WayHop tests a tunnel from the router itself, which the firewall always allows, "+
					"so %s answers the test and can be chosen for %s; the devices' own traffic to it is then dropped by the firewall", dev, state, dev, owner),
				Remedy: "In the firewall (LuCI: Network, Firewall) put " + dev + " into the zone the other tunnels are in, with forwarding from lan to it.",
			})
		}
	}
	return out
}

// namesHoldFindings says what a kill switch over names does on this plane, where the kernel cannot
// see names: the learned addresses, the hold in hybrid mode, and what is left open in fast mode.
func (s *Server) namesHoldFindings(cfg config.Config, plan *pbr.Plan) []PlanFinding {
	if plan == nil || !plan.GuardNames {
		return nil
	}
	const learned = "WayHop notes the addresses those names are reached at and the router's kernel holds them like any kill-switched address " +
		"(kept across reboots, forgotten a day after their last use): they may leave by a tunnel or the proxy core, never by the provider. " +
		"An address several sites share (a CDN) is held for all of them: while the core is down, a site that has nothing to do with " +
		"the list can be out of reach for up to a day, and longer if the router is restarted with the core still down. "
	const stopped = " Stopping WayHop does not release a kill switch: the kernel goes on holding what it holds; to release it, switch the " +
		"kill switch off and Apply, or uninstall."
	// A list whose names go to a tunnel that an open route uses too.
	var shared []string
	for _, ns := range plan.GuardNameSets {
		if ns.Shared {
			shared = append(shared, ns.ID+" (by "+strings.Join(ns.Outbounds, ", ")+")")
		}
	}
	sharing := ""
	if len(shared) > 0 {
		sharing = " The tunnel of " + strings.Join(shared, ", ") + " is also where a list, a rule or the default route with no kill switch sends " +
			"its traffic, so the tunnel alone does not say whose a connection is: WayHop notes an address for that list only when the core " +
			"reports the list's own rule for the connection, and never holds the other route's addresses. Give the list a group of its own " +
			"to make every one of its connections count."
	}
	hold := s.namesHold(plan)
	if hold.Seconds == 0 {
		return []PlanFinding{{
			ID: findingNamesUnheld, Setting: "kill switch",
			Requested: "kill switch over domain names", Effective: "addresses only",
			// To be acknowledged, not just read: in this mode the kill switch does not
			// do for names what it says.
			Severity: platform.SeverityPrivacy, Reason: platform.ReasonPlatformUnsupported, Blocks: platform.BlocksFeature,
			Detail: "a kill switch covers lists or rules that match domain names (or a rule-set not fetched yet). On OpenWrt the router's kernel " +
				"holds addresses; names are matched by the proxy core, and in this routing mode the core does not carry the home network's traffic: " +
				"those names are not sent to their tunnel at all and leave by the provider. Addresses WayHop noted for them earlier, in hybrid mode, " +
				"stay held until they are a day old; new ones are noted only for connections an application sends through the core's own proxy port." + sharing + stopped,
			Remedy: "Use hybrid mode, where the core carries those names and WayHop holds their addresses, or keep kill-switched lists to addresses (CIDR).",
		}}
	}
	period := fmt.Sprintf("for at most %d s", hold.Seconds)
	after := "After that the hold lets go by itself (the router's kernel times it out, WayHop does not have to be alive); the addresses already " +
		"noted stay held, and only a kill-switched name WayHop has not seen in use can then leave by the provider until the core is back " +
		"(WayHop looks at the core's open connections every few seconds, so a name used only by requests shorter than that can go unseen). " +
		"Set kill_switch_boot_hold_lift in config.json to change the period; negative never lets go."
	if hold.Seconds < 0 {
		period = "until the core runs again"
		after = "kill_switch_boot_hold_lift is negative: the hold never lets go by itself, so a core that cannot start keeps the LAN offline."
	}
	v6 := " IPv6 is not held by this hold: the installed core carries IPv4 only, so the home network's IPv6 passes beside it and a " +
		"kill-switched name reached over IPv6 leaves by the provider. Apply once more: with a kill switch over names WayHop now has the core carry IPv6 too."
	switch {
	case hold.V6:
		v6 = " With a kill switch over names the core carries the home network's IPv6 as well as its IPv4, so the hold covers both alike."
	case plan.CoreTun == "" || len(plan.GuardNameSets) == 0:
		// The plan a router holds when it is upgraded, until the first Apply.
		v6 = " The installed plan was applied by an earlier build of WayHop: until the next Apply the hold covers IPv4 only (a kill-switched " +
			"name reached over IPv6 leaves by the provider) and no addresses are noted for the names. Apply once."
	}
	return []PlanFinding{{
		ID: findingNamesHold, Setting: "kill switch",
		Requested: "kill switch over domain names", Effective: "their addresses held; new connections held while the core is down",
		Severity: platform.SeverityDegraded, Reason: platform.ReasonPlatformUnsupported, Blocks: platform.BlocksNothing,
		Detail: "a kill switch covers lists or rules that match domain names. " + learned + "For a name not yet seen in use the kernel cannot " +
			"tell its connections from any other, so while the proxy core is not running (the boot, a restart, a crash) WayHop holds every new " +
			"connection from the home network to the provider, " + period + ". Kill-switched addresses are held without any limit, as before. " + after + v6 + sharing + stopped,
		Remedy: "Nothing is required. To avoid the hold, keep kill-switched lists to addresses (CIDR).",
	}}
}

// offloadFindings says when connections opened beside the core cannot be taken back.
// With the firewall's flow offloading on, a connection opened straight to the provider while the
// core was down is offloaded and never looked at again; WayHop resets such connections when the core
// returns, which needs the kernel's conntrack netlink module. Without it a connection to a
// kill-switched name, opened in a lapse of the hold, stays on the provider until it ends. To be
// acknowledged: the kill switch does not hold what it says.
func offloadFindings(plan *pbr.Plan, firewall string) []PlanFinding {
	if plan == nil || !plan.GuardNames || !uciFlowOffloading(firewall) {
		return nil
	}
	t, err := ctflushOpen()
	if err == nil {
		_ = t.Close()
		return nil
	}
	return []PlanFinding{{
		ID: findingOffloadNoReset, Setting: "kill switch",
		Requested: "kill switch over domain names", Effective: "a connection opened while the core was down can stay on the provider",
		Severity: platform.SeverityPrivacy, Reason: platform.ReasonMissingKernelModule, Blocks: platform.BlocksFeature,
		Detail: "the firewall's flow offloading is on and the router's kernel cannot list or remove connections (" + ctflushReason(err) + "). " +
			"A connection the home network opens straight to the provider while the proxy core is down, after the hold has let go, is offloaded " +
			"and is not looked at again; WayHop cannot reset it when the core returns, so a kill-switched name can stay on the provider until " +
			"that connection ends",
		Remedy: "Install kmod-nf-conntrack-netlink on the router (apk add kmod-nf-conntrack-netlink), or switch flow offloading off " +
			"(LuCI: Network, Firewall), or keep kill-switched lists to addresses (CIDR).",
	}}
}

// uciFlowOffloading reads `uci show firewall` for the defaults section's flow_offloading:
//
//	firewall.@defaults[0].flow_offloading='1'
func uciFlowOffloading(firewall string) bool {
	for _, ln := range strings.Split(firewall, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(ln), "=")
		if ok && strings.HasPrefix(key, "firewall.@defaults[") && strings.HasSuffix(key, ".flow_offloading") {
			return strings.Trim(val, "'\"") == "1"
		}
	}
	return false
}

// ksGuardCeiling is how many addresses and prefixes the guard may copy before Review says so.
// Each is in the kernel twice (the plane's set and the guard's), a reload holds the
// old and the new table at once, nft parses the whole program in user space, and the boot copy on
// flash is rewritten when the list's content changes. 20 000 prefixes are about 0.5 MB of flash per
// rewrite and a few MB of nft's memory; a 256 MB router may have about 68 MB free.
const ksGuardCeiling = 20000

func guardSizeFindings(plan *pbr.Plan) []PlanFinding {
	n := plan.GuardedElements()
	if n <= ksGuardCeiling {
		return nil
	}
	return []PlanFinding{{
		ID: findingGuardLarge, Setting: "kill switch",
		Requested: "kill switch and block lists of any size", Effective: fmt.Sprintf("%d addresses and prefixes held twice", n),
		Severity: platform.SeverityDegraded, Reason: platform.ReasonPlatformUnsupported, Blocks: platform.BlocksNothing,
		Detail: fmt.Sprintf("the kill-switched and block lists hold %d addresses and prefixes (WayHop says so above %d). The kill switch keeps "+
			"its own copy of them in the router's kernel and one more on flash for the boot, and that copy is written again whenever a list's "+
			"content changes: with a feed that updates daily that is a large write to flash every day, and a load that needs several MB of memory", n, ksGuardCeiling),
		Remedy: "Aggregate the list, take a smaller feed, or update it less often. Lists without a kill switch are not copied.",
	}}
}

// resetUnavailableFindings says when "reset connections on switch" cannot work:
// OpenWrt does not ship the conntrack netlink module by default, and the reset is otherwise skipped
// silently.
func resetUnavailableFindings(prof *model.Profile) []PlanFinding {
	var lists []string
	for _, rl := range prof.RoutingLists {
		if rl.Fastest != nil && rl.Fastest.ResetOnSwitch && model.FastestActive(prof, rl) {
			lists = append(lists, rl.ID)
		}
	}
	if len(lists) == 0 {
		return nil
	}
	t, err := ctflushOpen()
	if err == nil {
		_ = t.Close()
		return nil
	}
	var out []PlanFinding
	for _, id := range lists {
		out = append(out, PlanFinding{
			ID: findingResetNoModule, Setting: "routing list", Item: id,
			Requested: "reset connections on switch", Effective: "connections move as they reconnect",
			Severity: platform.SeverityDegraded, Reason: platform.ReasonMissingKernelModule, Blocks: platform.BlocksNothing,
			Detail: "the router's kernel cannot list or remove connections (" + ctflushReason(err) + "), so a switch to another tunnel does not reset " +
				"this list's connections. IPv4 connections break and reconnect on their own; IPv6 ones stay on the old tunnel until they end",
			Remedy: "Install kmod-nf-conntrack-netlink on the router (apk add kmod-nf-conntrack-netlink), or switch the option off for this list.",
		})
	}
	return out
}

func ctflushReason(err error) string {
	switch err {
	case ctflush.ErrNoModule:
		return "the module nf_conntrack_netlink is not loaded"
	case ctflush.ErrUnsupported:
		return "conntrack netlink is not available"
	}
	return err.Error()
}
