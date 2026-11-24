package pbr

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// backstop.go is the kill switch's routing-layer backstop on the Keenetic plane.
//
// Everything else the kill switch does keys on the fwmark: the tunnel table's blackhole and the
// fail-closed rule catch MARKED traffic. Marks come from the mangle chain, and KeeneticOS rebuilds
// netfilter on its own: between NDM's rebuild and its netfilter.d hook putting the chain back (measured:
// the rule counters restart from zero after each hook run), nothing is marked and a kill-switched
// list's traffic goes by the main table, the WAN. The backstop does not depend on iptables at all: a
// routing table of blackhole routes for the kill-switched destinations, looked up by ip rules placed
// ahead of every rule that could route such a packet first (NDM's access-policy rules included,
// backstopRulePref), for packets forwarded from any interface but the WAN that carry no WayHop mark.
//
//   - Marked traffic never matches the backstop's rules (`fwmark 0/MASK`, `MASK/MASK`) and is routed by
//     its fwmark rule, as before; the fail-closed rule (RulePref+300) drops it when its table is empty.
//   - The router's own traffic (interface-bound probes, feed downloads, the tunnels' own packets to
//     their servers) arrives on no interface (`iif lo`), and the rules name interfaces, so it stays
//     out. The interfaces are every one traffic is forwarded from, not only the bridges:
//     a VPN server's clients and a site-to-site tunnel's traffic too, read at capture, and
//     one that comes up after the Apply is added by the daemon's mirror (BackstopRulesFor).
//   - A destination that a later zone sends elsewhere (direct, another tunnel) carries that zone's
//     mark in steady state, so `fwmark 0/MASK` lets it through. During NDM's window it is unmarked
//     and dropped, which only costs it the window.
//   - A packet of a device NDM puts in an access policy carries NDM's mark, whose bits in our mask
//     are all ones; the second rule (`fwmark MASK/MASK`) catches it unmarked by us as well.
//
// Only zones that cover every source are backstopped: a device-scoped list ("only", "except")
// sends other devices to the same destinations directly by design, and an ip rule cannot tell
// devices apart by MAC. The routes are installed by the daemon over netlink (see the server's
// backstop syncer), not by this shell program: tens of thousands of `ip route add` forks would take
// minutes on a router, and the netfilter.d hook re-runs the program after every rebuild.

// BackstopTable is the routing table of the backstop's blackhole routes. Every egress table is
// TableBase+i for fewer than 256 egresses (the mark space), so TableBase+256 can never be one.
func BackstopTable(opt Options) int {
	opt.withDefaults()
	return opt.TableBase + 256
}

// backstopRulePref is where the backstop's rules sit: ahead of every rule that could route an
// unmarked or NDM-marked LAN packet first. It followed the fail-closed rule at
// RulePref+301, after NDM's access-policy rules (100-109 on a live router): a policy device's packet
// carries NDM's mark in the rebuild window, NDM's rule matched first, and the policy's table has a
// default route, the provider's when the policy pins the device to it. The backstop only ever matches
// a packet without a WayHop mark, so it may come before WayHop's own rules too. The priority is
// derived at capture from the router's live rule list (BackstopPrefFromRules) and recorded in the
// artifact; 0 there means ahead of every WayHop rule. backstopStagePref holds a copy while the rule
// is rewritten, so the del-then-add of a re-run never has a moment without one.
func backstopRulePref(opt Options, io IpsetOptions) int {
	if io.BackstopPref >= 2 {
		return io.BackstopPref
	}
	return defaultBackstopPref(opt)
}
func backstopStagePref(opt Options, io IpsetOptions) int { return backstopRulePref(opt, io) - 1 }

// defaultBackstopPref precedes the hand-off return rules (RulePref-9..-7), the lowest WayHop has.
func defaultBackstopPref(opt Options) int { return opt.RulePref - 10 }

// BackstopPrefFromRules places the backstop ahead of the lowest rule in an `ip rule` dump that is not
// WayHop's and could route a forwarded packet before it: the kernel's local rule (0) and the main and
// default tables' rules are not counted, nor WayHop's own (its tables, the backstop's earlier place
// included). Without such a rule the backstop goes ahead of every WayHop rule. Never a hardcoded NDM
// number: KeeneticOS renumbers its policies.
func BackstopPrefFromRules(dump string, opt Options) int {
	opt.withDefaults()
	pref := defaultBackstopPref(opt)
	for _, p := range foreignRulePrefs(dump, opt) {
		if p <= pref {
			pref = p - 1
		}
	}
	if pref < 2 {
		pref = 2 // the stage copy needs a priority of its own above the local rule's 0
	}
	return pref
}

// BackstopUnpreceded names the foreign rules in a dump the backstop cannot be placed ahead of:
// priority 1 or 2, where the backstop and its stage copy have no room left.
func BackstopUnpreceded(dump string, opt Options) []int {
	opt.withDefaults()
	var out []int
	for _, p := range foreignRulePrefs(dump, opt) {
		if p <= 2 {
			out = append(out, p)
		}
	}
	return out
}

// foreignRulePrefs is the priority of every rule in an `ip rule` dump that is not WayHop's and could
// route a forwarded packet: not the local rule (0), not main and default (32766+). WayHop's own rules
// are told by selector, not by table number alone: a table in its range AND a mark mask
// inside its own bits. NDM numbers its tables freely; a policy table that happens to fall into 150..409
// must still be stepped ahead of.
func foreignRulePrefs(dump string, opt Options) []int {
	own := uint64(opt.MarkMask | HandoffBit | HandoffReturnBit)
	ours := func(rl ruleLine) bool {
		n, err := strconv.Atoi(rl.lookup)
		return err == nil && n >= opt.TableBase && n <= HandoffReturnTable(opt) &&
			rl.fwmask != 0 && rl.fwmask&^own == 0
	}
	var out []int
	for _, line := range strings.Split(dump, "\n") {
		rl, ok := parseRuleLine(line)
		if !ok || rl.pref <= 0 || rl.pref >= 32766 || ours(rl) {
			continue
		}
		out = append(out, rl.pref)
	}
	return out
}

// Backstop is what the backstop must cover for one plan: static prefixes (aggregated) and the domain
// sets whose members dnsmasq adds at query time, which the daemon mirrors into the table.
type Backstop struct {
	V4, V6 []netip.Prefix
	Sets4  []string
	Sets6  []string
	// ZoneSets4/6 are every set of a backstopped zone, static and domain: where the boot fill finds
	// the zone's static prefixes in the restore file.
	ZoneSets4, ZoneSets6 []string
}

// Active reports whether the plan has anything kill-switched to backstop.
func (b Backstop) Active() bool { return len(b.V4)+len(b.V6)+len(b.Sets4)+len(b.Sets6) > 0 }

// Routes is the static route count.
func (b Backstop) Routes() int { return len(b.V4) + len(b.V6) }

// KillSwitchBackstop collects the destinations of every zone that covers all sources and routes to a
// fail-closed egress (a kill-switched group, or a list's own egress under a kill switch or "block").
func (pl *Plan) KillSwitchBackstop(io IpsetOptions) Backstop {
	io.withDefaults()
	failClosed := map[string]bool{}
	for _, e := range pl.Egresses {
		if e.Kind == EgressInterface && e.FailClosed {
			failClosed[e.Tag] = true
		}
	}
	var b Backstop
	var v4, v6 []netip.Prefix
	for _, z := range pl.Zones {
		if z.SrcScoped || z.NDMPolicy != "" || !failClosed[z.EgressTag] {
			continue
		}
		for _, c := range z.V4 {
			if p, err := netip.ParsePrefix(c); err == nil {
				v4 = append(v4, p.Masked())
			}
		}
		for _, c := range z.V6 {
			if p, err := netip.ParsePrefix(c); err == nil {
				v6 = append(v6, p.Masked())
			}
		}
		if zoneHasDomains(z) {
			b.Sets4 = append(b.Sets4, io.setName(z.Name, "4"))
			b.Sets6 = append(b.Sets6, io.setName(z.Name, "6"))
			if io.DynamicDomainSets {
				b.Sets4 = append(b.Sets4, io.dynamicSetName(z.Name, "4"))
				b.Sets6 = append(b.Sets6, io.dynamicSetName(z.Name, "6"))
			}
		}
		if len(z.V4) > 0 || zoneHasDomains(z) {
			b.ZoneSets4 = append(b.ZoneSets4, io.setName(z.Name, "4"))
		}
		if len(z.V6) > 0 || zoneHasDomains(z) {
			b.ZoneSets6 = append(b.ZoneSets6, io.setName(z.Name, "6"))
		}
	}
	b.V4, b.V6 = AggregatePrefixes(v4), AggregatePrefixes(v6)
	sort.Strings(b.Sets4)
	sort.Strings(b.Sets6)
	sort.Strings(b.ZoneSets4)
	sort.Strings(b.ZoneSets6)
	return b
}

// AggregatePrefixes returns the smallest set of prefixes covering exactly the union of in: contained
// prefixes are dropped and sibling halves merged into their parent, repeatedly. The input is not
// modified.
func AggregatePrefixes(in []netip.Prefix) []netip.Prefix {
	if len(in) == 0 {
		return nil
	}
	ps := collapsePrefixes(append([]netip.Prefix(nil), in...))
	var stack []netip.Prefix
	for _, p := range ps {
		stack = append(stack, p)
		for len(stack) >= 2 {
			a, c := stack[len(stack)-2], stack[len(stack)-1]
			if a.Bits() != c.Bits() || a.Bits() == 0 {
				break
			}
			parent, err := a.Addr().Prefix(a.Bits() - 1)
			if err != nil || parent.Addr() != a.Addr() || !parent.Contains(c.Addr()) {
				break
			}
			stack = append(stack[:len(stack)-2], parent)
		}
	}
	return stack
}

// backstopFamilies is which families get backstop rules: v4 always, v6 when anything v6 is covered.
func (b Backstop) families() []string {
	out := []string{"ip"}
	if len(b.V6) > 0 || len(b.Sets6) > 0 {
		out = append(out, "ip -6")
	}
	return out
}

// backstopRuleSpecs is every backstop rule selector for ifaces, without the priority.
func (pl *Plan) backstopRuleSpecs(opt Options, ifaces []string) []string {
	mask := hexMark(pl.Mask)
	var out []string
	for _, ifc := range lanIfaces(ifaces) {
		for _, mark := range []string{hexMark(0) + "/" + mask, mask + "/" + mask} {
			out = append(out, fmt.Sprintf("iif %s fwmark %s table %d", ifc, mark, BackstopTable(opt)))
		}
	}
	return out
}

// lanIfaces is the LAN interfaces de-duplicated, sorted and stripped of anything that is not an
// interface name: they are rendered unquoted into shell.
func lanIfaces(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if validOffloadDev.MatchString(s) && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// BackstopNeedsLAN reports whether the plan needs a backstop but io names no LAN interface for it:
// the caller must refuse rather than install a kill switch with the window open.
func (pl *Plan) BackstopNeedsLAN(io IpsetOptions) bool {
	return pl.KillSwitchBackstop(io).Active() && len(lanIfaces(io.LANIfaces)) == 0
}

// renderBackstopRules writes the backstop's ip rules, each rewritten make-before-break: a copy at
// the staging priority first, then the rule itself, then the copy goes. The add at the rule's own
// priority is not best-effort: MissingIPRules reads it back, and a kernel that refused it fails the
// Apply.
func (pl *Plan) renderBackstopRules(b *strings.Builder, opt Options, io IpsetOptions) {
	opt.withDefaults()
	bs := pl.KillSwitchBackstop(io)
	specs := pl.backstopRuleSpecs(opt, io.LANIfaces)
	if !bs.Active() || len(specs) == 0 {
		return
	}
	b.WriteString("# kill switch backstop: unmarked forwarded traffic to kill-switched destinations is dropped by\n")
	b.WriteString("# routing, whatever the state of the mangle chain. Installed before the chain is (re)written.\n")
	pl.writeBootHold(b, opt, io, bs)
	pl.writeBackstopRules(b, opt, io, bs, specs)
}

// renderBootFill runs the boot fill and the hook-side second chance of the lift: after
// the hold routes and the backstop rules are in place and the sets are restored, so the broad hold
// already holds while the fill loads.
func (pl *Plan) renderBootFill(b *strings.Builder, opt Options, io IpsetOptions) {
	opt.withDefaults()
	bs := pl.KillSwitchBackstop(io)
	if !bs.Active() || len(pl.backstopRuleSpecs(opt, io.LANIfaces)) == 0 || io.BackstopReady == "" || !validStampPath.MatchString(io.BackstopReady) {
		return
	}
	fill := pl.fillCommand(opt, io, bs)
	if fill == "" && io.BootHoldLift <= 0 {
		return
	}
	r := io.BackstopReady
	// Without the ready stamp only. After a lift the block still runs: the drain goes on until the
	// narrow data is complete (the lift itself and the fill are guarded by .lifted).
	fmt.Fprintf(b, "[ -e %s ] || {\n", r)
	if fill != "" {
		fmt.Fprintf(b, "\t[ -e %s%s ] || [ -e %s%s ] || { echo 2>/dev/null > %s%s && %s >/dev/null 2>&1; }\n", r, StampLifted, r, StampTried, r, StampTried, fill)
	}
	if io.BootHoldLift > 0 {
		// Second chance, for a timer that died or never started. The rules, with D the
		// due second (liftFuncs):
		//   before D                 nothing.
		//   D .. D+grace+final       a live timer is left alone: it is bound by its own start, lifts
		//                            at D+grace at the latest and needs the rest for its drain.
		//                            Without one, a pass of at most bootHoldLoopBatch routes, then
		//                            the lift when the narrow data is complete. A pass that is
		//                            cut resumes at its last route.
		//   from D+grace+final       the lift first, whatever the drain's state and whoever else is
		//                            draining, then a pass. Nothing that can be cut or can fail stands
		//                            before that lift, so the bound (B) holds on any run that reaches
		//                            this line. It deliberately goes ahead of the narrow-route
		//                            guarantee (A) for the documented double fault (a file that cannot
		//                            be read, a route the kernel refuses) and for a drain the hook
		//                            runs since D did not finish.
		// An unreadable uptime counts as past every bound, as before.
		b.WriteString(pl.liftFuncs(opt, io, bs))
		b.WriteString("\twr_now; wr_due\n")
		b.WriteString("\t[ \"$wr_up\" -lt \"$wr_d\" ] 2>/dev/null || {\n")
		fmt.Fprintf(b, "\t\tif [ \"$wr_up\" -lt $((wr_d + %d)) ] 2>/dev/null; then\n", BootHoldLiftGrace+BootHoldLiftFinal)
		fmt.Fprintf(b, "\t\t\t%s\n", readArmed(r))
		fmt.Fprintf(b, "\t\t\t[ -n \"$wr_ap\" ] && kill -0 \"$wr_ap\" 2>/dev/null || { wr_drain %d && wr_lift; }\n", bootHoldLoopBatch)
		fmt.Fprintf(b, "\t\telse\n\t\t\twr_lift; wr_drain %d\n\t\tfi\n", bootHoldLoopBatch)
		b.WriteString("\t}\n")
	}
	b.WriteString("\t:\n}\n")
}

// readArmed reads the live timer's pid from the armed stamp into wr_ap ("" when there is none).
func readArmed(ready string) string {
	return fmt.Sprintf("wr_ap=; read -r wr_ap wr_x 2>/dev/null < %s%s; case \"$wr_ap\" in \"\"|*[!0-9]*) wr_ap= ;; esac", ready, stampArmed)
}

// liftFuncs is the shell the hook's second chance and the detached timer share, as functions: one
// program, two callers, no lock between them.
//
//	wr_now    wr_up = whole seconds of uptime ("" when /proc/uptime cannot be read).
//	wr_due    wr_d = D, the second of uptime the lift is due: the .due stamp the hold wrote when it
//	          was first installed this boot, BootHoldLift without one.
//	wr_drain  installs the kill-switched destinations from the restore file and the learned file,
//	          at most $1 routes (-1: no cap); status 0 when every record of both files is in.
//	wr_lift   liftCore: removes the broad hold unless a ready or lifted stamp says it is gone.
//
// Why no lock: a lock's own state machine is the larger source of defects. A drain is idempotent (`route replace`) and its progress stamps only ever state facts
// about one content of a file, named by its key (holdLoop): .pos "K N" is written after line N of
// content K was installed by a pass that started from an earlier valid position of K, .done "K"
// after a pass found content K whole and installed all of it without a failure. So any number of
// drains may run at once, a pass that dies loses at most its last route, and the next resumes from
// there. A lift is taken only (a) by a caller whose own wr_drain returned 0, when the data is
// complete whoever installed it, or (b) at a bound in seconds of uptime. Nothing a second actor does
// between two commands of the first can turn (a) into a lift without the data.
func (pl *Plan) liftFuncs(opt Options, io IpsetOptions, bs Backstop) string {
	r := io.BackstopReady
	var b strings.Builder
	b.WriteString("wr_now() { wr_up=0; read -r wr_up wr_x 2>/dev/null < /proc/uptime; wr_up=${wr_up%%.*}; }\n")
	fmt.Fprintf(&b, "wr_due() { wr_d=; read -r wr_d wr_x 2>/dev/null < %s%s; case \"$wr_d\" in \"\"|*[!0-9]*) wr_d=%d ;; esac; }\n", r, stampDue, io.BootHoldLift)
	b.WriteString("wr_drain() {\nwr_budget=$1; wr_all=1\n")
	if l := pl.holdLoop(opt, io, io.BootRestore, bs.ZoneSets4, bs.ZoneSets6, r+".restore", false, false); l != "" {
		b.WriteString(l + " || wr_all=0\n")
	}
	if len(bs.Sets4)+len(bs.Sets6) > 0 { // The learned members too
		if l := pl.holdLoop(opt, io, io.BootLearned, bs.Sets4, bs.Sets6, r+".learned", true, true); l != "" {
			b.WriteString(l + " || wr_all=0\n")
		}
	}
	b.WriteString("[ \"$wr_all\" = 1 ]\n}\n")
	fmt.Fprintf(&b, "wr_lift() { %s; }\n", pl.liftCore(opt, io, bs))
	return b.String()
}

// The boot hold's stamps, all in tmpfs beside BackstopReady (a reboot clears them).
const (
	// StampTried: the hook has started the fill once since boot.
	StampTried = ".tried"
	// StampFilled: the fill put the static kill-switched prefixes (and what it could of the learned
	// members) into the backstop table.
	StampFilled = ".filled"
	// StampPartial: the fill could not restore every kill-switched destination; holds the reason.
	StampPartial = ".partial"
	// StampLifted: the broad hold was lifted after BootHoldLift seconds without a full fill. The
	// shell writes it after its deletes; the daemon stamps first and keeps liftOwed until deletes pass.
	StampLifted = ".lifted"
	// stampArmed: the pid of the lift's timer, written by the timer itself.
	stampArmed = ".armed"
	// stampDue: D, the second of uptime the lift is due, written once per boot by the run that first
	// installs the hold. Every bound of the hook and of the timer counts from it.
	stampDue = ".due"
)

// holdExcludes are the destinations the broad hold never holds: private and
// shared address space, link-local, where LAN, guest, VPN-server and CGNAT-numbered peers live.
// The private ones are also pinned to the main table by the plane (privateExcludes), so a throw for
// them shadows nothing the plane would tunnel. The shared ones are not: their throws are
// rendered only where no kill-switched prefix contains them, and go with the hold.
var holdExcludes4 = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
var holdShared4 = []string{"100.64.0.0/10", "169.254.0.0/16"}
var holdExcludes6 = []string{"fc00::/7", "fe80::/10"}

// HoldSharedThrows are the hold's throw routes that must go with the hold: the daemon
// and the fill remove them when they release it.
func HoldSharedThrows() []netip.Prefix {
	out := make([]netip.Prefix, len(holdShared4))
	for i, s := range holdShared4 {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// DefaultBootHoldLift is how long the broad boot hold may last without a full fill.
const DefaultBootHoldLift = 600

// BootHoldLiftGrace is how long past its due second the broad hold stays when the narrow data could
// not be completed (a file that cannot be read, a route the kernel refuses): then the timer drains
// once more and lifts whatever the outcome, and the daemon does the same after failed syncs.
const BootHoldLiftGrace = 900

// BootHoldLiftFinal is what the hook leaves a live timer past due+grace for its last drain, and a
// timerless hook for its capped passes, before it lifts whatever the drain's state.
// due+grace+final is the last second a run of the hook finds the broad hold in place.
const BootHoldLiftFinal = 300

// holdThrows splits the shared exemptions: those no kill-switched prefix contains get a throw, the
// others none (a /10 throw would send the packets of a kill-switched /8 around it to the
// main table in every rebuild window).
func holdThrows(cover []netip.Prefix) (keep, drop []string) {
	for _, s := range holdShared4 {
		x := netip.MustParsePrefix(s)
		shadow := false
		for _, k := range cover {
			if k.Addr().Is4() && k.Bits() <= x.Bits() && k.Contains(x.Addr()) {
				shadow = true
				break
			}
		}
		if shadow {
			drop = append(drop, s)
		} else {
			keep = append(keep, s)
		}
	}
	return keep, drop
}

// writeBootHold holds the backstop closed at boot until the kill-switched destinations are in its
// table. The table's routes are RAM only: after a reboot the hook installs
// the backstop rules on NDM's first firewall build and the table is empty.
//
//  1. Broad hold, first: a default blackhole in the table (throw routes send private, shared and
//     link-local destinations on to the next rule) drops every unmarked forwarded packet to a public
//     address. The throws and the blackhole are one chain: when this ip refuses a throw in a non-main
//     table nothing is held broadly (it would blackhole the LAN to the guest segment too),
//     the narrow data below still is, and the failure is written to the kernel log. The hold's routes
//     and the backstop's rules come before the set restores and the fill, so the hold
//     holds while those load.
//  2. Bounded by itself: installing the hold arms a timer, once per boot, a background
//     `sleep` that lifts the broad hold BootHoldLift seconds after boot unless the ready stamp appeared
//     by then. No later event is needed. Each hook run is a second chance (renderBootFill).
//  3. Narrow data, once per boot (renderBootFill): `wayhop backstop-fill` (io.FillTool) installs the
//     static kill-switched prefixes and the learned members of kill-switched domain sets
//     (io.BootLearned, persisted by the daemon) over netlink. When it had every piece it writes the
//     ready stamp and removes the broad hold: from then on only kill-switched destinations are held,
//     whatever the daemon does.
//
// The lift logs loudly; the narrow data stays. If the fill never reported its routes in (a binary that
// cannot start), the lift first installs the static prefixes and the learned members from their files
// by the shell. The narrow hold is never lifted.
func (pl *Plan) writeBootHold(b *strings.Builder, opt Options, io IpsetOptions, bs Backstop) {
	if io.BackstopReady == "" || !validStampPath.MatchString(io.BackstopReady) {
		return
	}
	t := BackstopTable(opt)
	r := io.BackstopReady
	keep, drop := holdThrows(bs.V4)
	fmt.Fprintf(b, "[ -e %s ] || [ -e %s%s ] || {\n", r, r, StampLifted)
	for _, ip := range bs.families() {
		excl := append(append([]string(nil), holdExcludes4...), keep...)
		if ip != "ip" {
			excl = holdExcludes6
		}
		b.WriteString("\t{ ")
		for _, x := range excl {
			fmt.Fprintf(b, "%s route replace throw %s table %d && ", ip, x, t)
		}
		fmt.Fprintf(b, "%s route replace blackhole default table %d; } 2>/dev/null ||\n", ip, t)
		fmt.Fprintf(b, "\t\techo \"wayhop: kill switch boot hold: '%s route' refused a throw route, no broad hold (kill-switched destinations only)\" > /dev/kmsg 2>/dev/null\n", ip)
	}
	for _, x := range drop { // left by an earlier plan's hold: inside a kill-switched prefix now
		fmt.Fprintf(b, "\tip route del throw %s table %d 2>/dev/null\n", x, t)
	}
	if io.BootHoldLift > 0 {
		// The timer is detached from the hook (setsid, start-stop-daemon, or a
		// double fork that ignores SIGHUP), so NDM ending the hook's process group does not end it. The
		// child itself writes its live pid into the armed stamp; a launch that died therefore retries
		// on a later hook run instead of leaving an empty stamp that suppresses every retry.
		//
		// The due second D is fixed once per boot, by the run that first installs the hold: BootHoldLift,
		// or liftArmedLateWait from now when BootHoldLift has passed (a kill switch first applied late
		// in the uptime), so a fill started by the same hook run finishes first.
		b.WriteString("\twr_up=0; read -r wr_up wr_x 2>/dev/null < /proc/uptime; wr_up=${wr_up%%.*}\n")
		fmt.Fprintf(b, "\t[ -s %s%s ] || { wr_d=%d; [ \"${wr_up:-0}\" -lt %d ] 2>/dev/null || wr_d=$((${wr_up:-0} + %d)); echo \"$wr_d\" > %s%s; }\n",
			r, stampDue, io.BootHoldLift, io.BootHoldLift, liftArmedLateWait, r, stampDue)
		fmt.Fprintf(b, "\t%s\n", readArmed(r))
		fmt.Fprintf(b, "\t[ -n \"$wr_ap\" ] && kill -0 \"$wr_ap\" 2>/dev/null || {\n%s\n}\n", detached(pl.liftTimer(opt, io, bs), r+".tpid"))
	}
	b.WriteString("}\n")
	// A lift that ran between this run's stamp check and its route replaces leaves the
	// hold back in place behind .lifted, which every later run would skip. With .lifted and no ready
	// stamp the defaults go again: a few forks, only in that degraded state.
	if d := pl.holdDeletes(opt, bs); d != "" {
		fmt.Fprintf(b, "[ -e %s ] || [ ! -e %s%s ] || { %s; }\n", r, r, StampLifted, d)
	}
}

// liftTimer is the detached timer's program: its pid into the armed stamp, then the wait for D, a
// drain without a cap (every route checkpointed) and the lift when the data is complete. Otherwise
// it waits for D+grace, drains once more and lifts whatever the outcome: the bound that needs no
// later event. The waits are computed from the uptime, so a timer started again after an earlier one
// died keeps the same two seconds, and one started past them does not wait.
func (pl *Plan) liftTimer(opt Options, io IpsetOptions, bs Backstop) string {
	r := io.BackstopReady
	var timer strings.Builder
	fmt.Fprintf(&timer, "echo \"$$\" > %s%s\n", r, stampArmed)
	timer.WriteString(pl.liftFuncs(opt, io, bs))
	timer.WriteString("wr_wait() { wr_now; wr_s=$(($1 - ${wr_up:-0})); [ \"$wr_s\" -gt 0 ] 2>/dev/null && sleep \"$wr_s\"; }\n")
	timer.WriteString("wr_due; wr_wait \"$wr_d\"; wr_drain -1 && wr_lift\n")
	fmt.Fprintf(&timer, "[ -e %s ] || [ -e %s%s ] || { wr_wait $((wr_d + %d)); wr_drain -1; wr_lift; }\n", r, r, StampLifted, BootHoldLiftGrace)
	return timer.String()
}

// bootHoldLoopBatch bounds the routes one inline pass of the hook installs: the pass
// runs before the plane's chain is rewritten, so it must stay short.
const bootHoldLoopBatch = 64

// liftArmedLateWait is the least time between the hold's first install and its due second:
// a hold first installed past BootHoldLift (a kill switch first applied late in the uptime)
// would otherwise be lifted beside the fill the same hook run starts, whose budget is 20 s.
const liftArmedLateWait = 30

// detached runs a shell body in the background, out of the hook's session:
// setsid when present, else BusyBox start-stop-daemon -b (which calls setsid and closes extra fds),
// else a double fork that ignores SIGHUP. $wr_sh and $wr_bb are the authenticated shell and BusyBox
// paths from the plane's preamble. $wr_sha is "sh" when the resolved interpreter is BusyBox: running
// that binary with -c directly is the measured "applet not found" failure. The unquoted,
// default-empty expansion deliberately contributes no argument for a standalone shell.
// start-stop-daemon is itself dispatched through BusyBox, so a PATH lookup for its name would reject
// the measured router. Its own pidfile is removed before each launch, and a nonzero launch status
// falls back to the double fork. The body is single-quoted; one holding a quote keeps the
// plain background-subshell fallback.
func detached(body, pidfile string) string {
	if strings.Contains(body, "'") {
		return "( " + body + " ) </dev/null >/dev/null 2>&1 &"
	}
	sh := `"${wr_sh:-/opt/bin/sh}"`
	run := sh + ` ${wr_sha:-} -c "$wr_fns$wr_t"`
	fallback := "( trap '' HUP; " + run + " </dev/null >/dev/null 2>&1 & )"
	return "wr_t='" + body + "'; if command -v setsid >/dev/null 2>&1; then setsid " + run + " </dev/null >/dev/null 2>&1 & " +
		"elif [ -n \"$wr_bb\" ]; then rm -f " + pidfile + "; \"$wr_bb\" start-stop-daemon -S -b -x " + sh + " -m -p " + pidfile + " -- ${wr_sha:-} -c \"$wr_fns$wr_t\" || " + fallback + "; " +
		"else " + fallback + "; fi"
}

// liftCore removes the broad hold (the default blackholes, and the shared throws) and
// writes the lifted stamp only when every default is gone: a route that is not there
// ("No such process"), or that a read-back of the table no longer shows, counts as gone.
// A one-line shell compound, cheap: a few forks.
func (pl *Plan) liftCore(opt Options, io IpsetOptions, bs Backstop) string {
	r, t := io.BackstopReady, BackstopTable(opt)
	var del []string
	for _, ip := range bs.families() {
		all, list := netip.MustParsePrefix("0.0.0.0/0"), bs.V4
		if ip != "ip" {
			all, list = netip.MustParsePrefix("::/0"), bs.V6
		}
		if slices.Contains(list, all) {
			continue // a kill-switched list of everything keeps its route
		}
		// A failed delete is judged by reading the table back, not by its text. v4: the
		// read must work and show no default. v6: a kernel without IPv6 routing refuses the delete
		// ("Operation not supported") and the read, and holds nothing there.
		check := fmt.Sprintf("wr_r=$(%s route show table %d 2>/dev/null) && case \"$wr_r\" in *default*) wr_ok=0 ;; esac || wr_ok=0", ip, t)
		if ip != "ip" {
			check = fmt.Sprintf("case \"$(%s route show table %d 2>/dev/null)\" in *default*) wr_ok=0 ;; esac", ip, t)
		}
		del = append(del, fmt.Sprintf("wr_e=$(%s route del default table %d 2>&1) || case \"$wr_e\" in *\"No such process\"*) ;; *) %s ;; esac", ip, t, check))
	}
	for _, x := range holdShared4 {
		del = append(del, fmt.Sprintf("ip route del throw %s table %d 2>/dev/null", x, t))
	}
	// The deletes are repeated once the stamp is written, for a hook run that installed
	// the hold between this lift's deletes and its stamp (a run after the stamp undoes it itself).
	again := ""
	if d := pl.holdDeletes(opt, bs); d != "" {
		again = d + "; "
	}
	return fmt.Sprintf("[ -e %s ] || [ -e %s%s ] || { wr_ok=1; %s; [ \"$wr_ok\" = 1 ] && echo 2>/dev/null > %s%s && { %s"+
		"echo \"wayhop: kill switch: no full fill and no daemon sync %d s after boot; the broad boot hold is lifted, only kill-switched destinations stay held\" 2>/dev/null >/dev/kmsg; }; }",
		r, r, StampLifted, strings.Join(del, "; "), r, StampLifted, again, io.BootHoldLift)
}

// holdDeletes removes the broad hold's routes without judging the outcome: the defaults (not a
// kill-switched list of everything) and the shared throws. "" when there is nothing to remove.
func (pl *Plan) holdDeletes(opt Options, bs Backstop) string {
	t := BackstopTable(opt)
	var del []string
	for _, ip := range bs.families() {
		all, list := netip.MustParsePrefix("0.0.0.0/0"), bs.V4
		if ip != "ip" {
			all, list = netip.MustParsePrefix("::/0"), bs.V6
		}
		if !slices.Contains(list, all) {
			del = append(del, fmt.Sprintf("%s route del default table %d 2>/dev/null", ip, t))
		}
	}
	for _, x := range holdShared4 {
		del = append(del, fmt.Sprintf("ip route del throw %s table %d 2>/dev/null", x, t))
	}
	return strings.Join(del, "; ")
}

// fillCommand is the hook's `wayhop backstop-fill` call, "" without a fill tool.
func (pl *Plan) fillCommand(opt Options, io IpsetOptions, bs Backstop) string {
	if io.FillTool == "" || !validStampPath.MatchString(io.FillTool) {
		return ""
	}
	sets := append(append([]string(nil), bs.ZoneSets4...), bs.ZoneSets6...)
	if len(sets) == 0 {
		return ""
	}
	cmd := fmt.Sprintf("%s backstop-fill -table %d -ready %s -sets %s", io.FillTool, BackstopTable(opt), io.BackstopReady, strings.Join(sets, ","))
	if io.BootRestore != "" && validStampPath.MatchString(io.BootRestore) {
		cmd += " -static " + io.BootRestore
	}
	if doms := append(append([]string(nil), bs.Sets4...), bs.Sets6...); len(doms) > 0 {
		cmd += " -domains " + strings.Join(doms, ",")
		if io.BootLearned != "" && validStampPath.MatchString(io.BootLearned) {
			cmd += " -learned " + io.BootLearned
		}
	}
	return cmd
}

// holdLoop is one file's part of wr_drain: it installs the members of sets4/sets6 found in a drain
// file (KeyedRestore: the plane's restore file, or the learned file), one `ip route` fork each, and
// has status 0 when every record of the file's present content is installed.
//
// The file is opened once and its header read through that descriptor, so the key and the records
// are of one content even when an Apply replaces the file meanwhile (rename: this pass keeps the old
// one). Progress lives beside the other boot stamps, in tmpfs, and always carries the key of the
// content it describes: "<key> <line>" in <state>.pos after each installed route,
// written by a shell builtin (no fork), so a pass that is cut anywhere resumes at its last route;
// "<key>" in <state>.done after a pass that found the file whole. A stamp with another
// key is of another content and counts for nothing: the pass starts at the top.
//
// The file is whole when its last line is terminated and it holds as many `add` lines as its header
// says (and, for the learned file, as its trailer says: trailer true). A cut record is not installed
// and a cut file is never complete. A refused route stops the position where it is
// (nothing is skipped) while the records behind it are still installed. $wr_budget is the routes
// the pass may still install; at 0 it stops and reports "not complete" (-1 never reaches 0). The
// pass also stops once the ready stamp is there: the table is the daemon's from then on.
//
// A file that is not there: the learned file (absentOK) is written only once a plane has
// kill-switched domains, so its absence is an empty, complete input. The restore file exists
// whenever a kill switch is applied, so without it, without a header or unreadable the drain has
// failed and the hold waits for its bound.
func (pl *Plan) holdLoop(opt Options, io IpsetOptions, file string, sets4, sets6 []string, state string, absentOK, trailer bool) string {
	if file == "" || !validStampPath.MatchString(file) || len(sets4)+len(sets6) == 0 ||
		state == "" || !validStampPath.MatchString(state) {
		return ""
	}
	t, r := BackstopTable(opt), io.BackstopReady
	var arms []string
	for _, f := range []struct {
		ip   string
		sets []string
	}{{"ip", sets4}, {"ip -6", sets6}} {
		if len(f.sets) == 0 {
			continue
		}
		pats := make([]string, len(f.sets))
		for i, s := range f.sets {
			pats[i] = "\"add " + s + "\""
		}
		arms = append(arms, fmt.Sprintf("%s)\n"+
			"[ -e %s ] && { wr_more=1; break; }\n"+
			"[ \"$wr_budget\" = 0 ] && { wr_more=1; break; }\n"+
			"wr_budget=$((wr_budget-1))\n"+
			"if %s route replace blackhole \"$wr_m\" table %d; then [ \"$wr_ok\" = 0 ] || echo \"$wr_k $wr_n\" > %s.pos; else wr_ok=0; fi ;;",
			strings.Join(pats, "|"), r, f.ip, t, state))
	}
	count, whole := "\"add \"*) wr_adds=$((wr_adds+1)) ;;", "[ -z \"$wr_a\" ] && [ \"$wr_adds\" = \"$wr_c\" ]"
	if trailer {
		count += fmt.Sprintf(" \"%s\") wr_tr=$wr_m ;;", strings.TrimSpace(LearnedTrailer))
		whole += " && [ \"$wr_tr\" = \"$wr_c\" ]"
	}
	var b strings.Builder
	b.WriteString("{\nwr_ok=1; wr_more=0; wr_adds=0; wr_tr=\n")
	if absentOK {
		fmt.Fprintf(&b, "if [ -e %s ]; then\n", file)
	}
	b.WriteString("{\nwr_h1=; wr_h2=; wr_k=; wr_c=; read -r wr_h1 wr_h2 wr_k wr_c wr_x\n")
	fmt.Fprintf(&b, "case \"$wr_h1 $wr_h2\" in \"%s\") ;; *) wr_k= ;; esac\n", drainHeader)
	b.WriteString("case \"$wr_k\" in \"\"|*[!0-9a-f]*) wr_ok=0 ;; esac\n")
	b.WriteString("case \"$wr_c\" in \"\"|*[!0-9]*) wr_ok=0 ;; esac\n")
	fmt.Fprintf(&b, "wr_dk=; read -r wr_dk wr_x 2>/dev/null < %s.done\n", state)
	b.WriteString("if [ \"$wr_ok\" = 1 ] && [ \"$wr_dk\" != \"$wr_k\" ]; then\n")
	fmt.Fprintf(&b, "wr_pk=; wr_pos=; read -r wr_pk wr_pos wr_x 2>/dev/null < %s.pos\n", state)
	b.WriteString("[ \"$wr_pk\" = \"$wr_k\" ] || wr_pos=0\n")
	b.WriteString("case \"$wr_pos\" in \"\"|*[!0-9]*) wr_pos=0 ;; esac\n")
	b.WriteString("wr_n=1; wr_a=\nwhile read -r wr_a wr_s wr_m wr_x; do\nwr_n=$((wr_n+1))\n")
	fmt.Fprintf(&b, "case \"$wr_a $wr_s\" in %s esac\n", count)
	b.WriteString("[ \"$wr_n\" -le \"$wr_pos\" ] && continue\n")
	fmt.Fprintf(&b, "case \"$wr_a $wr_s\" in\n%s\nesac\ndone\n", strings.Join(arms, "\n"))
	fmt.Fprintf(&b, "if [ \"$wr_more\" = 0 ]; then\n%s || wr_ok=0\n[ \"$wr_ok\" = 0 ] || echo \"$wr_k\" > %s.done\nfi\n", whole, state)
	fmt.Fprintf(&b, "fi\n:\n} 2>/dev/null < %s || wr_ok=0\n", file)
	if absentOK {
		b.WriteString("fi\n")
	}
	b.WriteString("[ \"$wr_ok\" = 1 ] && [ \"$wr_more\" = 0 ]\n}")
	return b.String()
}

// validStampPath is a path rendered unquoted into shell.
var validStampPath = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// renderBootRestore restores the plane's sets from io.BootRestore when any is missing:
// kernel sets do not survive a reboot, and the hook ran the program without them, so its marking chain
// was refused and nothing was marked until the daemon re-applied. One `ipset list -n` per run; the
// restore itself only when a set is missing. The file is written by the daemon at Apply, and only
// when its content changed (flash).
func (pl *Plan) renderBootRestore(b *strings.Builder, io IpsetOptions) {
	names := pl.IpsetNames(io)
	if io.BootRestore == "" || !validStampPath.MatchString(io.BootRestore) || len(names) == 0 {
		return
	}
	b.WriteString("# the plane's sets, restored when missing (boot): the chain below names them.\n")
	b.WriteString("wr_sets=$(ipset list -n 2>/dev/null)\n")
	fmt.Fprintf(b, "for wr_s in %s; do\n", strings.Join(names, " "))
	b.WriteString("\tcase \"\n$wr_sets\n\" in *\"\n$wr_s\n\"*) ;; *)\n")
	fmt.Fprintf(b, "\t\t[ -r %s ] && ipset restore -! < %s\n", io.BootRestore, io.BootRestore)
	// The learned members of kill-switched domain sets: addresses clients may still
	// have cached from before the reboot. Each carries its remaining timeout, so stale ones age out.
	if bs := pl.KillSwitchBackstop(io); len(bs.Sets4)+len(bs.Sets6) > 0 && io.BootLearned != "" && validStampPath.MatchString(io.BootLearned) {
		fmt.Fprintf(b, "\t\t[ -r %s ] && ipset restore -! < %s\n", io.BootLearned, io.BootLearned)
	}
	b.WriteString("\t\tbreak ;;\n\tesac\ndone\n")
}

func (pl *Plan) writeBackstopRules(b *strings.Builder, opt Options, io IpsetOptions, bs Backstop, specs []string) {
	p, stage := backstopRulePref(opt, io), backstopStagePref(opt, io)
	for _, ip := range bs.families() {
		for _, s := range specs {
			var body strings.Builder
			fmt.Fprintf(&body, "%s rule add %s priority %d 2>/dev/null || true\n", ip, s, stage)
			fmt.Fprintf(&body, "while %s rule del %s priority %d 2>/dev/null; do :; done\n", ip, s, p)
			fmt.Fprintf(&body, "%s rule add %s priority %d\n", ip, s, p)
			fmt.Fprintf(&body, "while %s rule del %s priority %d 2>/dev/null; do :; done\n", ip, s, stage)
			guardRule(b, ip, s, p, body.String())
		}
	}
}

// needsV6Rules reports whether the program writes any v6 rule a guard checks.
func (pl *Plan) needsV6Rules(io IpsetOptions) bool {
	return pl.hasV6Zone() || len(pl.BypassV6) > 0 || len(pl.KillSwitchBackstop(io).families()) > 1
}

// BackstopRulesFor is the backstop's rules for interfaces that appeared after the Apply:
// the mirror adds them, at the artifact's priority, when a new interface traffic can be forwarded
// from comes up. "" when the plan has no backstop.
func (pl *Plan) BackstopRulesFor(opt Options, io IpsetOptions, ifaces []string) string {
	opt.withDefaults()
	bs := pl.KillSwitchBackstop(io)
	specs := pl.backstopRuleSpecs(opt, ifaces)
	if !bs.Active() || len(specs) == 0 {
		return ""
	}
	var b strings.Builder
	writeRuleDump(&b, len(bs.families()) > 1)
	pl.writeBackstopRules(&b, opt, io, bs, specs)
	return b.String()
}

// BackstopRulesTeardownFor removes the rules BackstopRulesFor added.
func (pl *Plan) BackstopRulesTeardownFor(opt Options, io IpsetOptions, ifaces []string) string {
	opt.withDefaults()
	bs := pl.KillSwitchBackstop(io)
	var b strings.Builder
	for _, ip := range bs.families() {
		for _, s := range pl.backstopRuleSpecs(opt, ifaces) {
			for _, pref := range []int{backstopRulePref(opt, io), backstopStagePref(opt, io)} {
				fmt.Fprintf(&b, "while %s rule del %s priority %d 2>/dev/null; do :; done\n", ip, s, pref)
			}
		}
	}
	return b.String()
}

// renderBackstopTeardown removes the backstop's rules and routes.
func (pl *Plan) renderBackstopTeardown(b *strings.Builder, opt Options, io IpsetOptions) {
	opt.withDefaults()
	bs := pl.KillSwitchBackstop(io)
	if !bs.Active() || len(pl.backstopRuleSpecs(opt, io.LANIfaces)) == 0 {
		return
	}
	b.WriteString(pl.BackstopRulesTeardownFor(opt, io, io.LANIfaces))
	for _, ip := range bs.families() {
		fmt.Fprintf(b, "%s route flush table %d 2>/dev/null || true\n", ip, BackstopTable(opt))
	}
}

// RenderKeeneticScript is the whole Keenetic program: the filter section, the kill switch backstop's
// rules, the ip rules and tables (the hand-off's included), and only then the marking chains, NAT, MSS
// and DNS redirect.
//
// Ordering invariant: for any mark, the ip rule and table that route it, and for a
// kill-switched egress the table's blackhole and the mark's blackhole rule, exist BEFORE any iptables
// rule can set that mark. The routing came after the chain: a mark the restore commit started setting
// (a new kill-switched group, a list's own egress, a renumbered mark, the hook's first run at boot)
// matched no rule until the script reached that egress's lines, skipped the backstop (which looks only
// at unmarked packets) and left by the main table, the WAN, with the plan's ctmark, so no sweep found
// it either. Rules for a mark nobody carries yet are inert. The teardown removes in the reverse order.
func (pl *Plan) RenderKeeneticScript(opt Options, io IpsetOptions) string {
	io.withDefaults()
	var b strings.Builder
	pl.renderFilterSection(&b, io)
	writeRuleDump(&b, pl.needsV6Rules(io))
	// The hold's routes and the backstop's rules first, then the set restores and the
	// fill, so nothing that takes time runs before the hold holds.
	pl.renderBackstopRules(&b, opt, io)
	pl.renderBootRestore(&b, io)
	pl.renderBootFill(&b, opt, io)
	b.WriteString(pl.RenderIPScript(opt))
	pl.renderHandoffIP(&b, opt, io)
	pl.renderMangleAndNat(&b, io)
	return b.String()
}
