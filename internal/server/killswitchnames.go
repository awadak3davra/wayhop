package server

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"wayhop/internal/clash"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
	"wayhop/internal/writebehind"
)

// killswitchnames.go holds kill-switched NAMES by address on the nft plane, as the
// Keenetic plane does with the sets its resolver fills (killswitchlearned.go).
//
// On OpenWrt a list's names are matched by the core. Until now nothing in the kernel knew which
// addresses they were, so with the core down the only thing between them and the provider was the
// broad names hold, and that one lets go after its period by design: from then on every kill-switched
// name left by the provider until the core was back. In fast mode there was no hold at all.
//
// Now the daemon learns the addresses. The core reports every connection it carries with the
// outbounds it chose; a connection that went through a kill-switched list's or rule's outbound is
// that list's traffic, whatever matched it (a name, a geo set, a port), and its destination goes into
// the list's set in the guard's table, with a timeout. The guard lets such an address leave by the
// core's TUN or by a tunnel and never by the provider, whether the core runs or not and in every
// routing mode. The broad hold is then needed only for an address nobody has reached yet.
//
// RAM: one map entry per address, at most ksNameMaxPerSet per set and ksNameMaxTotal in all (about
// 1 MB at the very top; tens of KB for a household's lists). The kernel's sets are bounded too
// (pbr.GuardNameSetSize). One read of the core's connection table per pass of the learn loop, while
// the core runs.
//
// Flash: the file is written through a writebehind.Writer, at most once an hour and only when the
// members changed (not when a timeout was renewed), plus on a graceful stop and when an Apply is
// saved. It is a plain nft program of `add element` lines with each entry's remaining timeout, which
// the boot loader loads after the guard, so the addresses are held from the first second of a boot.
//
// Limits, stated in NOTES: a connection that opens and closes between two passes of the learn loop
// (killswitchlearn.go, every 5 s) is not seen; a destination the core reaches through a fake address
// (fakeip) is not learned (the fake address reaches nothing without the core); in fast mode the core
// does not carry the home network, so only what an application sends through its proxy port is seen.

const (
	// ksNameTTL is how long an address stays held after it was last seen in use, in seconds.
	ksNameTTL = 24 * 3600
	// ksNameRefresh: an address seen again with less than this left gets a fresh ksNameTTL. Renewing
	// on every sighting would be an nft call per tick for every open connection.
	ksNameRefresh = ksNameTTL / 2
	// ksNameMinTTL floors a timeout written to flash: the file is rewritten only when the members
	// change, so its timeouts are a snapshot, and an address renewed since would come back after a
	// reboot with minutes left while devices still hold the answer (the same rule as the Keenetic file).
	ksNameMinTTL    = 3600
	ksNameMaxPerSet = pbr.GuardNameSetSize / 2
	ksNameMaxTotal  = 16384
	ksNameMaxBytes  = 1 << 20
	ksNameInterval  = time.Hour
	ksNamePollTime  = 5 * time.Second
	// ksNameFailLogEvery is the least time, in seconds, between two log lines about a failed load.
	ksNameFailLogEvery = 300
	// ksNameFileHead is the first line of the file.
	ksNameFileHead = "# Written by WayHop: addresses the kill-switched names were reached at. Loaded after ks-guard.nft.\n"
)

// ksNames is the learned addresses in RAM and their file's writer.
type ksNames struct {
	mu     sync.Mutex
	loaded bool
	// sets is set base name (pbr.GuardNameSet.Set) -> address -> expiry in unix seconds.
	sets map[string]map[netip.Addr]int64
	w    *writebehind.Writer
	// failLogged is when a failed load was last logged (unix seconds): the loop tries again every few
	// seconds, and a set the kernel has full would fill the log.
	failLogged int64
	// fileSets is the sets the file on flash names, as last written or read.
	fileSets map[string]bool
	// now and write stand in for the clock and the durable write in tests.
	now   func() time.Time
	write func(path string, data []byte, perm os.FileMode) error
}

func (n *ksNames) clock() int64 {
	if n.now != nil {
		return n.now().Unix()
	}
	return time.Now().Unix()
}

// ksNamesEnabled: the nft plane's guard exists on OpenWrt only, and the demo writes nothing.
func (s *Server) ksNamesEnabled() bool {
	return s != nil && !s.config().Demo && s.detectedPlatform() == platform.OpenWrt
}

// loadLocked reads the file on flash into RAM once. Each entry's timeout counts from now, as it does
// for the boot loader that put the same file into the kernel.
func (n *ksNames) loadLocked() {
	if n.loaded {
		return
	}
	n.loaded = true
	n.sets, n.fileSets = map[string]map[netip.Addr]int64{}, map[string]bool{}
	n.w = writebehind.New(ksBootLearnedFile, 0o600, writebehind.Options{Debounce: 2 * time.Second, MinInterval: ksNameInterval, Write: n.write, Now: n.now})
	data, err := os.ReadFile(ksBootLearnedFile)
	if err != nil {
		return
	}
	if fi, err := os.Stat(ksBootLearnedFile); err == nil {
		n.w.Seed(data, fi.ModTime())
	}
	now := n.clock()
	for _, line := range strings.Split(string(data), "\n") {
		set, addr, ttl, ok := parseLearnedLine(line)
		if !ok {
			continue
		}
		n.fileSets[set] = true
		if n.sets[set] == nil {
			n.sets[set] = map[netip.Addr]int64{}
		}
		n.sets[set][addr] = now + int64(ttl)
	}
}

// parseLearnedLine reads one line of the file:
//
//	add element inet wayhop_ks kn_ru_heavy_4 { 93.184.216.34 timeout 86400s }
func parseLearnedLine(line string) (set string, addr netip.Addr, ttl int, ok bool) {
	f := strings.Fields(line)
	if len(f) != 10 || f[0] != "add" || f[1] != "element" || f[2] != "inet" || f[3] != pbr.GuardTable ||
		f[5] != "{" || f[7] != "timeout" || f[9] != "}" {
		return "", netip.Addr{}, 0, false
	}
	set = strings.TrimSuffix(strings.TrimSuffix(f[4], "_4"), "_6")
	if set == f[4] {
		return "", netip.Addr{}, 0, false
	}
	addr, err := netip.ParseAddr(f[6])
	if err != nil {
		return "", netip.Addr{}, 0, false
	}
	ttl, err = strconv.Atoi(strings.TrimSuffix(f[8], "s"))
	if err != nil || ttl <= 0 {
		return "", netip.Addr{}, 0, false
	}
	return set, addr.Unmap(), ttl, true
}

// learnedLine renders one address of a set as the file and the replay carry it.
func learnedLine(set string, addr netip.Addr, ttl int) string {
	fam := "_4"
	if addr.Is6() {
		fam = "_6"
	}
	return fmt.Sprintf("add element inet %s %s%s { %s timeout %ds }\n", pbr.GuardTable, set, fam, addr, ttl)
}

// planNameSets is the plan's name sets by base name.
func planNameSets(plan *pbr.Plan) map[string]bool {
	out := map[string]bool{}
	if plan != nil {
		for _, n := range plan.GuardNameSets {
			out[n.Set] = true
		}
	}
	return out
}

// renderLocked renders the learned addresses of the given sets as `add element` lines, each with
// what is left of its timeout and never less than floor seconds. The newest entries are kept within
// the caps; the order is stable.
func (n *ksNames) renderLocked(sets map[string]bool, floor, maxEntries, maxBytes int) string {
	type entry struct {
		set  string
		addr netip.Addr
		left int
	}
	now := n.clock()
	var es []entry
	for set, addrs := range n.sets {
		if !sets[set] {
			continue
		}
		for a, exp := range addrs {
			if left := int(exp - now); left > 0 {
				es = append(es, entry{set, a, left})
			}
		}
	}
	sort.Slice(es, func(i, j int) bool {
		if es[i].left != es[j].left {
			return es[i].left > es[j].left
		}
		if es[i].set != es[j].set {
			return es[i].set < es[j].set
		}
		return es[i].addr.Less(es[j].addr)
	})
	var lines []string
	size := 0
	for _, e := range es {
		line := learnedLine(e.set, e.addr, max(e.left, floor))
		if len(lines) >= maxEntries || size+len(line) > maxBytes {
			break
		}
		lines = append(lines, line)
		size += len(line)
	}
	sort.Strings(lines)
	return strings.Join(lines, "")
}

// learnedNamesProgram is the program that puts the plan's learned addresses back into a guard that
// has just been loaded (the adapter appends it to the load's transaction).
func (s *Server) learnedNamesProgram(plan *pbr.Plan) string {
	if !s.ksNamesEnabled() || plan == nil || len(plan.GuardNameSets) == 0 {
		return ""
	}
	n := &s.ksn
	n.mu.Lock()
	defer n.mu.Unlock()
	n.loadLocked()
	return n.renderLocked(planNameSets(plan), 1, ksNameMaxTotal, ksNameMaxBytes)
}

// produceLearnedNames renders the file for the installed plan's sets.
func (s *Server) produceLearnedNames(sets map[string]bool) func() ([]byte, error) {
	return func() ([]byte, error) {
		n := &s.ksn
		n.mu.Lock()
		defer n.mu.Unlock()
		body := n.renderLocked(sets, ksNameMinTTL, ksNameMaxTotal, ksNameMaxBytes-len(ksNameFileHead))
		n.fileSets = map[string]bool{}
		for set := range sets {
			n.fileSets[set] = true
		}
		return []byte(ksNameFileHead + body), nil
	}
}

// syncLearnedFile keeps the file loadable into the installed plan's guard. nft refuses a whole file
// for one set the table does not have, so when the file names a set the plan no longer has it is
// written again now; that happens only when an Apply changed the kill-switched lists. A plan without
// name sets has no file.
func (s *Server) syncLearnedFile(plan *pbr.Plan) {
	if !s.ksNamesEnabled() {
		return
	}
	sets := planNameSets(plan)
	n := &s.ksn
	n.mu.Lock()
	n.loadLocked()
	stale := false
	for set := range n.fileSets {
		stale = stale || !sets[set]
	}
	for set := range n.sets {
		if !sets[set] {
			delete(n.sets, set)
		}
	}
	w := n.w
	n.mu.Unlock()
	if len(sets) == 0 {
		if err := os.Remove(ksBootLearnedFile); err != nil && !os.IsNotExist(err) {
			log.Printf("kill switch: remove %s: %v", ksBootLearnedFile, err)
		}
		n.mu.Lock()
		n.fileSets = map[string]bool{}
		n.mu.Unlock()
		return
	}
	if stale {
		w.Mark(s.produceLearnedNames(sets))
		if err := w.Flush(); err != nil {
			log.Printf("kill switch: learned addresses: %v", err)
		}
	}
}

// saveLearnedNamesNow writes the file now if there is anything pending (an Apply was saved).
func (s *Server) saveLearnedNamesNow(plan *pbr.Plan) {
	if !s.ksNamesEnabled() || plan == nil || len(plan.GuardNameSets) == 0 {
		return
	}
	n := &s.ksn
	n.mu.Lock()
	n.loadLocked()
	w := n.w
	n.mu.Unlock()
	if !w.Pending() {
		return
	}
	if err := w.Flush(); err != nil {
		log.Printf("kill switch: learned addresses: %v", err)
	}
}

// learnNamesTick is one pass of the learn loop (killswitchlearn.go): read the core's connections and
// learn from them. Only while the core runs and the plan has kill-switched names; one bounded HTTP read.
func (s *Server) learnNamesTick(ctx context.Context, plan *pbr.Plan, coreRunning bool, run func(context.Context, string) error) {
	if !s.ksNamesEnabled() || plan == nil || len(plan.GuardNameSets) == 0 || !coreRunning || s.clash == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, ksNamePollTime)
	defer cancel()
	conns, err := s.clash.Connections(ctx)
	if err != nil {
		return // the core is starting, or busy: the next tick reads again
	}
	s.learnNames(ctx, plan, conns.Connections, run)
}

// learnableAddr reports whether a connection's destination is an address worth holding: a public
// one that is not a tunnel's own server and not one of the core's fake addresses.
func learnableAddr(a netip.Addr, bypass []netip.Prefix) bool {
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsMulticast() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() {
		return false
	}
	for _, p := range ksNeverLearned {
		if p.Contains(a) {
			return false
		}
	}
	for _, p := range bypass {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// ksNeverLearned: carrier-grade NAT, the benchmark range sing-box's fakeip uses, and its IPv6 one.
var ksNeverLearned = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("240.0.0.0/4"),
}

// learnNames puts the destinations of the connections that went through a kill-switched list's or
// rule's outbound into that list's set: in RAM, and in the kernel through run (an nft program). A
// new address, and one seen again with less than half its timeout left, costs one line of one
// transaction per tick; a tick that sees nothing new runs nothing. A changed membership marks the
// file's writer.
func (s *Server) learnNames(ctx context.Context, plan *pbr.Plan, conns []clash.Conn, run func(context.Context, string) error) {
	byTag := map[string][]pbr.GuardNameSet{}
	for _, ns := range plan.GuardNameSets {
		for _, tag := range ns.Outbounds {
			byTag[tag] = append(byTag[tag], ns)
		}
	}
	if len(byTag) == 0 {
		return // a plan stored before the sets carried their outbounds
	}
	var bypass []netip.Prefix
	for _, c := range append(append([]string(nil), plan.BypassV4...), plan.BypassV6...) {
		if p, err := netip.ParsePrefix(c); err == nil {
			bypass = append(bypass, p)
		} else if a, err := netip.ParseAddr(c); err == nil {
			bypass = append(bypass, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	sets := planNameSets(plan)
	// One step against a load of the guard. A load renders the learned addresses and
	// then replaces the table; an address this pass put into RAM and into the old table between
	// those two was in neither the replay nor the new table, and RAM did not add it again until its
	// refresh, half a day later.
	s.ksGuardTx.Lock()
	defer s.ksGuardTx.Unlock()
	n := &s.ksn
	n.mu.Lock()
	n.loadLocked()
	now := n.clock()
	changed := false
	total := 0
	for set, addrs := range n.sets {
		for a, exp := range addrs {
			if exp <= now {
				delete(addrs, a) // the kernel timed it out at the same moment
				changed = true
			}
		}
		total += len(addrs)
		if len(addrs) == 0 {
			delete(n.sets, set)
		}
	}
	add := map[string]map[string]int{}
	var evict strings.Builder
	var undo []func()
	for _, c := range conns {
		a, err := netip.ParseAddr(c.Metadata.DestinationIP)
		if err != nil {
			continue
		}
		a = a.Unmap()
		if !learnableAddr(a, bypass) {
			continue
		}
		for _, tag := range routeTargets(c.Chains) {
			for _, ns := range byTag[tag] {
				if !connIsOf(c, ns) {
					continue
				}
				set := ns.Set
				addrs := n.sets[set]
				if addrs == nil {
					addrs = map[netip.Addr]int64{}
					n.sets[set] = addrs
				}
				exp, known := addrs[a]
				if known && exp-now >= ksNameRefresh {
					continue
				}
				if !known {
					for len(addrs) >= ksNameMaxPerSet || total >= ksNameMaxTotal {
						victimSet, victim, ok := n.oldestLocked(set, len(addrs) >= ksNameMaxPerSet)
						if !ok {
							break
						}
						delete(n.sets[victimSet], victim)
						delete(add[victimSet], victim.String())
						total--
						fam := "_4"
						if victim.Is6() {
							fam = "_6"
						}
						fmt.Fprintf(&evict, "delete element inet %s %s%s { %s }\n", pbr.GuardTable, victimSet, fam, victim)
					}
					total++
					changed = true
				}
				addrs[a] = now + ksNameTTL
				if add[set] == nil {
					add[set] = map[string]int{}
				}
				add[set][a.String()] = ksNameTTL
				set, a, exp, known := set, a, exp, known
				undo = append(undo, func() {
					if known {
						n.sets[set][a] = exp
					} else {
						delete(n.sets[set], a)
					}
				})
			}
		}
	}
	w := n.w
	n.mu.Unlock()

	if len(add) > 0 {
		if evict.Len() > 0 {
			// Its own transaction, and its failure is nothing: an evicted address the kernel has
			// already timed out would otherwise fail the adds with it.
			_ = run(ctx, evict.String())
		}
		names := make([]string, 0, len(add))
		for set := range add {
			names = append(names, set)
		}
		sort.Strings(names)
		var program strings.Builder
		for _, set := range names {
			program.WriteString(pbr.RenderGuardLearn(set, add[set]))
		}
		if err := run(ctx, program.String()); err != nil {
			// The kernel does not hold them, so RAM must not say it does: the next tick sees the
			// same connections and tries again.
			n.mu.Lock()
			for i := len(undo) - 1; i >= 0; i-- {
				undo[i]()
			}
			quiet := n.failLogged != 0 && n.clock()-n.failLogged < ksNameFailLogEvery
			if !quiet {
				n.failLogged = n.clock()
			}
			n.mu.Unlock()
			if quiet {
				return
			}
			log.Printf("kill switch: %d address(es) of kill-switched names were not added to the guard: %v", len(undo), strings.TrimSpace(err.Error()))
			return
		}
	}
	if changed {
		w.Mark(s.produceLearnedNames(sets))
	}
}

// routeTargets is the tags of a connection's chain that can be the outbound its route named: the two
// ends. The core reports the chain from the tunnel that carries the connection to the outbound the
// route rule named (a group, when there is more than one tag); both ends are read so that the order
// does not matter, and connIsOf tells the tunnel's end from the route's. Tags in between are groups
// inside groups, never a route's target (counting every tag would let a list
// whose candidate is a plain tunnel take every connection any other route sends through it).
func routeTargets(chains []string) []string {
	switch n := len(chains); {
	case n == 0:
		return nil
	case n == 1 || chains[0] == chains[n-1]:
		return chains[:1]
	default:
		return []string{chains[0], chains[n-1]}
	}
}

// connIsOf reports whether a connection whose chain ends in the set's outbound is that list's or
// rule's traffic.
func connIsOf(c clash.Conn, ns pbr.GuardNameSet) bool {
	// A tunnel named directly is the whole chain; at the end of a longer one it is a group's member.
	if ns.Direct && len(c.Chains) != 1 {
		return false
	}
	if !ns.Shared {
		return true
	}
	// Another route sends traffic no kill switch covers to the same outbound: only the rule the core
	// matched tells them apart. It reports the rule as text, with the rule-sets it names:
	// `rule_set=[rs-ID rsm-ID] => route(tag)`.
	for _, word := range strings.FieldsFunc(c.Rule+" "+c.RulePayload, func(r rune) bool {
		return r == ' ' || r == '[' || r == ']' || r == '=' || r == ',' || r == '(' || r == ')' || r == '"'
	}) {
		for _, tag := range ns.RuleSets {
			if word == tag {
				return true
			}
		}
	}
	return false
}

// oldestLocked finds the entry that expires first: in set when inSet, else in any set.
func (n *ksNames) oldestLocked(set string, inSet bool) (string, netip.Addr, bool) {
	var (
		bestSet string
		best    netip.Addr
		bestExp int64
		found   bool
	)
	for name, addrs := range n.sets {
		if inSet && name != set {
			continue
		}
		for a, exp := range addrs {
			if !found || exp < bestExp || exp == bestExp && a.Less(best) {
				bestSet, best, bestExp, found = name, a, exp, true
			}
		}
	}
	return bestSet, best, found
}
