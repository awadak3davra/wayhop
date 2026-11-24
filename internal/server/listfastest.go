package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"wayhop/internal/ctflush"
	"wayhop/internal/failover"
	"wayhop/internal/localtz"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
	"wayhop/internal/store"
	"wayhop/internal/writebehind"
)

// listfastest.go is the routing-list producer of the kernel elector's units ("fastest tunnel per
// list", on KeeneticOS's and OpenWrt's kernel planes): a list in "fastest" mode has its own mark and table (pbr.Options.ListEgresses),
// its own probe targets and its own measurement cycle, and the elector re-points that table at the
// fastest working candidate. Everything here is in RAM with fixed caps (see the RAM note at the end);
// the journal reaches flash at most once an hour (and at shutdown) and only when it changed.

const (
	// fastestJournalFile holds each list's last 50 events beside apply-state.json.
	fastestJournalFile = "fastest-journal.json"
	// fastestJournalEvery is the flash rate limit for the journal: hourly. Every 10
	// minutes a flapping list rewrote up to ~320 KB 144 times a day; a graceful stop still writes the
	// last hour (writebehind.FlushAll), a power loss loses at most an hour of switch history.
	fastestJournalEvery = time.Hour
	// fastestNotifyEvery is the Telegram anti-spam window per list.
	fastestNotifyEvery = 10 * time.Minute
	// fastestTargetsTTL is how long automatic targets are reused before they are picked again.
	fastestTargetsTTL = time.Hour
	// fastestResetLimit bounds a ResetOnSwitch flush like an Apply's.
	fastestResetLimit = 4096
)

// fastestState is the per-list scheduler, the last measurements of every list key, the automatic
// target cache, the alert window and the journal writer. Guarded by mu.
type fastestState struct {
	mu       sync.Mutex
	last     map[string]int64                           // list id -> unix ms of its last measurement cycle
	want     map[string]bool                            // list id -> "probe now" asked
	cache    map[failover.ProbeKey]failover.ProbeResult // the latest result of every list key
	targets  map[string]fastestTargets                  // list id -> automatic targets
	notified map[string]int64                           // list id -> unix ms of its last alert
	slow     bool                                       // the last cycle was slowed by load

	journalOnce   sync.Once
	journal       *writebehind.Writer
	journalVer    uint64
	throughputVer uint64
}

type fastestTargets struct {
	key  string
	at   int64
	list []string // the targets measured now (at most two)
	// pool is every target worth trying for an automatic list, in order of preference; next is the
	// first one not tried yet, ok the targets that answered through a tunnel at least once. A target
	// that answers through no tunnel is swapped for the next untried one, so a CIDR list
	// whose first host has nothing on 443 does not judge its tunnels by it. Bounded: pool <= 8.
	pool []string
	next int
	ok   map[string]bool
}

// fastestTargetPoolMax bounds the automatic targets tried per list.
const fastestTargetPoolMax = 8

// builtinFastestTargets are well-known lists' own addresses, matched by the list's id or name.
var builtinFastestTargets = []struct {
	keys    []string
	targets []string
}{
	{[]string{"telegram"}, []string{"149.154.167.51:443", "91.108.56.130:443"}},
	{[]string{"meta", "instagram", "facebook"}, []string{"instagram.com:443", "facebook.com:443"}},
	{[]string{"youtube"}, []string{"www.youtube.com:443"}},
}

// autoFastestTargets are the two automatic targets a list starts with (autoFastestTargetPool).
func autoFastestTargets(rl model.RoutingList) []string {
	pool := autoFastestTargetPool(rl)
	if len(pool) > 2 {
		pool = pool[:2]
	}
	return pool
}

// autoFastestTargetPool is every automatic target worth trying for a list the operator gave none:
// the built-in ones of a well-known list; else, in this order, the first host of the list's largest
// public IPv4 prefixes on 443, two of its domains on 443, a host from the middle of each prefix on 443,
// and the first hosts again on 80. A router at a prefix's first address often has nothing on 443,
// a domain usually does, and a refused port still answers (netdiag.TCPConnectViaIface).
func autoFastestTargetPool(rl model.RoutingList) []string {
	key := strings.ToLower(rl.ID + " " + rl.Name)
	for _, b := range builtinFastestTargets {
		for _, k := range b.keys {
			if strings.Contains(key, k) {
				return append([]string(nil), b.targets...)
			}
		}
	}
	var prefixes []netip.Prefix
	var domains []string
	scan := func(entries []string) {
		for _, raw := range entries {
			v := strings.TrimSpace(raw)
			if v == "" {
				continue
			}
			if p, err := netip.ParsePrefix(v); err == nil {
				if p.Addr().Is4() {
					prefixes = append(prefixes, p.Masked())
				}
				continue
			}
			if a, err := netip.ParseAddr(v); err == nil {
				if a.Is4() {
					prefixes = append(prefixes, netip.PrefixFrom(a, 32))
				}
				continue
			}
			if len(domains) < 2 {
				d := strings.TrimPrefix(strings.TrimPrefix(v, "*."), ".")
				if strings.Contains(d, ".") && !strings.ContainsAny(d, ":/ *") {
					domains = append(domains, d)
				}
			}
		}
	}
	scan(rl.Manual)
	scan(rl.CIDRCache)
	scan(rl.DomainCache)
	sort.SliceStable(prefixes, func(i, j int) bool { return prefixes[i].Bits() < prefixes[j].Bits() })
	var firsts, mids []netip.Addr
	for _, p := range prefixes {
		host := p.Addr()
		if p.Bits() < 32 {
			host = host.Next()
		}
		if model.ValidateFastestTarget(netip.AddrPortFrom(host, 443).String()) != nil {
			continue
		}
		firsts = append(firsts, host)
		if p.Bits() <= 30 {
			a := p.Addr().As4()
			v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
			v += uint32(1)<<(31-p.Bits()) + 1
			mid := netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
			if model.ValidateFastestTarget(netip.AddrPortFrom(mid, 443).String()) == nil {
				mids = append(mids, mid)
			}
		}
		if len(firsts) == 3 {
			break
		}
	}
	var out []string
	seen := map[string]bool{}
	add := func(t string) {
		if !seen[t] && len(out) < fastestTargetPoolMax {
			seen[t] = true
			out = append(out, t)
		}
	}
	for _, a := range firsts {
		add(netip.AddrPortFrom(a, 443).String())
	}
	for _, d := range domains {
		add(d + ":443")
	}
	for _, a := range mids {
		add(netip.AddrPortFrom(a, 443).String())
	}
	for _, a := range firsts {
		add(netip.AddrPortFrom(a, 80).String())
	}
	return out
}

// fastestTargetsFor is a list's targets: its own, or the automatic ones, re-picked hourly or when
// the list changed.
//
// addrOnly is a kill-switched list (model.ListKillSwitch), which is measured by address targets alone
// (see fastestUnitsFrom). Its automatic pool is picked from addresses to begin with. Picked from
// everything and filtered at the unit, a pair holding a name would be measured as one target while
// the pair kept here still held two, so rotateFastestTargets and fastestTargetsOnTrial would not
// recognise the unit's targets as theirs: a silent target would never be replaced. The operator's own
// targets are returned as typed; the unit filters those.
func (s *Server) fastestTargetsFor(rl model.RoutingList, addrOnly bool, now int64) []string {
	if rl.Fastest != nil && len(rl.Fastest.Targets) > 0 {
		return append([]string(nil), rl.Fastest.Targets...)
	}
	key := model.RoutingListRev(rl) + "/" + strconv.FormatInt(rl.CIDRRefreshed, 10) + "/" + strconv.FormatInt(rl.DomainRefreshed, 10)
	if addrOnly {
		key += "/addr" // a kill switch set or lifted picks again
	}
	f := &s.fastest
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.targets[rl.ID]; ok && c.key == key && now-c.at < fastestTargetsTTL.Milliseconds() {
		return append([]string(nil), c.list...)
	}
	if f.targets == nil {
		f.targets = map[string]fastestTargets{}
	}
	pool := autoFastestTargetPool(rl)
	if addrOnly {
		pool = addressTargets(pool)
	}
	n := len(pool)
	if n > 2 {
		n = 2
	}
	f.targets[rl.ID] = fastestTargets{key: key, at: now, list: append([]string(nil), pool[:n]...), pool: pool, next: n, ok: map[string]bool{}}
	return append([]string(nil), pool[:n]...)
}

// rotateFastestTargets validates automatic targets after a list's cycle: one that answered through a
// tunnel is kept for good; one that answered through none is swapped for the next untried target of
// the pool when that cannot be the tunnels' fault (another target answered through a tunnel), or when
// it never answered at all since it was picked. The swapped list is measured on the next tick. A list
// with its own targets is never touched: those are the operator's.
func (s *Server) rotateFastestTargets(states []failover.UnitState) {
	f := &s.fastest
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, st := range states {
		if st.List == nil {
			continue
		}
		id := st.List.List
		c, ok := f.targets[id]
		if !ok || len(c.pool) == 0 || !sameTargets(c.list, st.Targets) {
			continue
		}
		answered := map[string]bool{}
		for _, row := range st.List.Matrix {
			for t, cell := range row {
				if cell.OK {
					answered[t] = true
					c.ok[t] = true
				}
			}
		}
		changed := false
		for _, dead := range st.List.DeadTargets {
			if len(answered) == 0 && c.ok[dead] {
				continue // every target silent and this one answered before: the tunnels, not it
			}
			for i, t := range c.list {
				if t != dead || c.next >= len(c.pool) {
					continue
				}
				c.list[i] = c.pool[c.next]
				c.next++
				changed = true
			}
		}
		f.targets[id] = c
		if changed {
			if f.want == nil {
				f.want = map[string]bool{}
			}
			f.want[id] = true
		}
	}
}

// addressTargets keeps the "ip:port" targets.
// referenceCandidates are well-known anycast HTTPS endpoints of public resolvers, by address (the
// router resolves nothing for them), used only to tell "the internet is reachable by the router's own
// path" for a kill-switched list.
var referenceCandidates = []string{"1.1.1.1:443", "9.9.9.9:443", "8.8.8.8:443", "94.140.14.14:443"}

// neutralReferenceTargets are the reference candidates outside every fail-closed zone's static
// prefixes. Never nil: an empty answer means no reference is asked at all (the list's table is then
// kept as it is, "targets unreachable", which a kill switch drops the same way). Addresses a
// kill-switched DOMAIN list's set learns at run time are not known here; a resolver's anycast address
// in such a list is the residual.
func neutralReferenceTargets(plan *pbr.Plan) []string {
	fc := map[string]bool{}
	for _, e := range plan.Egresses {
		fc[e.Tag] = e.FailClosed || e.Kind == pbr.EgressBlackhole
	}
	var covered []netip.Prefix
	for _, z := range plan.Zones {
		if !fc[z.EgressTag] {
			continue
		}
		for _, c := range append(append([]string(nil), z.V4...), z.V6...) {
			if p, err := netip.ParsePrefix(c); err == nil {
				covered = append(covered, p)
			} else if a, err := netip.ParseAddr(c); err == nil {
				covered = append(covered, netip.PrefixFrom(a, a.BitLen()))
			}
		}
	}
	out := []string{}
	for _, t := range referenceCandidates {
		ap := netip.MustParseAddrPort(t)
		inside := false
		for _, p := range covered {
			if p.Contains(ap.Addr()) {
				inside = true
				break
			}
		}
		if !inside {
			out = append(out, t)
		}
	}
	return out
}

func addressTargets(ts []string) []string {
	var out []string
	for _, t := range ts {
		if _, err := netip.ParseAddrPort(t); err == nil {
			out = append(out, t)
		}
	}
	return out
}

func sameTargets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// fastestUnitsFrom is the list producer: one unit per list egress of the applied plan. Candidates are
// the list's tunnels the kernel can route; a list with fewer than two of them got no egress of its
// own from the compiler, so it never appears here.
func fastestUnitsFrom(plan *pbr.Plan, profile *model.Profile, ifaceOf map[string]string, targets func(model.RoutingList) []string, fresh map[string]bool, now int64) []failover.TableUnit {
	if plan == nil || profile == nil {
		return nil
	}
	var out []failover.TableUnit
	for _, eg := range plan.Egresses {
		id, ok := model.ListEgressID(eg.Tag)
		if !ok || eg.Kind != pbr.EgressInterface || eg.Table == 0 {
			continue
		}
		var rl *model.RoutingList
		for i := range profile.RoutingLists {
			if profile.RoutingLists[i].ID == id {
				rl = &profile.RoutingLists[i]
				break
			}
		}
		if rl == nil || rl.Fastest == nil {
			continue
		}
		f := *rl.Fastest
		iface := map[string]string{}
		var cands []string
		for _, c := range model.ListCandidates(profile, *rl) {
			if link := ifaceOf[c]; link != "" {
				iface[c] = link
				cands = append(cands, c)
			}
		}
		name := rl.Name
		if name == "" {
			name = rl.ID
		}
		// Under a kill switch "wan" runs as "block": the list's traffic never leaves by the provider.
		lp := &failover.ListPolicy{List: rl.ID, OnAllDown: model.EffectiveAllDown(profile, *rl), Fresh: fresh[rl.ID]}
		if f.PinActive(now/1000) && iface[f.Pinned] != "" {
			lp.Pinned = f.Pinned
			if f.PinnedUntil > 0 {
				lp.PinUntil = f.PinnedUntil * 1000
			}
		}
		for _, x := range f.Excluded {
			if iface[x] != "" {
				lp.Excluded = append(lp.Excluded, x)
			}
		}
		t := targets(*rl)
		if model.ListKillSwitch(profile, *rl) {
			// The router resolves a host-name target itself, by its own resolver, which may leave by the
			// provider: for a kill-switched list that would ask for the list's own names outside the
			// tunnel. Only address targets are measured for it.
			t = addressTargets(t)
			// And its "is the router's own path up" reference never dials the list's destinations by
			// the WAN: neutral addresses no kill-switched list holds.
			lp.RefTargets = neutralReferenceTargets(plan)
		}
		if len(t) == 0 {
			t = []string{groupProbeTarget(model.Group{})}
		}
		out = append(out, failover.TableUnit{
			Key:        failover.UnitKey{Owner: eg.Tag, Table: eg.Table},
			Name:       name,
			Policy:     electionPolicy(f.ElectionFor(*rl)),
			Candidates: cands,
			Iface:      iface,
			Targets:    t,
			Cfg: failover.Config{ToleranceMs: f.DeltaMs(), TolerancePct: f.DeltaPct(),
				MinDwellMS: int64(f.Dwell()) * 1000},
			List: lp,
		})
	}
	return out
}

// fastestUnits is fastestUnitsFrom with this server's target cache.
func (s *Server) fastestUnits(plan *pbr.Plan, profile *model.Profile, ifaceOf map[string]string, fresh map[string]bool, now int64) []failover.TableUnit {
	units := fastestUnitsFrom(plan, profile, ifaceOf, func(rl model.RoutingList) []string {
		return s.fastestTargetsFor(rl, model.ListKillSwitch(profile, rl), now)
	}, fresh, now)
	for i := range units {
		units[i].List.TargetsOnTrial = s.fastestTargetsOnTrial(units[i].List.List, units[i].Targets)
	}
	return units
}

// fastestTargetsOnTrial reports a list measured by automatic targets none of which has answered
// through a tunnel yet, while its pool has others to try (failover.ListPolicy.TargetsOnTrial). The
// targets must be the very ones rotateFastestTargets will replace after a silent cycle: that is what
// ends the trial, at the latest when the pool (at most fastestTargetPoolMax) is used up.
func (s *Server) fastestTargetsOnTrial(id string, targets []string) bool {
	f := &s.fastest
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.targets[id]
	if !ok || c.next >= len(c.pool) || !sameTargets(c.list, targets) {
		return false
	}
	for _, t := range c.list {
		if c.ok[t] {
			return false
		}
	}
	return true
}

// busyLoad reports a router whose 1-minute load is above twice its cores: measurements then run at
// half the rate.
var busyLoad = func() bool {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return false
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return false
	}
	l, err := strconv.ParseFloat(f[0], 64)
	return err == nil && l > float64(2*runtime.NumCPU())
}

// fastestDue picks the lists whose cycle is due (or that the operator asked to measure now) and
// starts their cycle.
func (s *Server) fastestDue(units []failover.TableUnit, intervalOf func(string) int, now int64) map[string]bool {
	if len(units) == 0 {
		return nil
	}
	slow := busyLoad()
	f := &s.fastest
	f.mu.Lock()
	defer f.mu.Unlock()
	if slow != f.slow {
		f.slow = slow
		if slow {
			log.Printf("list measurements slowed: the router is busy (load above twice its cores); intervals doubled")
		} else {
			log.Printf("list measurements back to their own intervals")
		}
	}
	if f.last == nil {
		f.last = map[string]int64{}
	}
	due := map[string]bool{}
	for _, u := range units {
		id := u.List.List
		every := int64(intervalOf(id)) * 1000
		if slow {
			every *= 2
		}
		if f.want[id] || now-f.last[id] >= every {
			due[id] = true
			f.last[id] = now
			delete(f.want, id)
		}
	}
	return due
}

// fastestStore keeps the results of this cycle's list keys and forgets keys no list needs any more,
// so the cache is bounded by the lists' own candidates x targets.
func (s *Server) fastestStore(units []failover.TableUnit, due map[string]bool, probes map[failover.ProbeKey]failover.ProbeResult) {
	f := &s.fastest
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cache == nil {
		f.cache = map[failover.ProbeKey]failover.ProbeResult{}
	}
	need := map[failover.ProbeKey]bool{}
	for _, k := range failover.ProbeKeys(units) {
		need[k] = true
	}
	for _, u := range units {
		if !due[u.List.List] {
			continue
		}
		for _, k := range failover.ProbeKeys([]failover.TableUnit{u}) {
			if r, ok := probes[k]; ok {
				f.cache[k] = r
			} else {
				delete(f.cache, k) // not measured this cycle: the monitor decides instead
			}
		}
	}
	for k := range f.cache {
		if !need[k] {
			delete(f.cache, k)
		}
	}
	for id := range f.last {
		found := false
		for _, u := range units {
			if u.List.List == id {
				found = true
				break
			}
		}
		if !found {
			delete(f.last, id)
			delete(f.notified, id)
		}
	}
}

// fastestMerge is what the elector judges by this tick: this cycle's probes over the lists' cached
// results (a list between its cycles decides nothing, but its panel keeps its last matrix).
func (s *Server) fastestMerge(probes map[failover.ProbeKey]failover.ProbeResult) map[failover.ProbeKey]failover.ProbeResult {
	f := &s.fastest
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.cache) == 0 {
		return probes
	}
	out := make(map[failover.ProbeKey]failover.ProbeResult, len(probes)+len(f.cache))
	for k, v := range f.cache {
		out[k] = v
	}
	for k, v := range probes {
		out[k] = v
	}
	return out
}

// requestFastestProbe asks for a list's measurement on the next tick (at most 20 s away).
func (s *Server) requestFastestProbe(id string) {
	f := &s.fastest
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.want == nil {
		f.want = map[string]bool{}
	}
	f.want[id] = true
}

// fastestPolicyChanged asks for a cycle now for every list whose pin, exclusions or all-down choice
// differ from what its unit last ran with: an Apply changed them, or a timed pin ran out. A list
// decides only on its own cycle, so an applied pin (or an excluded incumbent, or the end of a pin)
// would otherwise wait for the next one, up to ten minutes with the table still on the old tunnel,
// while the panel calls the change applied.
func (s *Server) fastestPolicyChanged(units []failover.TableUnit) {
	if len(units) == 0 {
		return
	}
	states := s.fastestStates()
	for _, u := range units {
		st, ok := states[u.List.List]
		if !ok || st.List == nil {
			continue // a new unit: its first cycle is due anyway
		}
		if st.List.Pinned != u.List.Pinned || st.List.OnAllDown != u.List.OnAllDown || !sameTargets(st.List.Excluded, u.List.Excluded) {
			s.requestFastestProbe(u.List.List)
			continue
		}
		// The table no longer holds what the list chose: an install of the plane seeded its first
		// tunnel over the elected one (a renumbered table, a restart of nothing but the plane), or an
		// Apply took the held tunnel out of the list. Between cycles the unit decides nothing, so
		// without this the list rode the seed for up to its whole interval.
		if st.List.AllDown {
			// Every tunnel was dead at the last cycle. A tunnel the list has gained since (an Apply
			// added it) was not among them, and may work: measure now instead of at the list's next
			// cycle, up to ten minutes away. Its row appears in the matrix with that
			// cycle, so this asks once.
			for _, id := range u.Candidates {
				if _, measured := st.List.Matrix[id]; u.Iface[id] != "" && !measured {
					s.requestFastestProbe(u.List.List)
					break
				}
			}
			continue
		}
		if st.List.TargetsDown {
			continue // nothing moves while no target answers; asking every tick would only probe more
		}
		held := st.CurrentIface
		if c := s.kernelElector().Committed(u.Key); (held != "" && !u.Accepts(held)) || (c != "" && u.Iface[c] != held) || st.Table != u.Key.Table {
			s.requestFastestProbe(u.List.List)
		}
	}
}

// fastestRetry asks again, on the next tick, for the list cycles that were measured but not decided.
func (s *Server) fastestRetry(fresh map[string]bool) {
	if len(fresh) == 0 {
		return
	}
	f := &s.fastest
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.want == nil {
		f.want = map[string]bool{}
	}
	for id, due := range fresh {
		if due {
			f.want[id] = true
		}
	}
}

// intervalOfList reads a list's measurement interval from profile.
func intervalOfList(profile *model.Profile) func(string) int {
	return func(id string) int {
		for _, rl := range profile.RoutingLists {
			if rl.ID == id && rl.Fastest != nil {
				return rl.Fastest.Interval()
			}
		}
		return model.DefaultFastestSec
	}
}

// onFastestEvents reports what the elector did to list tables: the log line, the Failover switch
// log (and through it the Telegram bot when the list asked for it, at most every 10 minutes), and
// the conntrack reset the list asked for.
func (s *Server) onFastestEvents(units []failover.TableUnit, evs []failover.UnitEvent, plan *pbr.Plan, profile *model.Profile) {
	for _, ev := range evs {
		id, ok := model.ListEgressID(ev.Key.Owner)
		if !ok || !(ev.Wrote || ev.Reason == failover.ReasonAllDown) {
			continue
		}
		u := unitByTable(units, ev)
		log.Printf("list fastest: %s (table %d) %s -> %s: %s (%s)", u.Name, ev.Key.Table, orNone(ev.FromIface), orNone(ev.ToIface), ev.Reason, ev.Detail)
		var pol model.FastestPolicy
		for _, rl := range profile.RoutingLists {
			if rl.ID == id && rl.Fastest != nil {
				pol = *rl.Fastest
			}
		}
		quiet := !pol.Notify
		if !quiet {
			now := time.Now().UnixMilli()
			s.fastest.mu.Lock()
			if s.fastest.notified == nil {
				s.fastest.notified = map[string]int64{}
			}
			if now-s.fastest.notified[id] < fastestNotifyEvery.Milliseconds() {
				quiet = true
			} else {
				s.fastest.notified[id] = now
			}
			s.fastest.mu.Unlock()
		}
		if s.monitor != nil {
			s.monitor.RecordListSwitch(ev.Key.Owner, u.Name, ev.From, ev.To, ev.RTTTo, quiet)
		}
		if pol.ResetOnSwitch && ev.Wrote {
			for _, eg := range plan.Egresses {
				if eg.Tag == ev.Key.Owner && eg.Mark != 0 {
					go s.flushListFlows(u.Name, eg.Mark, plan.Mask)
				}
			}
		}
	}
}

// fastestFlush is the conntrack flush; a variable so tests stand in for it.
var fastestFlush = func(mark, mask uint32) (ctflush.Result, error) {
	t, err := ctflushOpen()
	if err != nil {
		return ctflush.Result{}, err
	}
	defer t.Close()
	return ctflush.FlushMark(t, mark, mask, ctflush.Options{Limit: fastestResetLimit, Local: ctflushLocal()})
}

// flushListFlows drops a list's connections after its table moved, so they reconnect through the new
// tunnel at once instead of stalling on the old one's NAT binding.
func (s *Server) flushListFlows(name string, mark, mask uint32) {
	res, err := fastestFlush(mark, mask)
	switch {
	case errors.Is(err, ctflush.ErrUnsupported):
	case err != nil:
		log.Printf("list fastest: %s: connections not reset (%v); they move as they reconnect", name, err)
	case res.Deleted > 0:
		log.Printf("list fastest: %s: reset %d connection(s) after the switch", name, res.Deleted)
	}
}

// fastestJournalPath is where the journal lives, "" when this server has no state directory (tests).
func (s *Server) fastestJournalPath() string {
	if s.applyStateDir == "" && (s.cfg == nil || s.cfg.Demo) {
		return ""
	}
	dir := s.stateDir()
	if dir == "" {
		return ""
	}
	return statePath(filepath.Join(dir, fastestJournalFile))
}

// fastestJournalDoc is the journal on flash: per unit owner ("list:<id>"), its last 50 events, plus
// the optional small throughput result/budget state. Throughput shares this writer and flash budget.
type fastestJournalDoc struct {
	V          int                             `json:"v"`
	Lists      map[string][]failover.UnitEvent `json:"lists"`
	Throughput throughputJournalState          `json:"throughput,omitempty"`
}

// initFastestJournal restores the journal a previous run left and sets up its rate-limited writer.
// The writer keeps no copy: it renders both event and throughput state when it writes.
func (s *Server) initFastestJournal(e *failover.TableElector) {
	s.fastest.journalOnce.Do(func() {
		path := s.fastestJournalPath()
		if path == "" {
			return
		}
		w := writebehind.New(path, 0o600, writebehind.Options{Debounce: time.Minute, MinInterval: fastestJournalEvery})
		if b, err := os.ReadFile(path); err == nil {
			var doc fastestJournalDoc
			if json.Unmarshal(b, &doc) == nil {
				for owner, evs := range doc.Lists {
					e.SeedEvents(owner, evs)
				}
				s.restoreThroughputJournal(doc.Throughput)
			}
			mod := time.Now()
			if fi, err := os.Stat(path); err == nil {
				mod = fi.ModTime()
			}
			w.Seed(b, mod)
		}
		s.fastest.journal = w
		s.fastest.journalVer = e.JournalVersion()
		s.fastest.throughputVer = s.throughputRevision()
	})
}

// persistFastestJournal marks either kind of journal change. No producer overwrites the other: every
// mark renders the combined document. The shared writer still writes at most hourly and skips equal
// bytes; the producer takes snapshots without holding fastest.mu.
func (s *Server) persistFastestJournal(e *failover.TableElector) {
	v, tv := e.JournalVersion(), s.throughputRevision()
	s.fastest.mu.Lock()
	w := s.fastest.journal
	if w == nil || (v == s.fastest.journalVer && tv == s.fastest.throughputVer) {
		s.fastest.mu.Unlock()
		return
	}
	s.fastest.journalVer, s.fastest.throughputVer = v, tv
	s.fastest.mu.Unlock()
	w.Mark(func() ([]byte, error) {
		return json.Marshal(fastestJournalDoc{V: 1, Lists: e.Journals(), Throughput: s.throughputJournalSnapshot()})
	})
}

// fastestSupported reports whether this router runs the per-list choice, and why not. KeeneticOS runs
// it as before. Any other router (OpenWrt) runs it on the nft plane, which exists in hybrid and fast
// routing only: in tun and mixed mode nothing marks a list's packets, so there is no table to point.
func (s *Server) fastestSupported() (bool, string) {
	if s.config().Demo || s.detectedPlatform() == platform.Keenetic {
		return true, ""
	}
	switch s.routingMode(s.config()) {
	case "hybrid", "fast":
	default:
		return false, "fastest tunnel per list needs the kernel routing plane: switch routing to hybrid or fast mode; in the current mode the list uses its first tunnel"
	}
	if !s.kernelPBRAvailable() {
		return false, "fastest tunnel per list needs the kernel routing plane, and this router has no nftables; the list uses its first tunnel"
	}
	return true, ""
}

// fastestNamesNote says, for a plane that does not carry names (OpenWrt's nft plane: sets hold
// addresses, and a list's names are matched by the proxy core), what the choice covers there. "" on
// KeeneticOS, whose dnsmasq fills the list's own set from its names.
func (s *Server) fastestNamesNote() string {
	if s.config().Demo || s.detectedPlatform() == platform.Keenetic {
		return ""
	}
	return "On this router the choice steers the list's addresses (IP and CIDR entries). Names in the list are matched by the proxy core and keep the first tunnel."
}

// kernelLinkedCandidates splits a list's candidates the way the compiler does (pbr.Compile,
// ListEgresses): the enabled tunnels with an interface of their own, which the list's table can be
// pointed at, and the rest, which live inside the proxy core and are never chosen between.
func kernelLinkedCandidates(p *model.Profile, rl model.RoutingList) (linked, unlinked []string) {
	for _, id := range model.ListCandidates(p, rl) {
		if e := p.EndpointByID(id); e != nil && e.Enabled && pbr.KernelIface(e) != "" {
			linked = append(linked, id)
		} else {
			unlinked = append(unlinked, id)
		}
	}
	return linked, unlinked
}

// kernelLinkedEndpoints lists every enabled endpoint the kernel can route a table through. all is the
// demo, which routes nothing and shows every control.
func kernelLinkedEndpoints(p *model.Profile, all bool) []string {
	out := []string{}
	for i := range p.Endpoints {
		if e := &p.Endpoints[i]; e.Enabled && (all || pbr.KernelIface(e) != "") {
			out = append(out, e.ID)
		}
	}
	return out
}

// listEntryKinds counts a list's address entries and its names (anything that is not an IP or a
// prefix), over what the compiler reads: the typed entries and both feed caches.
func listEntryKinds(rl model.RoutingList) (addrs, names int) {
	for _, set := range [][]string{rl.Manual, rl.CIDRCache, rl.DomainCache} {
		for _, raw := range set {
			v := strings.TrimSpace(raw)
			if v == "" {
				continue
			}
			if _, err := netip.ParsePrefix(v); err == nil {
				addrs++
			} else if _, err := netip.ParseAddr(v); err == nil {
				addrs++
			} else {
				names++
			}
		}
	}
	return addrs, names
}

func endpointNames(p *model.Profile, ids []string) string {
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		names = append(names, endpointName(p, id))
	}
	return strings.Join(names, ", ")
}

// ---- API ----

// fastestCandidate is a candidate as the panel shows it.
type fastestCandidate struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Excluded bool   `json:"excluded,omitempty"`
	// NoLink: the tunnel lives inside the proxy core and has no interface the kernel can route a
	// table through, so the list never elects it and cannot be pinned to it.
	NoLink bool `json:"no_link,omitempty"`
}

// fastestSummary is one list in GET /api/lists/fastest.
type fastestSummary struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Enabled     bool               `json:"enabled"` // the saved setting
	Active      bool               `json:"active"`  // two or more candidates, list on
	Applied     bool               `json:"applied"` // the router runs it (a unit exists)
	Candidates  []fastestCandidate `json:"candidates"`
	Current     string             `json:"current,omitempty"`
	CurrentName string             `json:"current_name,omitempty"`
	RTTMs       int                `json:"rtt_ms,omitempty"`
	Mode        string             `json:"mode,omitempty"` // auto | pinned | fallback | all_down
	// Election is what the list elects by: latency | throughput | mixed (the media-list default
	// resolved); ElectionSet is false when that is the default rather than the operator's choice.
	Election    string `json:"election"`
	ElectionSet bool   `json:"election_set,omitempty"`
	// ElectionNow is the rule in force for a list that elects by throughput or mixed: "throughput",
	// or "delay" while the samples are not comparable (fewer than two live tunnels have a fresh one,
	// or the current tunnel has none). Sampled of SampledOf live tunnels have a fresh sample of
	// SampleClass ("media": the Telegram source; "generic": the test servers).
	ElectionNow string `json:"election_now,omitempty"`
	Sampled     int    `json:"sampled,omitempty"`
	SampledOf   int    `json:"sampled_of,omitempty"`
	SampleClass string `json:"sample_class,omitempty"`
	Since       int64  `json:"since,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Pinned      string `json:"pinned,omitempty"`
	PinnedUntil int64  `json:"pinned_until,omitempty"`
	Table       int    `json:"table,omitempty"`
}

func endpointName(p *model.Profile, id string) string {
	if e := p.EndpointByID(id); e != nil && e.Name != "" {
		return e.Name
	}
	return id
}

func (s *Server) fastestStates() map[string]failover.UnitState {
	out := map[string]failover.UnitState{}
	for _, st := range s.kernelElector().States() {
		if st.List != nil {
			out[st.List.List] = st
		}
	}
	return out
}

// fastestPinnable reports whether a list's table can be pointed at the tunnel: it has an interface the
// kernel routes through (pbr.KernelIface, the compiler's own rule for a list's candidates). The demo
// routes nothing and shows every control.
func (s *Server) fastestPinnable(p *model.Profile, id string) bool {
	if s.config().Demo {
		return true
	}
	e := p.EndpointByID(id)
	return e != nil && pbr.KernelIface(e) != ""
}

// fastestRuns reports whether the router runs the list's choice now: the applied kernel plan gave the
// list a table of its own, on a platform whose tables the elector owns.
func (s *Server) fastestRuns(id string) bool {
	if !s.kernelElectionPlatform() {
		return false
	}
	plan, _ := s.supervisedKernelPlan()
	if plan == nil {
		return false
	}
	for _, eg := range plan.Egresses {
		if got, ok := model.ListEgressID(eg.Tag); ok && got == id && eg.Kind == pbr.EgressInterface && eg.Table != 0 {
			return true
		}
	}
	return false
}

func (s *Server) fastestSummaryOf(p *model.Profile, rl model.RoutingList, st failover.UnitState, ok bool) fastestSummary {
	f := model.FastestPolicy{}
	if rl.Fastest != nil {
		f = *rl.Fastest
	}
	ex := map[string]bool{}
	for _, x := range f.Excluded {
		ex[x] = true
	}
	sum := fastestSummary{ID: rl.ID, Name: rl.Name, Enabled: f.Enabled, Active: model.FastestActive(p, rl),
		Election: string(f.ElectionFor(rl)), ElectionSet: f.Mode != ""}
	// Only a pin that holds: the stored one stays in the profile after its time ran out, and the panel
	// must not say "Pinned to X until <a time in the past>" over an automatic choice.
	// And only one the router can run: the producer drops a pin to a tunnel without a
	// kernel link, so showing it claimed an exit the list's traffic never takes.
	if f.PinActive(time.Now().Unix()) && s.fastestPinnable(p, f.Pinned) {
		sum.Pinned, sum.PinnedUntil = f.Pinned, f.PinnedUntil
	}
	if sum.Name == "" {
		sum.Name = rl.ID
	}
	for _, c := range model.ListCandidates(p, rl) {
		sum.Candidates = append(sum.Candidates, fastestCandidate{ID: c, Name: endpointName(p, c), Excluded: ex[c], NoLink: !s.fastestPinnable(p, c)})
	}
	if ok {
		sum.Applied, sum.Table = true, st.Table
		sum.Current, sum.Since, sum.Reason = st.Current, st.Since, st.Reason
		if st.Current != "" {
			sum.CurrentName = endpointName(p, st.Current)
			sum.RTTMs = st.Measurements[st.Current].MedianMs
		}
		if st.List != nil {
			sum.Mode = st.List.Mode
		}
		s.electionInForce(&sum, rl, st, ex)
	}
	return sum
}

// electionInForce fills what a throughput or mixed list chooses by right now (see ElectionNow).
func (s *Server) electionInForce(sum *fastestSummary, rl model.RoutingList, st failover.UnitState, excluded map[string]bool) {
	if sum.Election == string(model.ElectionLatency) {
		return
	}
	var ids []string
	for _, c := range sum.Candidates {
		if !excluded[c.ID] {
			ids = append(ids, c.ID)
		}
	}
	samples, class := s.throughputSamplesFor(ids, model.MediaList(rl))
	members := make([]failover.MemberHealth, 0, len(ids))
	for _, id := range ids {
		sample := samples[id]
		members = append(members, failover.MemberHealth{ID: id, Alive: st.Measurements[id].Alive,
			ThroughputKbps: sample.ThroughputKbps, ThroughputAt: sample.ThroughputAt})
	}
	now := s.throughputNow().UnixMilli()
	sum.Sampled, sum.SampledOf = failover.FreshSamples(members, now)
	sum.SampleClass, sum.ElectionNow = class, "throughput"
	currentSampled := st.Current == ""
	for _, m := range members {
		if m.ID == st.Current {
			one, _ := failover.FreshSamples([]failover.MemberHealth{m}, now)
			currentSampled = one == 1 || !m.Alive
		}
	}
	if sum.Sampled < 2 || !currentSampled {
		sum.ElectionNow = "delay"
	}
}

// handleFastestLists is GET /api/lists/fastest: every list with the setting, and what the router
// does with it now.
func (s *Server) handleFastestLists(w http.ResponseWriter, r *http.Request) {
	p := s.store.Profile()
	states := s.fastestStates()
	supported, why := s.fastestSupported()
	lists := []fastestSummary{}
	for _, rl := range p.RoutingLists {
		if rl.Fastest == nil && len(rl.Candidates) < 2 {
			continue
		}
		st, ok := states[rl.ID]
		lists = append(lists, s.fastestSummaryOf(&p, rl, st, ok))
	}
	writeJSON(w, http.StatusOK, map[string]any{"supported": supported, "reason": why, "max": model.MaxFastestLists, "lists": lists,
		// note: what the choice covers on a plane that does not carry names; linked: the tunnels a
		// list's table can be pointed at (the editor needs two of them among a list's tunnels).
		"note": s.fastestNamesNote(), "linked": kernelLinkedEndpoints(&p, s.config().Demo)})
}

// fastestDetail is GET /api/lists/{id}/fastest.
type fastestDetail struct {
	fastestSummary
	Targets      []string                                 `json:"targets"`
	AutoTargets  bool                                     `json:"auto_targets"`
	DeadTargets  []string                                 `json:"dead_targets,omitempty"`
	Matrix       map[string]map[string]failover.ProbeCell `json:"matrix"`
	Measurements map[string]failover.Measurement          `json:"measurements"`
	PinDead      bool                                     `json:"pin_dead,omitempty"`
	Calm         bool                                     `json:"calm,omitempty"`
	LastCycle    int64                                    `json:"last_cycle,omitempty"`
	Events       []failover.UnitEvent                     `json:"events"`
	Policy       model.FastestPolicy                      `json:"policy"`
}

func (s *Server) handleFastestList(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p := s.store.Profile()
	rl := findList(&p, id)
	if rl == nil {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("routing list %q does not exist", id))
		return
	}
	st, ok := s.fastestStates()[id]
	d := fastestDetail{fastestSummary: s.fastestSummaryOf(&p, *rl, st, ok), Matrix: map[string]map[string]failover.ProbeCell{},
		Measurements: map[string]failover.Measurement{}, Events: []failover.UnitEvent{}}
	if rl.Fastest != nil {
		d.Policy = *rl.Fastest
	}
	d.AutoTargets = len(d.Policy.Targets) == 0
	d.Targets = s.fastestTargetsFor(*rl, model.ListKillSwitch(&p, *rl), time.Now().UnixMilli())
	if ok {
		d.Targets = st.Targets
		d.Measurements = st.Measurements
		d.Events = st.Events
		if n := len(d.Events); n > 50 {
			d.Events = d.Events[n-50:]
		}
		if st.List != nil {
			d.Matrix, d.DeadTargets, d.PinDead, d.Calm, d.LastCycle = st.List.Matrix, st.List.DeadTargets, st.List.PinDead, st.List.Calm, st.List.LastCycle
		}
	}
	writeJSON(w, http.StatusOK, d)
}

func findList(p *model.Profile, id string) *model.RoutingList {
	for i := range p.RoutingLists {
		if p.RoutingLists[i].ID == id {
			return &p.RoutingLists[i]
		}
	}
	return nil
}

// handleFastestProbe is POST /api/lists/{id}/fastest/probe: measure on the next tick. Not a setting,
// so it takes effect without an Apply. Only a list the router runs is measured: for any other the
// request would be answered "queued" and consumed by nothing.
func (s *Server) handleFastestProbe(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p := s.store.Profile()
	if findList(&p, id) == nil {
		writeErr(w, http.StatusNotFound, fmt.Sprintf("routing list %q does not exist", id))
		return
	}
	if !s.fastestRuns(id) {
		writeErr(w, http.StatusConflict, "the router does not run the fastest-tunnel choice for this list, so there is nothing to measure: Review and Apply first")
		return
	}
	s.requestFastestProbe(id)
	writeJSON(w, http.StatusAccepted, map[string]any{"queued": true, "within_s": int(listFailoverInterval / time.Second)})
}

// handleFastestPin is POST /api/lists/{id}/fastest/pin {candidate, minutes}: a staged change like any
// other setting (Review shows it, Apply runs it). minutes 0 = until unpinned.
func (s *Server) handleFastestPin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Candidate string `json:"candidate"`
		Minutes   int    `json:"minutes"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil || body.Minutes < 0 || body.Minutes > 60*24*30 {
		writeErr(w, http.StatusBadRequest, `want {"candidate": "<tunnel id>", "minutes": 0..43200}`)
		return
	}
	s.editFastest(w, r.PathValue("id"), func(p *model.Profile, rl *model.RoutingList) error {
		if !isCandidate(p, *rl, body.Candidate) {
			return fmt.Errorf("%q is not one of this list's tunnels", body.Candidate)
		}
		// A tunnel inside the proxy core has no interface to point the list's table at: such a pin
		// would be stored, shown as "Pinned to X" and never run.
		if !s.fastestPinnable(p, body.Candidate) {
			return fmt.Errorf("%s has no interface of its own on the router, so a list cannot be pinned to it; the list chooses among its other tunnels", endpointName(p, body.Candidate))
		}
		rl.Fastest.Pinned, rl.Fastest.PinnedUntil = body.Candidate, 0
		if body.Minutes > 0 {
			rl.Fastest.PinnedUntil = time.Now().Add(time.Duration(body.Minutes) * time.Minute).Unix()
		}
		return nil
	})
}

// handleFastestUnpin is POST /api/lists/{id}/fastest/unpin.
func (s *Server) handleFastestUnpin(w http.ResponseWriter, r *http.Request) {
	s.editFastest(w, r.PathValue("id"), func(_ *model.Profile, rl *model.RoutingList) error {
		rl.Fastest.Pinned, rl.Fastest.PinnedUntil = "", 0
		return nil
	})
}

// handleFastestExclude is POST /api/lists/{id}/fastest/exclude {candidate, excluded}.
func (s *Server) handleFastestExclude(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Candidate string `json:"candidate"`
		Excluded  bool   `json:"excluded"`
	}
	if err := decodeJSONBody(r.Body, &body); err != nil {
		writeErr(w, http.StatusBadRequest, `want {"candidate": "<tunnel id>", "excluded": true|false}`)
		return
	}
	s.editFastest(w, r.PathValue("id"), func(p *model.Profile, rl *model.RoutingList) error {
		if !isCandidate(p, *rl, body.Candidate) {
			return fmt.Errorf("%q is not one of this list's tunnels", body.Candidate)
		}
		var keep []string
		for _, x := range rl.Fastest.Excluded {
			if x != body.Candidate {
				keep = append(keep, x)
			}
		}
		if body.Excluded {
			keep = append(keep, body.Candidate)
		}
		rl.Fastest.Excluded = keep
		if rl.Fastest.Pinned == body.Candidate && body.Excluded {
			rl.Fastest.Pinned, rl.Fastest.PinnedUntil = "", 0
		}
		return nil
	})
}

func isCandidate(p *model.Profile, rl model.RoutingList, id string) bool {
	for _, c := range model.ListCandidates(p, rl) {
		if c == id {
			return true
		}
	}
	return false
}

// editFastest saves one list's fastest policy through the store's revision check, retrying once on a
// concurrent write, and answers with the list as stored.
func (s *Server) editFastest(w http.ResponseWriter, id string, edit func(*model.Profile, *model.RoutingList) error) {
	for attempt := 0; ; attempt++ {
		p := s.store.Profile()
		cur := findList(&p, id)
		if cur == nil {
			writeErr(w, http.StatusNotFound, fmt.Sprintf("routing list %q does not exist", id))
			return
		}
		next := *cur
		if next.Fastest == nil {
			writeErr(w, http.StatusConflict, "this list is not in fastest mode")
			return
		}
		pol := *next.Fastest
		pol.Excluded = append([]string(nil), pol.Excluded...)
		next.Fastest = &pol
		if err := edit(&p, &next); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		saved, err := s.store.UpsertRoutingListAt(next, store.At(model.RoutingListRev(*cur)))
		if err != nil {
			if isStale(err) && attempt == 0 {
				continue
			}
			if isStale(err) {
				writeStale(w, "This routing list")
				return
			}
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		next.CIDRCache, next.DomainCache = nil, nil
		writeJSON(w, http.StatusOK, savedRev[model.RoutingList]{Object: next, Saved: saved})
		return
	}
}

// fastestZone is the zone a pin's end is written in for people: the router's own (localtz), not Go's
// time.Local. A variable so a test can stand in for it.
var fastestZone = localtz.Location

// fastestFindings are the review's notes on lists in fastest mode: over the limit (blocks Apply),
// fewer than two tunnels, a platform without the runtime choice, and an active pin.
func (s *Server) fastestFindings(prof *model.Profile) []PlanFinding {
	var out []PlanFinding
	active := 0
	supported, why := s.fastestSupported()
	now := time.Now().Unix()
	for _, rl := range prof.RoutingLists {
		if rl.Fastest == nil {
			continue
		}
		if rl.Fastest.Enabled && rl.Enabled && len(model.ListCandidates(prof, rl)) < 2 {
			out = append(out, PlanFinding{
				ID: "routing_list.fastest_one", Setting: "routing list", Item: rl.ID,
				Requested: "fastest tunnel", Effective: "its one tunnel",
				Severity: platform.SeverityDegraded, Reason: platform.ReasonOperatorChoice, Blocks: platform.BlocksNothing,
				Detail: "one tunnel, nothing to choose from: the list uses it as before",
				Remedy: "Add a second tunnel to the list to let it pick the fastest.",
			})
			continue
		}
		if !model.FastestActive(prof, rl) {
			continue
		}
		active++
		if !supported {
			out = append(out, PlanFinding{
				ID: "routing_list.fastest_platform", Setting: "routing list", Item: rl.ID,
				Requested: "fastest tunnel", Effective: "first tunnel",
				Severity: platform.SeverityDegraded, Reason: platform.ReasonPlatformUnsupported, Blocks: platform.BlocksNothing,
				Detail: why,
			})
		}
		linked, unlinked := kernelLinkedCandidates(prof, rl)
		switch {
		case !supported:
		case len(linked) < 2:
			// Decision (owrt-1122 stage 1): a tunnel that exists only inside the proxy core has no
			// table to point, so the option runs between kernel links only, and with fewer than two of
			// them it does not run at all.
			out = append(out, PlanFinding{
				ID: "routing_list.fastest_no_link", Setting: "routing list", Item: rl.ID,
				Requested: "fastest tunnel", Effective: "first tunnel",
				Severity: platform.SeverityDegraded, Reason: platform.ReasonPlatformUnsupported, Blocks: platform.BlocksNothing,
				Detail: "the choice is made between tunnels with an interface of their own on the router (WireGuard, AmneziaWG), and this list has fewer than two; " +
					endpointNames(prof, unlinked) + " run inside the proxy core, which the router cannot switch a list between",
				Remedy: "Add a second WireGuard or AmneziaWG tunnel to this list, or switch \"fastest tunnel\" off for it.",
			})
		case len(unlinked) > 0:
			out = append(out, PlanFinding{
				ID: "routing_list.fastest_no_link", Setting: "routing list", Item: rl.ID,
				Requested: "fastest of " + endpointNames(prof, append(append([]string(nil), linked...), unlinked...)),
				Effective: "fastest of " + endpointNames(prof, linked),
				Severity:  platform.SeverityDegraded, Reason: platform.ReasonPlatformUnsupported, Blocks: platform.BlocksNothing,
				Detail: endpointNames(prof, unlinked) + " run inside the proxy core and have no interface of their own: they are not measured and never chosen",
			})
		}
		if note := s.fastestNamesNote(); supported && note != "" && len(linked) >= 2 {
			if addrs, names := listEntryKinds(rl); names > 0 {
				effective := "addresses by the fastest tunnel, names by " + endpointName(prof, rl.Outbound)
				if addrs == 0 {
					effective = "first tunnel: the list holds names only"
				}
				out = append(out, PlanFinding{
					ID: "routing_list.fastest_names", Setting: "routing list", Item: rl.ID,
					Requested: "fastest tunnel", Effective: effective,
					Severity: platform.SeverityDegraded, Reason: platform.ReasonPlatformUnsupported, Blocks: platform.BlocksNothing,
					Detail: note,
				})
			}
		}
		if rl.Fastest.AllDown() == model.OnAllDownWAN && model.ListKillSwitch(prof, rl) {
			out = append(out, PlanFinding{
				ID: "routing_list.fastest_killswitch", Setting: "routing list", Item: rl.ID,
				Requested: "through the provider when every tunnel is down", Effective: "blocked",
				Severity: platform.SeverityDegraded, Reason: platform.ReasonOperatorChoice, Blocks: platform.BlocksNothing,
				Detail: "a kill switch covers this list's tunnels, so its traffic is dropped, never sent by the provider, while no tunnel works",
				Remedy: "Choose \"Block\" (or \"Stay on the last tunnel\") for this list, or switch the kill switch off.",
			})
		}
		if rl.Fastest.PinActive(now) {
			until := "until unpinned"
			if rl.Fastest.PinnedUntil > 0 {
				// In the router's zone, and named: Go's own time.Local is UTC on Keenetic and OpenWrt, so
				// a pin that ends at 15:00 by the router's clock would read "until 12:00".
				at := time.Unix(rl.Fastest.PinnedUntil, 0).In(fastestZone())
				until = "until " + at.Format("2006-01-02 15:04") + " (" + localtz.Label(at) + ")"
			}
			out = append(out, PlanFinding{
				ID: "routing_list.fastest_pinned", Setting: "routing list", Item: rl.ID,
				Requested: "fastest tunnel", Effective: "pinned to " + endpointName(prof, rl.Fastest.Pinned),
				Severity: platform.SeverityDegraded, Reason: platform.ReasonOperatorChoice, Blocks: platform.BlocksNothing,
				Detail: "the list is pinned to " + endpointName(prof, rl.Fastest.Pinned) + " " + until + " while that tunnel works",
			})
		}
	}
	if active > model.MaxFastestLists {
		out = append(out, PlanFinding{
			ID: "routing_list.fastest_limit", Setting: "routing lists",
			Requested: fmt.Sprintf("%d lists in fastest mode", active), Effective: "refused",
			Severity: platform.SeverityBlocked, Reason: platform.ReasonSavedValueIncompat, Blocks: platform.BlocksApply,
			Detail: fmt.Sprintf("%d lists ask for the fastest tunnel; each needs its own mark and routing table, and at most %d fit", active, model.MaxFastestLists),
			Remedy: fmt.Sprintf("Switch \"fastest tunnel\" off on %d of them.", active-model.MaxFastestLists),
		})
	}
	return out
}

// RAM (operator constraint, 256 MB routers), at the 32-list cap with 5 candidates and 3 targets:
// journal 32 x 50 events x ~200 B = ~320 KB; matrix + measurements 32 x 5 x 3 cells x ~80 B = ~40 KB;
// probe cache <= 480 keys x ~64 B = ~30 KB; runner/state maps ~20 KB. About 0.4 MB worst case, a few
// KB for a typical 2-4 lists. The journal writer holds no copy (Mark renders at write time).
