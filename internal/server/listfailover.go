package server

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// listfailover.go makes a failover group mean something for ROUTING LISTS on the kernel plane.
//
// What the router actually does today, measured on a live Keenetic:
//
//	ip rule 150: from all fwmark 0x20000/0xff0000 lookup 151
//	table 151:   default dev nwg3
//
// Table 151 is WayHop's alone — no other interface has it and no other rule looks at it — and it is
// written once, by Apply, pinned to the group's elected member. Nothing re-points it. The group
// "grp-primary" has five members; four of them sit idle while every list rides nwg3, and if
// nwg3 drops, the kernel flushes that route, the fwmark lookup finds an empty table and falls
// through to main — so the censored destinations the list exists for leave through the PROVIDER.
// That is a leak dressed as a failover.
//
// The plane's own renderer already anticipated an owner for this: it seeds the table with
// `ip route add` rather than `replace` specifically so it cannot clobber "the 1-min failover cron's
// elected live egress". There is no cron on this router — no /opt/etc/crontabs, no cron.d — so the
// seed has been the only writer since the day it was installed. This is that owner, in the daemon,
// where the health it needs already lives.
//
// Scope, deliberately narrow. It writes ONE command shape, `ip route replace default dev <iface>
// table <N>`, and only when all of the following hold: the table belongs to an egress the CURRENT
// compiled plan owns, the egress is a GROUP, and the interface is one of that group's own members.
// It never touches the main table, never the WAN, never a table the plan does not name. Anything
// wider belongs to Apply.

const (
	listFailoverInterval = 20 * time.Second
	listFailoverTimeout  = 6 * time.Second
)

// listFailoverLoop re-points each group-backed list table at a healthy member.
func (s *Server) listFailoverLoop(ctx context.Context) {
	ticker := time.NewTicker(listFailoverInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.listFailoverTick(ctx)
	}
}

// listFailoverTick is one pass. Silent when nothing needs to move, which is the normal case.
func (s *Server) listFailoverTick(ctx context.Context) {
	if s == nil || s.store == nil || s.monitor == nil {
		return
	}
	// The one precondition that is really about this loop: it writes with iproute2, so iproute2 has to
	// be there.
	//
	// It used to require ipset AND iptables — a Keenetic-shaped question that answers "no" on modern
	// OpenWrt, which carries nftables and often no iptables binary at all. The effect was that a
	// routing list backed by a native group on OpenWrt had no owner: the table stayed pinned to
	// whichever member Apply chose, and when that member died the fwmark lookup found an empty table
	// and fell through to the provider — the exact leak this file exists to close, closed on one
	// platform only.
	//
	// "Two owners for one decision" is still guarded, structurally rather than by platform:
	// listFailoverTargets only yields a table that the CURRENT compiled plan owns for a GROUP egress
	// of kind EgressInterface. A group the core carries produces no such egress, so there is nothing
	// here to fight the core over.
	if !iprouteAvailable() {
		return
	}
	for _, target := range s.listFailoverTargets() {
		want := target.Elected
		if want == "" || want == target.Current {
			continue
		}
		ctxCmd, cancel := context.WithTimeout(ctx, listFailoverTimeout)
		_, err := runHostCommandBounded(ctxCmd, listFailoverTimeout, kernelCounterOutputLimit,
			applyHostCommandWaitDelay, "ip", "route", "replace", "default", "dev", want, "table", fmt.Sprint(target.Table))
		cancel()
		if err != nil {
			// A refusal is not a switch: the table still holds what it held, and claiming otherwise in
			// the log would make the page report a move that did not happen.
			//
			// It is still worth saying ONCE. This whole file exists because the router's failover owner
			// was a cron that did not exist and nothing ever said so; an owner that runs and cannot
			// write would be the same silence with a process attached. Logged on the first failure for
			// a table and again when it recovers, never every 20 seconds.
			s.noteListFailoverWrite(target.Table, err)
			continue
		}
		s.noteListFailoverWrite(target.Table, nil)
		s.monitor.RecordSwitch(target.Group, target.Name, orNone(target.Current), want)
	}
}

// kernelElectableMembers reports, per GROUP whose routing lists the KERNEL carries, which members
// that plane can actually route to.
//
// A group can mix a native tunnel with one an engine carries — a live AX3000T has exactly
// that: group-failover is [tunnel-a (kernel link awg1), proxy-member (socks, sing-box)]. The Failover
// card counted both and printed "2 exits deep", a depth guarantee. For the four routing lists riding
// that group, one of which the kernel carries, the real depth is ONE: electMember skips a member
// with no kernel link, so when awg1 dies there is no candidate, the table keeps a route through a
// dead interface, and the fwmark lookup falls through to main — the provider. The card promised a
// second exit that the plane it belongs to cannot use.
//
// Computed from CAPABILITY, never from health: engine kind does not change while a tunnel is down,
// and a card that redraws its guarantee every time a member blinks teaches nobody anything. This is
// the same reasoning downloadPathChoices already applies to the download path.
//
// A group absent from this map is one the kernel plane does not route, so its members are whatever
// the core can reach and the ordinary count is honest. A group present with an EMPTY list is the
// worst case and is deliberately reported rather than omitted: its table exists and nothing can be
// elected into it at all.
func (s *Server) kernelElectableMembers() map[string][]string {
	if s == nil || s.store == nil {
		return nil
	}
	profile := s.store.Profile()
	plan, _, err := pbr.Compile(&profile, s.pbrCompileOptions(s.config()))
	if err != nil || plan == nil {
		return nil
	}
	ifaceOf := kernelIfaceByEndpoint(&profile)
	out := map[string][]string{}
	for _, egress := range plan.Egresses {
		if egress.Kind != pbr.EgressInterface || egress.Table == 0 {
			continue
		}
		group := profile.GroupByID(egress.Tag)
		if group == nil {
			continue // an endpoint egress has one interface and nothing to elect between
		}
		if _, seen := out[group.ID]; seen {
			continue
		}
		members := make([]string, 0, len(group.Members))
		for _, id := range group.Members {
			if ifaceOf[id] != "" {
				members = append(members, id)
			}
		}
		out[group.ID] = members
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// noteListFailoverWrite logs a table's write outcome only when it CHANGES, so a persistent refusal is
// visible without filling the router's bounded log with one line every tick.
func (s *Server) noteListFailoverWrite(table int, err error) {
	s.listFailoverErrMu.Lock()
	defer s.listFailoverErrMu.Unlock()
	if s.listFailoverErr == nil {
		s.listFailoverErr = map[int]string{}
	}
	prev, had := s.listFailoverErr[table]
	if err == nil {
		if had {
			delete(s.listFailoverErr, table)
			log.Printf("list failover: table %d is writable again", table)
		}
		return
	}
	if msg := err.Error(); !had || msg != prev {
		s.listFailoverErr[table] = msg
		log.Printf("list failover: cannot repoint table %d, so its list keeps the exit it has: %v", table, err)
	}
}

// iprouteAvailable reports whether the tool this loop writes with exists. Cached: the answer cannot
// change while the daemon runs, and this is asked on every tick.
var iprouteOnce struct {
	sync.Once
	ok bool
}

func iprouteAvailable() bool {
	iprouteOnce.Do(func() {
		_, err := exec.LookPath("ip")
		iprouteOnce.ok = err == nil
	})
	return iprouteOnce.ok
}

// listFailoverTarget is one table this loop may write, with the interface it holds now and the one
// health says it should hold.
type listFailoverTarget struct {
	Group   string
	Name    string
	Table   int
	Current string
	Elected string
}

// listFailoverTargets pairs the compiled plan with live health.
//
// The election is the operator's ORDER, first healthy member wins — the same fallback semantics the
// Failover page states for a native group, and the same rule Compile uses when it pins the table at
// Apply. A group whose members are all down elects nothing and the table is left exactly as it is:
// moving to a member that is also dead would be churn, and the fail-closed question (drop vs leak)
// is Apply's to answer, not this loop's.
func (s *Server) listFailoverTargets() []listFailoverTarget {
	profile := s.store.Profile()
	plan, _, err := pbr.Compile(&profile, s.pbrCompileOptions(s.config()))
	if err != nil || plan == nil {
		return nil
	}
	// endpoint id → kernel link, through the COMPILER's own resolver. Reading it off the plan's
	// egresses was the first cut and it elected nothing: a plan carries an egress per outbound tag it
	// actually uses, and a list routed through a group uses the GROUP tag — so the members, which are
	// exactly what this loop chooses between, had no entry at all. Measured on the router with the
	// elected tunnel down: the table stayed empty for 72 seconds while every other member was alive.
	ifaceOf := kernelIfaceByEndpoint(&profile)
	live := s.liveTableIfaces()
	var out []listFailoverTarget
	for _, egress := range plan.Egresses {
		if egress.Kind != pbr.EgressInterface || egress.Table == 0 {
			continue
		}
		group := profile.GroupByID(egress.Tag)
		if group == nil {
			continue // an endpoint egress has one interface and nothing to elect between
		}
		elected, ok := s.electHealthyMember(*group, ifaceOf)
		if !ok {
			continue
		}
		out = append(out, listFailoverTarget{
			Group: group.ID, Name: group.Name, Table: egress.Table,
			Current: live[egress.Table], Elected: elected,
		})
	}
	return out
}

// electHealthyMember asks the monitor which members are alive and applies the rule below.
func (s *Server) electHealthyMember(group model.Group, ifaceOf map[string]string) (string, bool) {
	if len(group.Members) == 0 {
		return "", false
	}
	alive := make(map[string]bool, len(group.Members))
	for _, h := range s.monitor.MemberHealth(group.Members) {
		alive[h.ID] = h.Alive
	}
	return electMember(group, ifaceOf, alive)
}

// kernelIfaceByEndpoint maps each endpoint to the kernel link it binds to, through the COMPILER's own
// resolver, skipping the ones that have none — a proxy endpoint is carried by an engine, not a link.
//
// One definition because two callers elect over it: this loop, which repoints a routing list's table
// at a healthy member, and the component downloader, which binds its socket to one. They were the
// same fold written twice, and a second copy is a second answer to "which link is this endpoint" the
// day one of them learns about a new engine kind.
func kernelIfaceByEndpoint(p *model.Profile) map[string]string {
	out := make(map[string]string, len(p.Endpoints))
	for i := range p.Endpoints {
		e := &p.Endpoints[i]
		if iface := pbr.KernelIface(e); iface != "" {
			out[e.ID] = iface
		}
	}
	return out
}

// electMember is the rule itself, kept apart from the monitor so it can be asserted directly rather
// than through a live health source: the operator's ORDER, first healthy member wins — the same
// semantics the Failover page states for a native group and the same one Apply pins the table with.
//
// A member the plan cannot route has no interface and is not a candidate however healthy it looks.
// Everything down elects NOTHING: moving to another dead member is churn, and turning the resulting
// leak into a drop is Apply's decision (the fail-closed blackhole), not this loop's.
func electMember(group model.Group, ifaceOf map[string]string, alive map[string]bool) (string, bool) {
	for _, id := range group.Members {
		if !alive[id] {
			continue
		}
		if iface := ifaceOf[id]; iface != "" {
			return iface, true
		}
	}
	return "", false
}

// liveTableIfaces reads which interface each routing table currently defaults to, so the loop writes
// only on a real change. A table it cannot read is absent rather than empty: writing on an unknown
// would make every tick a write.
func (s *Server) liveTableIfaces() map[int]string {
	out := map[int]string{}
	ctx, cancel := context.WithTimeout(context.Background(), listFailoverTimeout)
	defer cancel()
	text, err := runHostCommandBounded(ctx, listFailoverTimeout, kernelCounterOutputLimit,
		applyHostCommandWaitDelay, "ip", "route", "show", "table", "all")
	if err != nil {
		return out
	}
	for table, iface := range parseTableDefaults(text) {
		out[table] = iface
	}
	return out
}

// parseTableDefaults picks `default dev <iface> ... table <N>` lines out of `ip route show table all`.
// Only the metric-0 device route counts: the fail-closed blackhole and any via-gateway default belong
// to different questions.
func parseTableDefaults(text string) map[int]string {
	out := map[int]string{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] != "default" || fields[1] != "dev" {
			continue
		}
		iface := fields[2]
		table := 0
		for i := 3; i+1 < len(fields); i++ {
			if fields[i] == "table" {
				if _, err := fmt.Sscanf(fields[i+1], "%d", &table); err != nil {
					table = 0 // a value we cannot parse is not a table; the caller skips 0
				}
				break
			}
		}
		if table != 0 && iface != "" {
			out[table] = iface
		}
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
