package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sync"
	"time"

	"wayhop/internal/ctflush"
	"wayhop/internal/localtz"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// leaksweep.go resets the flows that left by the WAN while the marking chain was being (re)built.
//
// A flow whose first packet found no chain took the main table and the WAN's NAT binding, and its
// connection mark stays 0; the router's fast NAT then keeps forwarding it by that binding after the
// chain is back. Observed on KeeneticOS right after an Apply: LAN flows to block-list
// feed destinations with ctmark 0 NATed out of the WAN, QUIC among them. After every install of
// the chain (Apply, the reconcile's reinstall, the netfilter.d hook's re-assert) such flows are
// deleted, bounded and rate-limited, and they restart through the tunnel.

const (
	// leakSweepLimit bounds one sweep's deletions; leakSweepGap is the least time between sweeps.
	leakSweepLimit = 1024
	leakSweepGap   = 10 * time.Second
	// keeneticHookStamp is touched by the netfilter.d hook after each re-assert (a shell builtin
	// redirect into tmpfs: no tool, no flash write), which is how the daemon learns of one.
	keeneticHookStamp = "/tmp/wayhop-policy-hook.stamp"
)

// leakSweeper holds the sweeps' rate limit and the counters Review shows.
type leakSweeper struct {
	mu        sync.Mutex
	last      time.Time
	stamp     time.Time
	found     int
	flushed   int
	lastFound time.Time
	open      func() (ctflush.Table, error) // nil: ctflushOpen
	now       func() time.Time              // nil: time.Now
	// pending: a sweep was asked for and skipped inside the gap, or the last one hit its cap. The
	// mirror tick runs it once the gap has passed: a hook run inside the gap had its
	// stamp consumed and was otherwise never swept, and a capped sweep was never continued.
	pending bool
	// stampPath is the hook's stamp ("": keeneticHookStamp; tests stand in).
	stampPath string
}

func (l *leakSweeper) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// owed reports a sweep that was skipped or capped and may run now.
func (l *leakSweeper) owed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pending && l.clock().Sub(l.last) >= leakSweepGap
}

// leakCounts is what Review reports.
type leakCounts struct {
	Found, Flushed int
	Last           time.Time
}

func (l *leakSweeper) counts() leakCounts {
	l.mu.Lock()
	defer l.mu.Unlock()
	return leakCounts{Found: l.found, Flushed: l.flushed, Last: l.lastFound}
}

// livePlan is p with every domain zone's names replaced by the members its sets hold now, so the
// flush can judge flows to them. A set that cannot be read leaves its zone's names, and the flush
// then touches nothing behind it.
func livePlan(ctx context.Context, p *pbr.Plan, read ksMembers) *pbr.Plan {
	out, _ := livePlanRead(ctx, p, read)
	return out
}

// livePlanRead is livePlan, and whether a zone's sets could not be read (a sweep is then owed again).
func livePlanRead(ctx context.Context, p *pbr.Plan, read ksMembers) (*pbr.Plan, bool) {
	out := *p
	out.Zones = append([]pbr.Zone(nil), p.Zones...)
	io := pbr.IpsetOptions{}
	unread := false
	for i, z := range out.Zones {
		if len(z.Domains) == 0 || read == nil {
			continue
		}
		v4, err4 := read(ctx, io.ZoneSetName(z.Name, "4"))
		v6, err6 := read(ctx, io.ZoneSetName(z.Name, "6"))
		if err4 != nil || err6 != nil {
			unread = true
			continue
		}
		z.V4, z.V6 = append([]string(nil), z.V4...), append([]string(nil), z.V6...)
		for _, m := range append(v4, v6...) {
			if m.Addr().Is4() {
				z.V4 = append(z.V4, m.String())
			} else {
				z.V6 = append(z.V6, m.String())
			}
		}
		z.Domains = nil
		out.Zones[i] = z
	}
	return &out, unread
}

// sweep runs one bounded flush unless one ran within leakSweepGap (force: an Apply just installed the
// chain). It never fails the caller.
func (l *leakSweeper) sweep(ctx context.Context, p *pbr.Plan, read ksMembers, local func(netip.Addr) bool, force bool, why string) {
	if p == nil {
		return
	}
	l.mu.Lock()
	if !force && l.clock().Sub(l.last) < leakSweepGap {
		l.pending = true
		l.mu.Unlock()
		return
	}
	l.last = l.clock()
	l.pending = false
	l.mu.Unlock()
	open := l.open
	if open == nil {
		open = ctflushOpen
	}
	t, err := open()
	if err != nil {
		if !errors.Is(err, ctflush.ErrUnsupported) {
			log.Printf("kill switch: flows that left by the provider during %s were not checked: %v", why, err)
		}
		return
	}
	defer t.Close()
	live, unread := livePlanRead(ctx, p, read)
	res, err := ctflush.FlushUnrouted(t, live, ctflush.Options{Limit: leakSweepLimit, Local: local})
	found := res.Deleted + res.Gone
	if unread {
		// A zone whose sets were not read was left out (HUNT-K #5): its flows are judged next time.
		l.mu.Lock()
		l.pending = true
		l.mu.Unlock()
	}
	if res.Capped {
		found = leakSweepLimit
		l.mu.Lock()
		l.pending = true
		l.mu.Unlock()
	}
	if found > 0 {
		l.mu.Lock()
		l.found += found
		l.flushed += res.Deleted
		l.lastFound = l.clock()
		l.mu.Unlock()
		log.Printf("kill switch: %d flow(s) to listed destinations had left by the provider during %s; %d reset so they restart through their tunnel",
			found, why, res.Deleted)
	}
	if err != nil && !errors.Is(err, ctflush.ErrNoModule) {
		log.Printf("kill switch: leaked flow reset stopped: %v", err)
	}
}

// sweepLeakedFlows runs a sweep for an installed Keenetic plane.
func (s *Server) sweepLeakedFlows(ctx context.Context, plan *pbr.Plan, artifact executionKernelIpsetArtifactV1, force bool, why string) {
	if s.config().Demo || s.detectedPlatform() != platform.Keenetic {
		return
	}
	adapter, err := newExactKeeneticKernelAdapter(artifact)
	if err != nil {
		return
	}
	read := withDynamicMembers(ipsetMembers(adapter), plan, artifact.DynamicDomainSets)
	s.leaks.sweep(ctx, plan, read, ctflushLocal(), force, why)
}

// withDynamicMembers makes the reading of a domain zone's wr_ set include its wd_ set: in fast mode
// the resolver's answers go there (pbr DynamicDomainSets), and a reader of the wr_ set alone would see
// only the static prefixes and the members learned before the migration. A wd_ set that cannot be read
// is an error of the reading (HUNT-K #5): a zone known in part would pass for known. dynamic false
// returns read unchanged.
func withDynamicMembers(read ksMembers, plan *pbr.Plan, dynamic bool) ksMembers {
	if read == nil || plan == nil || !dynamic {
		return read
	}
	io := pbr.IpsetOptions{}
	extra := map[string]string{}
	for _, z := range plan.Zones {
		if len(z.Domains) == 0 && z.RemoteList == "" {
			continue
		}
		for _, fam := range []string{"4", "6"} {
			extra[io.ZoneSetName(z.Name, fam)] = io.DynamicSetName(z.Name, fam)
		}
	}
	return func(ctx context.Context, set string) ([]netip.Prefix, error) {
		got, err := read(ctx, set)
		if err != nil {
			return got, err
		}
		if wd, ok := extra[set]; ok {
			more, derr := read(ctx, wd)
			if derr != nil {
				return nil, fmt.Errorf("%s: %w", wd, derr)
			}
			got = append(got, more...)
		}
		return got, nil
	}
}

// hookRan reports whether the netfilter.d hook re-asserted the plane since the last call.
func (l *leakSweeper) hookRan() bool {
	path := l.stampPath
	if path == "" {
		path = keeneticHookStamp
	}
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !info.ModTime().After(l.stamp) {
		return false
	}
	first := l.stamp.IsZero()
	l.stamp = info.ModTime()
	return !first || time.Since(info.ModTime()) < time.Minute
}

// leakedFlowsFinding is Review's counter of the flows found and reset.
func leakedFlowsFinding(c leakCounts) []platform.Unsupported {
	if c.Found == 0 {
		return nil
	}
	return []platform.Unsupported{{
		Setting: findingLeakedFlows, Value: fmt.Sprint(c.Found), Severity: platform.SeverityDegraded,
		Reason: fmt.Sprintf("since the daemon started, %d connection(s) to listed destinations were found leaving by the provider right after "+
			"the marking rules were (re)installed, and %d of them were reset to restart through their tunnel (last at %s)",
			c.Found, c.Flushed, c.Last.In(localtz.Location()).Format("2006-01-02 15:04:05")),
		Remedy: "Nothing is required: they are reset as they are found.",
	}}
}

const findingLeakedFlows = "kill_switch.leaked_flows"
