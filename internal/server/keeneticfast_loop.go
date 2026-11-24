package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"wayhop/internal/ctflush"
	"wayhop/internal/pbr"
)

// keeneticFastTick is FastDNSLoop's work on the Keenetic fast plane: the retry after a back-out, the
// warm-up once after the start, the loop's dnsmasq check and the fresh-address reset.
func (s *Server) keeneticFastTick(ctx context.Context, st fastFresh, warmed *bool) fastFresh {
	k := s.kernelBaseline()
	if k == nil || !k.Ipset.DynamicDomainSets {
		return fastFresh{}
	}
	s.keeneticFastAdopt(k)
	s.keeneticFailOpenTick(ctx, k, fastDNSAlive(ctx, false) == nil)
	s.fastDNS.mu.Lock()
	backedOut := s.fastDNS.backedOut
	s.fastDNS.mu.Unlock()
	if backedOut {
		s.keeneticFastRestore(ctx, k)
	}
	if !keeneticPlanHasDomainNames(k.Plan) {
		return fastFresh{}
	}
	if !*warmed {
		*warmed = true
		s.startKeeneticWarmUp(k.Plan)
	}
	s.fastDNSResponsive(ctx)
	return s.keeneticFreshTick(ctx, st, k)
}

// keeneticSetMembers reads an installed plane's sets (a variable for tests).
var keeneticSetMembers = func(tool executionKernelIpsetArtifactV1) ksMembers {
	adapter, err := newExactKeeneticKernelAdapter(tool)
	if err != nil {
		return nil
	}
	return ipsetMembers(adapter)
}

// keeneticFreshTick reads the wd_ sets and resets the flows to the addresses new since the last look
// (at most fastFreshMax addresses and fastFreshFlushMax deletions a tick): only flows with no plan mark,
// or the WAN mark a direct list saved on an address a tunnel or block list's names have just taken,
// and not those a device-scoped direct list keeps on the WAN anyway, nor the router's own. The first
// look after a start only records: the sets carried over from before it have no "new" to tell.
func (s *Server) keeneticFreshTick(ctx context.Context, st fastFresh, k *executionKernelArtifactV1) fastFresh {
	names, beyond := k.Plan.DynamicSets(keeneticKillSwitchOptions(*k.Ipset))
	if len(names) == 0 {
		return fastFresh{}
	}
	read := keeneticSetMembers(*k.Ipset)
	if read == nil {
		return st
	}
	now, nowBeyond := map[netip.Addr]bool{}, map[netip.Addr]bool{}
	for _, name := range names {
		members, err := read(ctx, name)
		if err != nil {
			return st // a set not read now: compare at the next tick, not against a hole
		}
		for _, p := range members {
			if !p.IsSingleIP() {
				continue
			}
			now[p.Addr()] = true
			if beyond[name] {
				nowBeyond[p.Addr()] = true
			}
		}
	}
	next := fastFresh{key: "keenetic:" + strings.Join(names, ","), addrs: now, beyond: nowBeyond}
	if st.addrs == nil {
		return next
	}
	// What this tick does not finish stays new for the next one (HUNT-K #6): an address beyond the
	// fastFreshMax bound, and every address of a tick whose reset failed or hit fastFreshFlushMax.
	fresh := map[netip.Addr]bool{}
	var later []netip.Addr
	for a := range now {
		if st.addrs[a] {
			continue
		}
		if len(fresh) < fastFreshMax {
			fresh[a] = true
		} else {
			later = append(later, a)
		}
	}
	var stale map[netip.Addr]uint32
	var laterBeyond []netip.Addr
	if wan := k.Plan.WANMark(); wan != 0 {
		stale = map[netip.Addr]uint32{}
		for a := range nowBeyond {
			if st.beyond[a] {
				continue
			}
			if len(stale) < fastFreshMax && (fresh[a] || len(fresh) < fastFreshMax) {
				stale[a] = wan
				fresh[a] = true
			} else {
				laterBeyond = append(laterBeyond, a)
			}
		}
	}
	defer func() {
		for _, a := range later {
			delete(next.addrs, a)
		}
		for _, a := range laterBeyond {
			delete(next.beyond, a)
		}
	}()
	unfinished := func() {
		for a := range fresh {
			later = append(later, a)
		}
		for a := range stale {
			laterBeyond = append(laterBeyond, a)
		}
	}
	if len(fresh) == 0 {
		return next
	}
	t, err := ctflushOpen()
	if err != nil {
		unfinished()
		return next
	}
	defer t.Close()
	res, err := ctflush.FlushFresh(t, fresh, ctflush.Options{Limit: fastFreshFlushMax, Local: ctflushLocal()},
		ctflush.Fresh{Mask: k.Plan.Mask, Stale: stale, Keep: scopedDirectKeep(k.Plan)})
	switch {
	case err != nil && !errors.Is(err, ctflush.ErrNoModule):
		log.Printf("fast mode: connections to %d newly resolved addresses: %v", len(fresh), err)
		unfinished()
	case res.Capped:
		unfinished()
	}
	if res.Deleted > 0 {
		log.Printf("fast mode: %d connection(s) opened before their address entered a list's set were reset", res.Deleted)
	}
	s.fastDNS.mu.Lock()
	s.fastDNS.keenetic.freshLast, s.fastDNS.keenetic.freshAt = res.Deleted, time.Now()
	s.fastDNS.keenetic.freshTotal += res.Deleted
	s.fastDNS.mu.Unlock()
	return next
}

// keeneticWarmNames is the plan's names to ask for: each domain zone's entries (the base names of its
// suffixes), in zone order, the first fastWarmMax dnsmasq can take.
func keeneticWarmNames(plan *pbr.Plan) []string {
	var names []string
	seen := map[string]bool{}
	for _, z := range plan.Zones {
		for _, d := range z.Domains {
			if len(names) >= fastWarmMax {
				return names
			}
			if !seen[d] && pbr.ValidDnsmasqName(d) {
				seen[d] = true
				names = append(names, d)
			}
		}
	}
	return names
}

// keeneticFastWarmUp asks the router's resolver for the plan's names so dnsmasq fills the wd_ sets
// before the first client connects: one at a time, fastWarmPace apart, only while dnsmasq answers and
// reaches its upstreams. It never blocks an Apply.
func (s *Server) keeneticFastWarmUp(ctx context.Context, plan *pbr.Plan) {
	if plan == nil {
		return
	}
	names := keeneticWarmNames(plan)
	if len(names) == 0 {
		return
	}
	status := ""
	if fastDNSAlive(ctx, false) != nil || fastDNSUpstream(ctx) != nil {
		status = "skipped: the resolver was not answering"
	} else {
		asked, stop := warmNames(ctx, names, false, 10)
		switch stop {
		case warmCancelled:
			status = fmt.Sprintf("stopped after %d of %d names", asked, len(names))
		case warmResolverSilent:
			status = fmt.Sprintf("stopped after %d of %d names: the resolver stopped answering", asked, len(names))
		default:
			status = fmt.Sprintf("asked for %d names", asked)
		}
	}
	log.Printf("fast mode: the sets' warm-up %s", status)
	s.fastDNS.mu.Lock()
	s.fastDNS.keenetic.warm, s.fastDNS.keenetic.warmAt = status, time.Now()
	s.fastDNS.mu.Unlock()
}

// keeneticFastAdopt runs once a daemon start: the back-out of a policy file lives in RAM, so after a
// restart or a reboot the file on disk is compared with what the installed plane wrote.
// A different file is a back-out the daemon forgot: it is adopted as one, and the guarded retry puts
// the installed file back.
func (s *Server) keeneticFastAdopt(k *executionKernelArtifactV1) {
	conf := k.Ipset.DnsmasqConf
	s.fastDNS.mu.Lock()
	known := s.fastDNS.keenetic.installed != nil
	s.fastDNS.mu.Unlock()
	if known || len(conf) == 0 {
		return
	}
	disk, err := readKeeneticPolicy()
	if err != nil {
		return
	}
	tool := *k.Ipset
	s.fastDNS.mu.Lock()
	defer s.fastDNS.mu.Unlock()
	ks := &s.fastDNS.keenetic
	ks.installed, ks.tool = append([]byte(nil), conf...), &tool
	if disk.existed && bytes.Equal(disk.content, conf) {
		ks.backout = keeneticBackoutPolicy(keeneticPolicyFile{}, conf)
		return
	}
	ks.backout = keeneticBackoutPolicy(disk, conf)
	s.fastDNS.backedOut, s.fastDNS.retryAt = true, time.Time{}
	s.fastDNS.err = "the router's dnsmasq policy file is not the one the installed plane wrote (a back-out before WayHop restarted); it is put back, guarded, once dnsmasq answers"
}

// keeneticFailOpenAfter is how long dnsmasq may stay silent before fast mode's DNS enforcement is
// suspended.
var keeneticFailOpenAfter = 3 * time.Minute

// keeneticRunPlaneProgram runs a short program through an installed plane's pinned tools (a variable
// for tests).
var keeneticRunPlaneProgram = func(ctx context.Context, tool executionKernelIpsetArtifactV1, body string) error {
	adapter, err := newExactKeeneticKernelAdapter(tool)
	if err != nil {
		return err
	}
	return adapter.runProgram(ctx, tool, body)
}

// keeneticKillSwitched reports a plan with a fail-closed egress: its DNS enforcement is never suspended.
func keeneticKillSwitched(plan *pbr.Plan) bool {
	for _, e := range plan.Egresses {
		if e.FailClosed {
			return true
		}
	}
	return false
}

// keeneticFailOpenTick suspends fast mode's DNS enforcement when the router's dnsmasq has not answered
// for keeneticFailOpenAfter (the LAN's devices then reach their own resolvers; marking stays), and
// restores it when dnsmasq answers again. Never with a kill switch: the redirect is what
// keeps the kill-switched names on the router's pinned resolver, so the enforcement stays and
// Diagnostics says why.
func (s *Server) keeneticFailOpenTick(ctx context.Context, k *executionKernelArtifactV1, alive bool) {
	if !k.Ipset.FastDNSEnforce {
		return
	}
	s.fastDNS.mu.Lock()
	ks := &s.fastDNS.keenetic
	if alive {
		ks.silentSince = time.Time{}
	} else if ks.silentSince.IsZero() {
		ks.silentSince = time.Now()
	}
	silent := !alive && time.Since(ks.silentSince) >= keeneticFailOpenAfter
	if !silent {
		ks.failOpenHeld = ""
	}
	s.fastDNS.mu.Unlock()
	suspended := keeneticDNSSuspended()
	switch {
	case alive && suspended:
		if err := s.keeneticFailClosed(ctx, *k.Ipset); err != nil {
			log.Printf("fast mode: DNS enforcement was not restored: %v", err)
			return
		}
		log.Printf("fast mode: dnsmasq answers again; DNS enforcement is back")
	case silent && !suspended:
		if keeneticKillSwitched(k.Plan) {
			s.fastDNS.mu.Lock()
			ks.failOpenHeld = "dnsmasq has not answered since " + ks.silentSince.Format(time.RFC3339) +
				", but a kill switch is on, so DNS enforcement stays (the LAN has no DNS until dnsmasq answers)"
			s.fastDNS.mu.Unlock()
			return
		}
		var b strings.Builder
		b.WriteString(": > " + pbr.FastDNSOpenFlag + "\n")
		for _, r := range keeneticDNSRules(k.Ipset.Script) {
			if r.suspendable {
				b.WriteString(pbr.DeleteEveryCopy(r.tool, r.table, r.chain, r.spec))
			}
		}
		if err := keeneticRunPlaneProgram(ctx, *k.Ipset, b.String()); err != nil {
			log.Printf("fast mode: DNS enforcement could not be suspended: %v", err)
			return
		}
		log.Printf("fast mode: dnsmasq has not answered for %s; DNS enforcement is suspended until it does", keeneticFailOpenAfter)
	}
}

// keeneticFailClosed ends a suspension: the flag goes and the enforcement rules come back.
func (s *Server) keeneticFailClosed(ctx context.Context, tool executionKernelIpsetArtifactV1) error {
	var b strings.Builder
	b.WriteString("rm -f " + pbr.FastDNSOpenFlag + "\n")
	for _, r := range keeneticDNSRules(tool.Script) {
		if r.suspendable {
			b.WriteString(r.line + "\n")
		}
	}
	return keeneticRunPlaneProgram(ctx, tool, b.String())
}
