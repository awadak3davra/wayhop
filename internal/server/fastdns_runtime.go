package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"wayhop/internal/ctflush"
	"wayhop/internal/generator"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// fastdns_runtime.go is what the fast DNS plane does while the daemon runs: the check that dnsmasq
// answers after a restart, the warm-up of the sets after an Apply or a start, the live reload of the
// remote lists' content, and the flush of connections opened before their address entered a set.

// fastWarmPace is the gap between two warm-up queries (20 a second at most).
var fastWarmPace = 50 * time.Millisecond

const (
	// fastDNSTick is how often the daemon looks for new addresses in the dlist sets.
	fastDNSTick = 20 * time.Second
	// fastFreshMax bounds the new addresses one tick acts on, fastFreshFlushMax the deletions.
	fastFreshMax      = 4096
	fastFreshFlushMax = 512
	// Warm-up bounds (pbr prefetch): names asked, one at a time, each with its own timeout.
	fastWarmMax     = 500
	fastWarmTimeout = time.Second
)

var (
	// fastDNSAlive checks that dnsmasq runs and answers on 127.0.0.1:53; canary asks for the snippet's
	// own name and its own address, which only this dnsmasq with the snippet loaded gives.
	fastDNSAlive = func(ctx context.Context, canary bool) error {
		if out, err := exec.CommandContext(ctx, "pidof", "dnsmasq").Output(); err != nil || strings.TrimSpace(string(out)) == "" {
			return errors.New("dnsmasq is not running")
		}
		name, want := "localhost", ""
		if canary {
			name, want = pbr.FastCanaryName, pbr.FastCanaryAddr
		}
		return dnsAnswers(ctx, "127.0.0.1:53", name, want, time.Second)
	}
	// fastWarmResolve asks the router's resolver for a name; the answer itself is not used.
	fastWarmResolve = func(ctx context.Context, name string) {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", "127.0.0.1:53")
		}}
		cctx, cancel := context.WithTimeout(ctx, fastWarmTimeout)
		defer cancel()
		_, _ = r.LookupIPAddr(cctx, name)
	}
	// fastLoadProgram loads a program into nft outside an Apply (the live reload of remote content).
	fastLoadProgram = func(ctx context.Context, program string) error {
		// Sized by the work: 30 s, and a second more per 2 000 elements' worth of text.
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second+time.Duration(len(program)/40000)*time.Second)
		defer cancel()
		cmd := exec.CommandContext(cctx, "nft", "-f", "-")
		cmd.Stdin = strings.NewReader(program)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
)

// fastDNSUpstream checks that the router's dnsmasq resolves a real external name through its
// upstreams: a fresh random name under example.org (so no cache answers it), and any answer the
// upstream gives, NXDOMAIN included, counts; SERVFAIL, REFUSED and silence do not.
var fastDNSUpstream = func(ctx context.Context) error {
	name := fmt.Sprintf("wh%d.example.org", time.Now().UnixNano()%1000000007)
	rcode, err := dnsRcode(ctx, "127.0.0.1:53", name, 2*time.Second)
	if err != nil {
		return fmt.Errorf("the router's resolver does not reach its upstreams: %w", err)
	}
	if rcode != 0 && rcode != 3 {
		return fmt.Errorf("the router's resolver does not reach its upstreams (rcode %d for %s)", rcode, name)
	}
	return nil
}

// dnsRcode sends one A query and returns the reply's rcode.
func dnsRcode(ctx context.Context, addr, name string, timeout time.Duration) (int, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	q := []byte{0x57, 0x49, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	if _, err := conn.Write(q); err != nil {
		return 0, err
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, fmt.Errorf("no answer from %s: %w", addr, err)
	}
	if n < 12 || binary.BigEndian.Uint16(buf[:2]) != 0x5749 {
		return 0, fmt.Errorf("a malformed answer from %s", addr)
	}
	return int(buf[3] & 0x0f), nil
}

// fastDNSGuardWait is how long the DNS guard waits for the LAN's DNS after an install.
var fastDNSGuardWait = 20 * time.Second

// fastDNSGuard runs around a kernel install of a fast DNS plan: the LAN's DNS that resolved a real
// name before the install has to resolve one after it (plane and snippet together), within 20 s, or
// the step fails and the Apply rolls back (the local canary can still answer while the LAN's DNS is
// down). A resolver that did not work before is not the install's to judge.
func (s *Server) fastDNSGuard(ctx context.Context, plan *pbr.Plan) func() error {
	if plan == nil || !plan.FastDNS || s.config().Demo || s.detectedPlatform() != platform.OpenWrt {
		return func() error { return nil }
	}
	if fastDNSUpstream(ctx) != nil {
		return func() error { return nil }
	}
	return func() error {
		deadline := time.Now().Add(fastDNSGuardWait)
		var err error
		for {
			if err = fastDNSUpstream(ctx); err == nil {
				return nil
			}
			if time.Now().After(deadline) || ctx.Err() != nil {
				return fmt.Errorf("fast path: DNS stopped working after the install: %v", err)
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
			}
		}
	}
}

// dnsAnswers sends one A query for name and waits for the reply with its id. want "" takes any reply
// (NXDOMAIN included: the resolver is up); otherwise the answer must hold that IPv4 address.
func dnsAnswers(ctx context.Context, addr, name, want string, timeout time.Duration) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	q := []byte{0x57, 0x48, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	if _, err := conn.Write(q); err != nil {
		return err
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("no answer from %s: %w", addr, err)
	}
	if n < 12 || binary.BigEndian.Uint16(buf[:2]) != 0x5748 {
		return fmt.Errorf("a malformed answer from %s", addr)
	}
	if want == "" {
		return nil
	}
	a, err := netip.ParseAddr(want)
	if err != nil || !a.Is4() {
		return fmt.Errorf("canary address %q", want)
	}
	b4 := a.As4()
	rcode, ancount := buf[3]&0x0f, binary.BigEndian.Uint16(buf[6:8])
	if rcode != 0 || ancount == 0 || !strings.Contains(string(buf[len(q):n]), string(b4[:])) {
		return fmt.Errorf("the resolver on %s does not answer %s with %s: it is not dnsmasq with the fast path snippet", addr, name, want)
	}
	return nil
}

// fastDNSWarmUp asks the router's resolver for the plan's names, so dnsmasq fills the sets before the
// first client connects (pbr's prefetch): the plain base names of the suffixes, the first fastWarmMax,
// fastWarmWorkers at a time. Never blocks an Apply.
func (s *Server) fastDNSWarmUp(ctx context.Context, plan *pbr.Plan) {
	if plan == nil {
		return
	}
	remote, _, _ := s.planRemote(plan)
	var names []string
	for _, doms := range plan.FastNames(remote) {
		for _, d := range doms {
			if len(names) >= fastWarmMax {
				break
			}
			if pbr.ValidDnsmasqName(d) {
				names = append(names, d)
			}
		}
	}
	if len(names) == 0 {
		return
	}
	// Gentle (live 22.11): one name at a time, fastWarmPace apart, and only while dnsmasq answers
	// with the snippet loaded and reaches its upstreams; it stops at the first failure.
	if fastDNSAlive(ctx, true) != nil || fastDNSUpstream(ctx) != nil {
		log.Printf("fast path: the sets' warm-up was skipped: the resolver is not answering yet")
		return
	}
	// Paced by what an answer costs (live 22.11: every set add pays libnftables' cache of the whole
	// ruleset, 0.27 s and more): the next name waits three times as long as this one took, so the
	// warm-up keeps dnsmasq at most about a quarter busy, never at fastWarmPace's 20/s.
	asked, stop := warmNames(ctx, names, true, 50)
	switch stop {
	case warmCancelled:
	case warmResolverSilent:
		log.Printf("fast path: the sets' warm-up stopped after %d names: the resolver stopped answering", asked)
	default:
		log.Printf("fast path: asked the resolver for %d listed names to fill the sets", asked)
	}
}

// How a warm-up ended.
const (
	warmDone = iota
	warmCancelled
	warmResolverSilent
)

// warmNames asks the router's resolver for names one at a time, fastWarmPace apart (adaptive: three
// times as long as the last answer took, when that is longer), and checks every checkEvery names that
// dnsmasq still answers, stopping at the first time it does not.
func warmNames(ctx context.Context, names []string, adaptive bool, checkEvery int) (asked, stop int) {
	gap := fastWarmPace
	for _, n := range names {
		select {
		case <-ctx.Done():
			return asked, warmCancelled
		case <-time.After(gap):
		}
		started := time.Now()
		fastWarmResolve(ctx, n)
		if adaptive {
			gap = max(fastWarmPace, 3*time.Since(started))
		}
		asked++
		if asked%checkEvery == 0 && fastDNSAlive(ctx, false) != nil {
			return asked, warmResolverSilent
		}
	}
	return asked, warmDone
}

// fastDNSWatchFor and fastDNSWatchEvery pace the watch of the LAN's DNS after an install.
var (
	fastDNSWatchFor   = time.Minute
	fastDNSWatchEvery = 5 * time.Second
)

// startFastDNSWatch watches dnsmasq for a minute after an install of a plan with resolver-fed sets
// (dnsmasq can stall 10-20 s after the Apply has returned). armed says dnsmasq answered on
// 127.0.0.1:53 just before the install: a resolver that was down already (a boot before the WAN, a
// flap) is not the install's doing, and nothing is watched.
//
// The probe is dnsmasq's OWN answer, the snippet's canary, not a name its upstream has to resolve: an
// upstream outage is not dnsmasq stalling, and must not switch the names off. Three missed
// canaries in a row back the snippet out (fastDNSBackout); the loop puts it back with backoff once
// dnsmasq is healthy again. Each watch carries the install's generation, and a watch whose
// install was replaced stops.
func (s *Server) startFastDNSWatch(plan *pbr.Plan, armed bool) {
	// Every install ends the previous install's watch, a plan without names too: its
	// canary is gone, and a watch left running would back out, or roll back a Test, for nothing.
	s.stopFastDNSWatch()
	if plan == nil || len(plan.DlistSets()) == 0 || s.config().Demo || s.detectedPlatform() != platform.OpenWrt {
		return
	}
	s.fastDNS.mu.Lock()
	gen := s.fastDNS.watchGen
	s.fastDNS.backedOut = false
	// No snippet, no canary to ask for (only remote lists not loaded yet): nothing to watch.
	snippet := s.fastDNS.snippet
	s.fastDNS.mu.Unlock()
	if !armed || snippet == "" {
		return
	}
	parent := s.bgContext()
	s.goBackground(func() {
		ctx, cancel := context.WithTimeout(parent, fastDNSWatchFor+30*time.Second)
		defer cancel()
		deadline := time.Now().Add(fastDNSWatchFor)
		fails := 0
		for time.Now().Before(deadline) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(fastDNSWatchEvery):
			}
			if s.fastDNSWatchGen() != gen {
				return // a newer install has its own watch
			}
			if err := fastDNSAlive(ctx, true); err != nil {
				if fails++; fails >= 3 {
					s.fastDNSBackout(ctx, gen, "dnsmasq missed its own answer three times in a row after the install: "+err.Error())
					return
				}
				continue
			}
			fails = 0
		}
		// The snippet survived its whole watch: only now is the backoff and the back-out count reset
		// (a restore that stalls again must not start over at one minute).
		s.fastDNS.mu.Lock()
		if s.fastDNS.watchGen == gen {
			s.fastDNS.backoff, s.fastDNS.backouts = 0, 0
		}
		s.fastDNS.mu.Unlock()
	})
}

// fastDNSMaxOwedRestarts bounds the further dnsmasq restarts after a back-out (one per loop tick).
const fastDNSMaxOwedRestarts = 10

// fastDNSMaxBackouts is how many back-outs in a row, each with no clean watch between, end the
// retries until the next install.
const fastDNSMaxBackouts = 3

// fastDNSInstalled starts the back-out bookkeeping afresh for a new install.
func (s *Server) fastDNSInstalled() {
	s.fastDNS.mu.Lock()
	s.fastDNS.backouts, s.fastDNS.backoff, s.fastDNS.retryAt, s.fastDNS.gaveUp = 0, 0, time.Time{}, false
	s.fastDNS.mu.Unlock()
}

// stopFastDNSWatch ends a running post-install watch (its generation no longer matches): an install,
// a teardown or a retire of the plane.
func (s *Server) stopFastDNSWatch() {
	s.fastDNS.mu.Lock()
	s.fastDNS.watchGen++
	s.fastDNS.mu.Unlock()
}

func (s *Server) fastDNSWatchGen() int {
	s.fastDNS.mu.Lock()
	defer s.fastDNS.mu.Unlock()
	return s.fastDNS.watchGen
}

// fastDNSBackout gives the LAN its DNS back: a Test Apply still in its window is rolled back whole;
// otherwise the snippet is taken out (dnsmasq restarted without it), so the names stop filling the sets
// but nothing else of the plane moves. FastDNSLoop tries the snippet again with backoff (1 minute
// doubling to 30). Diagnostics shows why. A watch of a replaced install does nothing.
func (s *Server) fastDNSBackout(ctx context.Context, gen int, why string) {
	if s.fastDNSWatchGen() != gen {
		return
	}
	log.Printf("fast path: %s; backing out", why)
	if s.failsafe != nil && s.failsafe.Status().Pending {
		if code, _ := s.applyRollback(ctx, ""); code == 200 {
			// The rollback restarts dnsmasq for the baseline's snippet; one that left it silent is
			// restarted again by the loop, as after any back-out.
			s.oweRestartIfSilent(ctx)
			return
		}
	}
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if s.fastDNSWatchGen() != gen {
		return // an install ran while this waited for the lock
	}
	if err := s.syncFastDNS(ctx, nil); err != nil {
		log.Printf("fast path: the snippet could not be taken out: %v", err)
	}
	// The restart without the snippet may itself have failed, leaving the stalled dnsmasq running:
	// FastDNSLoop restarts it again until it answers.
	s.fastDNSNoteBackout(fastDNSAlive(ctx, false) != nil,
		why+"; the lists' names are off, and the snippet is tried again once dnsmasq is healthy",
		"%s; backed out %d times in a row, so the lists' names stay off until the next Apply", why)
}

// fastDNSNoteBackout is a back-out's bookkeeping, on either platform: a further restart owed when
// dnsmasq does not answer, the backoff (1 minute doubling to 30) before the retry, and the end of the
// retries after fastDNSMaxBackouts in a row (gaveUpFormat takes why and the count).
func (s *Server) fastDNSNoteBackout(owed bool, msg, gaveUpFormat, why string) {
	s.fastDNS.mu.Lock()
	defer s.fastDNS.mu.Unlock()
	s.fastDNS.restartOwed = owed
	s.fastDNS.backedOut = true
	s.fastDNS.backouts++
	switch {
	case s.fastDNS.backoff < time.Minute:
		s.fastDNS.backoff = time.Minute
	case s.fastDNS.backoff < 30*time.Minute:
		s.fastDNS.backoff *= 2
	}
	s.fastDNS.retryAt = time.Now().Add(s.fastDNS.backoff)
	s.fastDNS.err = msg
	if s.fastDNS.backouts >= fastDNSMaxBackouts {
		s.fastDNS.gaveUp = true
		s.fastDNS.err = fmt.Sprintf(gaveUpFormat, why, s.fastDNS.backouts)
	}
}

// oweRestartIfSilent marks a further dnsmasq restart owed when it does not answer now (after a
// back-out, or a Test rolled back by the watch).
func (s *Server) oweRestartIfSilent(ctx context.Context) {
	if fastDNSAlive(ctx, false) != nil {
		s.fastDNS.mu.Lock()
		s.fastDNS.restartOwed = true
		s.fastDNS.mu.Unlock()
	}
}

// fastDNSRestartOwed restarts dnsmasq again after a back-out whose restart left it not answering,
// once per loop tick, until it answers on 127.0.0.1:53.
func (s *Server) fastDNSRestartOwed(ctx context.Context) {
	s.fastDNS.mu.Lock()
	owed, tries := s.fastDNS.restartOwed, s.fastDNS.restartTries
	s.fastDNS.mu.Unlock()
	if !owed {
		return
	}
	if fastDNSAlive(ctx, false) == nil {
		s.fastDNS.mu.Lock()
		s.fastDNS.restartOwed, s.fastDNS.restartTries = false, 0
		s.fastDNS.mu.Unlock()
		return
	}
	if tries >= fastDNSMaxOwedRestarts {
		return // bounded: Diagnostics fails and says what to do
	}
	// Never beside an Apply (HUNT-K #9): its own guarded restart is in its startup window, and a second
	// restart would interrupt it. The next tick tries again; an Apply that restarted it settles it.
	if !s.applyMu.TryLock() {
		return
	}
	defer s.applyMu.Unlock()
	s.fastDNS.mu.Lock()
	owed = s.fastDNS.restartOwed
	s.fastDNS.mu.Unlock()
	if !owed || fastDNSAlive(ctx, false) == nil {
		return
	}
	s.fastDNS.mu.Lock()
	s.fastDNS.restartTries++
	s.fastDNS.mu.Unlock()
	if err := s.restartDnsmasq(ctx); err != nil {
		log.Printf("fast path: dnsmasq still does not answer after the back-out, and its restart failed: %v", err)
		return
	}
	if fastDNSAlive(ctx, false) == nil {
		s.fastDNS.mu.Lock()
		s.fastDNS.restartOwed, s.fastDNS.restartTries = false, 0
		s.fastDNS.mu.Unlock()
		log.Printf("fast path: dnsmasq answers again after a further restart")
	}
}

// fastDNSRestore puts a backed-out snippet back when its time has come and dnsmasq answers again:
// syncFastDNS restarts dnsmasq with it and requires the canary (and the upstream, if that worked
// before); a failure takes it out again and the wait doubles, up to 30 minutes.
func (s *Server) fastDNSRestore(ctx context.Context, plan *pbr.Plan) {
	s.fastDNS.mu.Lock()
	out, retryAt, gaveUp := s.fastDNS.backedOut, s.fastDNS.retryAt, s.fastDNS.gaveUp
	s.fastDNS.mu.Unlock()
	if !out || gaveUp || time.Now().Before(retryAt) || fastDNSAlive(ctx, false) != nil || !s.applyMu.TryLock() {
		return
	}
	defer s.applyMu.Unlock()
	if err := s.syncFastDNS(ctx, plan); err != nil {
		s.fastDNS.mu.Lock()
		if s.fastDNS.backoff < 30*time.Minute {
			s.fastDNS.backoff *= 2
		}
		s.fastDNS.retryAt = time.Now().Add(s.fastDNS.backoff)
		s.fastDNS.err = "the snippet was tried again and dnsmasq did not take it: " + err.Error()
		s.fastDNS.mu.Unlock()
		log.Printf("fast path: the snippet was not restored: %v", err)
		return
	}
	s.fastDNS.mu.Lock()
	// The backoff and the back-out count stay as they are until this snippet survives its watch.
	s.fastDNS.backedOut, s.fastDNS.retryAt = false, time.Time{}
	s.fastDNS.mu.Unlock()
	log.Printf("fast path: dnsmasq is healthy again; the lists' names are back")
	s.startFastDNSWatch(plan, true)
}

// fastDNSResponsive is the loop's check of dnsmasq: an answer on 127.0.0.1:53 to a name it has to ask
// its upstreams for. Failures are counted for Diagnostics.
func (s *Server) fastDNSResponsive(ctx context.Context) {
	err := fastDNSUpstream(ctx)
	s.fastDNS.mu.Lock()
	defer s.fastDNS.mu.Unlock()
	if err != nil {
		s.fastDNS.dnsFails++
		s.fastDNS.dnsErr = err.Error()
		return
	}
	s.fastDNS.dnsFails, s.fastDNS.dnsErr = 0, ""
}

// fastFresh is what the tick remembers of the dlist sets: their addresses at the last look, and which
// sets they were (a plan is known by its set names).
type fastFresh struct {
	key   string
	addrs map[netip.Addr]bool
	// beyond is the addresses that were in a tunnel, block or core list's set.
	beyond map[netip.Addr]bool
}

// FastDNSLoop runs the fast DNS plane's periodic work: warms the sets once after the start, reloads
// the installed sets and snippet when the remote lists' RAM copy changed, looks for new addresses in
// the sets every fastDNSTick and moves the connections opened to those before they entered (keen-pbr
// #129). The live reload takes applyMu (skipped while an Apply runs); the rest never writes the table.
func (s *Server) FastDNSLoop(ctx context.Context) {
	t := time.NewTicker(fastDNSTick)
	defer t.Stop()
	var st, kst fastFresh
	warmed, kwarmed := false, false
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cfg := s.config()
		if !cfg.Demo {
			// After a back-out, or a Test the watch rolled back to a plan of any mode.
			s.fastDNSRestartOwed(ctx)
		}
		// KeeneticOS fast mode (keeneticfast.go): the same retry, warm-up and fresh-address reset over
		// the plane's ipset wd_ sets.
		if !cfg.Demo && s.keeneticFastOn(cfg) {
			kst = s.keeneticFastTick(ctx, kst, &kwarmed)
			continue
		}
		kst, kwarmed = fastFresh{}, false
		if cfg.Demo || !s.fastDNSOn(cfg) {
			st = fastFresh{}
			continue
		}
		s.fastRemoteRefresh(ctx, time.Now())
		plan := s.installedKernelPlan()
		if plan == nil || !plan.FastDNS {
			st = fastFresh{}
			continue
		}
		s.fastDNS.mu.Lock()
		backedOut := s.fastDNS.backedOut
		s.fastDNS.mu.Unlock()
		if backedOut {
			s.fastDNSRestore(ctx, plan)
		} else {
			s.fastRemoteReload(ctx, plan)
		}
		// The large lists' tables are compared and repaired every tick: a failed or partial
		// load, a device that came back, routes someone flushed.
		s.repairRoutedTables(ctx)
		if len(plan.DlistSets()) == 0 {
			st = fastFresh{}
			continue
		}
		if !warmed {
			warmed = true
			s.goBackground(func() { s.fastDNSWarmUp(ctx, plan) })
		}
		s.fastDNSResponsive(ctx)
		st = s.fastFreshTick(ctx, st, plan)
	}
}

// fastRemoteReload puts the remote lists' current RAM copy into the installed plan's rlist sets and
// snippet when it moved since they were filled (a refresh; after a reboot, the first fetch), and sets
// the core pin's devices once every remote list is loaded. When the content changed, the remote
// zones' dlist sets are flushed with it, so addresses of names the list no longer holds do not live
// on by their own traffic. A failure keeps the last working state and is retried with backoff,
// 1 minute doubling to 30.
func (s *Server) fastRemoteReload(ctx context.Context, plan *pbr.Plan) {
	if len(plan.RemoteLists()) == 0 {
		return
	}
	_, sets, key := s.planRemote(plan)
	ready := remoteReady(plan, sets)
	s.fastDNS.mu.Lock()
	loaded, elemKey, pinReady, retryAt := s.fastDNS.loadedKey, s.fastDNS.elemKey, s.fastDNS.pinReady, s.fastDNS.retryAt
	prevLive := map[string]pbr.RemoteSet{}
	for id, set := range s.fastDNS.live {
		prevLive[id] = set
	}
	s.fastDNS.mu.Unlock()
	if key == loaded && key == elemKey && (pinReady || !ready) {
		return
	}
	if time.Now().Before(retryAt) || !s.applyMu.TryLock() {
		return
	}
	defer s.applyMu.Unlock()
	fail := func(what string, err error) {
		s.fastDNS.mu.Lock()
		if s.fastDNS.backoff < time.Minute {
			s.fastDNS.backoff = time.Minute
		} else if s.fastDNS.backoff < 30*time.Minute {
			s.fastDNS.backoff *= 2
		}
		s.fastDNS.retryAt = time.Now().Add(s.fastDNS.backoff)
		s.fastDNS.err = what + ": " + err.Error()
		next := s.fastDNS.backoff
		s.fastDNS.mu.Unlock()
		log.Printf("fast path: %s: %v; the last working state stays, next try in %s", what, err, next)
	}
	// The names first: if dnsmasq does not take the new snippet, the last working one
	// is back and nothing in the kernel has moved yet.
	if key != loaded {
		// A restart for new content is watched like an install, armed only when
		// dnsmasq answered before it.
		wasUp := fastDNSAlive(ctx, false) == nil
		s.fastDNS.mu.Lock()
		before := s.fastDNS.restarted
		s.fastDNS.mu.Unlock()
		if err := s.syncFastDNSMode(ctx, plan, true); err != nil {
			fail("the remote lists' names were not reloaded", err)
			return
		}
		s.fastDNS.mu.Lock()
		restarted := !s.fastDNS.restarted.Equal(before)
		s.fastDNS.mu.Unlock()
		if restarted {
			s.startFastDNSWatch(plan, wasUp)
		}
	}
	if key != elemKey || (ready && !pinReady) {
		// Only the lists whose prefixes moved are reloaded, all of them while the pin waits
		// for its first content.
		changed := map[string]bool{}
		for _, id := range plan.RemoteLists() {
			if old, ok := prevLive[id]; !ok || strings.Join(old.CIDRs, ",") != strings.Join(sets[id].CIDRs, ",") || key != elemKey && !pinReady {
				changed[id] = true
			}
		}
		prog := plan.RenderRemoteElementsOnly(sets, changed)
		// Only a zone whose list lost names loses the addresses they resolved to: names only
		// added keep every address, and the other lists keep theirs.
		for _, z := range append(append([]pbr.Zone(nil), plan.Zones...), plan.CoreZones...) {
			if z.RemoteList == "" || !namesRemoved(prevLive[z.RemoteList], sets[z.RemoteList]) {
				continue
			}
			prog += fmt.Sprintf("flush set inet %s %s\n", plan.DNSTable(), pbr.DlistSet(z.Name, 4))
			if z.DlistV6() {
				prog += fmt.Sprintf("flush set inet %s %s\n", plan.DNSTable(), pbr.DlistSet(z.Name, 6))
			}
		}
		prog += plan.RenderPinElements(ready)
		if prog != "" {
			if err := fastLoadProgram(ctx, prog); err != nil {
				fail("the remote lists' prefixes were not reloaded", err)
				return
			}
		}
		s.fastDNS.mu.Lock()
		s.fastDNS.elemKey, s.fastDNS.pinReady = key, ready
		s.fastDNS.mu.Unlock()
	}
	s.markRemoteLive(sets)
	// The warm-up runs after any flush; syncFastDNSMode leaves it to this in keep mode.
	if key != loaded {
		wctx := s.bgContext()
		s.goBackground(func() { s.fastDNSWarmUp(wctx, plan) })
	}
	// A large remote list's prefixes are routes (fastdns_routed.go): diffed, so a list whose content
	// did not move costs a read.
	if err := s.syncRoutedTables(ctx, plan); err != nil {
		log.Printf("fast path: %v", err)
	}
	s.fastDNS.mu.Lock()
	s.fastDNS.backoff, s.fastDNS.retryAt = 0, time.Time{}
	s.fastDNS.mu.Unlock()
	log.Printf("fast path: the remote lists' content was reloaded into the kernel and dnsmasq (core pin %v)", ready)
}

// namesRemoved reports a name of old that now is not in now.
func namesRemoved(old, now pbr.RemoteSet) bool {
	have := make(map[string]bool, len(now.Domains))
	for _, d := range now.Domains {
		have[d] = true
	}
	for _, d := range old.Domains {
		if !have[d] {
			return true
		}
	}
	return false
}

// fastFreshTick reads the dlist sets, and flushes the unmarked connections to the addresses that are
// new since the last look. The first look at a plan compares with the addresses carried into its
// table at the install, so flows to what the sets took in since are moved too.
func (s *Server) fastFreshTick(ctx context.Context, st fastFresh, plan *pbr.Plan) fastFresh {
	names := plan.DlistSets()
	key := plan.Table + ":" + strings.Join(names, ",")
	sets, err := listDlistSets(ctx, "", plan.DNSTable(), names)
	if err != nil {
		return st
	}
	now := map[netip.Addr]bool{}
	beyond := plan.DlistSetsBeyondWAN()
	nowBeyond := map[netip.Addr]bool{} // in a set of a zone that does not send it by the WAN
	for name, elems := range sets {
		for _, e := range elems {
			if a, err := netip.ParseAddr(e.Addr); err == nil {
				now[a] = true
				if beyond[name] {
					nowBeyond[a] = true
				}
			}
		}
	}
	next := fastFresh{key: key, addrs: now, beyond: nowBeyond}
	prev, prevBeyond := st.addrs, st.beyond
	if st.key != key {
		s.fastDNS.mu.Lock()
		seed, seedKey := s.fastDNS.seed, s.fastDNS.seedKey
		s.fastDNS.mu.Unlock()
		if seedKey != strings.Join(names, ",") || seed == nil {
			return next
		}
		prev, prevBeyond = seed, seed
	}
	fresh := map[netip.Addr]bool{}
	for a := range now {
		if !prev[a] && len(fresh) < fastFreshMax {
			fresh[a] = true
		}
	}
	// New to a tunnel, block or core list's set although another (direct) set held it already:
	// a flow a direct list saved as WAN is stale too.
	var stale map[netip.Addr]uint32
	if wan := plan.WANMark(); wan != 0 {
		stale = map[netip.Addr]uint32{}
		for a := range nowBeyond {
			if !prevBeyond[a] && len(stale) < fastFreshMax {
				stale[a] = wan
				fresh[a] = true
			}
		}
	}
	if len(fresh) == 0 {
		return next
	}
	t, err := ctflushOpen()
	if err != nil {
		return next
	}
	defer t.Close()
	// A flow a weaker direct list had saved with the WAN mark goes too: the connmark
	// restore would keep it on the WAN for as long as it lives. Not one a device-scoped direct list
	// keeps on the WAN anyway: its replacement would go the same way.
	res, err := ctflush.FlushFresh(t, fresh, ctflush.Options{Limit: fastFreshFlushMax, Local: ctflushLocal()},
		ctflush.Fresh{Mask: plan.Mask, CoreMark: generator.AutoRedirectInputMark, Stale: stale, Keep: scopedDirectKeep(plan)})
	switch {
	case err != nil && !errors.Is(err, ctflush.ErrNoModule):
		log.Printf("fast path: connections to %d newly resolved addresses: %v", len(fresh), err)
	case res.Deleted > 0:
		log.Printf("fast path: %d connection(s) opened before their address entered a list's set were reset", res.Deleted)
	}
	return next
}

// scopedDirectKeep reports a source a device-scoped direct list of plan covers. Such a list may match
// by MAC, device or port, which a conntrack entry does not show: then every source is kept, and no
// WAN flow is reset as stale.
func scopedDirectKeep(plan *pbr.Plan) func(netip.Addr) bool {
	kind := map[string]pbr.EgressKind{}
	for _, e := range plan.Egresses {
		kind[e.Tag] = e.Kind
	}
	var prefixes []netip.Prefix
	for _, z := range plan.Zones {
		if !z.SrcScoped || kind[z.EgressTag] != pbr.EgressWAN {
			continue
		}
		if z.SrcNegate || len(z.SrcMAC)+len(z.SrcIface)+len(z.SrcPort) > 0 {
			return func(netip.Addr) bool { return true }
		}
		for _, c := range append(append([]string(nil), z.SrcV4...), z.SrcV6...) {
			if p, err := netip.ParsePrefix(c); err == nil {
				prefixes = append(prefixes, p)
			} else if a, err := netip.ParseAddr(c); err == nil {
				prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
			}
		}
	}
	if len(prefixes) == 0 {
		return nil
	}
	return func(src netip.Addr) bool {
		for _, p := range prefixes {
			if p.Contains(src) {
				return true
			}
		}
		return false
	}
}
