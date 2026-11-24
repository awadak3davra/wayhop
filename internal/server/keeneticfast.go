package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// keeneticfast.go is the KeeneticOS fast plane's runtime, the counterpart of fastdns_runtime.go on the
// ipset plane: the guarded dnsmasq restart of an Apply (keeneticdnsguard.go), the minute's watch after
// it with its back-out and retry, the warm-up of the wd_ sets and the reset of the flows opened to an
// address before the resolver put it into one. The watch, back-out and retry bookkeeping is the one
// fastDNSRuntime keeps for OpenWrt; only one platform runs.

// keeneticFastState is what the Keenetic fast plane keeps beside fastDNSRuntime's shared fields.
type keeneticFastState struct {
	// installed is the policy file the installed plane wrote, backout what a back-out writes (the
	// previous working file, or the installed one without its ipset= lines: keeneticBackoutPolicy).
	installed, backout []byte
	// tool is the installed plane's artifact, whose pinned tools restart dnsmasq.
	tool *executionKernelIpsetArtifactV1
	// guardErr is why the last Apply's guarded restart failed ("" = it did not).
	guardErr string
	// freshLast is how many flows the last fresh-address reset deleted, freshAt when; freshTotal sums them.
	freshLast, freshTotal int
	freshAt               time.Time
	// warm is the last warm-up's outcome, warmAt when it ended; warmCancel stops the one running.
	warm       string
	warmAt     time.Time
	warmCancel context.CancelFunc
	// silentSince is when dnsmasq last stopped answering (zero: it answers); failOpenHeld says why DNS
	// enforcement was kept although it would be suspended (a kill switch).
	silentSince  time.Time
	failOpenHeld string
}

// keeneticFastOn reports the KeeneticOS fast plane: routing mode "fast" on KeeneticOS.
func (s *Server) keeneticFastOn(c config.Config) bool {
	return s.routingMode(c) == "fast" && s.detectedPlatform() == platform.Keenetic
}

// keeneticDnsmasqRestart restarts Entware's dnsmasq through an installed plane's pinned shell. A
// variable so tests count restarts without a router.
var keeneticDnsmasqRestart = func(ctx context.Context, tool *executionKernelIpsetArtifactV1) error {
	if tool == nil {
		return errors.New("no Keenetic plane is installed")
	}
	adapter, err := newExactKeeneticKernelAdapter(*tool)
	if err != nil {
		return err
	}
	return reloadKeeneticDnsmasqWith(ctx, adapter.runner.Run)
}

// restartDnsmasq restarts the router's dnsmasq the platform's way (an owed restart after a back-out).
func (s *Server) restartDnsmasq(ctx context.Context) error {
	if s.detectedPlatform() != platform.Keenetic {
		return fastDNSRestart(ctx)
	}
	s.fastDNS.mu.Lock()
	tool := s.fastDNS.keenetic.tool
	s.fastDNS.mu.Unlock()
	if tool == nil {
		if k := s.kernelBaseline(); k != nil {
			tool = k.Ipset
		}
	}
	return keeneticDnsmasqRestart(ctx, tool)
}

// keeneticFastPreInstall is read before an install writes the policy file: the file it replaces, and
// whether dnsmasq answered (arms the watch) and resolved a real name (the guard then requires one).
type keeneticFastPreInstall struct {
	before          keeneticPolicyFile
	armed, upstream bool
}

func keeneticFastBeforeInstall(ctx context.Context) (keeneticFastPreInstall, error) {
	before, err := readKeeneticPolicy()
	if err != nil {
		return keeneticFastPreInstall{}, fmt.Errorf("read the dnsmasq policy it replaces: %v", err)
	}
	pre := keeneticFastPreInstall{before: before, armed: fastDNSAlive(ctx, false) == nil}
	pre.upstream = pre.armed && fastDNSUpstream(ctx) == nil
	return pre, nil
}

// keeneticFastReload is a fast-mode Apply's dnsmasq restart for the policy file just written: guarded
// (dnsmasq --test, restart, an answer within keeneticDNSGuardWait), the previous file back and the step
// failed otherwise. Then the watch starts, and the warm-up when the file changed. Never the warm-up's
// wait: it runs on its own.
func (s *Server) keeneticFastReload(ctx context.Context, run keeneticToolRun, target executionKernelIpsetArtifactV1, plan *pbr.Plan, pre keeneticFastPreInstall) error {
	changed := !pre.before.existed || !bytes.Equal(pre.before.content, target.DnsmasqConf)
	// The same file, and dnsmasq answers its canary: it runs this policy already, so it is not
	// restarted. dnsmasq names a set on every add, so sets recreated meanwhile need none.
	if !changed && fastDNSAlive(ctx, true) == nil {
		s.fastDNS.mu.Lock()
		s.fastDNS.keenetic.guardErr = ""
		s.fastDNS.mu.Unlock()
		s.keeneticFastInstalled(target, keeneticFastPreInstall{before: pre.before})
		return nil
	}
	err := reloadKeeneticDnsmasqGuarded(ctx, run, func() error { return writeKeeneticPolicy(pre.before) }, pre.upstream)
	s.fastDNS.mu.Lock()
	s.fastDNS.keenetic.guardErr = ""
	if err != nil {
		s.fastDNS.keenetic.guardErr = err.Error()
	} else {
		s.fastDNS.restarted = time.Now()
	}
	s.fastDNS.mu.Unlock()
	if err != nil {
		// The rollback's restart may have left dnsmasq silent: the loop restarts it.
		s.oweRestartIfSilent(ctx)
		return fmt.Errorf("%w: fast mode: dnsmasq did not take the new routing policy, the previous one is back: %v", errExactProductionKernelApply, err)
	}
	s.keeneticFastInstalled(target, pre)
	if changed {
		s.startKeeneticWarmUp(plan)
	}
	// dnsmasq answers the new file: a suspended enforcement comes back with it.
	if keeneticDNSSuspended() {
		if err := s.keeneticFailClosed(ctx, target); err != nil {
			log.Printf("fast mode: DNS enforcement was not restored: %v", err)
		}
	}
	return nil
}

// startKeeneticWarmUp runs one warm-up at a time: a new one cancels the one running, and
// leaving fast mode cancels it too.
func (s *Server) startKeeneticWarmUp(plan *pbr.Plan) {
	ctx, cancel := context.WithCancel(context.Background())
	s.fastDNS.mu.Lock()
	if s.fastDNS.keenetic.warmCancel != nil {
		s.fastDNS.keenetic.warmCancel()
	}
	s.fastDNS.keenetic.warmCancel = cancel
	s.fastDNS.mu.Unlock()
	go s.keeneticFastWarmUp(ctx, plan)
}

// keeneticFastInstalled starts the back-out bookkeeping afresh for an install and the watch of it, when
// dnsmasq answered before it.
func (s *Server) keeneticFastInstalled(target executionKernelIpsetArtifactV1, pre keeneticFastPreInstall) {
	s.stopFastDNSWatch()
	s.fastDNSInstalled()
	tool := target
	s.fastDNS.mu.Lock()
	gen := s.fastDNS.watchGen
	s.fastDNS.backedOut, s.fastDNS.err = false, ""
	k := &s.fastDNS.keenetic
	k.installed = append([]byte(nil), target.DnsmasqConf...)
	k.backout = keeneticBackoutPolicy(pre.before, target.DnsmasqConf)
	k.tool = &tool
	s.fastDNS.mu.Unlock()
	if pre.armed {
		s.keeneticFastWatch(gen)
	}
}

// keeneticClearDNSOpen removes a suspension's flag: the rules it suspended went with the plane, or are
// rendered anew by the next program. A variable for tests.
var keeneticClearDNSOpen = func() { _ = os.Remove(pbr.FastDNSOpenFlag) }

// keeneticFastLeft forgets the fast plane's DNS state: an install that is not fast mode, or a teardown.
func (s *Server) keeneticFastLeft() {
	s.stopFastDNSWatch()
	s.fastDNS.mu.Lock()
	s.fastDNS.backedOut, s.fastDNS.gaveUp = false, false
	s.fastDNS.keenetic.installed, s.fastDNS.keenetic.backout = nil, nil
	if s.fastDNS.keenetic.warmCancel != nil {
		s.fastDNS.keenetic.warmCancel()
		s.fastDNS.keenetic.warmCancel = nil
	}
	s.fastDNS.keenetic.silentSince, s.fastDNS.keenetic.failOpenHeld = time.Time{}, ""
	s.fastDNS.mu.Unlock()
	keeneticClearDNSOpen()
}

// keeneticFastWatch watches dnsmasq for fastDNSWatchFor after an install of generation gen: three
// missed canaries in a row (pid, and the policy file's own answer on 127.0.0.1:53; an upstream outage is not dnsmasq
// stalling) back the policy out. A newer install's generation ends it.
func (s *Server) keeneticFastWatch(gen int) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), fastDNSWatchFor+30*time.Second)
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
				return
			}
			if err := fastDNSAlive(ctx, true); err != nil {
				if fails++; fails >= 3 {
					s.keeneticFastBackout(ctx, gen, "dnsmasq stopped answering three times in a row after the install: "+err.Error())
					return
				}
				continue
			}
			fails = 0
		}
		s.fastDNS.mu.Lock()
		if s.fastDNS.watchGen == gen {
			s.fastDNS.backoff, s.fastDNS.backouts = 0, 0
		}
		s.fastDNS.mu.Unlock()
	}()
}

// keeneticFastBackout gives the LAN its DNS back: a Test still in its window is rolled back whole;
// otherwise the back-out policy goes in (never no file: the fail-closed server= pins stay) and dnsmasq
// is restarted with it. The kernel plane does not move. The loop tries the installed policy again with
// backoff (keeneticFastRestore), at most fastDNSMaxBackouts times in a row.
func (s *Server) keeneticFastBackout(ctx context.Context, gen int, why string) {
	if s.fastDNSWatchGen() != gen {
		return
	}
	log.Printf("fast mode: %s; backing out", why)
	if s.failsafe != nil && s.failsafe.Status().Pending {
		if code, _ := s.applyRollback(ctx, ""); code == 200 {
			s.oweRestartIfSilent(ctx)
			return
		}
	}
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if s.fastDNSWatchGen() != gen {
		return
	}
	s.fastDNS.mu.Lock()
	backout, tool := s.fastDNS.keenetic.backout, s.fastDNS.keenetic.tool
	s.fastDNS.mu.Unlock()
	err := writeKeeneticPolicy(keeneticPolicyFile{content: backout, existed: true})
	if err == nil {
		err = keeneticDnsmasqRestart(ctx, tool)
	}
	if err != nil {
		log.Printf("fast mode: the previous dnsmasq policy could not be put back: %v", err)
	}
	s.fastDNSNoteBackout(fastDNSAlive(ctx, false) != nil,
		why+"; dnsmasq runs the previous routing policy for names, and the new one is tried again once dnsmasq is healthy",
		"%s; backed out %d times in a row, so dnsmasq keeps the previous routing policy for names until the next Apply", why)
}

// keeneticFastRestore puts a backed-out policy back when its time has come and dnsmasq answers again,
// guarded like an Apply (a failure restores the back-out policy and the wait doubles, up to 30 minutes).
// A plane installed since (another policy file) ends the retries.
func (s *Server) keeneticFastRestore(ctx context.Context, k *executionKernelArtifactV1) {
	s.fastDNS.mu.Lock()
	out, retryAt, gaveUp, gen := s.fastDNS.backedOut, s.fastDNS.retryAt, s.fastDNS.gaveUp, s.fastDNS.watchGen
	installed, backout := s.fastDNS.keenetic.installed, s.fastDNS.keenetic.backout
	s.fastDNS.mu.Unlock()
	if !out || gaveUp || time.Now().Before(retryAt) || k == nil || !bytes.Equal(k.Ipset.DnsmasqConf, installed) ||
		fastDNSAlive(ctx, false) != nil || !s.applyMu.TryLock() {
		return
	}
	defer s.applyMu.Unlock()
	// Under applyMu, again (HUNT-K #7): an Apply, a teardown or a change of mode that ran since the
	// snapshot has its own policy file, or none, and this retry must not write the old one over it.
	s.fastDNS.mu.Lock()
	same := s.fastDNS.backedOut && !s.fastDNS.gaveUp && s.fastDNS.watchGen == gen &&
		bytes.Equal(s.fastDNS.keenetic.installed, installed)
	s.fastDNS.mu.Unlock()
	if now := keeneticCurrentPlane(s); !same || now == nil || now.Ipset == nil || !bytes.Equal(now.Ipset.DnsmasqConf, installed) {
		return
	}
	restore := func() error { return writeKeeneticPolicy(keeneticPolicyFile{content: backout, existed: true}) }
	err := writeKeeneticPolicy(keeneticPolicyFile{content: installed, existed: true})
	if err == nil {
		err = keeneticFastGuardedRestart(ctx, *k.Ipset, restore, fastDNSUpstream(ctx) == nil)
	}
	if err != nil {
		s.fastDNS.mu.Lock()
		if s.fastDNS.backoff < 30*time.Minute {
			s.fastDNS.backoff *= 2
		}
		s.fastDNS.retryAt = time.Now().Add(s.fastDNS.backoff)
		s.fastDNS.err = "the routing policy for names was tried again and dnsmasq did not take it: " + err.Error()
		s.fastDNS.mu.Unlock()
		log.Printf("fast mode: the routing policy for names was not restored: %v", err)
		// The guard put the back-out file back and restarted once; one still silent is restarted again
		// by the loop (HUNT-K #8), as after a back-out.
		s.oweRestartIfSilent(ctx)
		return
	}
	s.stopFastDNSWatch()
	s.fastDNS.mu.Lock()
	s.fastDNS.backedOut, s.fastDNS.retryAt, s.fastDNS.err = false, time.Time{}, ""
	s.fastDNS.restarted = time.Now()
	gen = s.fastDNS.watchGen
	s.fastDNS.mu.Unlock()
	log.Printf("fast mode: dnsmasq is healthy again; the routing policy for names is back")
	s.keeneticFastWatch(gen)
}

// keeneticCurrentPlane is the installed Keenetic plane, read again under applyMu (a variable for tests).
var keeneticCurrentPlane = func(s *Server) *executionKernelArtifactV1 { return s.kernelBaseline() }

// keeneticFastGuardedRestart is reloadKeeneticDnsmasqGuarded through an installed plane's pinned tools.
var keeneticFastGuardedRestart = func(ctx context.Context, tool executionKernelIpsetArtifactV1, restore func() error, upstream bool) error {
	adapter, err := newExactKeeneticKernelAdapter(tool)
	if err != nil {
		return err
	}
	return reloadKeeneticDnsmasqGuarded(ctx, adapter.runner.Run, restore, upstream)
}
