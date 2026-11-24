package server

import (
	"context"
	"time"

	"wayhop/internal/pbr"
)

// killswitchlearn.go paces the learning of kill-switched names' addresses.
//
// The core's connection table lists open connections only, and it used to be read on the reconcile
// tick, every 30 s: a connection shorter than that was seen with a chance of about its length over
// the tick, and a name used only by short requests could stay unlearned, held by nothing once the
// broad hold had run out with the core still down. It is now read on a timer of its own, every 5 s
// while the core runs and the installed plan has kill-switched names.
//
// Cost, bounded: one HTTP read of the core's table and one JSON decode per pass (a household's table
// is tens to a few hundred KB; the client caps the body), nothing kept between passes but the learned
// addresses (ksNames, capped). The pace follows the pass's own duration: the next one waits at least
// twenty times as long as the last one took, so on a slow or busy router the loop costs at most about
// a twentieth of one core, and never waits longer than the reconcile tick used to. No nft process is
// started for a pass that learned nothing, and nothing is written to flash on this path (the file's
// writer coalesces to once an hour).
//
// What is left: a connection that opens and closes between two passes is still not seen, and nothing
// is learned from the passes that did not happen before a crash. A name used only that way is held by
// the broad hold alone. Closing it for good needs the resolver's answers (dnsmasq's nftset feed, or
// the core's DNS log), which is not built.

const (
	// ksLearnEvery is the pace while a pass is cheap, ksLearnSlowest the pace it never falls behind
	// (the reconcile tick's), and ksLearnDuty how many times the last pass's duration the next waits.
	ksLearnEvery   = 5 * time.Second
	ksLearnSlowest = 30 * time.Second
	ksLearnDuty    = 20
)

// ksLearnTarget is the installed plan and the tools its guard is loaded with.
type ksLearnTarget struct {
	plan *pbr.Plan
	nft  ExecutionToolIdentityV1
	ip   ExecutionToolIdentityV1
}

// setLearnTarget tells the learn loop which plan is installed; nil for none. Called where the boot
// copy of the guard is made to follow the plan: after an install, on the reconcile tick, and when
// the plane is taken down.
func (s *Server) setLearnTarget(plan *pbr.Plan, nft, ip ExecutionToolIdentityV1) {
	if plan == nil || len(plan.GuardNameSets) == 0 {
		s.ksLearn.Store(nil)
		return
	}
	if cur := s.ksLearn.Load(); cur != nil && cur.plan == plan && cur.nft == nft && cur.ip == ip {
		return
	}
	s.ksLearn.Store(&ksLearnTarget{plan: plan, nft: nft, ip: ip})
}

// ksLearnRun loads an nft program with the target's tool; tests replace it.
var ksLearnRun = func(t *ksLearnTarget) func(context.Context, string) error {
	return func(ctx context.Context, program string) error {
		_, err := exactKernelToolRunner{nft: t.nft, ip: t.ip}.Run(ctx, program, "nft", "-f", "-")
		return err
	}
}

// learnPace is how long the loop waits after a pass that took took.
func learnPace(took time.Duration) time.Duration {
	switch wait := took * ksLearnDuty; {
	case wait < ksLearnEvery:
		return ksLearnEvery
	case wait > ksLearnSlowest:
		return ksLearnSlowest
	default:
		return wait
	}
}

// learnNamesOnce is one pass; it returns how long to wait before the next.
func (s *Server) learnNamesOnce(ctx context.Context, coreRunning bool) time.Duration {
	t := s.ksLearn.Load()
	if t == nil || !coreRunning || !s.ksNamesEnabled() {
		return ksLearnEvery // nothing was read: looking again costs nothing
	}
	start := time.Now()
	s.learnNamesTick(ctx, t.plan, coreRunning, ksLearnRun(t))
	return learnPace(time.Since(start))
}

// learnNamesLoop runs the passes until ctx ends.
func (s *Server) learnNamesLoop(ctx context.Context) {
	wait := ksLearnEvery
	for {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		wait = s.learnNamesOnce(ctx, s.singbox != nil && s.singbox.Running())
	}
}
