// Package watchdog supervises a long-running process (sing-box, and best-effort
// the engine plugins) and restarts it when it crashes, with exponential backoff
// so a config that crash-loops doesn't thrash. It records restart accounting that
// the UI surfaces on the Dashboard / Diagnostics.
package watchdog

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"
)

// Supervisor is the minimal contract the watchdog needs from a managed process.
// *core.SingBox implements it.
type Supervisor interface {
	Desired() bool // is it supposed to be running?
	Alive() bool   // is the process currently up?
	Start() error  // (re)start it
}

// atomicRestarter is an OPTIONAL capability a Supervisor may also implement to
// make the crash-restart decision race-free. *core.SingBox implements it.
//
// StartIfDesiredDead must, entirely under the core's own lock, (re)start the
// process ONLY IF it is still desired AND not currently alive, and report
// whether it actually started. Combining the desired+alive check with the spawn
// under one lock closes the TOCTOU between the watchdog's separate Desired() →
// Alive() → Start() reads: an intentional Stop() (which clears desired and kills
// the process, e.g. a native-only apply) can no longer be straddled by the
// watchdog and overtaken by a stale Alive()=false read that would resurrect a
// redundant TUN core over the kernel-PBR datapath.
//
// It is an optional interface (not folded into Supervisor) so existing
// three-method Supervisors keep compiling; a Supervisor that doesn't implement
// it falls back to the legacy separate-acquisition path.
type atomicRestarter interface {
	StartIfDesiredDead() (started bool, err error)
}

// Stats is the JSON-facing watchdog state.
type Stats struct {
	Supervised  bool   `json:"supervised"`             // process is desired-running
	Alive       bool   `json:"alive"`                  // process is currently up
	Restarts    int    `json:"restarts"`               // crash-restarts since boot
	LastRestart string `json:"last_restart,omitempty"` // RFC3339 UTC
	LastError   string `json:"last_error,omitempty"`   // last restart error, if any
	BackoffMS   int64  `json:"backoff_ms,omitempty"`   // current backoff window
}

// Watchdog supervises one Supervisor on a fixed tick.
type Watchdog struct {
	name       string
	sup        Supervisor
	interval   time.Duration
	minBackoff time.Duration
	maxBackoff time.Duration
	stable     time.Duration // alive this long after a restart => clear backoff

	notify  func(string) // optional alert hook (e.g. WGBot); nil = off
	plugins func()       // optional per-tick plugin supervision; nil = off
	now     func() time.Time
	// rng returns a random int in [0,n) — injected so the backoff can be JITTERED (de-synchronise
	// co-crashing procs' retries). nil ⇒ no jitter (deterministic backoff = full window), which the
	// timing tests rely on; New() installs a real source for production.
	rng func(n int64) int64

	mu          sync.Mutex
	restarts    int
	lastRestart time.Time
	lastErr     string
	backoff     time.Duration
	nextAttempt time.Time
}

// New builds a watchdog with router-friendly defaults (3s tick, 1s→60s backoff).
func New(name string, sup Supervisor) *Watchdog {
	return &Watchdog{
		name:       name,
		sup:        sup,
		interval:   3 * time.Second,
		minBackoff: 1 * time.Second,
		maxBackoff: 60 * time.Second,
		stable:     30 * time.Second,
		now:        time.Now,
		rng: func(n int64) int64 {
			if n <= 0 {
				return 0
			}
			return rand.Int63n(n)
		},
	}
}

// jittered applies AWS "equal jitter" to a backoff window: keep half the window (so a crash loop
// always waits meaningfully) and randomise the other half. Two procs that co-crash on a shared
// upstream blip then retry at different times instead of hammering a weak router CPU/uplink in
// lockstep. With rng==nil (tests) it returns the full window, so the backoff stays deterministic.
func (w *Watchdog) jittered(d time.Duration) time.Duration {
	if w.rng == nil || d <= 0 {
		return d
	}
	half := d / 2
	return half + time.Duration(w.rng(int64(half)+1))
}

// SetNotify installs an optional alert hook, fired on each crash-restart. Off by
// default — wire it to WGBot only when the user opts in.
func (w *Watchdog) SetNotify(f func(string)) { w.notify = f }

// SetPluginSupervisor installs an optional per-tick callback to also supervise
// the engine plugins (best-effort restart of dead long-running plugin procs).
func (w *Watchdog) SetPluginSupervisor(f func()) { w.plugins = f }

// Run ticks until ctx is cancelled.
func (w *Watchdog) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.tick()
		}
	}
}

// tick is one supervision cycle (exported logic kept here for unit testing).
func (w *Watchdog) tick() {
	if w.plugins != nil {
		w.plugins()
	}
	if !w.sup.Desired() {
		w.clearBackoff()
		return
	}
	now := w.now()
	if w.sup.Alive() {
		// Clear the backoff only once it has stayed up for `stable` — so a
		// crash loop (dies again before that) keeps the window growing.
		w.mu.Lock()
		if w.backoff > 0 && !w.lastRestart.IsZero() && now.Sub(w.lastRestart) >= w.stable {
			w.backoff = 0
			w.nextAttempt = time.Time{}
		}
		w.mu.Unlock()
		return
	}

	// Crashed while it should be up — restart, honoring the backoff window.
	// Snapshot the pre-advance backoff so we can roll it back if the "crash" turns
	// out to be a deliberate Stop() that raced this tick (native-only apply).
	w.mu.Lock()
	if !w.nextAttempt.IsZero() && now.Before(w.nextAttempt) {
		w.mu.Unlock()
		return
	}
	prevBackoff, prevNextAttempt := w.backoff, w.nextAttempt
	if w.backoff == 0 {
		w.backoff = w.minBackoff
	} else if w.backoff < w.maxBackoff {
		w.backoff *= 2
		if w.backoff > w.maxBackoff {
			w.backoff = w.maxBackoff
		}
	}
	w.nextAttempt = now.Add(w.jittered(w.backoff))
	w.mu.Unlock()

	// Make the restart DECISION atomic when the supervisor supports it: spawn only
	// if it's STILL desired and not alive, all under the core's own lock. This is
	// the TOCTOU fix — a concurrent intentional Stop() (clears desired + kills the
	// proc) can no longer be straddled by the watchdog's separate reads and have a
	// stale Alive()=false resurrect a redundant TUN core over the kernel datapath.
	err, deliberateStop := w.restart()
	if deliberateStop {
		// Not a crash: the core was intentionally Stopped (no longer desired)
		// between the Alive() check and the restart decision. Undo the backoff we
		// optimistically charged, don't notify, don't count it as a restart, and
		// let this tick fall through as if the core is intentionally down (the
		// next tick will early-return via the Desired() gate).
		w.mu.Lock()
		w.backoff, w.nextAttempt = prevBackoff, prevNextAttempt
		w.mu.Unlock()
		return
	}

	w.mu.Lock()
	w.restarts++
	w.lastRestart = now
	if err != nil {
		w.lastErr = err.Error()
	} else {
		w.lastErr = ""
	}
	n, backoff := w.restarts, w.backoff
	w.mu.Unlock()

	if w.notify != nil {
		msg := fmt.Sprintf("%s crashed — restart #%d (next backoff %s)", w.name, n, backoff)
		if err != nil {
			msg = fmt.Sprintf("%s crashed — restart #%d FAILED: %v", w.name, n, err)
		}
		w.notify(msg)
	}
}

// restart performs the crash-restart action and reports whether it turned out to
// be a deliberate Stop() rather than a genuine crash. When the supervisor
// implements atomicRestarter, the still-desired + not-alive check and the spawn
// happen under the core's single lock (TOCTOU-safe); otherwise it falls back to
// the legacy unconditional Start() (timing-identical to the original tick).
//
//   - genuine crash, restart spawned:        (nil, false)   — count + notify
//   - genuine crash, spawn failed:           (err, false)   — count + notify(FAILED)
//   - deliberate Stop raced this tick:       (nil, true)    — roll back, stay quiet
func (w *Watchdog) restart() (err error, deliberateStop bool) {
	if ar, ok := w.sup.(atomicRestarter); ok {
		started, err := ar.StartIfDesiredDead()
		// started=false with no error means it was no longer desired (Stopped) —
		// the only non-crash outcome. A spawn error (err != nil) is a genuine
		// crash-restart attempt that failed and must be reported like before.
		if !started && err == nil {
			return nil, true
		}
		return err, false
	}
	return w.sup.Start(), false
}

func (w *Watchdog) clearBackoff() {
	w.mu.Lock()
	w.backoff = 0
	w.nextAttempt = time.Time{}
	w.mu.Unlock()
}

// Stats returns the current supervision state for the API/UI.
func (w *Watchdog) Stats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	st := Stats{
		Supervised: w.sup.Desired(),
		Alive:      w.sup.Alive(),
		Restarts:   w.restarts,
		LastError:  w.lastErr,
		BackoffMS:  w.backoff.Milliseconds(),
	}
	if !w.lastRestart.IsZero() {
		st.LastRestart = w.lastRestart.UTC().Format(time.RFC3339)
	}
	return st
}
