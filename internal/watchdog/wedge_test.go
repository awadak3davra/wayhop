package watchdog

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// wedgeSup is a fakeSup that can also name its process and stop it for the guard.
type wedgeSup struct {
	fakeSup
	pid          int
	terminations []int
	terminateOK  bool
	terminateErr error
}

func (s *wedgeSup) PID() int { return s.pid }

func (s *wedgeSup) TerminateWedged(pid int) (bool, error) {
	s.terminations = append(s.terminations, pid)
	if s.terminateErr != nil || !s.terminateOK {
		return false, s.terminateErr
	}
	s.alive = false
	return true, nil
}

// wedgeRig steps a watchdog one look at a time on a fake clock, with scripted probes.
type wedgeRig struct {
	sup       *wedgeSup
	w         *Watchdog
	clk       time.Time
	ticks     uint64
	perLook   uint64 // CPU ticks the process uses between looks
	queues    map[uint64]netlinkQueue
	ticksErr  error
	queuesErr error
	queueRead int
	notes     []string
}

func newWedgeRig() *wedgeRig {
	r := &wedgeRig{
		sup:     &wedgeSup{pid: 100, terminateOK: true},
		clk:     time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC),
		perLook: uint64(0.75 * clockTicksPerSecond * wedgeEvery.Seconds()),
		queues:  map[uint64]netlinkQueue{7: {rmem: 230400, drops: 446000}},
	}
	r.sup.desired, r.sup.alive = true, true
	r.sup.onStart = func() { r.sup.alive = true; r.sup.pid++ }
	r.w = New("sing-box", r.sup)
	r.w.rng = nil
	r.w.now = func() time.Time { return r.clk }
	r.w.SetNotify(func(m string) { r.notes = append(r.notes, m) })
	r.w.wedge.ticks = func(int) (uint64, error) { return r.ticks, r.ticksErr }
	r.w.wedge.queues = func(int) (map[uint64]netlinkQueue, error) {
		r.queueRead++
		return r.queues, r.queuesErr
	}
	return r
}

func (r *wedgeRig) look(n int) {
	for i := 0; i < n; i++ {
		r.clk = r.clk.Add(wedgeEvery)
		r.ticks += r.perLook
		r.w.tick()
	}
}

// looksToAct is how many looks a process that is wedged from the start takes to be stopped: one to
// meet the process, one for the first queue reading, then wedgeNeed stuck comparisons.
const looksToAct = wedgeNeed + 2

func TestWedge_StopsAStuckBusyProcessAndTheCrashPathBringsItBack(t *testing.T) {
	r := newWedgeRig()
	r.look(looksToAct - 1)
	if len(r.sup.terminations) != 0 {
		t.Fatalf("stopped after %d looks, want %d", looksToAct-1, looksToAct)
	}
	r.look(1)
	if len(r.sup.terminations) != 1 || r.sup.terminations[0] != 100 {
		t.Fatalf("terminations = %v, want [100]", r.sup.terminations)
	}
	if st := r.w.Stats(); st.WedgeRestarts != 1 || st.LastWedge == "" || st.Restarts != 0 {
		t.Fatalf("after the stop: %+v", st)
	}

	r.clk = r.clk.Add(3 * time.Second)
	r.w.tick()
	if r.sup.starts != 1 || !r.sup.alive {
		t.Fatalf("not restarted: starts=%d alive=%v", r.sup.starts, r.sup.alive)
	}
	if st := r.w.Stats(); st.Restarts != 1 || st.WedgeRestarts != 1 {
		t.Fatalf("after the restart: %+v", st)
	}
	if len(r.notes) != 1 || !strings.Contains(r.notes[0], "wedged") || !strings.Contains(r.notes[0], "230400") ||
		strings.Contains(r.notes[0], "crashed") {
		t.Fatalf("notes = %q, want one saying why, not a crash", r.notes)
	}
}

func TestWedge_LeavesAHealthyProcessAlone(t *testing.T) {
	cases := []struct {
		name    string
		perLook uint64
		queue   netlinkQueue
	}{
		// Real traffic: busy, and the subscription read to empty.
		{"busy with an empty queue", 10000, netlinkQueue{rmem: 0, drops: 446000}},
		// sing-box 1.12.17 right after start: bytes held, nothing ever lost.
		{"bytes held with no drops", 10000, netlinkQueue{rmem: 1280}},
		// sing-box 1.12.17 after an overflow: the same dead socket, without the spin.
		{"stuck socket without the spin", 100, netlinkQueue{rmem: 213248, drops: 65298}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newWedgeRig()
			r.perLook = c.perLook
			r.queues = map[uint64]netlinkQueue{7: c.queue}
			r.look(looksToAct * 4)
			if len(r.sup.terminations) != 0 {
				t.Fatalf("stopped a healthy process: %v", r.sup.terminations)
			}
		})
	}
}

func TestWedge_DoesNotWalkFdsOfAnIdleProcess(t *testing.T) {
	r := newWedgeRig()
	r.perLook = 1
	r.look(looksToAct * 2)
	if r.queueRead != 0 {
		t.Fatalf("read the sockets %d times for an idle process", r.queueRead)
	}
}

func TestWedge_AnyHealthyLookStartsTheCountOver(t *testing.T) {
	interrupts := map[string]func(r *wedgeRig) func(){
		"the queue drained": func(r *wedgeRig) func() {
			was := r.queues
			r.queues = map[uint64]netlinkQueue{7: {rmem: 0, drops: 446000}}
			return func() { r.queues = was }
		},
		"the queue shrank": func(r *wedgeRig) func() {
			was := r.queues
			r.queues = map[uint64]netlinkQueue{7: {rmem: 100, drops: 446000}}
			return func() { r.queues = was }
		},
		"the CPU calmed down": func(r *wedgeRig) func() {
			was := r.perLook
			r.perLook = 0
			return func() { r.perLook = was }
		},
		"the probe failed": func(r *wedgeRig) func() {
			r.queuesErr = errors.New("gone")
			return func() { r.queuesErr = nil }
		},
		"the CPU reading failed": func(r *wedgeRig) func() {
			r.ticksErr = errors.New("gone")
			return func() { r.ticksErr = nil }
		},
		"another process took over": func(r *wedgeRig) func() {
			r.sup.pid = 555
			return func() {}
		},
	}
	for name, interrupt := range interrupts {
		t.Run(name, func(t *testing.T) {
			r := newWedgeRig()
			r.look(looksToAct - 1)
			restore := interrupt(r)
			r.look(1)
			restore()
			r.look(wedgeNeed - 1)
			if len(r.sup.terminations) != 0 {
				t.Fatalf("stopped %v before a new full streak", r.sup.terminations)
			}
			r.look(looksToAct)
			if len(r.sup.terminations) != 1 {
				t.Fatalf("terminations = %v after a new full streak, want one", r.sup.terminations)
			}
		})
	}
}

func TestWedge_HoldsBetweenRestarts(t *testing.T) {
	r := newWedgeRig()
	r.look(looksToAct)
	r.clk = r.clk.Add(3 * time.Second)
	r.w.tick() // restarted; the new process wedges straight away
	if len(r.sup.terminations) != 1 || !r.sup.alive {
		t.Fatalf("setup: terminations=%v alive=%v", r.sup.terminations, r.sup.alive)
	}

	looksInHold := int(wedgeHold/wedgeEvery) - 1
	r.look(looksInHold)
	if len(r.sup.terminations) != 1 {
		t.Fatalf("stopped again inside the hold: %v", r.sup.terminations)
	}
	r.look(2)
	if len(r.sup.terminations) != 2 {
		t.Fatalf("terminations = %v after the hold, want a second", r.sup.terminations)
	}
}

func TestWedge_LostRaceIsNotCounted(t *testing.T) {
	r := newWedgeRig()
	r.sup.terminateOK = false
	r.look(looksToAct)
	if len(r.sup.terminations) != 1 {
		t.Fatalf("terminations = %v", r.sup.terminations)
	}
	if st := r.w.Stats(); st.WedgeRestarts != 0 || st.LastWedge != "" {
		t.Fatalf("counted a stop that did not happen: %+v", st)
	}
	if len(r.notes) != 0 {
		t.Fatalf("notes = %q", r.notes)
	}
}

func TestWedge_FailedStopIsReportedAndNotCounted(t *testing.T) {
	r := newWedgeRig()
	r.sup.terminateErr = errors.New("operation not permitted")
	r.look(looksToAct)
	if st := r.w.Stats(); st.WedgeRestarts != 0 {
		t.Fatalf("counted a failed stop: %+v", st)
	}
	if len(r.notes) != 1 || !strings.Contains(r.notes[0], "operation not permitted") {
		t.Fatalf("notes = %q", r.notes)
	}
}

func TestWedge_ARealCrashStillReadsAsACrash(t *testing.T) {
	r := newWedgeRig()
	r.look(looksToAct) // the guard stops it and the note below is the guard's
	r.clk = r.clk.Add(3 * time.Second)
	r.w.tick()
	r.notes = nil

	r.sup.alive = false
	r.clk = r.clk.Add(time.Minute)
	r.w.tick()
	if len(r.notes) != 1 || !strings.Contains(r.notes[0], "crashed") {
		t.Fatalf("notes = %q, want a crash", r.notes)
	}
}

func TestWedge_IsOffWithoutTheCapabilityOrTheIntent(t *testing.T) {
	r := newWedgeRig()
	w := New("sing-box", &fakeSup{desired: true, alive: true})
	w.now = r.w.now
	w.wedge = r.w.wedge
	for i := 0; i < looksToAct; i++ {
		r.clk = r.clk.Add(wedgeEvery)
		w.tick()
	}
	if r.queueRead != 0 {
		t.Fatalf("probed a supervisor that cannot stop its process: %d reads", r.queueRead)
	}

	r = newWedgeRig()
	r.sup.desired = false
	r.look(looksToAct)
	if r.queueRead != 0 || len(r.sup.terminations) != 0 {
		t.Fatalf("acted on a core not meant to run: reads=%d terminations=%v", r.queueRead, r.sup.terminations)
	}
}

func TestStuckQueue(t *testing.T) {
	prev := map[uint64]netlinkQueue{1: {rmem: 500, drops: 3}, 2: {rmem: 500, drops: 3}}
	if _, ok := stuckQueue(nil, prev); ok {
		t.Fatal("nothing to compare with")
	}
	if q, ok := stuckQueue(prev, map[uint64]netlinkQueue{1: {rmem: 900, drops: 9}}); !ok || q.rmem != 900 {
		t.Fatalf("a growing queue: %+v %v", q, ok)
	}
	if _, ok := stuckQueue(prev, map[uint64]netlinkQueue{3: {rmem: 900, drops: 9}}); ok {
		t.Fatal("a socket with no earlier reading")
	}
}
