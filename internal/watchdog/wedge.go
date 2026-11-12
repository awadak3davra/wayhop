package watchdog

import (
	"fmt"
	"log"
	"time"
)

// The wedge guard catches a process that is alive and useless, which the crash path cannot see.
//
// Found on a live Keenetic (sing-box 1.13.19: 75% of a core for days with no connections through it)
// and reproduced on 1.13.21 in a network namespace by stopping the process, flooding the route table
// and letting it continue. When a burst of route changes overflows the core's rtnetlink subscription,
// the next read fails with ENOBUFS. sagernet/netlink's subscriber returns on any read error, closes
// its channel and leaves the socket open and unread, and sing-tun's network monitor selects on that
// closed channel with no ok check, so it spins until the process dies. Nothing in the process ever
// recovers, and a restart costs about a second.
//
// It takes all of these together, in several consecutive looks, because each one alone happens on a
// healthy core:
//   - the process is burning CPU: real traffic does that too;
//   - a subscription socket has dropped messages: the counter never resets, so one old burst stays visible;
//   - that socket holds queued bytes which did not shrink since the last look: sing-box 1.12.17 was
//     measured holding 1280 bytes right after start, with no drops.
//
// Other versions took the same overflow differently. 1.14.3 and 1.15.0-alpha.12 keep reading and never
// match. 1.12.17 also leaves the socket unread, but without the spin; it is left alone, because that
// is a monitor which stopped following route changes, not a core burning the router, and nothing
// measured says a restart on the socket alone would be safe from false alarms.
const (
	wedgeEvery  = time.Minute      // how often to look; the rest of a tick stays 3 s
	wedgeNeed   = 3                // consecutive stuck looks before acting, so about 4 minutes in all
	wedgeHold   = 30 * time.Minute // at most one restart per this, so a router that keeps overflowing does not loop
	wedgeMinCPU = 0.25             // of one core; the measured spin is 0.75-1.0
)

// wedgeRestarter is an OPTIONAL capability, like atomicRestarter, of a Supervisor that can name its
// process and stop it on the guard's say-so. *core.SingBox implements it.
type wedgeRestarter interface {
	// PID is the supervised process, 0 when none is running.
	PID() int
	// TerminateWedged stops process pid and leaves it desired, so the next tick's crash path restarts
	// it. It reports false, having done nothing, when pid is no longer the desired process: an Apply
	// got there first.
	TerminateWedged(pid int) (bool, error)
}

// wedgeSample is one look at the process. queues stays nil when the CPU was too low to bother.
type wedgeSample struct {
	pid    int
	at     time.Time
	ticks  uint64
	queues map[uint64]netlinkQueue
}

// wedgeGuard is the guard's state, touched only from tick. Its probes are nil when it is off, which
// is the zero value; New() installs the real ones.
type wedgeGuard struct {
	ticks  func(pid int) (uint64, error)
	queues func(pid int) (map[uint64]netlinkQueue, error)

	next      time.Time
	prev      wedgeSample
	streak    int
	holdUntil time.Time
	reason    string // why the guard just stopped the process, for the crash path's message
}

// checkWedge is the Alive branch's extra look. Reading the CPU is one small file; the fd walk behind
// queues only happens once the process is already busy.
func (w *Watchdog) checkWedge(now time.Time) {
	g := &w.wedge
	g.reason = "" // alive again, so whoever restarted it, the crash path has nothing to explain
	wr, ok := w.sup.(wedgeRestarter)
	if !ok || g.ticks == nil || now.Before(g.next) {
		return
	}
	g.next = now.Add(wedgeEvery)

	pid := wr.PID()
	ticks, err := g.ticks(pid)
	if pid <= 0 || err != nil {
		g.prev, g.streak = wedgeSample{}, 0
		return
	}
	prev := g.prev
	g.prev = wedgeSample{pid: pid, at: now, ticks: ticks}
	if prev.pid != pid {
		g.streak = 0
		return
	}
	cpu := float64(ticks-prev.ticks) / clockTicksPerSecond / now.Sub(prev.at).Seconds()
	if cpu < wedgeMinCPU {
		g.streak = 0
		return
	}
	queues, err := g.queues(pid)
	if err != nil {
		g.streak = 0
		return
	}
	g.prev.queues = queues
	q, stuck := stuckQueue(prev.queues, queues)
	if !stuck {
		g.streak = 0
		return
	}
	g.streak++
	if g.streak < wedgeNeed || now.Before(g.holdUntil) {
		return
	}

	g.holdUntil = now.Add(wedgeHold)
	g.streak = 0
	reason := fmt.Sprintf("a netlink subscription stopped being read (%d bytes queued, %d dropped) while it used %.0f%% of a core",
		q.rmem, q.drops, cpu*100)
	log.Printf("watchdog: %s pid %d is wedged: %s; restarting it", w.name, pid, reason)
	stopped, err := wr.TerminateWedged(pid)
	if err != nil {
		log.Printf("watchdog: could not stop wedged %s pid %d: %v", w.name, pid, err)
		if w.notify != nil {
			w.notify(fmt.Sprintf("%s is wedged and could not be stopped: %v", w.name, err))
		}
		return
	}
	if !stopped {
		return
	}
	g.reason = reason
	w.mu.Lock()
	w.wedgeRestarts++
	w.lastWedge = now
	w.mu.Unlock()
}

// stuckQueue finds a subscription socket that has overflowed and was not read between two looks.
func stuckQueue(prev, cur map[uint64]netlinkQueue) (netlinkQueue, bool) {
	for inode, q := range cur {
		if p, ok := prev[inode]; ok && q.drops > 0 && p.rmem > 0 && q.rmem >= p.rmem {
			return q, true
		}
	}
	return netlinkQueue{}, false
}
