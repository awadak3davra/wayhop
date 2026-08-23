package server

import (
	"context"
	"fmt"
)

// A single TCP connection cannot go faster than its receive window divided by the round trip. That
// is ordinary arithmetic, and it stays invisible while window scaling is in effect, because the
// window grows to cover the delay. When the far end answers a SYN without the window-scale option —
// RFC 7323 says scaling is then off in BOTH directions — the window is pinned at the 16-bit maximum
// and the ceiling becomes real.
//
// This row exists because that arithmetic cost days of hunting. Measured on a live tunnel:
// the exit's round trip is 145 ms, one server answered without wscale, the window sat at 65535 for
// the whole transfer, and the connection ran at 0.44 MB/s with ZERO packet loss, zero
// retransmissions and clean counters everywhere. A 54.5 MB file then needs about two minutes, which
// every download client reports as a stall or a timeout rather than as a slow connection. The panel
// showed the latency all along and never said what it implied.

// maxUnscaledWindow is the largest receive window expressible without the window-scale option.
const maxUnscaledWindow = 65535

// rttCeilingWarnBelow is the ceiling under which the effect becomes visible as "downloads fail":
// below roughly a megabyte a second, an ordinary large file outlives the default timeout of most
// clients. Above it the same arithmetic is true but nobody notices.
const rttCeilingWarnBelow = 1 << 20

// singleFlowCeiling is bytes per second for one connection over a path of the given round trip when
// the window cannot scale. Pure. Zero or negative RTT means "not measured", not "infinitely fast".
func singleFlowCeiling(rttMs int) int {
	if rttMs <= 0 {
		return 0
	}
	return maxUnscaledWindow * 1000 / rttMs
}

// rttCeilingVerdict turns a measured exit round trip into the row. It never claims the ceiling is in
// force — whether a given server negotiates scaling is that server's choice and changes per
// connection — it states what the path costs when one does not.
func rttCeilingVerdict(exit string, rttMs int) (status, summary, fix string) {
	if rttMs <= 0 {
		return "na", "no exit round trip has been measured yet", ""
	}
	c := singleFlowCeiling(rttMs)
	rate := fmt.Sprintf("%.2f MB/s", float64(c)/(1<<20))
	if c >= rttCeilingWarnBelow {
		return "pass", fmt.Sprintf("%s answers in %d ms — one connection can still reach %s without window scaling", exit, rttMs, rate), ""
	}
	return "warn",
		fmt.Sprintf("%s answers in %d ms — a single connection is capped at %s whenever the far end skips window scaling", exit, rttMs, rate),
		"Nothing is broken and nothing is being dropped: the window simply cannot cover the delay. " +
			"A large file then takes minutes and most clients call that a failed download. Fetch big " +
			"files with several connections at once, each of which gets its own window, or route them " +
			"through an exit that answers sooner."
}

// rttCeilingCheck reports the arithmetic for the fastest exit currently answering — the best case,
// so the row never overstates the problem. Read-only.
func (s *Server) rttCeilingCheck(_ context.Context) healthRow {
	row := healthRow{ID: "rtt-ceiling", Label: "Latency limits one connection"}
	// The monitor is absent in server builds that never start one. Reaching into it here panicked
	// inside the battery goroutine, which does not merely fail the row — an unrecovered panic there
	// takes the daemon down on a router. "Not measured" is both true and safe.
	if s == nil || s.monitor == nil {
		row.Status, row.Summary, row.Fix = rttCeilingVerdict("", 0)
		return row
	}
	best, name := 0, ""
	for _, v := range s.monitor.Snapshot() {
		if v.Kind != "endpoint" || v.State != "alive" || v.LatencyMs <= 0 {
			continue
		}
		if best == 0 || v.LatencyMs < best {
			best, name = v.LatencyMs, v.Name
			if name == "" {
				name = v.ID
			}
		}
	}
	row.Status, row.Summary, row.Fix = rttCeilingVerdict(name, best)
	if best > 0 {
		row.Detail = fmt.Sprintf("%d bytes of window over a %d ms round trip", maxUnscaledWindow, best)
	}
	return row
}
