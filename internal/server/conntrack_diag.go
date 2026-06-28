package server

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// conntrackVerdict maps the kernel connection-tracking table's fill ratio to a battery status. Pure
// for unit-testing. max <= 0 (the table isn't exposed — a non-Linux host, or the conntrack module
// isn't loaded) is a PASS: the router simply isn't tracking connections here, nothing to flag.
func conntrackVerdict(count, max int) (status, summary, fix string) {
	if max <= 0 {
		return "pass", "connection tracking not in use", ""
	}
	pct := count * 100 / max
	switch {
	case pct >= 95:
		return "fail", fmt.Sprintf("conntrack table %d%% full (%d/%d)", pct, count, max),
			"The kernel connection-tracking table is almost full, so the router is dropping NEW connections — sites intermittently won't load. Raise it (`sysctl -w net.netfilter.nf_conntrack_max=<bigger>`, persisted), or cut the connection load (a P2P client can open thousands of connections)."
	case pct >= 80:
		return "warn", fmt.Sprintf("conntrack table %d%% full (%d/%d)", pct, count, max),
			"The connection-tracking table is filling up; once it reaches 100% the router drops new connections. Consider raising `net.netfilter.nf_conntrack_max`, especially with many devices or a P2P client."
	default:
		return "pass", fmt.Sprintf("conntrack table %d%% used (%d/%d)", pct, count, max), ""
	}
}

// conntrackCheck is a Diagnostics-battery probe: how full is the kernel connection-tracking table?
// A full table silently drops NEW connections — a confusing "some sites randomly won't load" failure
// under heavy load (many devices, a P2P client) that looks like a VPN problem but isn't. The
// Dashboard shows the raw count/max; this surfaces it proactively in "Run all checks" with a fix.
// Read-only; reuses readConntrackMax (conntrack.go).
func conntrackCheck(_ context.Context) healthRow {
	row := healthRow{ID: "conntrack", Label: "Connection-tracking table has room"}
	row.Status, row.Summary, row.Fix = conntrackVerdict(readConntrackCount(), readConntrackMax())
	return row
}

// readConntrackCount reads the live conntrack entry count (0 if unavailable), mirroring
// readConntrackMax.
func readConntrackCount() int {
	b, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count")
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}
