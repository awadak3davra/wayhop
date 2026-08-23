package server

import (
	"context"
	"strconv"
	"strings"
	"time"

	"wayhop/internal/pbr"
)

// listtraffic_kernel.go answers "how much has this list actually matched?" on a router with no proxy
// core.
//
// The Matched column was fed only from the core's connection API, so on a kernel-routed router every
// list read "nothing yet" while the kernel was demonstrably matching them — measured on a live
// own box, where the mangle chain showed hits on three lists at the same moment the page claimed none.
// The counters were there the whole time; nothing was reading them.
//
// What this reads is the same rule the plane installs: one `-m set --match-set <zone set> dst -j MARK`
// per zone, whose packet/byte counters the kernel maintains. They count since the rules were installed
// (an Apply), which is what the page already says about its own numbers.

const (
	kernelCounterTimeout     = 4 * time.Second
	kernelCounterOutputLimit = 1 << 20
)

// kernelListCounters returns per-list packets/bytes read from the mangle chain, keyed by routing-list
// id. A missing binary, an absent chain or an unparsable line yields no entry for that list rather
// than a zero: "not measured" and "matched nothing" are different answers and the page words them
// differently.
func (s *Server) kernelListCounters(ctx context.Context, listIDs []string) map[string]listStats {
	if s == nil || len(listIDs) == 0 {
		return nil
	}
	opts := keeneticPBROptions("")
	// set name → list id, built from the same helpers the renderer uses.
	want := make(map[string]string, len(listIDs)*2)
	for _, id := range listIDs {
		zone := pbr.ListZoneName(id)
		want[opts.ZoneSetName(zone, "4")] = id
		want[opts.ZoneSetName(zone, "6")] = id
	}
	out := map[string]listStats{}
	for _, tool := range []string{executionToolIptables, executionToolIp6tables} {
		text, err := runHostCommandBounded(ctx, kernelCounterTimeout, kernelCounterOutputLimit,
			applyHostCommandWaitDelay, tool, "-t", "mangle", "-L", pbrChainName(opts), "-v", "-x", "-n")
		if err != nil {
			continue // one family missing is not an answer about the other
		}
		for _, line := range strings.Split(text, "\n") {
			set, ok := matchSetOf(line)
			if !ok {
				continue
			}
			id, ok := want[set]
			if !ok {
				continue
			}
			pkts, bytes, ok := leadingCounters(line)
			if !ok {
				continue
			}
			st := out[id]
			st.Conns += pkts // packets matched; the column reads it as "how much has hit this list"
			st.Bytes += bytes
			out[id] = st
		}
	}
	return out
}

// matchSetOf pulls the ipset name out of an `iptables -L -v` line describing a set match.
func matchSetOf(line string) (string, bool) {
	i := strings.Index(line, "match-set ")
	if i < 0 {
		return "", false
	}
	rest := strings.Fields(line[i+len("match-set "):])
	if len(rest) == 0 {
		return "", false
	}
	return rest[0], true
}

// leadingCounters reads the packet and byte counts iptables prints first on a -v -x rule line.
func leadingCounters(line string) (pkts, bytes int64, ok bool) {
	f := strings.Fields(line)
	if len(f) < 2 {
		return 0, 0, false
	}
	p, err1 := strconv.ParseInt(f[0], 10, 64)
	b, err2 := strconv.ParseInt(f[1], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return p, b, true
}

// pbrChainName is the mangle chain the plane installs, defaulted the same way the renderer defaults
// it — an empty Chain means "the standard one", and reading the live kernel has to agree.
func pbrChainName(o pbr.IpsetOptions) string {
	if strings.TrimSpace(o.Chain) == "" {
		return "WR_PREROUTING"
	}
	return o.Chain
}
