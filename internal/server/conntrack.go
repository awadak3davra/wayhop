package server

import (
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"velinx/internal/model"
	"velinx/internal/pbr"
)

// Conn is one kernel connection-tracking entry, parsed from /proc/net/nf_conntrack. Unlike
// the Clash /connections view (sing-box only), this sees EVERY connection — including the
// kernel fast-path that bypasses sing-box in "fast" mode. nf_conntrack_acct=1 on the
// target gives per-connection byte counters in both directions.
type Conn struct {
	Proto     string `json:"proto"`           // tcp / udp / icmp …
	Src       string `json:"src"`             // original src (the LAN client)
	Dst       string `json:"dst"`             // original dst (the remote)
	Dport     int    `json:"dport"`           // remote service port
	State     string `json:"state,omitempty"` // TCP state ("" for udp/icmp)
	UpBytes   int64  `json:"up_bytes"`        // original-direction bytes (client → remote)
	DownBytes int64  `json:"down_bytes"`      // reply-direction bytes (remote → client)
	Mark      uint32 `json:"mark"`            // connmark = egress fwmark once pbr saves it (0 = general/WAN)
	Exit      string `json:"exit,omitempty"`  // resolved egress tag (server-side, via the pbr plan)
}

var tcpStates = map[string]bool{
	"ESTABLISHED": true, "SYN_SENT": true, "SYN_RECV": true, "FIN_WAIT": true,
	"TIME_WAIT": true, "CLOSE": true, "CLOSE_WAIT": true, "LAST_ACK": true,
	"LISTEN": true, "CLOSING": true, "UNREPLIED": false,
}

// parseConntrack parses /proc/net/nf_conntrack into per-connection entries. Pure (file-I/O-
// free) so it is unit-tested with captured samples. Each line lists the ORIGINAL tuple then
// the REPLY tuple; the first src/dst/dport and the first bytes= are the original (upstream)
// direction, the second bytes= is the reply (download). mark= is the connmark.
func parseConntrack(s string) []Conn {
	out := []Conn{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		c := Conn{Proto: f[2]}
		seenBytes := 0
		for _, tok := range f {
			k, v, ok := strings.Cut(tok, "=")
			if !ok {
				if c.State == "" && tcpStates[tok] {
					c.State = tok
				}
				continue
			}
			switch k {
			case "src":
				if c.Src == "" {
					c.Src = v
				}
			case "dst":
				if c.Dst == "" {
					c.Dst = v
				}
			case "dport":
				if c.Dport == 0 {
					c.Dport, _ = strconv.Atoi(v)
				}
			case "bytes":
				n, _ := strconv.ParseInt(v, 10, 64)
				switch seenBytes {
				case 0:
					c.UpBytes = n
				case 1:
					c.DownBytes = n
				}
				seenBytes++
			case "mark":
				if n, err := strconv.ParseUint(v, 10, 32); err == nil {
					c.Mark = uint32(n)
				}
			}
		}
		if c.Src == "" || c.Dst == "" {
			continue // not a usable tuple
		}
		out = append(out, c)
	}
	return out
}

// clientAgg is per-LAN-client aggregated traffic (Dashboard "connected devices").
type clientAgg struct {
	IP        string `json:"ip"`
	Name      string `json:"name,omitempty"`
	UpBytes   int64  `json:"up_bytes"`
	DownBytes int64  `json:"down_bytes"`
	Conns     int    `json:"conns"`
}

// handleConntrack reports the REAL connection table for the Dashboard: top connections by
// bytes, per-exit totals (WAN vs each tunnel, via the connmark→pbr-egress map), and
// per-client aggregates (joined to DHCP-lease hostnames). Degrades to empty off-Linux.
func (s *Server) handleConntrack(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("/proc/net/nf_conntrack")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"available": false})
		return
	}
	conns := parseConntrack(string(data))

	// Resolve each conn's egress from its connmark via the live pbr plan, and tag the
	// LAN-client name from the DHCP leases.
	markExit := s.markExitResolver()
	leases := readLeases()
	exits := map[string]int64{} // egress tag -> total bytes
	clients := map[string]*clientAgg{}
	for i := range conns {
		c := &conns[i]
		c.Exit = markExit(c.Mark)
		exits[c.Exit] += c.UpBytes + c.DownBytes
		ca := clients[c.Src]
		if ca == nil {
			ca = &clientAgg{IP: c.Src, Name: leases[c.Src]}
			clients[c.Src] = ca
		}
		ca.UpBytes += c.UpBytes
		ca.DownBytes += c.DownBytes
		ca.Conns++
	}

	total := len(conns)
	sort.Slice(conns, func(i, j int) bool {
		return conns[i].UpBytes+conns[i].DownBytes > conns[j].UpBytes+conns[j].DownBytes
	})
	const maxRows = 80
	if len(conns) > maxRows {
		conns = conns[:maxRows]
	}
	cl := make([]*clientAgg, 0, len(clients))
	for _, c := range clients {
		cl = append(cl, c)
	}
	sort.Slice(cl, func(i, j int) bool {
		return cl[i].UpBytes+cl[i].DownBytes > cl[j].UpBytes+cl[j].DownBytes
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"available": true,
		"total":     total, // pre-cap connection count
		"max":       readConntrackMax(),
		"conns":     conns,
		"exits":     exits,
		"clients":   cl,
	})
}

// exitResolverTTL bounds how stale the cached connmark→exit-tag map may be. The map only
// changes on Apply, so a few seconds is invisible; this turns a per-poll Profile()+Compile()
// into at most one recompute per TTL while the Dashboard is polling /api/conntrack.
const exitResolverTTL = 15 * time.Second

// markExitResolver returns a cached func mapping a connmark to a human egress tag (built by
// computeMarkExitResolver). It is recomputed at most once per exitResolverTTL instead of on
// every /api/conntrack poll. The returned closure is read-only, so concurrent callers may
// share it safely. (Marks: 0 / WAN-bypass → "direct"; a tunnel mark → its endpoint tag.)
func (s *Server) markExitResolver() func(uint32) string {
	now := time.Now().UnixMilli()
	s.exitResolverMu.Lock()
	defer s.exitResolverMu.Unlock()
	if s.exitResolver != nil && now < s.exitResolverExp {
		return s.exitResolver
	}
	r := s.computeMarkExitResolver()
	s.exitResolver = r
	s.exitResolverExp = now + exitResolverTTL.Milliseconds()
	return r
}

// computeMarkExitResolver builds the connmark→egress-tag lookup from the live profile + pbr
// plan (the expensive Profile() deep-clone + pbr.Compile() the cache above amortises). Until
// the pbr connmark-save ships, every conn reads mark=0 → "direct", so the grouping is correct
// (single-bucket) and lights up per-exit automatically once `ct mark set meta mark` is deployed.
func (s *Server) computeMarkExitResolver() func(uint32) string {
	p := s.store.Profile()
	plan, _, err := pbr.Compile(&p, pbr.Options{})
	if err != nil || plan == nil {
		return func(uint32) string { return "direct" }
	}
	byMark := map[uint32]string{}
	for _, e := range plan.Egresses {
		byMark[e.Mark] = e.Tag
	}
	mask := plan.Mask
	return func(m uint32) string {
		owned := m & mask
		if owned == 0 {
			return "direct"
		}
		if tag, ok := byMark[owned]; ok && tag != model.OutboundDirect {
			return tag
		}
		return "direct"
	}
}

func readConntrackMax() int {
	b, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_max")
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}
