package server

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// ifaceSnap is one timestamped snapshot of every interface's cumulative byte counters. The client
// turns successive snapshots into per-interface rates (the SAME delta math the live /api/system poll
// uses), so a freshly-loaded dashboard can paint the last few minutes of per-interface throughput
// immediately instead of starting from an empty graph.
type ifaceSnap struct {
	T      int64   `json:"t"`      // unix milliseconds
	Ifaces []Iface `json:"ifaces"` // cumulative rx/tx counters at time T
}

// ifaceRing is a fixed-size, RAM-only ring of ifaceSnap. Nothing here is ever serialized to disk —
// the router's flash is never touched — so continuous sampling is safe (that flash-wear concern is
// exactly why this history lives only in memory). Index math mirrors internal/traffic.Hub.
type ifaceRing struct {
	mu    sync.Mutex
	buf   []ifaceSnap
	size  int
	start int
	count int
}

func newIfaceRing(size int) *ifaceRing {
	if size < 1 {
		size = 1
	}
	return &ifaceRing{buf: make([]ifaceSnap, size), size: size}
}

func (r *ifaceRing) push(s ifaceSnap) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.count < r.size {
		r.buf[(r.start+r.count)%r.size] = s
		r.count++
		return
	}
	r.buf[r.start] = s
	r.start = (r.start + 1) % r.size
}

// recentN returns a copy of the last n snapshots, oldest-first (all held snapshots if n<=0 or n>count).
func (r *ifaceRing) recentN(n int) []ifaceSnap {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 || n > r.count {
		n = r.count
	}
	out := make([]ifaceSnap, n)
	for i := 0; i < n; i++ {
		out[i] = r.buf[(r.start+r.count-n+i)%r.size]
	}
	return out
}

// A day of one-minute activity buckets, for the Dashboard's time ribbon.
//
// The existing ifaceRing holds ~7.5 minutes at a 5s cadence — enough to seed a live graph, nowhere
// near enough to answer "was the router busy overnight". This is the coarse companion: one bucket
// per minute, 24 hours of them, ~35 KB of RAM and not one byte written to flash. That last point is
// the constraint that shapes it: a router's overlay is small and rewriting a history file every
// minute would wear it out, so the history is deliberately lost on restart and the UI says so.
//
// What a bucket holds is ACTIVITY, not WAN throughput: the summed rx+tx delta across every interface
// in /proc/net/dev. The same packet crosses a LAN port and the WAN port, so this number is larger
// than the link rate — calling it throughput would be a lie by a factor of about two, and there is no
// WAN marker in the counters to single one out. Naming it what it is costs nothing and misleads
// nobody: it still answers "when was this router doing something".
const dayBuckets = 1440 // minutes in a day

type dayBucket struct {
	T       int64 `json:"t"`       // unix ms at the START of the minute
	Bytes   int64 `json:"bytes"`   // rx+tx summed across all interfaces during that minute
	Samples int   `json:"samples"` // 5s samples folded in; a short bucket is a partial minute
}

type dayRing struct {
	mu   sync.Mutex
	buf  []dayBucket
	n    int   // buckets filled (caps at dayBuckets)
	head int   // oldest slot once wrapped
	cur  int64 // unix ms of the minute currently accumulating (0 = none)
	prev []Iface
}

func newDayRing() *dayRing { return &dayRing{buf: make([]dayBucket, dayBuckets)} }

func minuteOf(ms int64) int64 { return ms - ms%60000 }

// observe folds one interface snapshot into the ring. The first snapshot only establishes a
// baseline: without a previous reading there is no delta, and counting the cumulative totals as one
// minute's traffic would put a spike at the daemon's start every time it restarts.
func (r *dayRing) observe(t int64, ifs []Iface) {
	r.mu.Lock()
	defer r.mu.Unlock()
	prev := r.prev
	r.prev = ifs
	if prev == nil {
		r.cur = minuteOf(t)
		return
	}
	byName := make(map[string]Iface, len(prev))
	for _, f := range prev {
		byName[f.Name] = f
	}
	var delta int64
	for _, f := range ifs {
		p, ok := byName[f.Name]
		if !ok {
			continue // an interface that appeared between samples has no delta yet
		}
		// A counter that went backwards means the interface was reset or the box wrapped a 32-bit
		// counter. Counting the raw difference would subtract; counting the new total would invent a
		// burst. Skipping it loses one interval and claims nothing.
		if f.RxBytes >= p.RxBytes {
			delta += f.RxBytes - p.RxBytes
		}
		if f.TxBytes >= p.TxBytes {
			delta += f.TxBytes - p.TxBytes
		}
	}
	m := minuteOf(t)
	if r.cur == 0 {
		r.cur = m
	}
	if r.n == 0 {
		r.alloc(r.cur)
	}
	// Advance one minute at a time, allocating a bucket for each. Skipping straight to m would leave
	// the silent minutes out entirely, and the ribbon would then close the gap up — sliding later
	// activity earlier on the timeline, which is worse than an empty slot because it moves an event
	// to a time it did not happen.
	for r.cur < m {
		r.cur += 60000
		r.alloc(r.cur)
	}
	i := (r.head + r.n - 1) % dayBuckets
	r.buf[i].Bytes += delta
	r.buf[i].Samples++
}

func (r *dayRing) alloc(minute int64) int {
	if r.n < dayBuckets {
		i := (r.head + r.n) % dayBuckets
		r.buf[i] = dayBucket{T: minute}
		r.n++
		return i
	}
	i := r.head
	r.buf[i] = dayBucket{T: minute}
	r.head = (r.head + 1) % dayBuckets
	return i
}

// snapshot returns every bucket, oldest first.
func (r *dayRing) snapshot() []dayBucket {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]dayBucket, r.n)
	for i := 0; i < r.n; i++ {
		out[i] = r.buf[(r.head+i)%dayBuckets]
	}
	return out
}

// handleSystemDay serves the activity ribbon.
func (s *Server) handleSystemDay(w http.ResponseWriter, r *http.Request) {
	if s.dayHist == nil {
		writeJSON(w, http.StatusOK, map[string]any{"buckets": []any{}, "known": false})
		return
	}
	b := s.dayHist.snapshot()
	// Off a router there is no /proc/net/dev, so nothing can ever be measured and the ribbon would
	// be permanently blank — which is honest but leaves the whole view undeveloped and untested.
	// Demo mode synthesises a plausible few hours instead, flagged as demo in the response exactly
	// like the per-outbound rates are, so no caller can mistake it for a measurement.
	if s.config().Demo && len(b) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{
			"buckets": demoDayBuckets(time.Now()), "known": true, "demo": true,
			"since_ms": s.startedAt.UnixMilli(), "bucket_s": 60,
			"capacity": dayBuckets, "persistent": false,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"buckets": b,
		"known":   true,
		// The window the ribbon can possibly cover. An empty ribbon on a router that has been up for
		// a week means the daemon restarted, not that nothing happened — the page says which.
		"since_ms":   s.startedAt.UnixMilli(),
		"bucket_s":   60,
		"capacity":   dayBuckets,
		"persistent": false,
	})
}

// demoDayBuckets synthesises a few hours of plausible activity for demo mode: a quiet night, a busy
// evening, and two minutes with no sample at all so the "hole in the record" rendering is exercised
// rather than only existing in theory.
func demoDayBuckets(now time.Time) []dayBucket {
	const n = 240 // four hours
	end := minuteOf(now.UnixMilli())
	out := make([]dayBucket, 0, n)
	for i := n - 1; i >= 0; i-- {
		t := end - int64(i)*60000
		mins := int64(i)
		// A slow diurnal swell plus a burst, so the ribbon has shape instead of noise.
		base := 900_000 + (mins%37)*40_000
		if mins > 60 && mins < 95 {
			base += 6_000_000
		}
		if mins > 150 && mins < 160 {
			base = 40_000
		}
		b := dayBucket{T: t, Bytes: base, Samples: 12}
		if mins == 120 || mins == 121 {
			b = dayBucket{T: t} // no sample: a gap in the record, not a quiet minute
		}
		out = append(out, b)
	}
	return out
}

// SampleInterfacesLoop appends one interface snapshot every 5s (matching the dashboard's /api/system
// poll cadence, so seeded history density matches live points) until ctx is cancelled. The daemon
// starts it once. Purely in-RAM: readInterfaces() only reads /proc + /sys, nothing is persisted.
func (s *Server) SampleInterfacesLoop(ctx context.Context) {
	if s.ifaceHist == nil {
		return
	}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	// One sample right away so a dashboard opened moments after boot isn't blank.
	first := readInterfaces()
	s.ifaceHist.push(ifaceSnap{T: time.Now().UnixMilli(), Ifaces: first})
	if s.dayHist != nil {
		s.dayHist.observe(time.Now().UnixMilli(), first) // baseline only; no delta exists yet
	}
	s.sampleOutbounds(ctx) // prime the per-outbound (proxy-exit) rate baseline
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now, ifs := time.Now().UnixMilli(), readInterfaces()
			s.ifaceHist.push(ifaceSnap{T: now, Ifaces: ifs})
			if s.dayHist != nil {
				s.dayHist.observe(now, ifs)
			}
			s.sampleOutbounds(ctx) // refresh proxy-exit rates (VLESS/SOCKS have no kernel iface)
		}
	}
}

// obSampler derives an approximate per-OUTBOUND throughput. Proxy exits (VLESS/SOCKS/etc.) egress
// through sing-box and have no kernel interface, so /proc/net/dev can't see their speed. sing-box's
// Clash /connections list, however, reports each active connection's cumulative bytes + the outbound
// tags in its chain; summing each connection's byte DELTA across polls into its chain tags yields a
// live per-outbound rate. Approximate (only active connections are visible — a connection that closes
// between polls loses its last interval) but good enough for a live indicator. Purely in-RAM.
type obSampler struct {
	mu    sync.Mutex
	prev  map[string]int64   // clash connection id -> cumulative (up+down) bytes at the last sample
	prevT int64              // unix ms of the last sample (0 = none yet)
	rates map[string]float64 // outbound tag -> bytes/s (up+down)
	// Per-routing-list totals for the Routing page (see listtraffic.go). Accumulated here rather
	// than in a second sampler because this loop already holds every connection's byte delta, and a
	// second poll of /connections would both cost a request and see a different set of connections.
	listBytes map[string]int64 // routing list id -> cumulative bytes attributed since start
	listConns map[string]int64 // routing list id -> connections first seen since start
	listLive  map[string]int   // routing list id -> connections open at the last sample
}

func newObSampler() *obSampler {
	return &obSampler{prev: map[string]int64{}, rates: map[string]float64{},
		listBytes: map[string]int64{}, listConns: map[string]int64{}, listLive: map[string]int{}}
}

// obStaleMs bounds how long a Clash outage may freeze the last per-outbound rates before they're
// cleared. Longer than one sample interval (5s) so a single missed poll is tolerated, but short enough
// that a durably-down/idle sing-box stops showing phantom throughput on the tiles.
const obStaleMs = 15000

// sampleOutbounds polls Clash once and refreshes the per-outbound rate map. A single missed poll (a
// transient blip) leaves the last rates in place; a DURABLE outage (>obStaleMs) clears them and resets
// the baseline so dead/idle proxies read 0 and the recovery poll re-primes without a huge-dt dip.
// Bounded by a short timeout so it can't stall the sampling loop.
func (s *Server) sampleOutbounds(ctx context.Context) {
	if s.outbound == nil || s.clash == nil {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conns, err := s.clash.Connections(cctx)
	now := time.Now().UnixMilli()
	o := s.outbound
	o.mu.Lock()
	defer o.mu.Unlock()
	if err != nil {
		// Durable outage: clear rates (stop phantom throughput) and reset the baseline so the next
		// successful poll is treated as a fresh first sample (no rate computed against an outage-spanning
		// dt). A brief blip (<= obStaleMs) is tolerated — rates + baseline are left intact.
		if o.prevT != 0 && now-o.prevT > obStaleMs {
			o.rates = map[string]float64{}
			o.prev = map[string]int64{}
			o.prevT = 0
		}
		return
	}
	first := o.prevT == 0
	dt := float64(now-o.prevT) / 1000
	cur := make(map[string]int64, len(conns.Connections))
	tagBytes := map[string]int64{}
	live := map[string]int{}
	for _, c := range conns.Connections {
		total := c.Upload + c.Download
		cur[c.ID] = total
		listID := listIDFromRulePayload(c.RulePayload)
		if listID != "" {
			live[listID]++
			// A connection is counted once, on the poll that first sees it. Counting every poll
			// would report a single long-lived download as hundreds of connections.
			if _, seen := o.prev[c.ID]; !seen {
				o.listConns[listID]++
			}
		}
		if first {
			continue
		}
		delta := total - o.prev[c.ID] // 0 for an id we haven't seen (prev absent → 0)
		if delta < 0 {                // id reused or a counter reset → count the current total
			delta = total
		}
		for _, tag := range c.Chains {
			tagBytes[tag] += delta
		}
		if listID != "" {
			o.listBytes[listID] += delta
		}
	}
	// Live is a snapshot, so it is replaced rather than accumulated; the cumulative counters above
	// are the ones that persist.
	o.listLive = live
	if !first && dt > 0 {
		rates := make(map[string]float64, len(tagBytes))
		for tag, b := range tagBytes {
			rates[tag] = float64(b) / dt
		}
		o.rates = rates // absent tag = idle this interval; the client fills 0 for its known proxy exits
	}
	o.prev = cur
	o.prevT = now
}

// handleTrafficOutbounds returns the current per-outbound-tag rate map (bytes/s, up+down). The client
// looks up each proxy exit's rate by the endpoint id (which is its sing-box outbound tag). RAM-only.
func (s *Server) handleTrafficOutbounds(w http.ResponseWriter, r *http.Request) {
	if s.config().Demo {
		writeJSON(w, http.StatusOK, demoOutboundRates(time.Now())) // proxy-exit rates without a Clash core
		return
	}
	out := map[string]float64{}
	if s.outbound != nil {
		s.outbound.mu.Lock()
		for k, v := range s.outbound.rates {
			out[k] = v
		}
		s.outbound.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSystemRecent returns the in-RAM per-interface counter history (last n snapshots, oldest-first).
// The client seeds its per-interface graph series from this on load. RAM-only; no flash access.
func (s *Server) handleSystemRecent(w http.ResponseWriter, r *http.Request) {
	n := 0
	if v := r.URL.Query().Get("n"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	if s.config().Demo {
		writeJSON(w, http.StatusOK, demoIfaceHistory(time.Now())) // synthesize a full seed window off-router
		return
	}
	if s.ifaceHist == nil {
		writeJSON(w, http.StatusOK, []ifaceSnap{})
		return
	}
	writeJSON(w, http.StatusOK, s.ifaceHist.recentN(n))
}
