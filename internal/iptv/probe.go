package iptv

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Probe health constants. The hysteresis mirrors the health monitor's F1 (fast-out / slow-in): a
// live channel needs failThreshold consecutive failures to drop (debounces a transient blip), and a
// channel that has previously failed needs aliveThreshold consecutive successes to come back. A
// never-probed channel commits its first outcome immediately (Unknown→state), so a freshly built
// list reflects reachability after ONE pass rather than two.
const (
	aliveThreshold = 2
	failThreshold  = 2
	defaultProbeUA = "VLC/3.0.20 LibVLC/3.0.20" // a player UA so servers that gate on it still answer
)

// ProbeConfig tunes health probing for a small router: bounded parallelism, a short per-probe
// deadline, a tiny bounded read, and incremental rotation so a large list is spread over passes.
type ProbeConfig struct {
	Concurrency int           // parallel probes (default 8)
	Timeout     time.Duration // per-probe deadline (default 6s)
	BatchSize   int           // channels checked per Probe call, 0 = all (incremental rotation)
	MaxRead     int64         // bytes read to classify the response (default 64 KiB)
}

func (c ProbeConfig) concurrency() int {
	if c.Concurrency > 0 {
		return c.Concurrency
	}
	return 8
}

func (c ProbeConfig) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 6 * time.Second
}

func (c ProbeConfig) maxRead() int64 {
	if c.MaxRead > 0 {
		return c.MaxRead
	}
	return 64 << 10
}

// Prober probes channel health incrementally. It holds a rotation cursor so successive Probe calls
// cover the whole list over several passes rather than hammering every channel each tick — bounded,
// steady load. It is safe to reuse across passes but not to call concurrently on the same instance.
type Prober struct {
	cfg ProbeConfig
	cur int // rotation cursor into the channel slice
}

// NewProber returns a Prober with the given (defaulted) config.
func NewProber(cfg ProbeConfig) *Prober { return &Prober{cfg: cfg} }

// Probe checks a rotating BatchSize-sized window of chs, updates each probed channel's
// Live/Status/LastGood/LastFail with hysteresis, and returns the number probed. `now` is the caller's
// timestamp (unix seconds) so the pure package stays clock-free and tests are deterministic. Probes
// run concurrency-bounded; each sends the channel's UA/Referrer, does a short bounded read, and
// classifies alive / geo-blocked (403) / dead. chs is mutated in place. A nil client probes nothing.
func (p *Prober) Probe(ctx context.Context, client *http.Client, chs []Channel, now int64) int {
	if client == nil || len(chs) == 0 {
		return 0
	}
	batch := p.cfg.BatchSize
	if batch <= 0 || batch > len(chs) {
		batch = len(chs)
	}
	// The rotating window [cur, cur+batch) mod len — indices are unique within a pass because
	// batch <= len, so the concurrent goroutines write disjoint chs elements (no data race).
	idx := make([]int, batch)
	for i := 0; i < batch; i++ {
		idx[i] = (p.cur + i) % len(chs)
	}
	p.cur = (p.cur + batch) % len(chs)

	oks := make([]bool, batch)
	geos := make([]bool, batch)
	sem := make(chan struct{}, p.cfg.concurrency())
	var wg sync.WaitGroup
	for k, ci := range idx {
		wg.Add(1)
		go func(k, ci int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			pctx, cancel := context.WithTimeout(ctx, p.cfg.timeout())
			defer cancel()
			oks[k], geos[k] = probeOne(pctx, client, chs[ci], p.cfg.maxRead())
		}(k, ci)
	}
	wg.Wait()
	// Apply outcomes serially (single writer) after the concurrent reads complete.
	for k, ci := range idx {
		apply(&chs[ci], oks[k], geos[k], now)
	}
	return batch
}

// apply folds one probe outcome into a channel's health with the F1 hysteresis.
func apply(c *Channel, ok, geo bool, now int64) {
	if ok {
		c.ConsecOK++
		c.ConsecFail = 0
		// Come up on the first success if never failed (Unknown→Alive), else require aliveThreshold.
		if !c.Live && (c.LastFail == 0 || c.ConsecOK >= aliveThreshold) {
			c.Live = true
		}
		c.LastGood = now
		c.Status = "alive"
		return
	}
	c.ConsecFail++
	c.ConsecOK = 0
	if c.Live && c.ConsecFail >= failThreshold {
		c.Live = false
	}
	c.LastFail = now
	if geo {
		c.Status = "geo"
	} else {
		c.Status = "dead"
	}
}

// probeOne performs a single bounded GET and classifies the result. Returns (ok, geo): ok=true for a
// reachable stream, geo=true when the response is a 403 (region-locked — the stream exists but needs
// the right exit, distinct from dead so the UI/VPN-routing can treat it specially).
func probeOne(ctx context.Context, client *http.Client, c Channel, maxRead int64) (ok, geo bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return false, false
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	} else {
		req.Header.Set("User-Agent", defaultProbeUA)
	}
	if c.Referrer != "" {
		req.Header.Set("Referer", c.Referrer)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, false // timeout / connection refused / DNS — dead
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRead))
	switch {
	case resp.StatusCode == http.StatusForbidden:
		return false, true // 403 — geo-blocked
	case resp.StatusCode >= 200 && resp.StatusCode < 400:
		return classifyBody(resp.Header.Get("Content-Type"), body), false
	default:
		return false, false // 4xx/5xx — dead
	}
}

// classifyBody decides whether a 2xx/3xx response is a real stream. An HLS manifest (#EXTM3U /
// #EXT-X-) or a media/stream content-type is alive; an HTML page served with 200 (a soft error /
// captive page) is dead; anything else (direct TS, unknown content-type) is accepted as alive.
func classifyBody(contentType string, body []byte) bool {
	ct := strings.ToLower(contentType)
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	trimmed = bytes.TrimPrefix(trimmed, []byte{0xEF, 0xBB, 0xBF}) // strip a leading UTF-8 BOM
	if bytes.HasPrefix(trimmed, []byte("#EXTM3U")) || bytes.Contains(body, []byte("#EXT-X-")) {
		return true
	}
	switch {
	case strings.Contains(ct, "mpegurl"), strings.Contains(ct, "mpeg"),
		strings.Contains(ct, "video/"), strings.Contains(ct, "octet-stream"),
		strings.Contains(ct, "dash+xml"):
		return true
	case strings.Contains(ct, "html"), bytes.HasPrefix(trimmed, []byte("<")):
		return false // soft-error HTML page behind a 200
	default:
		return true
	}
}
