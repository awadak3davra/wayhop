package server

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/failover"
	"wayhop/internal/model"
	"wayhop/internal/netdiag"
	"wayhop/internal/speedtest"
)

// throughput.go owns heavy download measurements. Latency probes stay on their existing fast cycle;
// these runs are explicit or opt-in scheduled, globally serialized, byte-budgeted and bound to the
// candidate's kernel device. Only the small result records enter the existing hourly list journal.

const (
	throughputFreshWindow   = 24 * time.Hour
	throughputScheduleEvery = 6 * time.Hour
	throughputJitterMax     = 30 * time.Minute
	throughputQueueCap      = 32
	throughputTunnelCap     = 128
	throughputSourceCap     = 8
	defaultWANIdleKbps      = int64(1024)
	defaultMonthlyBudgetMB  = int64(3072)
	// defaultCoreMaxBytes and defaultCoreMinFreeMB bound a measurement through the proxy core
	// (throughputcore.go): both ends and the TLS run on the router there, so the volume is held at a
	// quarter of the bound one and nothing starts on a router short of memory.
	defaultCoreMaxBytes  = int64(25_000_000)
	defaultCoreMinFreeMB = int64(48)
	// throughputTelegramID is the media source's id: its samples are kept apart from the others'.
	throughputTelegramID = "telegram"
	// throughputScheduledBytes is the smallest scheduled sample. When the month cannot afford it at
	// the configured spacing, the spacing grows; a larger sample is taken only when it can.
	throughputScheduledBytes = int64(25_000_000)
	// throughputReserveDiv: one part in three of the month's budget is never spent by the schedule,
	// so the "Measure speed" button keeps working.
	throughputReserveDiv = 3
	throughputMonthHours = 31 * 24
	// throughputPreferFor is how long a tunnel keeps asking first the source that answered when
	// others did not.
	throughputPreferFor = 7 * 24 * time.Hour
	// throughputClockSlack is how far behind the newest timestamp ever seen the clock may be and
	// still be believed (a time-zone change, an NTP correction).
	throughputClockSlack = 48 * time.Hour
)

// throughputClockFloor: a clock before this is a router that has not synchronized yet (no RTC: 1970,
// or the firmware's build date). The month's counter is neither rolled nor is the schedule run on it.
var throughputClockFloor = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// throughputTunnelState keeps the latest attempt and the latest usable success separately: a failed
// retry must not erase the speed that election may still use until it is 24 hours old.
type throughputTunnelState struct {
	Latest    speedtest.DownloadResult `json:"latest"`
	At        int64                    `json:"at"`
	Success   speedtest.DownloadResult `json:"success"`
	SuccessAt int64                    `json:"success_at,omitempty"`
	// Media is the last usable sample taken from the media source (a Telegram CDN video). It never
	// overwrites Success nor is overwritten by it: figures from different sources are not comparable.
	Media   speedtest.DownloadResult `json:"media"`
	MediaAt int64                    `json:"media_at,omitempty"`
	Error   string                   `json:"error,omitempty"`
	// Reason classifies a failed last attempt for the panel: rate_limited | unreachable | restricted |
	// too_short | budget | no_interface | unsupported | cancelled | core_down | needs_apply. Empty
	// after a success.
	Reason string `json:"reason,omitempty"`
	// Restricted: the exit is up but does not carry every test server (it forwards some destinations
	// only). Not a failure: with Success it says the figure came from a source the exit does carry.
	Restricted bool `json:"restricted,omitempty"`
	// Prefer is the source that answered when earlier ones gave no response; it is asked first until
	// PreferAt + throughputPreferFor, or until it fails itself.
	Prefer   string `json:"prefer,omitempty"`
	PreferAt int64  `json:"prefer_at,omitempty"`
	// Sources is the tunnel x source table of Diagnostics: what each source last gave this tunnel.
	Sources map[string]throughputSourceCell `json:"sources,omitempty"`
	Running bool                            `json:"running,omitempty"`
	// LiveMbps and LiveBytes follow a running measurement; they are never persisted.
	LiveMbps  float64 `json:"live_mbps,omitempty"`
	LiveBytes int64   `json:"live_bytes,omitempty"`
	Next      int64   `json:"next_ms,omitempty"`
}

// throughputSourceCell is one tunnel's last outcome at one source.
type throughputSourceCell struct {
	At     int64   `json:"at"`
	Mbps   float64 `json:"mbps,omitempty"`
	Status int     `json:"status,omitempty"`
	Error  string  `json:"error,omitempty"`
}

const (
	reasonRateLimited = "rate_limited"
	reasonUnreachable = "unreachable"
	reasonRestricted  = "restricted"
	reasonTooShort    = "too_short"
	reasonBudget      = "budget"
	reasonNoInterface = "no_interface"
	reasonUnsupported = "unsupported"
	reasonCancelled   = "cancelled"
	reasonLowMemory   = "low_memory"
)

var (
	errThroughputBudget      = errors.New("the monthly throughput-measurement budget is exhausted")
	errThroughputQueueFull   = errors.New("the throughput measurement queue is full")
	errThroughputNoInterface = errors.New("tunnel has no kernel interface")
	errThroughputUnsupported = errors.New("interface-bound downloads are unsupported on this platform")
)

// throughputJournalState is the optional part of fastest-journal.json. Nothing is written per run:
// revision changes mark the shared writebehind writer, whose minimum interval remains one hour.
// A power cut therefore loses what was counted since the last write (under an hour) and the "last"
// stamps; that is accepted in exchange for no flash write per measurement. Only body bytes are
// counted: TLS, TCP and tunnel overhead and the unread tail of an aborted response are not.
type throughputJournalState struct {
	Tunnels map[string]throughputTunnelState `json:"tunnels,omitempty"`
	Last    map[string]int64                 `json:"last,omitempty"`
	Month   string                           `json:"month,omitempty"`
	Used    int64                            `json:"used_bytes,omitempty"`
}

type throughputRequest struct {
	Scope string `json:"scope"`
	ID    string `json:"id"`
	// Media asks a single tunnel for the media sources (a Telegram CDN object first), as a media
	// list's own measurement does.
	Media bool `json:"media,omitempty"`
	// Scheduled marks the schedule's own run; a request from the API never carries it.
	Scheduled bool `json:"scheduled,omitempty"`
}

type throughputState struct {
	mu      sync.Mutex
	tunnels map[string]throughputTunnelState
	last    map[string]int64
	next    map[string]int64
	month   string
	used    int64
	// unplaced is the part of used downloaded while the clock was not plausible, in RAM only: the
	// month it belongs to is known when the clock is.
	unplaced int64
	rev      uint64
	queue    []throughputRequest
	wake     chan struct{}
	// active is the request being executed, from the moment it leaves the queue to the end of its
	// scope: "busy" and the duplicate check read it, so there is no gap between two tunnels of a group.
	active *throughputRequest
	cancel context.CancelFunc
	// clockHigh is the newest timestamp ever recorded (unix ms), restored from the journal.
	clockHigh int64
}

func (s *Server) throughputNow() time.Time {
	if s.throughputNowOf != nil {
		return s.throughputNowOf()
	}
	return time.Now()
}

func throughputSettings(c config.Config) config.Throughput {
	t := c.Throughput
	if t.ScheduleHours <= 0 {
		t.ScheduleHours = 6
	}
	if t.ScheduleHours < 6 { // a hand-edited invalid config must not defeat the six-hour floor
		t.ScheduleHours = 6
	}
	if t.MaxBytes <= 0 {
		t.MaxBytes = speedtest.DefaultDownloadBytes
	}
	if t.MaxDurationSec <= 0 {
		t.MaxDurationSec = int(speedtest.DefaultDownloadTimeout / time.Second)
	}
	if t.MonthlyBudgetMB <= 0 {
		t.MonthlyBudgetMB = defaultMonthlyBudgetMB
	}
	if t.CoreMaxBytes <= 0 {
		t.CoreMaxBytes = defaultCoreMaxBytes
	}
	if t.CoreMinFreeMB <= 0 {
		t.CoreMinFreeMB = defaultCoreMinFreeMB
	}
	if t.WANIdleKbps <= 0 {
		t.WANIdleKbps = defaultWANIdleKbps
	}
	if t.TelegramChannel == "" {
		t.TelegramChannel = "https://t.me/s/telegram"
	}
	return t
}

func throughputBudgetBytes(t config.Throughput) int64 {
	return throughputSettings(config.Config{Throughput: t}).MonthlyBudgetMB * 1024 * 1024
}

func throughputMonth(at time.Time) string { return at.Format("2006-01") }

// clockPlausibleLocked reports whether at can be the real time: not before the floor, and not far
// behind the newest timestamp this router ever recorded. Caller holds mu.
func (t *throughputState) clockPlausibleLocked(at time.Time) bool {
	return !at.Before(throughputClockFloor) && at.UnixMilli() >= t.clockHigh-throughputClockSlack.Milliseconds()
}

// normalizeMonthLocked rolls the RAM/persisted counter at the month boundary, forward only and only
// on a plausible clock: a router that boots without RTC shows 1970 until NTP answers, and a counter
// zeroed on every such step would hand out a fresh budget on every reboot. Caller holds mu.
func (t *throughputState) normalizeMonthLocked(at time.Time) {
	if !t.clockPlausibleLocked(at) {
		return
	}
	if ms := at.UnixMilli(); ms > t.clockHigh {
		t.clockHigh = ms
	}
	month := throughputMonth(at)
	// What was downloaded while the clock could not be trusted (before NTP) belongs to the month the
	// router is in now, so it is carried into it, never zeroed with the month it could not be put in:
	// otherwise the first measurement of a router that boots in 1970 would be erased from the budget
	// when the clock arrives. A counter that has no month yet is all of that kind.
	switch {
	case t.month == "":
		t.month = month
		t.rev++
	case month > t.month:
		t.month, t.used = month, t.unplaced
		t.rev++
	}
	t.unplaced = 0
}

// chargeLocked adds a run's bytes to the month's use. Caller holds mu.
func (t *throughputState) chargeLocked(at time.Time, bytes int64) {
	t.normalizeMonthLocked(at)
	t.used += bytes
	if !t.clockPlausibleLocked(at) {
		t.unplaced += bytes
	}
}

func (t *throughputState) usageLocked(at time.Time, budget int64) (month string, used, remaining int64) {
	t.normalizeMonthLocked(at)
	remaining = budget - t.used
	if remaining < 0 {
		remaining = 0
	}
	return t.month, t.used, remaining
}

// throughputPlan is what the schedule may spend: derived from the budget, never the other way round.
type throughputPlan struct {
	Tunnels       int   `json:"tunnels"`
	RunBytes      int64 `json:"run_bytes"`
	IntervalHours int   `json:"interval_hours"`
	MonthlyBytes  int64 `json:"monthly_bytes"`
	ReserveBytes  int64 `json:"reserve_bytes"`
}

// throughputSchedulePlan fits the schedule into the month: the budget less the manual reserve, over
// every run of every scheduled tunnel. A run is never smaller than throughputScheduledBytes (less is
// not a sample) nor larger than the configured volume; when the month cannot afford the smallest run
// at the configured spacing, the spacing grows instead.
func throughputSchedulePlan(t config.Throughput, tunnels int) throughputPlan {
	t = throughputSettings(config.Config{Throughput: t})
	budget := throughputBudgetBytes(t)
	plan := throughputPlan{Tunnels: tunnels, IntervalHours: t.ScheduleHours, ReserveBytes: budget / throughputReserveDiv}
	if tunnels <= 0 {
		return plan
	}
	available := budget - plan.ReserveBytes
	floor := throughputScheduledBytes
	if floor > t.MaxBytes {
		floor = t.MaxBytes
	}
	runs := int64(tunnels) * int64((throughputMonthHours+t.ScheduleHours-1)/t.ScheduleHours)
	plan.RunBytes = available / runs
	if plan.RunBytes > t.MaxBytes {
		plan.RunBytes = t.MaxBytes
	}
	if plan.RunBytes < floor {
		plan.RunBytes = floor
		rounds := available / (floor * int64(tunnels)) // whole rounds of every tunnel the month affords
		if rounds < 1 {
			rounds = 1
		}
		plan.IntervalHours = int((throughputMonthHours + rounds - 1) / rounds)
		runs = int64(tunnels) * rounds
	}
	plan.MonthlyBytes = plan.RunBytes * runs
	return plan
}

// throughputScheduledIDs is who the schedule measures: the candidates of the lists and groups that
// elect by throughput (or mixed). A tunnel nothing chooses by speed costs the month nothing.
func throughputScheduledIDs(p *model.Profile) map[string]bool {
	out := map[string]bool{}
	if p == nil {
		return out
	}
	for _, rl := range p.RoutingLists {
		if !model.FastestActive(p, rl) || rl.Fastest.ElectionFor(rl) == model.ElectionLatency {
			continue
		}
		for _, id := range model.ListCandidates(p, rl) {
			out[id] = true
		}
	}
	for _, g := range p.Groups {
		if g.Type != model.GroupURLTest || g.Election() == model.ElectionLatency {
			continue
		}
		for _, id := range model.ListCandidates(p, model.RoutingList{Candidates: g.Members}) {
			out[id] = true
		}
	}
	return out
}

// throughputSourceID is a short stable display/key value, never an interface or endpoint name.
func throughputSourceID(raw string, n int) string {
	u, err := url.Parse(raw)
	if err == nil {
		host := strings.ToLower(u.Hostname())
		switch host {
		case "speed.cloudflare.com":
			return "cloudflare"
		case "proof.ovh.net":
			return "ovh"
		case "fsn1-speed.hetzner.com":
			return "hetzner"
		case "dl.google.com":
			return "google"
		case "t.me":
			return throughputTelegramID
		}
		if host != "" {
			return host
		}
	}
	return fmt.Sprintf("source-%d", n+1)
}

// throughputSources resolves configured sources on every run, so Settings changes need no restart.
// Media lists try a real Telegram CDN object first; the channel page itself is never the payload.
func throughputSources(t config.Throughput, media bool) []speedtest.DownloadSource {
	t = throughputSettings(config.Config{Throughput: t})
	var raw []speedtest.DownloadSource
	if t.CustomURL != "" {
		raw = append(raw, speedtest.DownloadSource{ID: "custom", URL: t.CustomURL})
	}
	if media {
		raw = append(raw, speedtest.DownloadSource{ID: throughputTelegramID, URL: t.TelegramChannel, Telegram: true})
	}
	if len(t.Sources) == 0 {
		raw = append(raw, speedtest.DefaultDownloadSources()...)
	} else {
		for i, u := range t.Sources {
			if u = strings.TrimSpace(u); u != "" {
				raw = append(raw, speedtest.DownloadSource{ID: throughputSourceID(u, i), URL: u})
			}
		}
	}
	out := make([]speedtest.DownloadSource, 0, len(raw))
	seen := map[string]bool{}
	for _, src := range raw {
		if seen[src.ID] || len(out) == throughputSourceCap {
			continue
		}
		seen[src.ID] = true
		out = append(out, src)
	}
	return out
}

// preferSource moves the source id to the front of the generic sources (a Telegram source stays
// first: its sample is a different one). Unknown id: the order is left alone.
func preferSource(sources []speedtest.DownloadSource, id string) []speedtest.DownloadSource {
	at := -1
	for i, src := range sources {
		if src.ID == id && !src.Telegram {
			at = i
		}
	}
	if at < 0 {
		return sources
	}
	out := make([]speedtest.DownloadSource, 0, len(sources))
	for _, src := range sources {
		if src.Telegram {
			out = append(out, src)
		}
	}
	out = append(out, sources[at])
	for i, src := range sources {
		if i != at && !src.Telegram {
			out = append(out, src)
		}
	}
	return out
}

// throughputScope expands a button's tunnel/group/list to concrete endpoints. List groups are
// expanded by the model's existing recursive walker. No direct/WAN leg is ever added.
func throughputScope(p *model.Profile, req throughputRequest) ([]model.Endpoint, bool, error) {
	if p == nil {
		return nil, false, errors.New("no profile is loaded")
	}
	var ids []string
	media := false
	switch req.Scope {
	case "tunnel":
		e := p.EndpointByID(req.ID)
		if e == nil {
			return nil, false, fmt.Errorf("tunnel %q does not exist", req.ID)
		}
		if !e.Enabled {
			return nil, false, fmt.Errorf("tunnel %q is disabled", req.ID)
		}
		ids = []string{req.ID}
		media = req.Media
	case "group":
		g := p.GroupByID(req.ID)
		if g == nil {
			return nil, false, fmt.Errorf("group %q does not exist", req.ID)
		}
		ids = model.ListCandidates(p, model.RoutingList{Candidates: g.Members})
	case "list":
		rl := findList(p, req.ID)
		if rl == nil {
			return nil, false, fmt.Errorf("routing list %q does not exist", req.ID)
		}
		ids = model.ListCandidates(p, *rl)
		media = model.MediaList(*rl)
	default:
		return nil, false, errors.New("scope must be tunnel, group or list")
	}
	out := make([]model.Endpoint, 0, len(ids))
	for _, id := range ids {
		if e := p.EndpointByID(id); e != nil && e.Enabled {
			out = append(out, *e)
		}
	}
	if len(out) == 0 {
		return nil, media, errors.New("the scope has no enabled tunnels")
	}
	return out, media, nil
}

// queueThroughput accepts work without holding an HTTP request open for a 20-second (or group-sized)
// transfer. A duplicate scope is already queued/running work, not another download.
func (s *Server) queueThroughput(req throughputRequest) (bool, error) {
	p := s.store.Profile()
	_, _, err := throughputScope(&p, req)
	if err != nil {
		return false, err
	}
	t := throughputSettings(s.config())
	now := s.throughputNow()
	s.throughput.mu.Lock()
	defer s.throughput.mu.Unlock()
	_, _, remaining := s.throughput.usageLocked(now, throughputBudgetBytes(t))
	if remaining <= 0 {
		return false, errThroughputBudget
	}
	if s.throughput.active != nil && *s.throughput.active == req {
		return false, nil
	}
	for _, q := range s.throughput.queue {
		if q == req {
			return false, nil
		}
	}
	if len(s.throughput.queue) >= throughputQueueCap {
		return false, errThroughputQueueFull
	}
	s.throughput.queue = append(s.throughput.queue, req)
	if s.throughput.wake == nil {
		s.throughput.wake = make(chan struct{}, 1)
	}
	select {
	case s.throughput.wake <- struct{}{}:
	default:
	}
	return true, nil
}

func (s *Server) popThroughput() (throughputRequest, bool) {
	s.throughput.mu.Lock()
	defer s.throughput.mu.Unlock()
	if len(s.throughput.queue) == 0 {
		return throughputRequest{}, false
	}
	req := s.throughput.queue[0]
	s.throughput.queue = append([]throughputRequest(nil), s.throughput.queue[1:]...)
	s.throughput.active = &req // busy without a gap until runThroughputScope ends it
	return req, true
}

// beginThroughput makes req the active request and returns the context its downloads run under.
func (s *Server) beginThroughput(ctx context.Context, req throughputRequest) (context.Context, func()) {
	run, cancel := context.WithCancel(ctx)
	s.throughput.mu.Lock()
	s.throughput.active, s.throughput.cancel = &req, cancel
	s.throughput.mu.Unlock()
	return run, func() {
		cancel()
		s.throughput.mu.Lock()
		s.throughput.active, s.throughput.cancel = nil, nil
		s.throughput.mu.Unlock()
	}
}

// cancelThroughput stops the running measurement and drops what is queued: the operator's Stop, and
// every Apply (the tunnels a run was started for may be gone, and the run holds the speed slot).
func (s *Server) cancelThroughput() (stopped bool) {
	s.throughput.mu.Lock()
	defer s.throughput.mu.Unlock()
	stopped = s.throughput.cancel != nil || len(s.throughput.queue) > 0
	s.throughput.queue = nil
	if s.throughput.cancel != nil {
		s.throughput.cancel()
	}
	return stopped
}

// throughputLoop drains manual work before considering one scheduled tunnel. StartApply starts it
// once; an empty/disabled schedule performs no network operation at all.
func (s *Server) throughputLoop(ctx context.Context) {
	s.kernelElector() // restore the shared journal before the first status/result change
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		for {
			req, ok := s.popThroughput()
			if !ok {
				break
			}
			s.runThroughputScope(ctx, req)
		}
		s.runScheduledThroughput(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-s.throughputWake():
		}
	}
}

func (s *Server) throughputWake() <-chan struct{} {
	s.throughput.mu.Lock()
	defer s.throughput.mu.Unlock()
	if s.throughput.wake == nil {
		s.throughput.wake = make(chan struct{}, 1)
	}
	return s.throughput.wake
}

func (s *Server) runThroughputScope(ctx context.Context, req throughputRequest) {
	ctx, end := s.beginThroughput(ctx, req)
	defer end()
	p := s.store.Profile()
	endpoints, media, err := throughputScope(&p, req)
	if err != nil {
		return // the profile changed while the request waited
	}
	for i, e := range endpoints {
		if ctx.Err() != nil {
			return
		}
		if i > 0 && !s.throughputStillInScope(req, e.ID) {
			continue
		}
		s.runThroughputTunnel(ctx, e, throughputRun{media: media, core: req.Scope == "tunnel"})
	}
}

// throughputStillInScope re-reads the profile between two tunnels of a scope: a tunnel disabled,
// deleted or taken out of the group or list while the others were measured is not downloaded through.
func (s *Server) throughputStillInScope(req throughputRequest, id string) bool {
	p := s.store.Profile()
	endpoints, _, err := throughputScope(&p, req)
	if err != nil {
		return false
	}
	for _, e := range endpoints {
		if e.ID == id {
			return true
		}
	}
	return false
}

// throughputRun is how one tunnel is measured: with the media sources or not, and, for the
// schedule, with its own smaller volume that stays out of the manual reserve.
type throughputRun struct {
	media bool
	// core allows a connection without a kernel link to be measured through the proxy core's own
	// outbound (throughputcore.go). Only the button on that connection asks for it: such a connection
	// is no candidate of an election, so a group's, a list's or the schedule's run does not spend the
	// month's budget on it.
	core     bool
	maxBytes int64 // 0: the configured volume
	reserve  int64 // bytes of the month's budget this run must leave untouched
}

// lockThroughput shares speedMu with the legacy panel and Telegram speed tests, but remains
// cancellable while another component owns it.
func (s *Server) lockThroughput(ctx context.Context) bool {
	for {
		if s.speedMu.TryLock() {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// runThroughputTunnel measures one tunnel: budget first, then the shared speed slot, then a download
// bound to the tunnel's own kernel link. There is no unbound fallback: a tunnel without a link is
// reported as such, never measured by the router's default route (which is the WAN, and for a
// kill-switched list exactly the path its traffic must not take).
func (s *Server) runThroughputTunnel(ctx context.Context, e model.Endpoint, how throughputRun) {
	cfg := throughputSettings(s.config())
	now := s.throughputNow()
	media := how.media
	s.throughput.mu.Lock()
	_, _, remaining := s.throughput.usageLocked(now, throughputBudgetBytes(cfg))
	remaining -= how.reserve
	prefer := ""
	if st := s.throughput.tunnels[e.ID]; st.Prefer != "" && now.UnixMilli()-st.PreferAt < throughputPreferFor.Milliseconds() {
		prefer = st.Prefer
	}
	if s.throughput.last == nil {
		s.throughput.last = map[string]int64{}
	}
	if remaining > 0 {
		s.throughput.last[e.ID] = now.UnixMilli()
		delete(s.throughput.next, e.ID)
		s.throughput.markRunningLocked(e.ID, true)
		s.throughput.rev++
	}
	s.throughput.mu.Unlock()
	if remaining <= 0 {
		s.finishThroughput(e.ID, speedtest.DownloadResult{}, errThroughputBudget, now)
		return
	}
	s.persistFastestJournal(s.kernelElector())

	if !s.lockThroughput(ctx) {
		s.finishThroughput(e.ID, speedtest.DownloadResult{}, context.Canceled, now)
		return
	}
	defer s.speedMu.Unlock()

	// Another measurement may have finished while this one waited for the shared speed slot.
	_, _, remaining = s.throughputUsage(s.throughputNow(), cfg)
	remaining -= how.reserve
	if remaining <= 0 {
		s.finishThroughput(e.ID, speedtest.DownloadResult{}, errThroughputBudget, s.throughputNow())
		return
	}
	native, known := s.currentNativeInterfaceBindings()
	link := tunnelLink(e, native, known)
	run := s.throughputRunOf
	if run == nil {
		run = s.runBoundThroughput
		if s.config().Demo {
			run = demoThroughputRun
		}
	}
	viaCore := false
	if link == "" && !s.config().Demo {
		// No device to bind to. On OpenWrt a connection the core carries is measured through the
		// core's own outbound; anywhere else, and for anything else, it is reported as it was.
		exit, err := coreExit{}, errThroughputNoInterface
		if how.core {
			exit, err = s.throughputCoreExit(e)
		}
		if err == nil {
			err = s.throughputCoreMemoryGate(cfg)
		}
		if err != nil {
			s.finishThroughput(e.ID, speedtest.DownloadResult{}, err, s.throughputNow())
			return
		}
		viaCore = true
		run = func(ctx context.Context, _ model.Endpoint, _ string, opts speedtest.DownloadOptions) (speedtest.DownloadResult, error) {
			if s.throughputCoreRunOf != nil {
				return s.throughputCoreRunOf(ctx, exit, opts)
			}
			return s.runCoreThroughput(ctx, exit, opts)
		}
	}
	maxBytes := cfg.MaxBytes
	if how.maxBytes > 0 && how.maxBytes < maxBytes {
		maxBytes = how.maxBytes
	}
	if viaCore && cfg.CoreMaxBytes > 0 && cfg.CoreMaxBytes < maxBytes {
		maxBytes = cfg.CoreMaxBytes
	}
	if remaining < maxBytes {
		maxBytes = remaining
	}
	id := e.ID
	opts := speedtest.DownloadOptions{
		MaxBytes: maxBytes, MaxTotalBytes: remaining,
		MaxDuration: time.Duration(cfg.MaxDurationSec) * time.Second,
		Warmup:      speedtest.DefaultWarmup, Sources: preferSource(throughputSources(cfg, media), prefer),
		// The tunnels carry IPv4 only (see over4), whatever family their own server address has.
		Network: "tcp4",
		Progress: func(bytes int64, mbps float64) {
			s.throughput.mu.Lock()
			if st, ok := s.throughput.tunnels[id]; ok && st.Running {
				st.LiveBytes, st.LiveMbps = bytes, mbps
				s.throughput.tunnels[id] = st
			}
			s.throughput.mu.Unlock()
		},
	}
	res, err := run(ctx, e, link, opts)
	s.finishThroughput(e.ID, res, err, s.throughputNow())
}

// demoThroughputRun stands in for the download in demo mode: no network, a figure that depends only
// on the tunnel's id, and one tunnel in four refused the way a shared VPN exit is.
func demoThroughputRun(ctx context.Context, e model.Endpoint, _ string, opts speedtest.DownloadOptions) (speedtest.DownloadResult, error) {
	var h uint32
	for _, c := range []byte(e.ID) {
		h = h*31 + uint32(c)
	}
	mbps := 8 + float64(h%900)/10
	for i := 1; i <= 3; i++ {
		select {
		case <-ctx.Done():
			return speedtest.DownloadResult{}, ctx.Err()
		case <-time.After(700 * time.Millisecond):
		}
		if opts.Progress != nil {
			opts.Progress(int64(mbps*1e6/8*0.7)*int64(i), mbps*(0.8+0.07*float64(i)))
		}
	}
	src := opts.Sources[0]
	if h%4 == 3 {
		res := speedtest.DownloadResult{Attempts: []speedtest.SourceAttempt{{Source: src.ID, URL: src.URL, Status: http.StatusTooManyRequests, Error: "unexpected HTTP status 429"}}}
		return res, errors.New("download failed: unexpected HTTP status 429")
	}
	bytes := int64(mbps * 1e6 / 8 * 2.1)
	return speedtest.DownloadResult{Source: src.ID, URL: src.URL, Bytes: bytes, TotalBytes: bytes, ElapsedMs: 2100, TTFBMs: 180,
		SteadyMbps: mbps, MaxPauseMs: 40, Attempts: []speedtest.SourceAttempt{{Source: src.ID, URL: src.URL, Status: http.StatusOK, Bytes: bytes, TTFBMs: 180}}}, nil
}

// runBoundThroughput refuses an unbound fallback. Public-IP resolution and pinning happen inside the
// bound dial, including every source and the Telegram page, so a custom URL cannot become a LAN probe.
func (s *Server) runBoundThroughput(ctx context.Context, _ model.Endpoint, link string, opts speedtest.DownloadOptions) (speedtest.DownloadResult, error) {
	if link == "" {
		return speedtest.DownloadResult{}, errThroughputNoInterface
	}
	dial := speedBindDial(link)
	if dial == nil {
		return speedtest.DownloadResult{}, errThroughputUnsupported
	}
	opts.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		resolved, err := netdiag.ResolveProbeTarget(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("resolve public download source: %w", err)
		}
		return dial(ctx, network, resolved)
	}
	return speedtest.MeasureDownload(ctx, opts)
}

func (t *throughputState) markRunningLocked(id string, running bool) {
	if t.tunnels == nil {
		t.tunnels = map[string]throughputTunnelState{}
	}
	st := t.tunnels[id]
	st.Running = running
	t.tunnels[id] = st
}

// throughputReason classifies a failed attempt by what the sources answered. alive is the health
// monitor's verdict on the tunnel: an exit that is up while not one test server gave any response is
// restricted (it forwards some destinations only), not dead.
func throughputReason(res speedtest.DownloadResult, err error, alive bool) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, errThroughputBudget):
		return reasonBudget
	case errors.Is(err, errThroughputNoInterface):
		return reasonNoInterface
	case errors.Is(err, errThroughputUnsupported):
		return reasonUnsupported
	case errors.Is(err, errThroughputCoreDown):
		return reasonCoreDown
	case errors.Is(err, errThroughputNeedApply):
		return reasonNeedApply
	case errors.Is(err, errThroughputLowMemory):
		return reasonLowMemory
	case errors.Is(err, context.Canceled):
		return reasonCancelled
	}
	silent := len(res.Attempts) > 0
	for _, a := range res.Attempts {
		if a.Status == http.StatusTooManyRequests || a.Status == http.StatusForbidden {
			return reasonRateLimited
		}
		if a.Status != 0 {
			silent = false
		}
	}
	if silent && alive {
		return reasonRestricted
	}
	return reasonUnreachable
}

// throughputSilentBefore reports whether a source asked before the accepted one gave no response at
// all (no status): the mark of an exit that does not carry that destination.
func throughputSilentBefore(res speedtest.DownloadResult) bool {
	for _, a := range res.Attempts {
		if a.Source == res.Source {
			return false
		}
		if a.Status == 0 && a.Error != "" {
			return true
		}
	}
	return false
}

// tunnelAlive is the health monitor's current verdict; false when there is no monitor to ask.
func (s *Server) tunnelAlive(id string) bool {
	if s.throughputAliveOf != nil {
		return s.throughputAliveOf(id)
	}
	if s.monitor == nil {
		return false
	}
	for _, m := range s.monitor.MemberHealth([]string{id}) {
		if m.ID == id {
			return m.Alive
		}
	}
	return false
}

// trimThroughputResult bounds what one result keeps in RAM and in the journal: a Telegram CDN URL is
// several hundred bytes of signature nobody reads.
func trimThroughputResult(res speedtest.DownloadResult, keepAttempts bool) speedtest.DownloadResult {
	const maxURL = 120
	short := func(u string) string {
		if i := strings.IndexByte(u, '?'); i >= 0 {
			u = u[:i]
		}
		if len(u) > maxURL {
			u = u[:maxURL]
		}
		return u
	}
	res.URL = short(res.URL)
	if !keepAttempts {
		res.Attempts = nil
		return res
	}
	if len(res.Attempts) > throughputSourceCap+1 {
		res.Attempts = res.Attempts[:throughputSourceCap+1]
	}
	attempts := make([]speedtest.SourceAttempt, len(res.Attempts))
	for i, a := range res.Attempts {
		a.URL = short(a.URL)
		attempts[i] = a
	}
	res.Attempts = attempts
	return res
}

func (s *Server) finishThroughput(id string, res speedtest.DownloadResult, err error, at time.Time) {
	res = trimThroughputResult(res, true)
	// A sample too short to judge by (a budget tail, a transfer inside the warm-up) is shown as the
	// last attempt; it never becomes the tunnel's speed and never reaches an election.
	ok := err == nil && res.Bytes > 0 && res.SteadyMbps > 0 && !res.TooShort
	alive := false
	if err != nil {
		alive = s.tunnelAlive(id)
	}
	s.throughput.mu.Lock()
	s.throughput.chargeLocked(at, res.TotalBytes)
	st := s.throughput.tunnels[id]
	st.Latest, st.At, st.Running, st.LiveMbps, st.LiveBytes = res, at.UnixMilli(), false, 0, 0
	switch {
	case ok:
		st.Error, st.Reason = "", ""
		kept := trimThroughputResult(res, false)
		if res.Source == throughputTelegramID {
			st.Media, st.MediaAt = kept, at.UnixMilli()
		} else {
			st.Success, st.SuccessAt = kept, at.UnixMilli()
			// The generic sources say whether the exit carries everything; the media source's own
			// refusal says nothing about that.
			st.Restricted = throughputSilentBefore(res)
			if st.Restricted {
				st.Prefer, st.PreferAt = res.Source, at.UnixMilli()
			} else if st.Prefer != res.Source {
				st.Prefer, st.PreferAt = "", 0
			}
		}
	case err != nil:
		st.Error, st.Reason = shortThroughputError(err), throughputReason(res, err, alive)
		switch st.Reason {
		case reasonRestricted:
			st.Restricted = true
		case reasonUnreachable, reasonRateLimited:
			st.Restricted, st.Prefer, st.PreferAt = false, "", 0 // the preferred source failed too
		}
	case res.TooShort && res.Bytes > 0:
		st.Error, st.Reason = "the sample is too short to judge the tunnel by", reasonTooShort
	default:
		st.Error, st.Reason = "no usable download sample", reasonUnreachable
	}
	cells := make(map[string]throughputSourceCell, len(st.Sources)+len(res.Attempts))
	for k, v := range st.Sources {
		cells[k] = v
	}
	for _, a := range res.Attempts {
		cell := throughputSourceCell{At: at.UnixMilli(), Status: a.Status, Error: a.Error}
		if ok && a.Source == res.Source && a.Error == "" {
			cell.Mbps = res.SteadyMbps
		}
		cells[a.Source] = cell
	}
	for len(cells) > throughputSourceCap+2 {
		oldest := ""
		for k, v := range cells {
			if oldest == "" || v.At < cells[oldest].At || (v.At == cells[oldest].At && k < oldest) {
				oldest = k
			}
		}
		delete(cells, oldest)
	}
	if len(cells) > 0 {
		st.Sources = cells
	}
	if s.throughput.tunnels == nil {
		s.throughput.tunnels = map[string]throughputTunnelState{}
	}
	s.throughput.tunnels[id] = st
	s.throughput.pruneLocked()
	s.throughput.rev++
	s.throughput.mu.Unlock()
	s.persistFastestJournal(s.kernelElector())
}

func shortThroughputError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

// pruneLocked bounds result RAM when old endpoints outlive profile edits. Caller holds mu.
func (t *throughputState) pruneLocked() {
	for len(t.tunnels) > throughputTunnelCap {
		oldest, at := "", int64(0)
		for id, st := range t.tunnels {
			if oldest == "" || st.At < at {
				oldest, at = id, st.At
			}
		}
		delete(t.tunnels, oldest)
		delete(t.last, oldest)
		delete(t.next, oldest)
	}
}

func (s *Server) throughputRevision() uint64 {
	s.throughput.mu.Lock()
	defer s.throughput.mu.Unlock()
	return s.throughput.rev
}

func (s *Server) throughputJournalSnapshot() throughputJournalState {
	s.throughput.mu.Lock()
	defer s.throughput.mu.Unlock()
	out := throughputJournalState{Month: s.throughput.month, Used: s.throughput.used,
		Tunnels: make(map[string]throughputTunnelState, len(s.throughput.tunnels)), Last: make(map[string]int64, len(s.throughput.last))}
	for id, st := range s.throughput.tunnels {
		st.Running, st.Next, st.LiveMbps, st.LiveBytes = false, 0, 0, 0
		out.Tunnels[id] = st
	}
	for id, at := range s.throughput.last {
		out.Last[id] = at
	}
	return out
}

// restoreThroughputJournal is called once before the loops start. Restored state is clean and capped;
// Running/Next are runtime-only and never resurrected from flash.
func (s *Server) restoreThroughputJournal(in throughputJournalState) {
	s.throughput.mu.Lock()
	defer s.throughput.mu.Unlock()
	s.throughput.tunnels = map[string]throughputTunnelState{}
	ids := make([]string, 0, len(in.Tunnels))
	for id := range in.Tunnels {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) > throughputTunnelCap {
		ids = ids[:throughputTunnelCap]
	}
	for _, id := range ids {
		st := in.Tunnels[id]
		st.Running, st.Next, st.LiveMbps, st.LiveBytes = false, 0, 0, 0
		s.throughput.tunnels[id] = st
	}
	s.throughput.last = map[string]int64{}
	for _, id := range ids {
		if at := in.Last[id]; at > 0 {
			s.throughput.last[id] = at
		}
	}
	s.throughput.month, s.throughput.used = in.Month, in.Used
	// The newest stamp the previous run left bounds how far back the clock may be believed.
	s.throughput.clockHigh = 0
	for _, st := range s.throughput.tunnels {
		if st.At > s.throughput.clockHigh {
			s.throughput.clockHigh = st.At
		}
	}
	for _, at := range s.throughput.last {
		if at > s.throughput.clockHigh {
			s.throughput.clockHigh = at
		}
	}
	s.throughput.rev = 0
}

// Sample classes: figures from the media source and from the generic test servers are never compared
// with each other.
const (
	sampleClassGeneric = "generic"
	sampleClassMedia   = "media"
)

func throughputSampleOf(res speedtest.DownloadResult, at int64) (failover.ThroughputSample, bool) {
	if at <= 0 || res.Bytes <= 0 || res.SteadyMbps <= 0 || res.TooShort {
		return failover.ThroughputSample{}, false
	}
	kbps := int64(res.SteadyMbps * 1000)
	if kbps < 1 {
		kbps = 1
	}
	return failover.ThroughputSample{ThroughputKbps: kbps, ThroughputAt: at}, true
}

// throughputSamplesFor returns one class of samples for a unit's candidates, and which class. A media
// list is elected by the media-source samples when at least two of its candidates have a fresh one
// (so there is something to compare); otherwise, and for every other unit, by the generic samples. A
// tunnel that the media source refused has no media sample and is simply unsampled in that class: its
// generic figure is never set against the others' media figures. The pure policy enforces the 24-hour
// cutoff again; old samples are returned so the API can show their age.
func (s *Server) throughputSamplesFor(candidates []string, media bool) (map[string]failover.ThroughputSample, string) {
	now := s.throughputNow().UnixMilli()
	s.throughput.mu.Lock()
	defer s.throughput.mu.Unlock()
	generic, mediaSamples := map[string]failover.ThroughputSample{}, map[string]failover.ThroughputSample{}
	freshMedia := 0
	for _, id := range candidates {
		st, ok := s.throughput.tunnels[id]
		if !ok {
			continue
		}
		if sample, ok := throughputSampleOf(st.Success, st.SuccessAt); ok {
			generic[id] = sample
		}
		if sample, ok := throughputSampleOf(st.Media, st.MediaAt); ok {
			mediaSamples[id] = sample
			if age := now - sample.ThroughputAt; age >= 0 && age <= throughputFreshWindow.Milliseconds() {
				freshMedia++
			}
		}
	}
	if media && freshMedia >= 2 {
		return mediaSamples, sampleClassMedia
	}
	return generic, sampleClassGeneric
}

// unitIsMedia reports whether a unit belongs to a media list of the profile.
func unitIsMedia(p *model.Profile, u failover.TableUnit) bool {
	if u.List == nil || p == nil {
		return false
	}
	rl := findList(p, u.List.List)
	return rl != nil && model.MediaList(*rl)
}

func (s *Server) attachThroughput(units []failover.TableUnit) {
	var p *model.Profile
	if s.store != nil {
		cur := s.store.Profile()
		p = &cur
	}
	for i := range units {
		if units[i].Policy != failover.PolicyThroughput && units[i].Policy != failover.PolicyMixed {
			continue
		}
		// The class is chosen among the tunnels the election may choose, as the panel's summary does
		// (electionInForce): an excluded tunnel's media sample would make a media list compare media
		// figures that only one eligible tunnel had, falling back to delay while two eligible tunnels
		// had comparable generic ones.
		eligible := units[i].Candidates
		if lp := units[i].List; lp != nil && len(lp.Excluded) > 0 {
			eligible = make([]string, 0, len(units[i].Candidates))
			for _, c := range units[i].Candidates {
				if !containsString(lp.Excluded, c) {
					eligible = append(eligible, c)
				}
			}
		}
		units[i].Throughput, _ = s.throughputSamplesFor(eligible, unitIsMedia(p, units[i]))
	}
}

// wanAverageKbps computes RX+TX over consecutive counter snapshots. Incomplete, stale, missing-WAN or
// reset-counter history is UNKNOWN, never silently idle; scheduled downloads run only on known idle.
func wanAverageKbps(snaps []ifaceSnap, wan string, now time.Time) (float64, bool) {
	if wan == "" || len(snaps) < 2 {
		return 0, false
	}
	start := now.Add(-5 * time.Minute).UnixMilli()
	first := -1
	for i := range snaps {
		if snaps[i].T >= start {
			first = i
			break
		}
	}
	if first < 1 { // need a baseline at/before the window, not just its first inside sample
		return 0, false
	}
	first--
	last := len(snaps) - 1
	if snaps[last].T < start || now.UnixMilli()-snaps[last].T > 15_000 || snaps[last].T-snaps[first].T < 290_000 {
		return 0, false
	}
	var bytes int64
	for i := first + 1; i <= last; i++ {
		before, aok := ifaceByName(snaps[i-1].Ifaces, wan)
		after, bok := ifaceByName(snaps[i].Ifaces, wan)
		if !aok || !bok || after.RxBytes < before.RxBytes || after.TxBytes < before.TxBytes || snaps[i].T <= snaps[i-1].T {
			return 0, false
		}
		bytes += after.RxBytes - before.RxBytes + after.TxBytes - before.TxBytes
	}
	seconds := float64(snaps[last].T-snaps[first].T) / 1000
	return float64(bytes) * 8 / seconds / 1000, true
}

func ifaceByName(ifs []Iface, name string) (Iface, bool) {
	for _, iface := range ifs {
		if iface.Name == name {
			return iface, true
		}
	}
	return Iface{}, false
}

func (s *Server) throughputWANIdle(at time.Time, threshold int64) (average float64, known, idle bool) {
	if s.ifaceHist == nil {
		return 0, false, false
	}
	wanOf := s.throughputWANOf
	if wanOf == nil {
		wanOf = probeWANInterface
	}
	wan, err := wanOf()
	if err != nil {
		return 0, false, false
	}
	average, known = wanAverageKbps(s.ifaceHist.recentN(0), wan, at)
	return average, known, known && average < float64(threshold)
}

func (s *Server) throughputJitter(max time.Duration) time.Duration {
	if s.throughputJitterOf != nil {
		return s.throughputJitterOf(max)
	}
	if max <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(max) + 1))
}

// runScheduledThroughput measures at most one due endpoint per pass. The six-hour interval is the
// minimum; nonnegative jitter can only postpone it. Busy/unknown WAN and budget exhaustion leave the
// due item in place for a later pass rather than spending traffic.
func (s *Server) runScheduledThroughput(ctx context.Context) {
	cfg := s.config()
	if !cfg.Throughput.Scheduled || cfg.Demo || s.store == nil || s.applyInProgress.Load() || s.routingIsOff() || ctx.Err() != nil {
		return
	}
	t := throughputSettings(cfg)
	now := s.throughputNow()
	_, _, remaining := s.throughputUsage(now, t)
	if remaining <= 0 {
		return
	}
	// The spacing and the month are wall-clock arithmetic: not on a clock that is not the real one.
	s.throughput.mu.Lock()
	clockOK := s.throughput.clockPlausibleLocked(now)
	s.throughput.mu.Unlock()
	if !clockOK {
		return
	}
	_, known, idle := s.throughputWANIdle(now, t.WANIdleKbps)
	if !known || !idle {
		return
	}
	p := s.store.Profile()
	native, knownNative := s.currentNativeInterfaceBindings()
	wanted := throughputScheduledIDs(&p)
	var ids []string
	links := map[string]string{}
	for _, e := range p.Endpoints {
		if e.Enabled && wanted[e.ID] && tunnelLink(e, native, knownNative) != "" {
			ids = append(ids, e.ID)
			links[e.ID] = tunnelLink(e, native, knownNative)
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return
	}
	s.throughput.mu.Lock()
	if s.throughput.last == nil {
		s.throughput.last = map[string]int64{}
	}
	if s.throughput.next == nil {
		s.throughput.next = map[string]int64{}
	}
	plan := throughputSchedulePlan(t, len(ids))
	if remaining-plan.ReserveBytes < plan.RunBytes { // the rest of the month belongs to the button
		s.throughput.mu.Unlock()
		return
	}
	interval := time.Duration(plan.IntervalHours) * time.Hour
	if interval < throughputScheduleEvery {
		interval = throughputScheduleEvery
	}
	pick := ""
	for _, id := range ids {
		due, ok := s.throughput.next[id]
		if !ok {
			base := now
			if last := s.throughput.last[id]; last > 0 {
				base = time.UnixMilli(last)
			}
			due = base.Add(interval + s.throughputJitter(throughputJitterMax)).UnixMilli()
			s.throughput.next[id] = due
		}
		if now.UnixMilli() >= due {
			pick = id
			break
		}
	}
	for id := range s.throughput.next {
		if links[id] == "" {
			delete(s.throughput.next, id)
		}
	}
	s.throughput.mu.Unlock()
	if pick == "" {
		return
	}
	run, end := s.beginThroughput(ctx, throughputRequest{Scope: "tunnel", ID: pick, Scheduled: true})
	defer end()
	s.runThroughputTunnel(run, *p.EndpointByID(pick), throughputRun{maxBytes: plan.RunBytes, reserve: plan.ReserveBytes})
}

// throughputPlanNow is the schedule's plan for the tunnels it would measure now.
func (s *Server) throughputPlanNow(cfg config.Throughput) throughputPlan {
	n := 0
	if s.store != nil {
		p := s.store.Profile()
		native, known := s.currentNativeInterfaceBindings()
		wanted := throughputScheduledIDs(&p)
		for _, e := range p.Endpoints {
			if e.Enabled && wanted[e.ID] && (s.config().Demo || tunnelLink(e, native, known) != "") {
				n++
			}
		}
	}
	return throughputSchedulePlan(cfg, n)
}

func (s *Server) throughputUsage(at time.Time, cfg config.Throughput) (string, int64, int64) {
	s.throughput.mu.Lock()
	defer s.throughput.mu.Unlock()
	return s.throughput.usageLocked(at, throughputBudgetBytes(cfg))
}

// ---- API ----

// handleThroughput is GET /api/throughput: every tunnel's last measurement, what is queued or running,
// the month's traffic use, and whether a scheduled run would be allowed now.
func (s *Server) handleThroughput(w http.ResponseWriter, _ *http.Request) {
	conf := s.config()
	cfg := throughputSettings(conf)
	now := s.throughputNow()
	month, used, remaining := s.throughputUsage(now, cfg)
	average, known, idle := s.throughputWANIdle(now, cfg.WANIdleKbps)
	// measurable names the tunnels a download can be bound to: the ones with a kernel link. A
	// tunnel that lives only inside the proxy core has none, and the panel says so instead of
	// offering a button that would fail.
	// On OpenWrt a connection the core carries is measured through the core's own outbound
	// (throughputcore.go): via says which way each one goes, unmeasurable why one cannot be measured
	// (no_interface | core_down | needs_apply).
	measurable := []string{}
	via, unmeasurable := map[string]string{}, map[string]string{}
	if s.store != nil {
		p := s.store.Profile()
		native, knownNative := s.currentNativeInterfaceBindings()
		for _, e := range p.Endpoints {
			if !e.Enabled {
				continue
			}
			if how, why := s.throughputPathOf(e, native, knownNative); how != "" {
				measurable = append(measurable, e.ID)
				via[e.ID] = how
			} else {
				unmeasurable[e.ID] = why
			}
		}
	}
	s.throughput.mu.Lock()
	tunnels := make(map[string]throughputTunnelState, len(s.throughput.tunnels))
	running := ""
	for id, st := range s.throughput.tunnels {
		st.Next = s.throughput.next[id]
		if st.Running {
			running = id
		}
		tunnels[id] = st
	}
	queued := append([]throughputRequest{}, s.throughput.queue...)
	var active *throughputRequest
	if s.throughput.active != nil {
		cp := *s.throughput.active
		active = &cp
	}
	clockOK := s.throughput.clockPlausibleLocked(now)
	s.throughput.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"tunnels": tunnels, "queued": queued, "running": running, "active": active,
		"busy":       active != nil || running != "" || len(queued) > 0,
		"measurable": measurable, "via": via, "unmeasurable": unmeasurable, "scheduled": cfg.Scheduled, "now": now.UnixMilli(), "clock_ok": clockOK,
		"max_bytes": cfg.MaxBytes, "plan": s.throughputPlanNow(cfg),
		"usage":   map[string]any{"month": month, "used_bytes": used, "budget_bytes": throughputBudgetBytes(cfg), "remaining_bytes": remaining},
		"wan":     map[string]any{"average_kbps": average, "known": known, "idle": idle, "threshold_kbps": cfg.WANIdleKbps},
		"sources": throughputSources(cfg, false), "media_sources": throughputSources(cfg, true),
		"fresh_hours": int(throughputFreshWindow / time.Hour), "supported": conf.Demo || netdiag.CanBindToDevice(),
	})
}

func (s *Server) handleThroughputMeasure(w http.ResponseWriter, r *http.Request) {
	var req throughputRequest
	if err := decodeJSONBody(r.Body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, `want {"scope":"tunnel|group|list","id":"..."}`)
		return
	}
	req.Scheduled = false
	queued, err := s.queueThroughput(req)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errThroughputBudget) || errors.Is(err, errThroughputQueueFull) {
			status = http.StatusTooManyRequests
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"queued": queued, "already_queued": !queued, "scope": req.Scope, "id": req.ID})
}

// handleThroughputCancel is DELETE /api/throughput/measure: stop the running measurement and drop the
// queue. What was downloaded so far stays counted; the tunnel's last good figure stays.
func (s *Server) handleThroughputCancel(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"stopped": s.cancelThroughput()})
}

// electionPolicy maps a list's or group's election mode onto the decision policy.
func electionPolicy(m model.ElectionMode) failover.Policy {
	switch m {
	case model.ElectionThroughput:
		return failover.PolicyThroughput
	case model.ElectionMixed:
		return failover.PolicyMixed
	}
	return failover.PolicyLatency
}
