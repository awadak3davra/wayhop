package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/failover"
	"wayhop/internal/model"
	"wayhop/internal/speedtest"
)

// throughputProfile is three kernel tunnels (each names its link the way an adopted tunnel does), one
// tunnel the proxy core alone carries, a group over two of them, and a Telegram list over all three.
func throughputProfile() model.Profile {
	tunnel := func(id, link string) model.Endpoint {
		return model.Endpoint{ID: id, Name: id, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
			Server: "198.51.100.10", Port: 443, Params: map[string]any{"uuid": "u", "interface": link}, Enabled: true}
	}
	return model.Profile{
		Endpoints: []model.Endpoint{
			tunnel("nl", "tun-a"), tunnel("ca", "tun-b"), tunnel("de", "tun-c"),
			{ID: "core", Name: "core", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "198.51.100.11",
				Port: 443, Params: map[string]any{"uuid": "u"}, Enabled: true},
		},
		Groups: []model.Group{{ID: "g", Name: "G", Type: model.GroupURLTest, Members: []string{"nl", "ca"}}},
		RoutingLists: []model.RoutingList{{ID: "telegram", Name: "Telegram", Enabled: true, Outbound: "nl", Manual: []string{"149.154.160.0/20"},
			Candidates: []string{"nl", "ca", "de"}, Fastest: &model.FastestPolicy{Enabled: true}}},
	}
}

type throughputRunSeen struct {
	ids   []string
	links []string
	opts  []speedtest.DownloadOptions
}

// throughputServer is a non-demo server over throughputProfile whose download is fake: it records what
// it was asked and answers with answer (nil: 40 Mbit/s over 10 MB).
func throughputServer(t *testing.T, answer func(id string) (speedtest.DownloadResult, error)) (*Server, *throughputRunSeen) {
	t.Helper()
	s := servererrorpaths_server(t)
	s.cfg.Demo = false
	if err := s.store.Replace(throughputProfile()); err != nil {
		t.Fatal(err)
	}
	seen := &throughputRunSeen{}
	s.throughputRunOf = func(_ context.Context, e model.Endpoint, link string, opts speedtest.DownloadOptions) (speedtest.DownloadResult, error) {
		seen.ids, seen.links, seen.opts = append(seen.ids, e.ID), append(seen.links, link), append(seen.opts, opts)
		if answer != nil {
			return answer(e.ID)
		}
		return speedtest.DownloadResult{Source: "ovh", Bytes: 10_000_000, TotalBytes: 10_000_000, SteadyMbps: 40,
			Attempts: []speedtest.SourceAttempt{{Source: "ovh", Status: 200, Bytes: 10_000_000}}}, nil
	}
	return s, seen
}

func TestThroughputScopeExpandsToTunnelsOnly(t *testing.T) {
	p := throughputProfile()
	ids := func(req throughputRequest) ([]string, bool) {
		t.Helper()
		es, media, err := throughputScope(&p, req)
		if err != nil {
			t.Fatalf("%+v: %v", req, err)
		}
		var out []string
		for _, e := range es {
			out = append(out, e.ID)
		}
		return out, media
	}
	if got, media := ids(throughputRequest{Scope: "tunnel", ID: "ca"}); len(got) != 1 || got[0] != "ca" || media {
		t.Errorf("tunnel scope = %v media=%v", got, media)
	}
	if got, _ := ids(throughputRequest{Scope: "group", ID: "g"}); len(got) != 2 || got[0] != "nl" || got[1] != "ca" {
		t.Errorf("group scope = %v", got)
	}
	// A media list: its three tunnels, the media sources, and no direct leg (ListCandidates never
	// yields a built-in, so a kill-switched list is not measured by the WAN either).
	got, media := ids(throughputRequest{Scope: "list", ID: "telegram"})
	if len(got) != 3 || !media {
		t.Errorf("list scope = %v media=%v", got, media)
	}
	for _, id := range got {
		if id == model.OutboundDirect {
			t.Fatal("a list's measurement included the WAN")
		}
	}
	for _, bad := range []throughputRequest{{Scope: "tunnel", ID: "nope"}, {Scope: "wan", ID: "x"}, {Scope: "list", ID: "nope"}} {
		if _, _, err := throughputScope(&p, bad); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
}

func TestThroughputSourcesRotationOrder(t *testing.T) {
	names := func(srcs []speedtest.DownloadSource) (out []string) {
		for _, s := range srcs {
			out = append(out, s.ID)
		}
		return
	}
	plain := names(throughputSources(config.Throughput{}, false))
	if len(plain) != 4 || plain[0] != "cloudflare" || plain[1] != "ovh" || plain[3] != "google" {
		t.Errorf("default sources = %v", plain)
	}
	media := throughputSources(config.Throughput{CustomURL: "https://files.example/100.bin"}, true)
	if got := names(media); len(got) != 6 || got[0] != "custom" || got[1] != "telegram" || !media[1].Telegram {
		t.Errorf("media sources = %v", got)
	}
	own := names(throughputSources(config.Throughput{Sources: []string{"https://proof.ovh.net/files/100Mb.dat", "https://mirror.example/f"}}, false))
	if len(own) != 2 || own[0] != "ovh" || own[1] != "mirror.example" {
		t.Errorf("configured sources = %v", own)
	}
}

// A measurement is bound to the tunnel's own link, capped by what the month has left, and a tunnel
// without a link is reported, never measured by the default route.
func TestThroughputRunBindsBudgetsAndRecords(t *testing.T) {
	s, seen := throughputServer(t, nil)
	s.cfg.Throughput.MonthlyBudgetMB = 15 // 15 728 640 bytes: one full run, then a capped one
	s.cfg.Throughput.MaxBytes = 10_000_000
	ctx := context.Background()

	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "ca"})
	if len(seen.links) != 1 || seen.links[0] != "tun-b" {
		t.Fatalf("bound to %v, want tun-b", seen.links)
	}
	o := seen.opts[0]
	if o.MaxBytes != 10_000_000 || o.MaxTotalBytes != 15*1024*1024 || o.Network != "tcp4" || o.MaxDuration != 20*time.Second {
		t.Fatalf("first run options: %+v", o)
	}
	st := s.throughput.tunnels["ca"]
	if st.Running || st.SuccessAt == 0 || st.Success.SteadyMbps != 40 || st.Reason != "" || st.Sources["ovh"].Mbps != 40 {
		t.Fatalf("recorded state: %+v", st)
	}
	if _, used, remaining := s.throughputUsage(s.throughputNow(), throughputSettings(s.config())); used != 10_000_000 || remaining != 15*1024*1024-10_000_000 {
		t.Fatalf("usage used=%d remaining=%d", used, remaining)
	}

	// The second run may spend only what is left.
	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "nl"})
	if o := seen.opts[1]; o.MaxBytes != 15*1024*1024-10_000_000 || o.MaxTotalBytes != o.MaxBytes {
		t.Fatalf("second run was not capped by the budget: %+v", o)
	}

	// The month is spent: nothing is downloaded, the button's request is refused, the reason is kept.
	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "de"})
	if len(seen.ids) != 2 {
		t.Fatalf("a run started past the budget: %v", seen.ids)
	}
	if st := s.throughput.tunnels["de"]; st.Reason != reasonBudget || st.Running {
		t.Fatalf("budget refusal state: %+v", st)
	}
	if _, err := s.queueThroughput(throughputRequest{Scope: "tunnel", ID: "de"}); !errors.Is(err, errThroughputBudget) {
		t.Fatalf("queue past the budget: %v", err)
	}
	w := servererrorpaths_post(s.handleThroughputMeasure, "/api/throughput/measure", `{"scope":"tunnel","id":"de"}`)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("measure past the budget: %d %s", w.Code, w.Body.String())
	}

	// A new month starts from zero.
	s.throughputNowOf = func() time.Time { return time.Now().AddDate(0, 1, 1) }
	if _, used, _ := s.throughputUsage(s.throughputNow(), throughputSettings(s.config())); used != 0 {
		t.Fatalf("the month did not roll: used=%d", used)
	}
}

func TestThroughputNeverFallsBackToTheDefaultRoute(t *testing.T) {
	s, seen := throughputServer(t, nil)
	s.runThroughputScope(context.Background(), throughputRequest{Scope: "tunnel", ID: "core"})
	if len(seen.ids) != 0 {
		t.Fatal("a tunnel without a kernel link was measured")
	}
	if st := s.throughput.tunnels["core"]; st.Reason != reasonNoInterface || st.SuccessAt != 0 {
		t.Fatalf("state: %+v", st)
	}

	// The production run: no link, or a platform that cannot bind, is an error and no dial is made.
	dialed := false
	prev := speedBindDial
	speedBindDial = func(string) func(context.Context, string, string) (net.Conn, error) { return nil }
	t.Cleanup(func() { speedBindDial = prev })
	opts := speedtest.DownloadOptions{DialContext: func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("unbound dial")
	}}
	if _, err := s.runBoundThroughput(context.Background(), model.Endpoint{}, "", opts); !errors.Is(err, errThroughputNoInterface) {
		t.Fatalf("no link: %v", err)
	}
	if _, err := s.runBoundThroughput(context.Background(), model.Endpoint{}, "tun-a", opts); !errors.Is(err, errThroughputUnsupported) {
		t.Fatalf("no bind support: %v", err)
	}
	if dialed {
		t.Fatal("an unbound dial was made")
	}
}

// A failed retry keeps the last good figure for election and names why it failed.
func TestThroughputFailureKeepsLastSuccessAndClassifies(t *testing.T) {
	fail := false
	s, _ := throughputServer(t, func(string) (speedtest.DownloadResult, error) {
		if !fail {
			return speedtest.DownloadResult{Source: "cloudflare", Bytes: 5_000_000, TotalBytes: 5_000_000, SteadyMbps: 19.6}, nil
		}
		return speedtest.DownloadResult{TotalBytes: 300, Attempts: []speedtest.SourceAttempt{
			{Source: "cloudflare", Status: 429, Error: "unexpected HTTP status 429"},
			{Source: "ovh", Error: "source did not answer in time", URL: "https://proof.ovh.net/files/100Mb.dat?sig=" + string(make([]byte, 600))},
		}}, errors.New("download failed: source did not answer in time")
	})
	ctx := context.Background()
	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "nl"})
	fail = true
	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "nl"})
	st := s.throughput.tunnels["nl"]
	if st.Reason != reasonRateLimited || st.Error == "" || st.Success.SteadyMbps != 19.6 || st.SuccessAt == 0 {
		t.Fatalf("state after a failed retry: %+v", st)
	}
	if st.Sources["cloudflare"].Status != 429 || st.Sources["ovh"].Error == "" {
		t.Fatalf("source table: %+v", st.Sources)
	}
	if len(st.Latest.Attempts[1].URL) > 120 {
		t.Fatalf("a signed URL was kept whole: %d bytes", len(st.Latest.Attempts[1].URL))
	}
	if s.throughput.used != 5_000_300 {
		t.Fatalf("failed attempts were not charged to the budget: %d", s.throughput.used)
	}
	samples, _ := s.throughputSamplesFor([]string{"nl"}, false)
	if got := samples["nl"]; got.ThroughputKbps != 19600 || got.ThroughputAt != st.SuccessAt {
		t.Fatalf("election sample: %+v", got)
	}

	// Samples reach only the units that elect by them.
	units := []failover.TableUnit{
		{Policy: failover.PolicyLatency, Candidates: []string{"nl"}},
		{Policy: failover.PolicyMixed, Candidates: []string{"nl", "ca"}},
	}
	s.attachThroughput(units)
	if units[0].Throughput != nil || units[1].Throughput["nl"].ThroughputKbps != 19600 || len(units[1].Throughput) != 1 {
		t.Fatalf("attached: %+v", units)
	}
}

func throughputSnaps(now time.Time, wan string, bytesPerStep int64) []ifaceSnap {
	var snaps []ifaceSnap
	for i := 0; i <= 80; i++ { // 400 s at the sampler's 5 s
		at := now.Add(-time.Duration(80-i) * 5 * time.Second).UnixMilli()
		snaps = append(snaps, ifaceSnap{T: at, Ifaces: []Iface{{Name: wan, RxBytes: int64(i) * bytesPerStep, TxBytes: 0}}})
	}
	return snaps
}

func TestWANAverageKnownIdleBusyUnknown(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	// 62 500 bytes per 5 s = 100 kbit/s.
	if avg, ok := wanAverageKbps(throughputSnaps(now, "wan0", 62_500), "wan0", now); !ok || avg < 99 || avg > 101 {
		t.Errorf("steady line: %v %v", avg, ok)
	}
	if _, ok := wanAverageKbps(throughputSnaps(now, "wan0", 62_500), "other", now); ok {
		t.Error("a missing WAN was read as idle")
	}
	if _, ok := wanAverageKbps(throughputSnaps(now, "wan0", 62_500)[70:], "wan0", now); ok {
		t.Error("fifty seconds of history was read as a five-minute average")
	}
	if _, ok := wanAverageKbps(throughputSnaps(now.Add(-time.Minute), "wan0", 62_500), "wan0", now); ok {
		t.Error("stale history was read as current")
	}
	reset := throughputSnaps(now, "wan0", 62_500)
	reset[60].Ifaces[0].RxBytes = 0
	if _, ok := wanAverageKbps(reset, "wan0", now); ok {
		t.Error("a counter reset was read as a rate")
	}
}

// The schedule: off by default; on, it waits six hours plus jitter per tunnel, runs only on a known
// idle line and measures one tunnel per pass.
func TestThroughputScheduleIsOptInIdleOnlyAndSixHourly(t *testing.T) {
	s, seen := throughputServer(t, nil)
	now := time.Unix(1_800_000_000, 0)
	s.throughputNowOf = func() time.Time { return now }
	s.throughputWANOf = func() (string, error) { return "wan0", nil }
	s.throughputJitterOf = func(time.Duration) time.Duration { return 10 * time.Minute }
	fill := func(bytesPerStep int64) {
		s.ifaceHist = newIfaceRing(90)
		for _, snap := range throughputSnaps(now, "wan0", bytesPerStep) {
			s.ifaceHist.push(snap)
		}
	}
	ctx := context.Background()
	fill(1000) // 1.6 kbit/s: idle

	if (config.Default().Throughput.Scheduled) || s.config().Throughput.Scheduled {
		t.Fatal("scheduled measurements must be off by default")
	}
	s.runScheduledThroughput(ctx)
	if len(seen.ids) != 0 || len(s.throughput.next) != 0 {
		t.Fatalf("a disabled schedule ran or planned: %v", seen.ids)
	}

	s.cfg.Throughput.Scheduled = true
	s.cfg.Throughput.MonthlyBudgetMB = 16384 // affords three tunnels every six hours (see the plan's own test)
	s.runScheduledThroughput(ctx)            // plans every tunnel six hours and the jitter from now
	if len(seen.ids) != 0 {
		t.Fatalf("the schedule measured at once: %v", seen.ids)
	}
	now = now.Add(6 * time.Hour)
	fill(1000)
	s.runScheduledThroughput(ctx)
	if len(seen.ids) != 0 {
		t.Fatal("the schedule ran before its jitter was over")
	}

	now = now.Add(11 * time.Minute)
	fill(10_000_000) // 16 Mbit/s: the family is using the line
	s.runScheduledThroughput(ctx)
	if len(seen.ids) != 0 {
		t.Fatal("the schedule ran on a busy line")
	}
	s.ifaceHist = newIfaceRing(90) // no history: unknown is not idle
	s.runScheduledThroughput(ctx)
	if len(seen.ids) != 0 {
		t.Fatal("the schedule ran with the line's load unknown")
	}

	fill(1000)
	s.runScheduledThroughput(ctx)
	if len(seen.ids) != 1 || seen.ids[0] != "ca" {
		t.Fatalf("one pass measured %v, want one tunnel", seen.ids)
	}
	if seen.links[0] != "tun-b" {
		t.Fatalf("scheduled run bound to %q", seen.links[0])
	}
	s.runScheduledThroughput(ctx)
	s.runScheduledThroughput(ctx)
	s.runScheduledThroughput(ctx) // "core" has no link and is never due
	if len(seen.ids) != 3 {
		t.Fatalf("the due tunnels were not each measured once: %v", seen.ids)
	}

	// The same tunnel is not measured again inside six hours.
	now = now.Add(5*time.Hour + 59*time.Minute)
	fill(1000)
	s.runScheduledThroughput(ctx)
	if len(seen.ids) != 3 {
		t.Fatalf("a tunnel was measured twice within six hours: %v", seen.ids)
	}
	now = now.Add(12 * time.Minute)
	fill(1000)
	s.runScheduledThroughput(ctx)
	if len(seen.ids) != 4 {
		t.Fatalf("the next round did not start: %v", seen.ids)
	}

	// A spent month stops the schedule.
	s.throughput.mu.Lock()
	s.throughput.used = throughputBudgetBytes(s.config().Throughput)
	s.throughput.mu.Unlock()
	now = now.Add(7 * time.Hour)
	fill(1000)
	s.runScheduledThroughput(ctx)
	if len(seen.ids) != 4 {
		t.Fatal("the schedule spent past the monthly budget")
	}
}

func TestThroughputScheduleFloorIsSixHours(t *testing.T) {
	if got := throughputSettings(config.Config{Throughput: config.Throughput{ScheduleHours: 1}}).ScheduleHours; got != 6 {
		t.Fatalf("a one-hour schedule was accepted as %d h", got)
	}
	c := config.Default()
	c.Throughput.ScheduleHours = 2
	if err := c.Validate(); err == nil {
		t.Fatal("config accepted a two-hour schedule")
	}
	if d := config.Default().Throughput; d.MonthlyBudgetMB != 3072 || d.MaxBytes != 100_000_000 || d.MaxDurationSec != 20 {
		t.Fatalf("defaults: %+v", d)
	}
}

// What goes to flash with the hourly journal is the results and the month's use, never the running
// state, and it comes back capped.
func TestThroughputJournalRoundTrip(t *testing.T) {
	s, _ := throughputServer(t, nil)
	s.runThroughputScope(context.Background(), throughputRequest{Scope: "group", ID: "g"})
	s.throughput.mu.Lock()
	s.throughput.markRunningLocked("nl", true)
	s.throughput.mu.Unlock()
	snap := s.throughputJournalSnapshot()
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 4096 {
		t.Fatalf("two tunnels cost %d bytes of journal", len(raw))
	}
	var back throughputJournalState
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < throughputTunnelCap+20; i++ {
		back.Tunnels["x"+string(rune('a'+i%26))+string(rune('a'+i/26))] = throughputTunnelState{At: 1}
	}
	s2, _ := throughputServer(t, nil)
	s2.restoreThroughputJournal(back)
	if n := len(s2.throughput.tunnels); n != throughputTunnelCap {
		t.Fatalf("restored %d tunnels, cap %d", n, throughputTunnelCap)
	}
	st := s2.throughput.tunnels["nl"]
	if st.Running || st.Success.SteadyMbps != 40 || s2.throughput.used != 20_000_000 || s2.throughput.month == "" {
		t.Fatalf("restored state: %+v used=%d", st, s2.throughput.used)
	}
}

func TestThroughputAPI(t *testing.T) {
	s, seen := throughputServer(t, nil)
	if w := servererrorpaths_post(s.handleThroughputMeasure, "/api/throughput/measure", `{"scope":"wan","id":"x"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad scope: %d", w.Code)
	}
	w := servererrorpaths_post(s.handleThroughputMeasure, "/api/throughput/measure", `{"scope":"list","id":"telegram"}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("measure: %d %s", w.Code, w.Body.String())
	}
	// The same request again is the same work, not a second download.
	w = servererrorpaths_post(s.handleThroughputMeasure, "/api/throughput/measure", `{"scope":"list","id":"telegram"}`)
	var again struct {
		Queued bool `json:"queued"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &again); err != nil || again.Queued {
		t.Fatalf("duplicate request: %s", w.Body.String())
	}
	req, ok := s.popThroughput()
	if !ok {
		t.Fatal("nothing was queued")
	}
	s.runThroughputScope(context.Background(), req)
	if len(seen.ids) != 3 || seen.opts[0].Sources[0].ID != "telegram" || !seen.opts[0].Sources[0].Telegram {
		t.Fatalf("list run: %v sources %+v", seen.ids, seen.opts[0].Sources)
	}

	rec := httptest.NewRecorder()
	s.handleThroughput(rec, httptest.NewRequest(http.MethodGet, "/api/throughput", nil))
	var got struct {
		Tunnels    map[string]throughputTunnelState `json:"tunnels"`
		Measurable []string                         `json:"measurable"`
		Busy       bool                             `json:"busy"`
		Scheduled  bool                             `json:"scheduled"`
		Usage      struct {
			Used   int64 `json:"used_bytes"`
			Budget int64 `json:"budget_bytes"`
		} `json:"usage"`
		FreshHours int `json:"fresh_hours"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Tunnels) != 3 || got.Tunnels["de"].Success.SteadyMbps != 40 || got.Busy || got.Scheduled {
		t.Fatalf("state: %s", rec.Body.String())
	}
	if len(got.Measurable) != 3 || got.Usage.Used != 30_000_000 || got.Usage.Budget != 3072*1024*1024 || got.FreshHours != 24 {
		t.Fatalf("state: %s", rec.Body.String())
	}
}

func TestElectionPolicyOfGroupsAndLists(t *testing.T) {
	if electionPolicy("") != failover.PolicyLatency || electionPolicy(model.ElectionThroughput) != failover.PolicyThroughput || electionPolicy(model.ElectionMixed) != failover.PolicyMixed {
		t.Fatal("election mode mapping")
	}
	p := throughputProfile()
	rl := p.RoutingLists[0]
	if got := (model.FastestPolicy{}).ElectionFor(rl); got != model.ElectionMixed {
		t.Fatalf("a Telegram list elects by %q, want mixed", got)
	}
	if got := (model.FastestPolicy{Mode: model.ElectionLatency}).ElectionFor(rl); got != model.ElectionLatency {
		t.Fatalf("the operator's choice lost to the default: %q", got)
	}
	if got := (model.FastestPolicy{}).ElectionFor(model.RoutingList{ID: "work", Name: "Work"}); got != model.ElectionLatency {
		t.Fatalf("an ordinary list elects by %q", got)
	}
}
