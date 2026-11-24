package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/failover"
	"wayhop/internal/model"
	"wayhop/internal/speedtest"
)

func tpResult(source string, mbps float64, bytes int64) speedtest.DownloadResult {
	return speedtest.DownloadResult{Source: source, Bytes: bytes, TotalBytes: bytes, SteadyMbps: mbps,
		Attempts: []speedtest.SourceAttempt{{Source: source, Status: 200, Bytes: bytes}}}
}

// A Telegram sample and a Cloudflare sample are two different figures. Neither replaces
// the other, and a media list is elected by one class only.
func TestThroughputMediaAndGenericSamplesStayApart(t *testing.T) {
	answers := map[string]speedtest.DownloadResult{}
	s, _ := throughputServer(t, func(id string) (speedtest.DownloadResult, error) { return answers[id], nil })
	ctx := context.Background()
	all := []string{"nl", "ca", "de"}

	// Every tunnel has a generic figure.
	answers["nl"], answers["ca"], answers["de"] = tpResult("cloudflare", 60, 9e6), tpResult("cloudflare", 90, 9e6), tpResult("cloudflare", 150, 9e6)
	s.runThroughputScope(ctx, throughputRequest{Scope: "group", ID: "g"})
	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "de"})

	// The list's media run: nl reaches the Telegram CDN, the CDN refuses ca and de, which rotate to
	// Cloudflare.
	answers["nl"] = tpResult(throughputTelegramID, 30, 9e6)
	s.runThroughputScope(ctx, throughputRequest{Scope: "list", ID: "telegram"})
	nl := s.throughput.tunnels["nl"]
	if nl.Media.SteadyMbps != 30 || nl.Success.SteadyMbps != 60 {
		t.Fatalf("the media sample and the generic one were mixed: media %v, generic %v", nl.Media.SteadyMbps, nl.Success.SteadyMbps)
	}
	if de := s.throughput.tunnels["de"]; de.MediaAt != 0 || de.Success.SteadyMbps != 150 {
		t.Fatalf("a Cloudflare figure was filed as a media sample: %+v", de)
	}

	// One media sample is nothing to compare: the list is elected by the generic class.
	samples, class := s.throughputSamplesFor(all, true)
	if class != sampleClassGeneric || len(samples) != 3 || samples["nl"].ThroughputKbps != 60_000 {
		t.Fatalf("one media sample: class %q, samples %+v", class, samples)
	}

	// Two media samples: the media class, and the tunnel the CDN refused is unsampled in it. Its
	// 150 Mbit/s from Cloudflare must not win the Telegram list.
	answers["ca"] = tpResult(throughputTelegramID, 45, 9e6)
	s.runThroughputScope(ctx, throughputRequest{Scope: "list", ID: "telegram"})
	samples, class = s.throughputSamplesFor(all, true)
	if class != sampleClassMedia || len(samples) != 2 || samples["ca"].ThroughputKbps != 45_000 {
		t.Fatalf("two media samples: class %q, samples %+v", class, samples)
	}
	if _, ok := samples["de"]; ok {
		t.Fatal("a generic figure was set against media figures")
	}
	// A unit that is not a media list never sees the media class.
	if _, class = s.throughputSamplesFor(all, false); class != sampleClassGeneric {
		t.Fatalf("an ordinary unit got class %q", class)
	}
	units := []failover.TableUnit{{Policy: failover.PolicyMixed, Candidates: all, List: &failover.ListPolicy{List: "telegram"}}}
	s.attachThroughput(units)
	if len(units[0].Throughput) != 2 || units[0].Throughput["nl"].ThroughputKbps != 30_000 {
		t.Fatalf("the Telegram list's unit got %+v", units[0].Throughput)
	}
}

// A sample too short to judge is shown as the last attempt and goes no further.
func TestThroughputTooShortSampleIsNotASuccess(t *testing.T) {
	short := false
	s, _ := throughputServer(t, func(string) (speedtest.DownloadResult, error) {
		r := tpResult("cloudflare", 80, 9e6)
		if short {
			r = tpResult("cloudflare", 3, 400_000)
			r.TooShort = true
		}
		return r, nil
	})
	ctx := context.Background()
	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "nl"})
	short = true
	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "nl"})
	st := s.throughput.tunnels["nl"]
	if st.Reason != reasonTooShort || st.Success.SteadyMbps != 80 || st.Latest.SteadyMbps != 3 {
		t.Fatalf("state: reason %q, success %v, latest %v", st.Reason, st.Success.SteadyMbps, st.Latest.SteadyMbps)
	}
	if st.Sources["cloudflare"].Mbps != 0 {
		t.Fatalf("the short figure entered the source table: %+v", st.Sources["cloudflare"])
	}
	samples, _ := s.throughputSamplesFor([]string{"nl"}, false)
	if samples["nl"].ThroughputKbps != 80_000 {
		t.Fatalf("election sample: %+v", samples["nl"])
	}
	if s.throughput.used != 9_400_000 {
		t.Fatalf("the short sample's bytes were not charged: %d", s.throughput.used)
	}
}

// An exit that is up but forwards only some destinations is "restricted", not a dead
// tunnel; the source it does carry is asked first next time.
func TestThroughputRestrictedExit(t *testing.T) {
	silent := func(ids ...string) (out []speedtest.SourceAttempt) {
		for _, id := range ids {
			out = append(out, speedtest.SourceAttempt{Source: id, Error: "source did not answer in time"})
		}
		return
	}
	googleWorks := false
	s, seen := throughputServer(t, func(string) (speedtest.DownloadResult, error) {
		if !googleWorks {
			return speedtest.DownloadResult{Attempts: silent("cloudflare", "ovh", "hetzner", "google")}, errors.New("download failed: source did not answer in time")
		}
		r := tpResult("google", 70, 9e6)
		r.Attempts = append(silent("cloudflare", "ovh", "hetzner"), r.Attempts...)
		return r, nil
	})
	alive := true
	s.throughputAliveOf = func(string) bool { return alive }
	ctx := context.Background()
	req := throughputRequest{Scope: "tunnel", ID: "ca"}

	s.runThroughputScope(ctx, req)
	if st := s.throughput.tunnels["ca"]; st.Reason != reasonRestricted || !st.Restricted {
		t.Fatalf("an alive exit with silent test servers: reason %q restricted %v", st.Reason, st.Restricted)
	}
	alive = false
	s.runThroughputScope(ctx, req)
	if st := s.throughput.tunnels["ca"]; st.Reason != reasonUnreachable || st.Restricted {
		t.Fatalf("a dead tunnel: reason %q restricted %v", st.Reason, st.Restricted)
	}

	alive, googleWorks = true, true
	s.runThroughputScope(ctx, req)
	st := s.throughput.tunnels["ca"]
	if st.Reason != "" || !st.Restricted || st.Success.SteadyMbps != 70 || st.Prefer != "google" {
		t.Fatalf("a figure through the one source the exit carries: %+v", st)
	}
	samples, _ := s.throughputSamplesFor([]string{"ca"}, false)
	if samples["ca"].ThroughputKbps != 70_000 {
		t.Fatalf("a restricted exit's figure is a sample like any other: %+v", samples)
	}
	// The next run does not wait three timeouts again; a media run still asks Telegram first.
	s.runThroughputScope(ctx, req)
	if got := seen.opts[len(seen.opts)-1].Sources[0].ID; got != "google" {
		t.Fatalf("the next run asks %q first, want google", got)
	}
	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "ca", Media: true})
	if src := seen.opts[len(seen.opts)-1].Sources; src[0].ID != throughputTelegramID || src[1].ID != "google" {
		t.Fatalf("media run order: %s, %s", src[0].ID, src[1].ID)
	}
	if got := throughputSources(config.Throughput{}, false); got[len(got)-1].ID != "google" || !strings.Contains(got[len(got)-1].URL, "dl.google.com") {
		t.Fatalf("the Google-hosted source is not in the rotation: %+v", got)
	}
}

// The schedule is derived from the budget.
func TestThroughputSchedulePlanFitsTheBudget(t *testing.T) {
	const mb = 1024 * 1024
	for _, tt := range []struct {
		name            string
		cfg             config.Throughput
		tunnels         int
		run             int64
		hours           int
		reserveAtLeast  int64
		monthlyAtMostMB int64
	}{
		{name: "default budget, four tunnels: 25 MB and a longer spacing", tunnels: 4, run: 25_000_000, hours: 36, monthlyAtMostMB: 2048},
		{name: "one tunnel fits six hours", tunnels: 1, run: 25_000_000, hours: 9, monthlyAtMostMB: 2048},
		{name: "a large budget buys the full volume", cfg: config.Throughput{MonthlyBudgetMB: 102400}, tunnels: 2, run: 100_000_000, hours: 6, monthlyAtMostMB: 68267},
		{name: "a twelve-hour schedule", cfg: config.Throughput{ScheduleHours: 12, MonthlyBudgetMB: 8192}, tunnels: 3, run: 30_788_296, hours: 12, monthlyAtMostMB: 5462},
	} {
		t.Run(tt.name, func(t *testing.T) {
			plan := throughputSchedulePlan(tt.cfg, tt.tunnels)
			budget := throughputBudgetBytes(tt.cfg)
			if plan.RunBytes != tt.run || plan.IntervalHours != tt.hours {
				t.Fatalf("plan = %+v, want %d bytes every %d h", plan, tt.run, tt.hours)
			}
			if plan.MonthlyBytes+plan.ReserveBytes > budget || plan.ReserveBytes < budget/3 || plan.MonthlyBytes > tt.monthlyAtMostMB*mb {
				t.Fatalf("plan = %+v does not fit the budget %d with its reserve", plan, budget)
			}
			// Spending by the plan for a month never exceeds what it says.
			rounds := int64((throughputMonthHours + plan.IntervalHours - 1) / plan.IntervalHours)
			if spent := rounds * int64(tt.tunnels) * plan.RunBytes; spent > budget-plan.ReserveBytes {
				t.Fatalf("a month by this plan spends %d of %d", spent, budget-plan.ReserveBytes)
			}
		})
	}
	if plan := throughputSchedulePlan(config.Throughput{}, 0); plan.RunBytes != 0 || plan.MonthlyBytes != 0 {
		t.Fatalf("nothing to measure costs %+v", plan)
	}
}

func TestThroughputScheduleMeasuresOnlyWhatElectsBySpeedAndKeepsTheReserve(t *testing.T) {
	s, seen := throughputServer(t, nil)
	now := time.Unix(1_800_000_000, 0)
	s.throughputNowOf = func() time.Time { return now }
	s.throughputWANOf = func() (string, error) { return "wan0", nil }
	s.throughputJitterOf = func(time.Duration) time.Duration { return 0 }
	idle := func() {
		s.ifaceHist = newIfaceRing(90)
		for _, snap := range throughputSnaps(now, "wan0", 1000) {
			s.ifaceHist.push(snap)
		}
	}
	s.cfg.Throughput.Scheduled = true
	ctx := context.Background()

	// The Telegram list elects by delay now, the group always did: nothing chooses by speed.
	p := throughputProfile()
	p.RoutingLists[0].Fastest.Mode = model.ElectionLatency
	if err := s.store.Replace(p); err != nil {
		t.Fatal(err)
	}
	if ids := throughputScheduledIDs(&p); len(ids) != 0 {
		t.Fatalf("scheduled without a unit that elects by speed: %v", ids)
	}
	idle()
	s.runScheduledThroughput(ctx)
	if len(s.throughput.next) != 0 {
		t.Fatalf("planned %v", s.throughput.next)
	}

	// The group elects by throughput: its two members, not the third tunnel.
	p.Groups[0].ElectionMode = model.ElectionThroughput
	if err := s.store.Replace(p); err != nil {
		t.Fatal(err)
	}
	s.runScheduledThroughput(ctx)
	plan := throughputSchedulePlan(s.config().Throughput, 2)
	now = now.Add(time.Duration(plan.IntervalHours)*time.Hour + time.Minute)
	idle()
	s.runScheduledThroughput(ctx)
	s.runScheduledThroughput(ctx)
	s.runScheduledThroughput(ctx)
	if len(seen.ids) != 2 || seen.ids[0] == "de" || seen.ids[1] == "de" {
		t.Fatalf("scheduled runs: %v, want the group's two members", seen.ids)
	}
	if got := seen.opts[0].MaxBytes; got != plan.RunBytes || got >= s.config().Throughput.MaxBytes {
		t.Fatalf("a scheduled run asks for %d bytes, plan %d", got, plan.RunBytes)
	}
	if got, want := seen.opts[0].MaxTotalBytes, throughputBudgetBytes(s.config().Throughput)-plan.ReserveBytes; got > want {
		t.Fatalf("a scheduled run may spend %d, past the reserve line %d", got, want)
	}

	// Two thirds of the month are gone: the schedule stops, the button does not.
	s.throughput.mu.Lock()
	s.throughput.used = throughputBudgetBytes(s.config().Throughput) - plan.ReserveBytes
	s.throughput.mu.Unlock()
	now = now.Add(time.Duration(plan.IntervalHours)*time.Hour + time.Minute)
	idle()
	s.runScheduledThroughput(ctx)
	if len(seen.ids) != 2 {
		t.Fatalf("the schedule spent the manual reserve: %v", seen.ids)
	}
	if queued, err := s.queueThroughput(throughputRequest{Scope: "tunnel", ID: "nl"}); err != nil || !queued {
		t.Fatalf("a manual measurement was refused with the reserve intact: %v", err)
	}
}

// The month's counter survives a clock that is not the real one.
func TestThroughputMonthRolloverNeedsAPlausibleClock(t *testing.T) {
	s, _ := throughputServer(t, nil)
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	s.throughputNowOf = func() time.Time { return now }
	cfg := s.config().Throughput
	ctx := context.Background()
	s.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "nl"})
	if month, used, _ := s.throughputUsage(now, cfg); month != "2026-11" || used != 10_000_000 {
		t.Fatalf("usage %s %d", month, used)
	}

	// The journal comes back after a power cut; the router has no RTC and shows 1970 until NTP.
	s2, _ := throughputServer(t, nil)
	s2.restoreThroughputJournal(s.throughputJournalSnapshot())
	for _, bad := range []time.Time{time.Unix(120, 0), time.Date(2025, 12, 31, 0, 0, 0, 0, time.UTC), now.Add(-72*time.Hour).AddDate(0, -1, 0)} {
		if month, used, _ := s2.throughputUsage(bad, cfg); month != "2026-11" || used != 10_000_000 {
			t.Fatalf("clock %s zeroed the month: %s %d", bad.Format(time.RFC3339), month, used)
		}
	}
	// A run on the wrong clock is still charged to the month it belongs to.
	bad := time.Unix(300, 0)
	s2.throughputNowOf = func() time.Time { return bad }
	s2.runThroughputScope(ctx, throughputRequest{Scope: "tunnel", ID: "ca"})
	if month, used, _ := s2.throughputUsage(now, cfg); month != "2026-11" || used != 20_000_000 {
		t.Fatalf("after NTP: %s %d", month, used)
	}
	// The schedule does not run on that clock at all.
	s2.cfg.Throughput.Scheduled = true
	s2.throughputWANOf = func() (string, error) { return "wan0", nil }
	s2.ifaceHist = newIfaceRing(90)
	for _, snap := range throughputSnaps(bad, "wan0", 1000) {
		s2.ifaceHist.push(snap)
	}
	s2.runScheduledThroughput(ctx)
	if len(s2.throughput.next) != 0 {
		t.Fatal("the schedule planned on an implausible clock")
	}

	// A step back inside the month (time zone, NTP correction) changes nothing; the next month rolls.
	if _, used, _ := s2.throughputUsage(now.Add(-26*time.Hour), cfg); used != 20_000_000 {
		t.Fatalf("a small step back changed the use: %d", used)
	}
	if month, used, _ := s2.throughputUsage(time.Date(2026, 12, 1, 0, 5, 0, 0, time.UTC), cfg); month != "2026-12" || used != 0 {
		t.Fatalf("the new month did not start: %s %d", month, used)
	}
	if month, _, _ := s2.throughputUsage(time.Date(2026, 11, 30, 23, 0, 0, 0, time.UTC), cfg); month != "2026-12" {
		t.Fatalf("the month went back to %s", month)
	}
}

// Busy from the moment a request leaves the queue to the end of its scope; the same
// request is not accepted twice while it runs; it can be stopped.
func TestThroughputBusyDedupeAndCancel(t *testing.T) {
	started, release := make(chan string, 4), make(chan struct{})
	s, _ := throughputServer(t, nil)
	s.throughputRunOf = func(ctx context.Context, e model.Endpoint, _ string, _ speedtest.DownloadOptions) (speedtest.DownloadResult, error) {
		started <- e.ID
		select {
		case <-ctx.Done():
			return speedtest.DownloadResult{TotalBytes: 1000}, ctx.Err()
		case <-release:
			return tpResult("ovh", 40, 9e6), nil
		}
	}
	busy := func() (bool, string) {
		rec := httptest.NewRecorder()
		s.handleThroughput(rec, httptest.NewRequest(http.MethodGet, "/api/throughput", nil))
		return strings.Contains(rec.Body.String(), `"busy":true`), rec.Body.String()
	}
	req := throughputRequest{Scope: "group", ID: "g"}
	if queued, err := s.queueThroughput(req); err != nil || !queued {
		t.Fatalf("queue: %v", err)
	}
	popped, ok := s.popThroughput()
	if !ok {
		t.Fatal("nothing queued")
	}
	// Popped, not started yet: the gap in which the button used to spring back.
	if b, body := busy(); !b {
		t.Fatalf("not busy between the queue and the run: %s", body)
	}
	if queued, err := s.queueThroughput(req); err != nil || queued {
		t.Fatalf("the running request was queued again (queued=%v, err=%v)", queued, err)
	}

	done := make(chan struct{})
	go func() { s.runThroughputScope(context.Background(), popped); close(done) }()
	if got := <-started; got != "nl" {
		t.Fatalf("first tunnel %q", got)
	}
	if queued, _ := s.queueThroughput(req); queued {
		t.Fatal("a second tab queued the same group while it ran")
	}
	// Another request waits in the queue; Stop drops it and ends the run before the second tunnel.
	if queued, _ := s.queueThroughput(throughputRequest{Scope: "tunnel", ID: "de"}); !queued {
		t.Fatal("a different request was refused")
	}
	rec := httptest.NewRecorder()
	s.handleThroughputCancel(rec, httptest.NewRequest(http.MethodDelete, "/api/throughput/measure", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"stopped":true`) {
		t.Fatalf("cancel: %d %s", rec.Code, rec.Body.String())
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the run did not stop")
	}
	select {
	case id := <-started:
		t.Fatalf("tunnel %q was measured after Stop", id)
	default:
	}
	if st := s.throughput.tunnels["nl"]; st.Reason != reasonCancelled || st.Running {
		t.Fatalf("the stopped tunnel: %+v", st)
	}
	if b, body := busy(); b {
		t.Fatalf("still busy after Stop: %s", body)
	}
	if _, ok := s.popThroughput(); ok {
		t.Fatal("Stop left work in the queue")
	}
	s.throughput.mu.Lock()
	s.throughput.active = nil // popThroughput above set nothing; keep the state clean
	s.throughput.mu.Unlock()
	if s.throughput.used != 1000 {
		t.Fatalf("what was downloaded before Stop is not counted: %d", s.throughput.used)
	}
	if rec := httptest.NewRecorder(); true {
		s.handleThroughputCancel(rec, httptest.NewRequest(http.MethodDelete, "/api/throughput/measure", nil))
		if !strings.Contains(rec.Body.String(), `"stopped":false`) {
			t.Fatalf("nothing to stop: %s", rec.Body.String())
		}
	}
	close(release)
}

// A tunnel taken out of the list while the others are measured is not downloaded through.
func TestThroughputScopeRunSkipsATunnelRemovedMeanwhile(t *testing.T) {
	var s *Server
	var seen *throughputRunSeen
	s, seen = throughputServer(t, func(id string) (speedtest.DownloadResult, error) {
		if id == "nl" {
			p := throughputProfile()
			p.RoutingLists[0].Candidates = []string{"nl", "ca"} // de leaves the list
			if err := s.store.Replace(p); err != nil {
				t.Error(err)
			}
		}
		return tpResult("ovh", 40, 9e6), nil
	})
	s.runThroughputScope(context.Background(), throughputRequest{Scope: "list", ID: "telegram"})
	if len(seen.ids) != 2 || seen.ids[1] != "ca" {
		t.Fatalf("measured %v, want nl and ca", seen.ids)
	}
}

// The list panel is told which rule is in force right now.
func TestFastestSummarySaysWhichRuleIsInForce(t *testing.T) {
	answers := map[string]speedtest.DownloadResult{"nl": tpResult("cloudflare", 60, 9e6), "ca": tpResult("cloudflare", 90, 9e6)}
	s, _ := throughputServer(t, func(id string) (speedtest.DownloadResult, error) { return answers[id], nil })
	p := s.store.Profile()
	rl := p.RoutingLists[0]
	alive := map[string]failover.Measurement{"nl": {Alive: true}, "ca": {Alive: true}, "de": {Alive: true}}
	st := failover.UnitState{Current: "de", Measurements: alive}

	s.runThroughputScope(context.Background(), throughputRequest{Scope: "tunnel", ID: "nl"})
	sum := s.fastestSummaryOf(&p, rl, st, true)
	if sum.Election != "mixed" || sum.ElectionNow != "delay" || sum.Sampled != 1 || sum.SampledOf != 3 || sum.SampleClass != sampleClassGeneric {
		t.Fatalf("one sample of three: %+v", sum)
	}
	s.runThroughputScope(context.Background(), throughputRequest{Scope: "tunnel", ID: "ca"})
	if sum = s.fastestSummaryOf(&p, rl, st, true); sum.ElectionNow != "delay" || sum.Sampled != 2 {
		t.Fatalf("an unsampled current tunnel: %+v", sum)
	}
	st.Current = "ca"
	if sum = s.fastestSummaryOf(&p, rl, st, true); sum.ElectionNow != "throughput" {
		t.Fatalf("two samples and a sampled current tunnel: %+v", sum)
	}
	rl.Fastest = &model.FastestPolicy{Enabled: true, Mode: model.ElectionLatency}
	if sum = s.fastestSummaryOf(&p, rl, st, true); sum.ElectionNow != "" || sum.Sampled != 0 {
		t.Fatalf("a list that elects by delay: %+v", sum)
	}
}

// The sample class is chosen among the tunnels the election may choose. An excluded
// tunnel's media sample must not make a media list compare media figures only one eligible tunnel has.
func TestThroughputExcludedTunnelDoesNotChooseTheClass(t *testing.T) {
	s, _ := throughputServer(t, nil)
	now := s.throughputNow().UnixMilli()
	s.throughput.mu.Lock()
	s.throughput.tunnels = map[string]throughputTunnelState{
		"nl": {Success: tpResult("cloudflare", 60, 9e6), SuccessAt: now, Media: tpResult(throughputTelegramID, 30, 9e6), MediaAt: now},
		"ca": {Success: tpResult("cloudflare", 90, 9e6), SuccessAt: now},
		"de": {Media: tpResult(throughputTelegramID, 45, 9e6), MediaAt: now},
	}
	s.throughput.mu.Unlock()
	unit := func(excluded ...string) failover.TableUnit {
		units := []failover.TableUnit{{Policy: failover.PolicyMixed, Candidates: []string{"nl", "ca", "de"},
			List: &failover.ListPolicy{List: "telegram", Excluded: excluded}}}
		s.attachThroughput(units)
		return units[0]
	}
	u := unit("de")
	if u.Throughput["nl"].ThroughputKbps != 60_000 || u.Throughput["ca"].ThroughputKbps != 90_000 {
		t.Fatalf("excluded de chose the media class; the eligible tunnels lost their comparable generic samples: %+v", u.Throughput)
	}
	// With de eligible two tunnels have a fresh media sample, and that class is compared.
	u = unit()
	if u.Throughput["nl"].ThroughputKbps != 30_000 || u.Throughput["de"].ThroughputKbps != 45_000 {
		t.Fatalf("two eligible media samples: %+v", u.Throughput)
	}
	if _, ok := u.Throughput["ca"]; ok {
		t.Fatalf("a generic figure set against media ones: %+v", u.Throughput)
	}
}

// What was downloaded before the clock was set stays charged when it is, in the month the
// router turns out to be in, also across a month the journal remembers.
func TestThroughputPreNTPDownloadStaysCharged(t *testing.T) {
	s, _ := throughputServer(t, nil)
	clock := time.Unix(300, 0)
	s.throughputNowOf = func() time.Time { return clock }
	s.runThroughputScope(context.Background(), throughputRequest{Scope: "tunnel", ID: "nl"})
	good := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	if month, used, _ := s.throughputUsage(good, s.config().Throughput); month != "2026-11" || used != 10_000_000 {
		t.Fatalf("the first download, made before NTP, vanished when the clock was set: month=%s used=%d", month, used)
	}
	// A router that remembers October boots in December with no clock and measures once.
	s2, _ := throughputServer(t, nil)
	s2.restoreThroughputJournal(throughputJournalState{Month: "2026-10", Used: 70_000_000})
	s2.throughputNowOf = func() time.Time { return clock }
	s2.runThroughputScope(context.Background(), throughputRequest{Scope: "tunnel", ID: "nl"})
	december := time.Date(2026, 12, 2, 12, 0, 0, 0, time.UTC)
	if month, used, _ := s2.throughputUsage(december, s2.config().Throughput); month != "2026-12" || used != 10_000_000 {
		t.Fatalf("a new month starts with what this boot already downloaded: month=%s used=%d", month, used)
	}
	// And an ordinary roll with a good clock still starts at zero.
	s3, _ := throughputServer(t, nil)
	s3.restoreThroughputJournal(throughputJournalState{Month: "2026-10", Used: 70_000_000})
	if _, used, _ := s3.throughputUsage(december, s3.config().Throughput); used != 0 {
		t.Fatalf("a new month starts empty: used=%d", used)
	}
}
