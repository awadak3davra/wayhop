package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// A deterministic sync error (here, static routes over the configured cap) keeps the
// broad hold during the hook's grace. Past the hard bound the daemon installs the static plan routes
// itself, without letting that cap block the lift, and only then removes the defaults.
func TestDaemonFailedSyncLiftInstallsStaticPastGrace(t *testing.T) {
	s, table, _ := mirrorServer(t)
	s.applyState.rec.Committed.Materialization.Kernel.Plan = ksPlan(t, nil)
	s.applyState.rec.Committed.Materialization.Kernel.Ipset.BootHoldLift = 600
	s.cfg.KillSwitchBackstopMax = 1
	s.ksb.reader = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(context.Context, string) ([]netip.Prefix, error) { return nil, nil }
	}
	hold4 := netip.MustParsePrefix("0.0.0.0/0")
	table.routes[hold4] = true
	up := 700
	s.ksb.uptime = func() (int, bool) { return up, true }
	s.killSwitchMirrorTick(context.Background())
	if !table.routes[hold4] || table.adds != 0 {
		t.Fatalf("the failed sync installed or lifted during the hook's grace: routes %v adds %d", table.routes, table.adds)
	}
	var logs strings.Builder
	oldLog := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(oldLog)
	up = 1600
	s.killSwitchMirrorTick(context.Background())
	if table.routes[hold4] {
		t.Fatal("the failed sync blocked the daemon's hard-bound lift")
	}
	for _, text := range []string{"149.154.160.0/20", "2001:67c:4e8::/48"} {
		if !table.routes[netip.MustParsePrefix(text)] {
			t.Errorf("the applied static prefix %s was not installed before the lift: %v", text, table.routes)
		}
	}
	lastStatic, firstHoldDelete := -1, -1
	for i, op := range table.ops {
		if strings.Contains(op, "add 149.154.160.0/20") || strings.Contains(op, "add 2001:67c:4e8::/48") {
			lastStatic = i
		}
		if firstHoldDelete < 0 && strings.Contains(op, "del 0.0.0.0/0") {
			firstHoldDelete = i
		}
	}
	if lastStatic < 0 || firstHoldDelete < 0 || lastStatic > firstHoldDelete {
		t.Fatalf("static routes were not installed before the broad hold delete: %v", table.ops)
	}
	if msg := logs.String(); !strings.Contains(msg, "sync") || !strings.Contains(msg, "incomplete") {
		t.Fatalf("the failed-sync lift did not say that narrow routes may be incomplete:\n%s", msg)
	}
}

// A static-only plan can skip the sync entirely during unread backoff. The skipped tick must retain
// the failed-sync deadline, then still perform the static install and lift at the hard bound.
func TestDaemonFailedSyncBackoffKeepsGraceAndHardBound(t *testing.T) {
	s, table, _ := mirrorServer(t)
	s.applyState.rec.Committed.Materialization.Kernel.Plan = ksPlan(t, func(p *model.Profile) {
		p.RoutingLists = p.RoutingLists[:1] // no domain sets, so a backed-off tick has doSync=false
	})
	s.applyState.rec.Committed.Materialization.Kernel.Ipset.BootHoldLift = 600
	hold4 := netip.MustParsePrefix("0.0.0.0/0")
	table.routes[hold4] = true
	table.addErr = errors.New("route add refused")
	up := 700
	s.ksb.uptime = func() (int, bool) { return up, true }
	s.killSwitchMirrorTick(context.Background())
	if table.adds == 0 || !table.routes[hold4] {
		t.Fatal("the first tick did not stage the failed static sync")
	}
	s.ksb.unreadStreak.Store(ksUnreadBackoffAfter)
	up = 701
	s.killSwitchMirrorTick(context.Background()) // doSync=false after the failure
	if !table.routes[hold4] {
		t.Fatal("a backed-off sync skipped the error path and lifted during the hook's grace")
	}
	up = 1600
	table.addErr = nil
	s.killSwitchMirrorTick(context.Background())
	if table.routes[hold4] || !table.routes[netip.MustParsePrefix("149.154.160.0/20")] {
		t.Fatalf("the backed-off hard bound did not install static data and lift: %v", table.routes)
	}
}

// .lifted is deliberately written first. A failed delete therefore has to remain
// owed and be retried despite the stamp; success clears the one-failure log latch for a later episode.
func TestDaemonLiftRetriesDeletesAndResetsFailureLog(t *testing.T) {
	s, table, _ := mirrorServer(t)
	s.applyState.rec.Committed.Materialization.Kernel.Ipset.BootHoldLift = 600
	s.ksb.uptime = func() (int, bool) { return 601, true }
	s.ksb.reader = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(context.Context, string) ([]netip.Prefix, error) { return nil, errors.New("set unavailable") }
	}
	hold4, hold6 := netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")
	table.routes[hold4], table.routes[hold6] = true, true
	table.delErr = errors.New("delete refused")
	var logs strings.Builder
	oldLog := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(oldLog)
	for range 2 {
		s.killSwitchMirrorTick(context.Background())
	}
	if !table.routes[hold4] || !table.routes[hold6] {
		t.Fatal("the fixture did not keep the hold behind the failed deletes")
	}
	if got := strings.Count(logs.String(), "lift the boot hold"); got != 1 {
		t.Fatalf("one failed lift episode logged %d times, want once:\n%s", got, logs.String())
	}
	table.delErr = nil
	s.killSwitchMirrorTick(context.Background())
	if table.routes[hold4] || table.routes[hold6] {
		t.Fatalf("the lifted stamp suppressed the owed delete retry: %v", table.routes)
	}

	// Stage a later, distinct lift failure. The first success must have re-armed its failure log.
	if err := os.Remove(s.ksb.ready + pbr.StampLifted); err != nil {
		t.Fatal(err)
	}
	table.routes[hold4] = true
	table.delErr = errors.New("a later delete failure")
	k := s.kernelBaseline()
	s.ksDaemonLift(k.Plan, *k.Ipset)
	if got := strings.Count(logs.String(), "lift the boot hold"); got != 2 {
		t.Fatalf("the failure log latch did not reset after success: got %d logs, want 2:\n%s", got, logs.String())
	}
}

// A .lifted stamp written by the hook is operationally important even though this
// daemon did not write it. Seeing it produces one alert, not silence and not an alert every tick.
func TestDaemonAlertsOnceForHookSideLift(t *testing.T) {
	alerts := make(chan string, 2)
	hook := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		var body struct {
			Text string `json:"text"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		alerts <- body.Text
	}))
	defer hook.Close()
	s, table, _ := mirrorServer(t)
	s.applyState.rec.Committed.Materialization.Kernel.Ipset.BootHoldLift = 600
	s.allowInternalFetch = true
	s.cfg.Watchdog.NotifyURL = hook.URL
	if err := os.WriteFile(s.ksb.ready+pbr.StampLifted, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	table.routes[netip.MustParsePrefix("0.0.0.0/0")] = true
	k := s.kernelBaseline()
	s.ksDaemonLift(k.Plan, *k.Ipset)
	select {
	case msg := <-alerts:
		if !strings.Contains(strings.ToLower(msg), "hook") || !strings.Contains(msg, "broad boot hold") {
			t.Fatalf("hook-side lift alert = %q", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the daemon did not alert on the hook-side lift")
	}
	s.ksDaemonLift(k.Plan, *k.Ipset)
	select {
	case msg := <-alerts:
		t.Fatalf("the same hook-side lift alerted again: %q", msg)
	case <-time.After(100 * time.Millisecond):
	}
}
