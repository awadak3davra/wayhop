package server

import (
	"context"
	"errors"
	"log"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

// The detached launcher receives the authenticated BusyBox and shell paths from
// the same artifact preamble as the other tools.
func TestKeeneticPBRPreamblePinsDetachedTools(t *testing.T) {
	preamble, err := keeneticPBRPreamble(keeneticPBRTestTools())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"wr_sh=/opt/bin/busybox", "wr_sha=sh", "wr_bb=/opt/bin/busybox"} {
		if !strings.Contains(preamble, want) {
			t.Fatalf("preamble is missing %q:\n%s", want, preamble)
		}
	}
}

// A failed sync has not installed all the narrow routes, so the daemon leaves the
// broad hold in place throughout the hook's grace. The later hard-bound lift has its own R7 test.
func TestDaemonLiftWaitsForSuccessfulSync(t *testing.T) {
	s, table, _ := mirrorServer(t)
	s.applyState.rec.Committed.Materialization.Kernel.Ipset.BootHoldLift = 600
	s.ksb.uptime = func() (int, bool) { return 700, true }
	table.addErr = errors.New("route add refused")
	hold4 := netip.MustParsePrefix("0.0.0.0/0")
	table.routes[hold4] = true
	s.killSwitchMirrorTick(context.Background())
	if table.adds == 0 {
		t.Fatal("the test did not stage a failed sync")
	}
	if !table.routes[hold4] {
		t.Fatal("the daemon lifted the broad hold after a failed sync")
	}
}

// An unwritable lifted stamp must leave the defaults alone (no delete/stamp flap), and
// one failed lift episode is logged once rather than on every five-second tick.
func TestDaemonLiftStampFailureDoesNotDeleteOrLogEveryTick(t *testing.T) {
	s, table, _ := mirrorServer(t)
	k := s.kernelBaseline()
	k.Ipset.BootHoldLift = 600
	s.ksb.uptime = func() (int, bool) { return 601, true }
	s.ksb.ready = filepath.Join(t.TempDir(), "missing", "ready")
	hold4, hold6 := netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")
	table.routes[hold4], table.routes[hold6] = true, true
	var logs strings.Builder
	oldLog := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(oldLog)
	for range 2 {
		s.ksDaemonLift(k.Plan, *k.Ipset)
	}
	if table.dels != 0 || !table.routes[hold4] || !table.routes[hold6] {
		t.Fatalf("the hold was deleted before its stamp could be written: dels=%d routes=%v", table.dels, table.routes)
	}
	if got := strings.Count(logs.String(), "lift the boot hold"); got != 1 {
		t.Fatalf("failed lift logged %d times, want once:\n%s", got, logs.String())
	}
}
