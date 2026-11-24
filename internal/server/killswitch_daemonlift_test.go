package server

import (
	"context"
	"errors"
	"log"
	"net/netip"
	"os"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// A live daemon that cannot read a kill-switched set keeps the boot hold on purpose
// and had no lift of its own: the bound rested on the hook's background timer alone. Past the
// plane's BootHoldLift seconds of uptime with no ready stamp the mirror now lifts the broad hold itself
// (the defaults and the shared throws), writes .lifted, and keeps the narrow routes.
func TestDaemonLiftsTheBootHoldPastItsBound(t *testing.T) {
	s, table, _ := mirrorServer(t)
	s.applyState.rec.Committed.Materialization.Kernel.Ipset.BootHoldLift = 600
	hold4, hold6 := netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")
	table.routes[hold4], table.routes[hold6] = true, true
	s.ksb.reader = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(context.Context, string) ([]netip.Prefix, error) { return nil, errors.New("no such set") }
	}
	up := 599
	s.ksb.uptime = func() (int, bool) { return up, true }
	s.killSwitchMirrorTick(context.Background())
	if !table.routes[hold4] {
		t.Fatal("the hold went before its bound")
	}
	up = 601
	s.killSwitchMirrorTick(context.Background())
	if table.routes[hold4] || table.routes[hold6] {
		t.Fatalf("the hold outlived its bound with the daemon up: %v", table.routes)
	}
	if len(table.throwDels) == 0 {
		t.Fatal("the shared throws stayed")
	}
	if _, err := os.Stat(s.ksb.ready + pbr.StampLifted); err != nil {
		t.Fatal("no lifted stamp")
	}
	if _, err := os.Stat(s.ksb.ready); err == nil {
		t.Fatal("the daemon's lift wrote the ready stamp")
	}
	if !table.routes[netip.MustParsePrefix("91.108.4.0/22")] {
		t.Fatalf("the narrow routes went with the hold: %v", table.routes)
	}

	// Clearing the process-local latches simulates a restart over the same tmpfs. The
	// hook-side alert is still once per boot, and ready+lifted is a healthy completed boot.
	t.Run("hook alert persists across restart", func(t *testing.T) {
		s.ksb.ready += ".hook"
		s.ksb.liftOwed.Store(false)
		s.ksb.liftHook.Store(false)
		s.ksb.liftAlerted.Store(false)
		if err := os.WriteFile(s.ksb.ready+pbr.StampLifted, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		var logs strings.Builder
		oldLog := log.Writer()
		log.SetOutput(&logs)
		defer log.SetOutput(oldLog)
		k := s.kernelBaseline()
		s.ksDaemonLift(k.Plan, *k.Ipset)
		if got := strings.Count(logs.String(), "KILL SWITCH"); got != 1 {
			t.Fatalf("first hook-side lift produced %d alerts, want 1:\n%s", got, logs.String())
		}
		s.ksb.liftAlerted.Store(false)
		s.ksb.liftHook.Store(false)
		s.ksDaemonLift(k.Plan, *k.Ipset)
		if got := strings.Count(logs.String(), "KILL SWITCH"); got != 1 {
			t.Fatalf("a daemon restart repeated the hook-side alert:\n%s", logs.String())
		}
		if err := os.WriteFile(s.ksb.ready, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		s.ksb.liftAlerted.Store(false)
		s.ksb.liftHook.Store(false)
		s.ksDaemonLift(k.Plan, *k.Ipset)
		if got := strings.Count(logs.String(), "KILL SWITCH"); got != 1 {
			t.Fatalf("a healthy ready+lifted boot alerted:\n%s", logs.String())
		}
	})
}

// Strict (no bound) and an unknown uptime never lift. Neither does a plane without a
// kill switch, through either the !doSync tick or the failed-sync daemon path.
func TestDaemonLiftNeedsABoundAnUptimeAndKillSwitch(t *testing.T) {
	var logs strings.Builder
	oldLog := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(oldLog)
	for _, c := range []struct {
		lift                int
		ok, off, failedSync bool
	}{{0, true, false, false}, {600, false, false, false}, {600, true, true, false}, {600, true, true, true}} {
		s, table, _ := mirrorServer(t)
		k := &s.applyState.rec.Committed.Materialization.Kernel
		k.Ipset.BootHoldLift = c.lift
		if c.off {
			k.Plan = ksPlan(t, func(p *model.Profile) { p.Groups[0].KillSwitch = false })
		}
		hold4 := netip.MustParsePrefix("0.0.0.0/0")
		table.routes[hold4] = true
		s.ksb.reader = func(executionKernelIpsetArtifactV1) ksMembers {
			return func(context.Context, string) ([]netip.Prefix, error) { return nil, errors.New("no such set") }
		}
		ok := c.ok
		s.ksb.uptime = func() (int, bool) { return 100000, ok }
		if c.failedSync {
			s.ksb.syncFailed.Store(true)
			s.ksDaemonLiftAfterFailedSync(k.Plan, *k.Ipset)
		} else {
			s.killSwitchMirrorTick(context.Background())
		}
		if !table.routes[hold4] {
			t.Fatalf("lift %d uptime known %v kill switch off %v: the hold was lifted", c.lift, c.ok, c.off)
		}
		if c.off {
			if _, err := os.Stat(s.ksb.ready + pbr.StampLifted); err == nil {
				t.Fatal("a plane without a kill switch wrote the lifted stamp")
			}
			if table.dels != 0 || strings.Contains(logs.String(), "KILL SWITCH") {
				t.Fatalf("a plane without a kill switch deleted routes or alerted: ops %v\n%s", table.ops, logs.String())
			}
		}
	}
}
