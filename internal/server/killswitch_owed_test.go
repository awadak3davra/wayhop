package server

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"
)

// The hook stamp was consumed and the tick counted before applyMu was tried. A tick that
// lost the lock (or a sync that failed) left the kernel re-read for 60 ticks later: five minutes of a
// stale table, at boot five minutes of hold.
func TestKillSwitchMirrorOwesTheResyncItCouldNotDo(t *testing.T) {
	s, table, stamp := mirrorServer(t)
	s.ksb.reader = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(context.Context, string) ([]netip.Prefix, error) { return nil, nil }
	}
	ctx := context.Background()
	s.killSwitchMirrorTick(ctx)
	lists := table.lists
	if err := os.WriteFile(stamp, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	s.applyMu.Lock()
	s.killSwitchMirrorTick(ctx) // the hook's tick loses the lock
	s.applyMu.Unlock()
	s.killSwitchMirrorTick(ctx)
	if table.lists == lists {
		t.Fatal("the re-read a hook run asked for was dropped with the lost lock")
	}
}

// A sync whose set read failed keeps the boot hold: the table lacks exactly the names resolved.
func TestKillSwitchBootHoldStaysWhenASetReadFails(t *testing.T) {
	s, table, _ := mirrorServer(t)
	hold := netip.MustParsePrefix("0.0.0.0/0")
	table.routes[hold] = true
	s.ksb.reader = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(context.Context, string) ([]netip.Prefix, error) { return nil, errors.New("no such set") }
	}
	s.killSwitchMirrorTick(context.Background())
	if !table.routes[hold] {
		t.Fatal("the hold was released after a failed set read")
	}
	if _, err := os.Stat(s.ksb.ready); err == nil {
		t.Fatal("ready stamp written after a failed set read")
	}
	s.ksb.reader = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(context.Context, string) ([]netip.Prefix, error) { return nil, nil }
	}
	s.killSwitchMirrorTick(context.Background())
	if table.routes[hold] {
		t.Fatal("the hold outlived a good sync")
	}
}

// A set that stays unreadable no longer turns every tick into a full kernel re-read;
// after a few, the owed re-read waits for every ksUnreadBackoffEvery-th tick. A good sync ends it.
func TestKillSwitchUnreadableSetBacksOff(t *testing.T) {
	s, table, _ := mirrorServer(t)
	s.ksb.reader = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(context.Context, string) ([]netip.Prefix, error) { return nil, errors.New("no such set") }
	}
	ctx := context.Background()
	const ticks = 48
	for i := 0; i < ticks; i++ {
		s.killSwitchMirrorTick(ctx)
	}
	if max := ksUnreadBackoffAfter + ticks/ksUnreadBackoffEvery + 2; table.lists > max {
		t.Fatalf("%d kernel re-reads in %d ticks with an unreadable set, want at most %d", table.lists, ticks, max)
	}
	s.ksb.reader = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(context.Context, string) ([]netip.Prefix, error) { return nil, nil }
	}
	for i := 0; i < ksUnreadBackoffEvery; i++ {
		s.killSwitchMirrorTick(ctx)
	}
	if s.ksb.unreadStreak.Load() != 0 || s.ksb.owed.Load() {
		t.Fatalf("after a good sync: streak %d owed %v", s.ksb.unreadStreak.Load(), s.ksb.owed.Load())
	}
}

// A sync that fails (a refused route) never advanced the tick counter the periodic re-read
// keys on, so from a start every tick re-read the kernel and the back-off never engaged.
func TestKillSwitchFailingSyncBacksOff(t *testing.T) {
	s, table, _ := mirrorServer(t)
	table.addErr = errors.New("operation not permitted")
	s.ksb.reader = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(context.Context, string) ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("198.51.100.9/32")}, nil
		}
	}
	ctx := context.Background()
	const ticks = 48
	for i := 0; i < ticks; i++ {
		s.killSwitchMirrorTick(ctx)
	}
	if max := ksUnreadBackoffAfter + ticks/ksUnreadBackoffEvery + 2; table.lists > max {
		t.Fatalf("%d kernel re-reads in %d ticks with a failing sync, want at most %d", table.lists, ticks, max)
	}
}

// The ready path is set once at construction; the tick (which runs beside readers that
// take no lock) never writes it.
func TestKillSwitchTickNeverWritesTheReadyPath(t *testing.T) {
	s, _, _ := mirrorServer(t)
	s.ksb.ready = ""
	s.ksb.reader = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(context.Context, string) ([]netip.Prefix, error) { return nil, nil }
	}
	s.killSwitchMirrorTick(context.Background())
	if s.ksb.ready != "" {
		t.Fatalf("the tick set the ready path to %q", s.ksb.ready)
	}
}
