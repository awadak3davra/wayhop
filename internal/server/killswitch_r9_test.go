package server

import (
	"context"
	"errors"
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"wayhop/internal/pbr"
)

// Both files the hook's shell fallback drains carry the drain header (a key of the
// content and the number of add lines), the learned file its trailer as before, and the Go fill still
// reads them. A learned file an older build left without the header is written again when an Apply is
// saved, although its members did not change: the new hook cannot drain a file without the key.
func TestDrainFilesAreKeyedAndAnOldLearnedFileIsRewritten(t *testing.T) {
	es := []ksEntry{
		{"wr_list_dom_4", netip.MustParsePrefix("198.51.100.7/32"), 5000},
		{"wr_list_dom_4", netip.MustParsePrefix("198.51.100.8/32"), 6000},
	}
	data := renderLearned(es, 100, 1<<20)
	first := strings.Fields(strings.SplitN(string(data), "\n", 2)[0])
	if !pbr.HasDrainHeader(data) || len(first) != 4 || first[3] != "2" || !strings.HasSuffix(string(data), ksLearnedTrailer+"2\n") {
		t.Fatalf("learned file:\n%s", data)
	}
	if got, err := readLearnedKS(strings.NewReader(string(data)), []string{"wr_list_dom_4"}); err != nil || len(got) != 2 {
		t.Fatalf("the fill reads the keyed learned file as %v, %v", got, err)
	}
	other := renderLearned(es[:1], 100, 1<<20)
	if strings.Fields(string(other))[2] == first[2] {
		t.Fatal("two learned contents share a key")
	}
	restore := keeneticBootRestoreFile(executionKernelIpsetArtifactV1{Restore: []byte("create wr_list_tg_4 hash:net\nadd wr_list_tg_4 192.0.2.0/24 -exist\n")})
	if !pbr.HasDrainHeader(restore) || strings.Fields(string(restore))[3] != "1" {
		t.Fatalf("restore file:\n%s", restore)
	}
	if got, err := readStaticKS(strings.NewReader(string(restore)), []string{"wr_list_tg_4"}); err != nil || len(got) != 1 {
		t.Fatalf("the fill reads the keyed restore file as %v, %v", got, err)
	}

	s, _, _ := mirrorServer(t)
	member := netip.MustParsePrefix("198.51.100.9/32")
	s.ksb.reader = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(context.Context, string) ([]netip.Prefix, error) { return []netip.Prefix{member}, nil }
	}
	k := s.kernelBaseline()
	bs := k.Plan.KillSwitchBackstop(keeneticKillSwitchOptions(*k.Ipset))
	var old strings.Builder
	sets := append(append([]string(nil), bs.Sets4...), bs.Sets6...)
	for _, set := range sets {
		old.WriteString("add " + set + " 198.51.100.9 timeout 86400 -exist\n")
	}
	old.WriteString(ksLearnedTrailer + strconv.Itoa(len(sets)) + "\n")
	if err := os.WriteFile(s.ksl.path, []byte(old.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	s.saveLearnedNow()
	now, err := os.ReadFile(s.ksl.path)
	if err != nil || !pbr.HasDrainHeader(now) {
		t.Fatalf("an unkeyed learned file with unchanged members was left as it was: %v\n%s", err, now)
	}
	if !strings.Contains(string(now), "198.51.100.9 timeout") || !strings.HasSuffix(string(now), ksLearnedTrailer+strconv.Itoa(len(sets))+"\n") {
		t.Fatalf("rewritten learned file:\n%s", now)
	}
	_ = s.learnedWriter().Close()
}

// markerProbe is a log sink that records, at the moment the lift alert is logged (the line directly
// before the alert is handed over), whether the per-boot alert marker already exists.
type markerProbe struct {
	mu          sync.Mutex
	marker      string
	lines       []string
	markerFirst bool
}

func (p *markerProbe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if strings.Contains(string(b), "KILL SWITCH") {
		p.lines = append(p.lines, string(b))
		if _, err := os.Stat(p.marker); err == nil {
			p.markerFirst = true
		}
	}
	return len(b), nil
}

// The alert marker is written after the alert is sent, never before (a daemon that died
// between the two never alerted in that boot), and it names the origin. The daemon's own lifted stamp
// names the daemon, so a restart between the lift and the marker does not report its lift as the hook's.
func TestLiftAlertMarkerFollowsTheAlertAndNamesItsOrigin(t *testing.T) {
	s, table, _ := mirrorServer(t)
	s.applyState.rec.Committed.Materialization.Kernel.Ipset.BootHoldLift = 600
	table.routes[netip.MustParsePrefix("0.0.0.0/0")] = true
	s.ksb.reader = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(context.Context, string) ([]netip.Prefix, error) { return nil, errors.New("no such set") }
	}
	s.ksb.uptime = func() (int, bool) { return 601, true }
	marker := s.ksb.ready + pbr.StampLifted + ".alerted"
	probe := &markerProbe{marker: marker}
	oldLog := log.Writer()
	log.SetOutput(probe)
	defer log.SetOutput(oldLog)

	s.killSwitchMirrorTick(context.Background())
	if len(probe.lines) != 1 {
		t.Fatalf("the daemon's lift logged %d alerts, want 1: %q", len(probe.lines), probe.lines)
	}
	if probe.markerFirst {
		t.Fatal("the alert marker existed before the alert was sent")
	}
	if raw, err := os.ReadFile(marker); err != nil || strings.TrimSpace(string(raw)) != "daemon" {
		t.Fatalf("marker after the daemon's lift = %q, %v; want the origin \"daemon\"", raw, err)
	}

	// A restart between liftHold and the marker: the process latches are gone, the marker was never
	// written, the stamp is there. The alert is repeated (once) and still names the daemon.
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	s.ksb.liftOwed.Store(false)
	s.ksb.liftHook.Store(false)
	s.ksb.liftAlerted.Store(false)
	k := s.kernelBaseline()
	s.ksDaemonLift(k.Plan, *k.Ipset)
	if len(probe.lines) != 2 {
		t.Fatalf("a lift whose alert was never marked was not alerted after the restart: %q", probe.lines)
	}
	if strings.Contains(probe.lines[1], "the hook lifted") {
		t.Fatalf("the daemon's own lift was reported as the hook's after a restart: %q", probe.lines[1])
	}
	s.ksb.liftAlerted.Store(false)
	s.ksb.liftHook.Store(false)
	s.ksDaemonLift(k.Plan, *k.Ipset)
	if len(probe.lines) != 2 {
		t.Fatalf("the marked alert repeated: %q", probe.lines)
	}

	// The hook's stamp is empty. The daemon repeats the deletes behind it without taking the stamp
	// over, so the origin stays the hook's.
	s.ksb.ready += ".hook"
	probe.mu.Lock()
	probe.marker, probe.markerFirst = s.ksb.ready+pbr.StampLifted+".alerted", false
	probe.mu.Unlock()
	s.ksb.liftOwed.Store(false)
	s.ksb.liftHook.Store(false)
	s.ksb.liftAlerted.Store(false)
	if err := os.WriteFile(s.ksb.ready+pbr.StampLifted, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	s.ksDaemonLift(k.Plan, *k.Ipset)
	if len(probe.lines) != 3 || !strings.Contains(probe.lines[2], "the hook lifted") || probe.markerFirst {
		t.Fatalf("hook-side lift: alerts %q, marker first %v", probe.lines, probe.markerFirst)
	}
	if raw, err := os.ReadFile(s.ksb.ready + pbr.StampLifted); err != nil || len(raw) != 0 {
		t.Fatalf("the daemon took the hook's stamp over: %q, %v", raw, err)
	}
	if raw, err := os.ReadFile(s.ksb.ready + pbr.StampLifted + ".alerted"); err != nil || strings.TrimSpace(string(raw)) != "hook" {
		t.Fatalf("marker after the hook's lift = %q, %v; want the origin \"hook\"", raw, err)
	}
}
