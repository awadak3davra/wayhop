package server

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/pbr"
)

// What the hook did before the daemon was up is said loudly and in Diagnostics: a lifted
// broad hold, a partial fill, a hook no applied state owns.
func TestKillSwitchBootStatusSurfaces(t *testing.T) {
	s, _, _ := mirrorServer(t)
	r := s.ksb.readyPath()
	row := s.killSwitchBootCheck(context.Background())
	if row.Status != "warn" || !strings.Contains(row.Summary, "not been filled") {
		t.Fatalf("before any fill: %+v", row)
	}
	_ = os.WriteFile(r+pbr.StampPartial, []byte("learned addresses: missing\n"), 0o644)
	_ = os.WriteFile(r+pbr.StampLifted, nil, 0o644)
	st := s.ksBootStatus()
	if !st.Lifted || st.Partial != "learned addresses: missing" || !strings.Contains(st.summary(), "LIFTED") {
		t.Fatalf("status %+v: %s", st, st.summary())
	}
	if row := s.killSwitchBootCheck(context.Background()); row.Status != "warn" || !strings.Contains(row.Summary, "lifted") {
		t.Fatalf("lifted: %+v", row)
	}
	// A hook on disk with no applied state behind it.
	s.applyState.rec.Committed = nil
	s.ksb.hookPath = filepath.Join(t.TempDir(), "50-wayhop-policy.sh")
	_ = os.WriteFile(s.ksb.hookPath, []byte("#!/opt/bin/sh\n"), 0o755)
	if row := s.killSwitchBootCheck(context.Background()); row.Status != "fail" {
		t.Fatalf("orphan hook: %+v", row)
	}
}

// The first backstop sync happens before converge, from the committed record.
func TestKillSwitchFirstSyncBeforeConverge(t *testing.T) {
	s, table, _ := mirrorServer(t)
	s.ksb.reader = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(context.Context, string) ([]netip.Prefix, error) { return nil, nil }
	}
	hold := netip.MustParsePrefix("0.0.0.0/0")
	table.routes[hold] = true
	// StartApply runs exactly this before convergeOnBoot (applyboot.go): the committed record is enough.
	s.reportKillSwitchBoot()
	s.killSwitchMirrorTick(context.Background())
	if table.routes[hold] || len(table.routes) == 0 {
		t.Fatalf("first sync: %v", table.routes)
	}
}

// A fill tool started from tmpfs is replaced by the installed binary when there is one,
// and a plane whose fill tool is gone says so in Diagnostics.
func TestKillSwitchFillToolSurvivesTheReboot(t *testing.T) {
	yes := func(string) bool { return true }
	no := func(string) bool { return false }
	for _, c := range []struct {
		exe  string
		ok   func(string) bool
		want string
	}{
		{"/tmp/wr", yes, ksInstalledBinary},
		{"/tmp/wr", no, "/tmp/wr"},
		{"/opt/sbin/wayhop", yes, "/opt/sbin/wayhop"},
		{"/opt/bin/wayhop-dev", yes, "/opt/bin/wayhop-dev"},
		{"/tmp/w r", yes, ksInstalledBinary},
		{"/tmp/w r", no, ""},
	} {
		if got := ksFillToolFor(c.exe, ksInstalledBinary, c.ok); got != c.want {
			t.Errorf("%s: %q, want %q", c.exe, got, c.want)
		}
	}
	s, _, _ := mirrorServer(t)
	_ = os.WriteFile(s.ksb.readyPath(), nil, 0o644)
	s.applyState.rec.Committed.Materialization.Kernel.Ipset.FillTool = "/tmp/wr"
	s.ksb.fillToolOK = no
	if row := s.killSwitchBootCheck(context.Background()); row.Status != "warn" || !strings.Contains(row.Detail, "/tmp/wr") {
		t.Fatalf("gone fill tool: %+v", row)
	}
	s.ksb.fillToolOK = yes
	if row := s.killSwitchBootCheck(context.Background()); row.Status != "pass" {
		t.Fatalf("fill tool present: %+v", row)
	}
}
