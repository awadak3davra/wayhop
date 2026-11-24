package pbr

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// execCommand feeds the simulation over stdin, as the authenticated runner does. Besides avoiding
// Windows argv quoting and length limits, this preserves positional parameters for the body.
func execCommand(sh, script string, args ...string) (string, error) {
	argv := append([]string{"-s"}, args...)
	cmd := exec.Command(sh, argv...)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// BusyBox's start-stop-daemon is the middle branch when setsid is absent, with
// no PATH gate for an applet dispatched through wr_bb; the double-fork fallback remains.
func TestDetachedTimerUsesStartStopDaemonWithoutSetsid(t *testing.T) {
	script := backstopPlan(t).RenderKeeneticScript(Options{}, holdOptions())
	mustContain(t, script, "start-stop-daemon -S -b")
	mustContain(t, script, `"$wr_bb" start-stop-daemon`)
	mustContain(t, script, "( trap '' HUP;")
	if strings.Contains(script, "command -v start-stop-daemon") {
		t.Fatal("start-stop-daemon was gated on PATH")
	}
	if strings.Index(script, "command -v setsid") > strings.Index(script, `"$wr_bb" start-stop-daemon`) {
		t.Fatal("start-stop-daemon is not the fallback when setsid is absent")
	}
}

// Every detached interpreter is the pinned shell with its multicall applet when
// required, never `sh` from PATH and never a resolved BusyBox called with bare -c.
func TestDetachedChildUsesPinnedShell(t *testing.T) {
	script := backstopPlan(t).RenderKeeneticScript(Options{}, holdOptions())
	mustContain(t, script, `"${wr_sh:-/opt/bin/sh}" ${wr_sha:-} -c "$wr_fns$wr_t"`)
	for _, unwanted := range []string{"setsid sh -c", "( trap '' HUP; sh -c", `"${wr_sh:-/opt/bin/sh}" -c "$wr_fns$wr_t"`} {
		if strings.Contains(script, unwanted) {
			t.Fatalf("detached child uses the wrong interpreter: %q", unwanted)
		}
	}
}

// Once both data files reached EOF, a later table-judgement failure must not rerun the
// whole route loop on every hook invocation.
func TestLiftDataLoopRunsOnceAfterTableJudgeFails(t *testing.T) {
	sh, dir, native := shDir(t)
	pl := backstopPlan(t)
	io := holdOptions()
	io.BackstopReady = dir + "/ready"
	io.BootRestore = dir + "/restore.ipset"
	io.BootLearned = dir + "/learned.ipset"
	bs := pl.KillSwitchBackstop(io)
	if len(bs.ZoneSets4) == 0 || len(bs.Sets4) == 0 {
		t.Fatal("the fixture has no v4 data loops")
	}
	if err := os.WriteFile(filepath.Join(native, "restore.ipset"),
		drainFile(fmt.Sprintf("add %s 192.0.2.1 -exist\n", bs.ZoneSets4[0])), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(native, "learned.ipset"),
		learnedFile(fmt.Sprintf("add %s 198.51.100.1 -exist\n", bs.Sets4[0])), 0o644); err != nil {
		t.Fatal(err)
	}
	pre := `R="$1"
ip() {
	case "$*" in
	*"route replace blackhole"*) echo "$*" >> "$R.route-adds"; return 0 ;;
	*"route del default"*) echo "Operation not permitted" >&2; return 2 ;;
	*"route show"*) echo "blackhole default"; return 0 ;;
	esac
	return 0
}
`
	body := liftProgramForTest(pl, io)
	firstLiftLines := 0
	for run := 1; run <= 2; run++ {
		if out, err := execCommand(sh, pre+body, io.BackstopReady); err != nil {
			t.Fatalf("lift %d: %v: %s", run, err, out)
		}
		if _, err := os.Stat(filepath.Join(native, "ready"+StampLifted)); err == nil {
			t.Fatal("the test failed to stage a table-judgement failure")
		}
		data, err := os.ReadFile(filepath.Join(native, "ready.route-adds"))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Count(string(data), "\n")
		if run == 1 && lines == 0 {
			t.Fatal("the first lift ran no data loop")
		}
		if run == 2 && lines != firstLiftLines {
			t.Fatalf("the data loop repeated after a failed table judgement: %d -> %d lines", firstLiftLines, lines)
		}
		if run == 1 {
			firstLiftLines = lines
		}
	}
}
