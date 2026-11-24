package pbr

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The authenticated interpreter is the resolved BusyBox binary, not the sh symlink.
// Calling it with -c is the measured router failure; the sh applet argument is mandatory.
func TestDetachedShellRunsResolvedBusyBoxAsSh(t *testing.T) {
	sh, dir, native := shDir(t)
	bb := `#!/bin/sh
if [ "$1" = "-c" ]; then
	echo "-c: applet not found" >&2
	exit 127
fi
[ "$1" = sh ] || exit 127
shift
exec /bin/sh "$@"
`
	if err := os.WriteFile(filepath.Join(native, "busybox"), []byte(bb), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "echo ok > " + dir + "/child"
	// With no setsid, this host also rejects start-stop-daemon: the checked failure must reach the
	// double fork, whose child then works only because BusyBox receives argv[1]=sh.
	script := "wr_sh=" + dir + "/busybox; wr_sha=sh; wr_bb=" + dir + "/busybox; wr_fns=; " + detached(body, dir+"/tpid") + "; wait\n"
	if out, err := execCommand(sh, script); err != nil {
		t.Fatalf("detached launcher: %v: %s", err, out)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		data, err := os.ReadFile(filepath.Join(native, "child"))
		if err == nil && strings.TrimSpace(string(data)) == "ok" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the resolved BusyBox was not run through its sh applet: data %q, err %v", data, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Start-stop-daemon needs no PATH lookup, starts the resolved shell with its
// applet, removes a stale pidfile, and a synchronous launch failure falls back to the double fork.
func TestDetachedStartStopDaemonChecksLaunch(t *testing.T) {
	script := detached("echo ok", "/tmp/wayhop-test.tpid")
	for _, want := range []string{
		`setsid "${wr_sh:-/opt/bin/sh}" ${wr_sha:-} -c`,
		`rm -f /tmp/wayhop-test.tpid; "$wr_bb" start-stop-daemon -S -b -x "${wr_sh:-/opt/bin/sh}" -m -p /tmp/wayhop-test.tpid -- ${wr_sha:-} -c`,
		`|| ( trap '' HUP; "${wr_sh:-/opt/bin/sh}" ${wr_sha:-} -c`,
	} {
		mustContain(t, script, want)
	}
	if strings.Contains(script, "command -v start-stop-daemon") {
		t.Fatal("the BusyBox applet was gated on an unrelated PATH lookup")
	}
}

// An empty/stale .armed file is not proof of a live timer. Such a stamp rearms, while
// a stamp naming the current shell suppresses a duplicate launch.
func TestBootHoldRearmsWithoutLiveTimer(t *testing.T) {
	sh, dir, native := shDir(t)
	pl := backstopPlan(t)
	io := holdOptions()
	io.BackstopReady = dir + "/ready"
	var hook strings.Builder
	pl.writeBootHold(&hook, Options{}, io, pl.KillSwitchBackstop(io))
	if err := os.WriteFile(filepath.Join(native, "ready"+stampArmed), []byte("999999 600\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pre := `R="$1"
ip() { return 0; }
setsid() { echo "$*" > "$R.setsid"; }
`
	if out, err := execCommand(sh, pre+hook.String()+"\nwait\n", io.BackstopReady); err != nil {
		t.Fatalf("stale armed stamp: %v: %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(native, "ready.setsid")); err != nil {
		t.Fatal("a stale armed stamp suppressed the timer launch")
	}
	second := `R="$1"
echo "$$" > "$R.armed"
rm -f "$R.setsid"
` + pre + hook.String()
	if out, err := execCommand(sh, second, io.BackstopReady); err != nil {
		t.Fatalf("live armed stamp: %v: %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(native, "ready.setsid")); err == nil {
		t.Fatal("a live timer pid launched a duplicate")
	}
}

func writeSecondChanceData(t *testing.T, pl *Plan, io IpsetOptions, native string, routes int) int {
	t.Helper()
	bs := pl.KillSwitchBackstop(io)
	if len(bs.ZoneSets4) == 0 || len(bs.ZoneSets6) == 0 || len(bs.Sets4) == 0 {
		t.Fatal("the fixture needs v4/v6 static data and a learned set")
	}
	var restore strings.Builder
	for i := 0; i < routes; i++ {
		fmt.Fprintf(&restore, "add %s 198.51.%d.%d -exist\n", bs.ZoneSets4[0], i/256, i%256)
	}
	fmt.Fprintf(&restore, "add %s 2001:db8::1 -exist\n", bs.ZoneSets6[0])
	if err := os.WriteFile(filepath.Join(native, "restore.ipset"), drainFile(restore.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	learned := fmt.Sprintf("add %s 203.0.113.9 -exist\n", bs.Sets4[0])
	if err := os.WriteFile(filepath.Join(native, "learned.ipset"), learnedFile(learned), 0o644); err != nil {
		t.Fatal(err)
	}
	return routes + 2
}

func renderSecondChanceForTest(t *testing.T, pl *Plan, io IpsetOptions) string {
	t.Helper()
	var b strings.Builder
	pl.renderBootFill(&b, Options{}, io)
	return b.String()
}

// The inline second chance fills static and learned routes before it lifts. A run is
// capped, keeps the broad hold at the cap, and resumes rather than starting the same batch again.
func TestSecondChanceInstallsBoundedDataBeforeLifting(t *testing.T) {
	sh, dir, native := shDir(t)
	pl := backstopPlan(t)
	io := holdOptions()
	io.FillTool = ""
	io.BackstopReady = dir + "/ready"
	io.BootRestore = dir + "/restore.ipset"
	io.BootLearned = dir + "/learned.ipset"
	total := writeSecondChanceData(t, pl, io, native, 130)
	body := renderSecondChanceForTest(t, pl, io)
	pre := `R="$1"; UP="$2"
read() {
	if [ "${2-}" = wr_up ]; then wr_up=$UP; wr_x=0; return 0; fi
	command read "$@"
}
ip() { echo "$*" >> "$R.ops"; return 0; }
`
	for run, want := range []int{64, 128, total} {
		if out, err := execCommand(sh, pre+body, io.BackstopReady, strconv.Itoa(700+run)); err != nil {
			t.Fatalf("run %d: %v: %s", run+1, err, out)
		}
		raw, err := os.ReadFile(filepath.Join(native, "ready.ops"))
		if err != nil {
			t.Fatal(err)
		}
		ops := string(raw)
		if got := strings.Count(ops, "route replace blackhole"); got != want {
			t.Fatalf("run %d installed %d routes total, want %d", run+1, got, want)
		}
		_, liftedErr := os.Stat(filepath.Join(native, "ready"+StampLifted))
		if run < 2 {
			if liftedErr == nil || strings.Contains(ops, "route del default") {
				t.Fatalf("run %d lifted at its work cap", run+1)
			}
			continue
		}
		if liftedErr != nil {
			t.Fatal("the completed data loop did not lift")
		}
		lastAdd, firstLift := strings.LastIndex(ops, "route replace blackhole"), strings.Index(ops, "route del default")
		if lastAdd < 0 || firstLift < 0 || lastAdd > firstLift {
			t.Fatalf("the broad hold was removed before the narrow data:\n%s", ops)
		}
		for _, f := range []string{"ready.restore.done", "ready.learned.done"} {
			if _, err := os.Stat(filepath.Join(native, f)); err != nil {
				t.Fatalf("the completed fallback did not write %s", f)
			}
		}
	}
}

// The hard bound remains a bound even when a previous soft pass exhausted its batch budget. It
// drains the small fixture first, so this path too installs the narrow routes before the deletes.
func TestSecondChanceHardBoundDrainsDataAndLifts(t *testing.T) {
	sh, dir, native := shDir(t)
	pl := backstopPlan(t)
	io := holdOptions()
	io.FillTool = ""
	io.BackstopReady = dir + "/ready"
	io.BootRestore = dir + "/restore.ipset"
	io.BootLearned = dir + "/learned.ipset"
	total := writeSecondChanceData(t, pl, io, native, 66)
	body := renderSecondChanceForTest(t, pl, io)
	pre := `R="$1"; UP="$2"
read() {
	if [ "${2-}" = wr_up ]; then wr_up=$UP; wr_x=0; return 0; fi
	command read "$@"
}
ip() { echo "$*" >> "$R.ops"; return 0; }
`
	if out, err := execCommand(sh, pre+body, io.BackstopReady, "700"); err != nil {
		t.Fatalf("capped run: %v: %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(native, "ready"+StampLifted)); err == nil {
		t.Fatal("the soft pass did not stop at its cap")
	}
	if out, err := execCommand(sh, pre+body, io.BackstopReady, "1500"); err != nil {
		t.Fatalf("hard-bound run: %v: %s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(native, "ready.ops"))
	if err != nil {
		t.Fatal(err)
	}
	// The log also contains the first soft pass's 64 replacements; the hard pass resumes after them.
	if got := strings.Count(string(raw), "route replace blackhole"); got != total {
		t.Fatalf("soft+hard passes installed %d routes, want %d", got, total)
	}
	if _, err := os.Stat(filepath.Join(native, "ready"+StampLifted)); err != nil {
		t.Fatal("the lock-independent hard bound did not lift")
	}
}

// The final data loop's failure must prevent both .data and the lift. Fixing the file
// lets the next invocation finish the learned routes and then lift.
func TestLiftDataLastLoopFailureIsNotStamped(t *testing.T) {
	sh, dir, native := shDir(t)
	pl := backstopPlan(t)
	io := holdOptions()
	io.BackstopReady = dir + "/ready"
	io.BootRestore = dir + "/restore.ipset"
	io.BootLearned = dir + "/learned.ipset"
	bs := pl.KillSwitchBackstop(io)
	if err := os.WriteFile(filepath.Join(native, "restore.ipset"),
		drainFile(fmt.Sprintf("add %s 192.0.2.1 -exist\n", bs.ZoneSets4[0])), 0o644); err != nil {
		t.Fatal(err)
	}
	// A present but invalid learned file is a failed drain (unlike an absent file).
	if err := os.Mkdir(filepath.Join(native, "learned.ipset"), 0o755); err != nil {
		t.Fatal(err)
	}
	pre := `R="$1"
ip() {
	case "$*" in
	*"route replace blackhole"*) echo "$*" >> "$R.route-adds" ;;
	esac
	return 0
}
`
	body := liftProgramForTest(pl, io)
	if out, err := execCommand(sh, pre+body, io.BackstopReady); err != nil {
		t.Fatalf("failed data pass: %v: %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(native, "ready.learned.done")); err == nil {
		t.Fatal("the unreadable last loop was stamped complete")
	}
	if _, err := os.Stat(filepath.Join(native, "ready"+StampLifted)); err == nil {
		t.Fatal("the broad hold lifted without the learned data")
	}
	if err := os.Remove(filepath.Join(native, "learned.ipset")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(native, "learned.ipset"),
		learnedFile(fmt.Sprintf("add %s 198.51.100.1 -exist\n", bs.Sets4[0])), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := execCommand(sh, pre+body, io.BackstopReady); err != nil {
		t.Fatalf("completed data pass: %v: %s", err, out)
	}
	for _, suffix := range []string{".learned.done", StampLifted} {
		if _, err := os.Stat(filepath.Join(native, "ready"+suffix)); err != nil {
			t.Fatalf("missing %s after the completed pass", suffix)
		}
	}
}
