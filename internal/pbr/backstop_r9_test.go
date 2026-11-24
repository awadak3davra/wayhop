package pbr

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// liftProgramForTest is the shared functions and the timer's first step: an uncapped drain, then the
// lift when the narrow data is complete.
func liftProgramForTest(pl *Plan, io IpsetOptions) string {
	return pl.liftFuncs(Options{}, io, pl.KillSwitchBackstop(io)) + "wr_drain -1 && wr_lift\n:\n"
}

// drainFile is a restore fixture as the daemon writes it: under its drain header.
func drainFile(body string) []byte { return KeyedRestore([]byte(body)) }

// learnedFile is a learned fixture as the daemon writes it: header, entries, trailer.
func learnedFile(body string) []byte {
	return KeyedRestore([]byte(body + LearnedTrailer + strconv.Itoa(strings.Count(body, "add ")) + "\n"))
}

// drainKey is the key in a drain file's header.
func drainKey(data []byte) string {
	if f := strings.Fields(string(data)); len(f) > 2 {
		return f[2]
	}
	return ""
}

func r9Write(t *testing.T, native, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(native, name), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func r9Exists(native, name string) bool {
	_, err := os.Stat(filepath.Join(native, name))
	return err == nil
}

func r9Records(set string, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "add %s 198.51.100.%d -exist\n", set, i+1)
	}
	return b.String()
}

// r9CutIP stands in for ip and ends the whole shell before the (after+1)th narrow route of a run:
// a run that is cut at an arbitrary point, as a hook NDM ends or a timer that is killed.
func r9CutIP(after int) string {
	return fmt.Sprintf(`ip() {
	case "$*" in *"route replace blackhole"*) wr_cut=$((${wr_cut:-0}+1)); [ "$wr_cut" -gt %d ] && exit 9 ;; esac
	echo "$*" >> "$R.ops"; return 0
}
`, after)
}

// A drain that is cut makes progress. Every installed route is checkpointed, so each
// run resumes at the last one, the position only grows, no route is installed twice and the hold
// lifts once the last record is in. The hook past due+grace and the timer's uncapped drain alike:
// before, only a capped pass wrote a position and a cut uncapped drain started over on every run.
func TestCutDrainResumesForwardAndLifts(t *testing.T) {
	for _, c := range []struct{ name, up string }{{"hook", "1600"}, {"timer", ""}} {
		t.Run(c.name, func(t *testing.T) {
			sh, _, native, pl, io, body := r8SecondChanceSetup(t, c.name)
			if c.up == "" {
				body = liftProgramForTest(pl, io)
			}
			bs := pl.KillSwitchBackstop(io)
			r9Write(t, native, c.name+".restore", drainFile(r9Records(bs.ZoneSets4[0], 10)))
			r9Write(t, native, c.name+".learned", learnedFile(""))
			pos := func() int {
				raw, _ := os.ReadFile(filepath.Join(native, c.name+".restore.pos"))
				f := strings.Fields(string(raw))
				if len(f) == 0 {
					return 0
				}
				n, _ := strconv.Atoi(f[len(f)-1])
				return n
			}
			last := 0
			for run := 1; run <= 4; run++ {
				_, _ = execCommand(sh, r8SecondChancePre+r9CutIP(3)+body, io.BackstopReady, c.up) // cut runs exit 9
				ops := r8Ops(t, native, c.name)
				if got, want := strings.Count(ops, "route replace blackhole"), min(3*run, 10); got != want {
					t.Fatalf("run %d: %d routes installed in all, want %d (a cut run must resume, not repeat):\n%s", run, got, want, ops)
				}
				if run < 4 {
					if p := pos(); p <= last {
						t.Fatalf("run %d: position %d did not move past %d", run, p, last)
					} else {
						last = p
					}
					if r9Exists(native, c.name+StampLifted) {
						t.Fatalf("run %d lifted with %d of 10 routes", run, 3*run)
					}
				}
			}
			ops := r8Ops(t, native, c.name)
			for i := 1; i <= 10; i++ {
				if n := strings.Count(ops, fmt.Sprintf("blackhole 198.51.100.%d table", i)); n != 1 {
					t.Fatalf("route %d installed %d times, want once", i, n)
				}
			}
			if !r9Exists(native, c.name+StampLifted) {
				t.Fatal("the completed drain did not lift")
			}
			if strings.LastIndex(ops, "route replace blackhole") > strings.Index(ops, "route del default") {
				t.Fatalf("the broad hold went before the narrow data:\n%s", ops)
			}
		})
	}
}

// The final bound does not depend on the drain. A hook whose every run is cut at its
// first route, or whose restore file cannot be read, still lifts at due+grace+final, because the lift
// comes first there; one second earlier it does not. After that lift the drain goes on.
func TestFinalBoundLiftsBeforeAnythingThatCanBeCut(t *testing.T) {
	final := strconv.Itoa(600 + BootHoldLiftGrace + BootHoldLiftFinal)
	before := strconv.Itoa(600 + BootHoldLiftGrace + BootHoldLiftFinal - 1)
	for _, c := range []struct {
		name       string
		unreadable bool
	}{{"cut", false}, {"unreadable", true}} {
		t.Run(c.name, func(t *testing.T) {
			sh, _, native, pl, io, body := r8SecondChanceSetup(t, c.name)
			bs := pl.KillSwitchBackstop(io)
			if c.unreadable {
				if err := os.Mkdir(filepath.Join(native, c.name+".restore"), 0o755); err != nil {
					t.Fatal(err)
				}
			} else {
				r9Write(t, native, c.name+".restore", drainFile(r9Records(bs.ZoneSets4[0], 5)))
			}
			r9Write(t, native, c.name+".learned", learnedFile(""))
			_, _ = execCommand(sh, r8SecondChancePre+r9CutIP(0)+body, io.BackstopReady, before)
			if r9Exists(native, c.name+StampLifted) {
				t.Fatal("lifted before the final bound without the narrow data")
			}
			_, _ = execCommand(sh, r8SecondChancePre+r9CutIP(0)+body, io.BackstopReady, final)
			if !r9Exists(native, c.name+StampLifted) {
				t.Fatal("the final bound did not lift: it still depends on the drain")
			}
			if ops := r8Ops(t, native, c.name); !strings.Contains(ops, "route del default") || strings.Contains(ops, "route replace blackhole") {
				t.Fatalf("ops at the final bound:\n%s", ops)
			}
			if c.unreadable {
				return
			}
			// The drain goes on behind the lift: the narrow routes still protect.
			if out, err := execCommand(sh, r8SecondChancePre+body, io.BackstopReady, final); err != nil {
				t.Fatalf("run after the lift: %v: %s", err, out)
			}
			if got := strings.Count(r8Ops(t, native, c.name), "route replace blackhole"); got != 5 {
				t.Fatalf("after the final lift the drain installed %d of 5 routes", got)
			}
		})
	}
}

// The lift has no lock, so no lock state can skip the drain. A lock left behind by an
// older hook, and one that reappears whenever it is removed (the race the round-8 form lost: its
// drain hung on a mkdir that another actor could win), change nothing: routes first, then the lift.
func TestNoLockStateSkipsTheDrain(t *testing.T) {
	for _, c := range []struct{ name, pre string }{
		{"stale lock", "mkdir \"$R.lk\"; echo \"999999 1\" > \"$R.lk/own\"\n"},
		{"live lock", "mkdir \"$R.lk\"; echo \"$$ 1599\" > \"$R.lk/own\"\n"},
		{"lock retaken", "mkdir \"$R.lk\"; echo \"999999 1\" > \"$R.lk/own\"\nrm() { command rm \"$@\"; command mkdir \"$R.lk\" 2>/dev/null; return 0; }\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			name := strings.ReplaceAll(c.name, " ", "_")
			sh, _, native, pl, io, body := r8SecondChanceSetup(t, name)
			bs := pl.KillSwitchBackstop(io)
			r9Write(t, native, name+".restore", drainFile(fmt.Sprintf("add %s 192.0.2.1 -exist\nadd %s 2001:db8::1 -exist\n", bs.ZoneSets4[0], bs.ZoneSets6[0])))
			r9Write(t, native, name+".learned", learnedFile(fmt.Sprintf("add %s 198.51.100.1 -exist\n", bs.Sets4[0])))
			pre := r8SecondChancePre + "sleep() { echo \"$*\" >> \"$R.sleeps\"; }\n" + c.pre
			if out, err := execCommand(sh, pre+body+"\ntrue\n", io.BackstopReady, "1600"); err != nil {
				t.Fatalf("run: %v: %s", err, out)
			}
			ops := r8Ops(t, native, name)
			if got := strings.Count(ops, "route replace blackhole"); got != 3 {
				t.Fatalf("installed %d narrow routes, want 3:\n%s", got, ops)
			}
			lastAdd, firstDel := strings.LastIndex(ops, "route replace blackhole"), strings.Index(ops, "route del default")
			if firstDel < 0 || lastAdd > firstDel {
				t.Fatalf("the broad hold was lifted without the drain before it:\n%s", ops)
			}
			if r9Exists(native, name+".sleeps") {
				t.Fatal("the hook waited inline")
			}
		})
	}
}

// A live timer is bound by its own start, not by a flat wait: the hook leaves it alone
// through due+grace+final (no drain, no lift, no sleep; before, the first rebuild past due+grace
// repeated the timer's drain inline). At the final bound the hook lifts. Without a live timer the
// hook takes over at once and resumes at the timer's last route instead of redoing its work.
func TestSecondChanceBoundsALiveTimerByItsStart(t *testing.T) {
	final := 600 + BootHoldLiftGrace + BootHoldLiftFinal
	for _, c := range []struct {
		name, armed, due string
		up, pos          int
		routes           int
		lifted           bool
	}{
		{name: "before due", up: 599},
		{name: "no timer in the window", up: 700, routes: 3, lifted: true},
		{name: "dead timer in the window", armed: "999999", up: 700, routes: 3, lifted: true},
		{name: "dead timer resumes its work", armed: "999999", up: 1600, pos: 2, routes: 1, lifted: true},
		{name: "live timer in the window", armed: "$$", up: 700},
		{name: "live timer past the grace", armed: "$$", up: 1600},
		{name: "live timer one second before the final bound", armed: "$$", up: final - 1},
		{name: "live timer at the final bound", armed: "$$", up: final, routes: 3, lifted: true},
		{name: "late due not reached", due: "5030", up: 5029},
		{name: "late due reached", due: "5030", up: 5030, routes: 3, lifted: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			name := strings.ReplaceAll(c.name, " ", "_")
			sh, _, native, pl, io, body := r8SecondChanceSetup(t, name)
			bs := pl.KillSwitchBackstop(io)
			r9Write(t, native, name+".restore", drainFile(r9Records(bs.ZoneSets4[0], 3)))
			r9Write(t, native, name+".learned", learnedFile(""))
			pre := r8SecondChancePre + "sleep() { echo \"$*\" >> \"$R.sleeps\"; }\n"
			if c.armed != "" {
				pre += "echo \"" + c.armed + "\" > \"$R.armed\"\n"
			}
			if c.due != "" {
				pre += "echo " + c.due + " > \"$R.due\"\n"
			}
			if c.pos > 0 {
				pre += r9PosStamp(c.pos+r9HeaderLines, native, name+".restore")
			}
			if out, err := execCommand(sh, pre+body+"\ntrue\n", io.BackstopReady, strconv.Itoa(c.up)); err != nil {
				t.Fatalf("run: %v: %s", err, out)
			}
			ops := r8Ops(t, native, name)
			if got := strings.Count(ops, "route replace blackhole"); got != c.routes {
				t.Fatalf("installed %d routes, want %d:\n%s", got, c.routes, ops)
			}
			if got := r9Exists(native, name+StampLifted); got != c.lifted {
				t.Fatalf("lifted = %v, want %v:\n%s", got, c.lifted, ops)
			}
			if !c.lifted && ops != "" {
				t.Fatalf("a run that must leave the hold alone touched the table:\n%s", ops)
			}
			if r9Exists(native, name+".sleeps") {
				t.Fatal("the hook waited inline")
			}
		})
	}
}

// r9HeaderLines is how many lines precede the records in a drain file.
const r9HeaderLines = 1

// r9PosStamp is shell that writes the position stamp of a drain that installed through line n of
// the file's present content.
func r9PosStamp(n int, native, file string) string {
	raw, _ := os.ReadFile(filepath.Join(native, file))
	return fmt.Sprintf("echo \"%s %d\" > \"$R.restore.pos\"\n", drainKey(raw), n)
}

// The timer is the bound that needs no later event (requirement B): it waits for the due second,
// lifts when the data is complete, and otherwise waits for due+grace and lifts whatever its drain
// did. A timer started again past a bound does not wait for it, and one that finds the ready stamp
// leaves everything alone.
func TestLiftTimerIsBoundedByItself(t *testing.T) {
	for _, c := range []struct {
		name, due, up   string
		unreadable      bool
		readyDuringWait bool
		sleeps          string
		routes          int
		lifted          bool
	}{
		{name: "complete at due", up: "10", sleeps: "590", routes: 2, lifted: true},
		{name: "failed drain waits for the grace", up: "10", unreadable: true, sleeps: "590 900", routes: 1, lifted: true},
		{name: "restarted past both bounds", up: "2000", unreadable: true, routes: 1, lifted: true},
		{name: "restarted inside the grace", up: "1000", unreadable: true, sleeps: "500", routes: 1, lifted: true},
		{name: "late due", due: "5030", up: "5000", sleeps: "30", routes: 2, lifted: true},
		{name: "ready while waiting", up: "10", readyDuringWait: true, sleeps: "590"},
	} {
		t.Run(c.name, func(t *testing.T) {
			name := strings.ReplaceAll(c.name, " ", "_")
			sh, _, native, pl, io, _ := r8SecondChanceSetup(t, name)
			bs := pl.KillSwitchBackstop(io)
			if c.unreadable {
				if err := os.Mkdir(filepath.Join(native, name+".restore"), 0o755); err != nil {
					t.Fatal(err)
				}
			} else {
				r9Write(t, native, name+".restore", drainFile(r9Records(bs.ZoneSets4[0], 1)))
			}
			r9Write(t, native, name+".learned", learnedFile(fmt.Sprintf("add %s 203.0.113.9 -exist\n", bs.Sets4[0])))
			pre := r8SecondChancePre + "sleep() { echo \"$1\" >> \"$R.sleeps\"; UP=$((UP+$1)); "
			if c.readyDuringWait {
				pre += ": > \"$R\"; "
			}
			pre += "}\n"
			if c.due != "" {
				pre += "echo " + c.due + " > \"$R.due\"\n"
			}
			if out, err := execCommand(sh, pre+pl.liftTimer(Options{}, io, bs)+"\ntrue\n", io.BackstopReady, c.up); err != nil {
				t.Fatalf("timer: %v: %s", err, out)
			}
			raw, _ := os.ReadFile(filepath.Join(native, name+".sleeps"))
			if got := strings.Join(strings.Fields(string(raw)), " "); got != c.sleeps {
				t.Fatalf("waits %q, want %q", got, c.sleeps)
			}
			ops := r8Ops(t, native, name)
			if got := strings.Count(ops, "route replace blackhole"); got != c.routes {
				t.Fatalf("installed %d routes, want %d:\n%s", got, c.routes, ops)
			}
			if got := r9Exists(native, name+StampLifted); got != c.lifted {
				t.Fatalf("lifted = %v, want %v:\n%s", got, c.lifted, ops)
			}
			if armed, err := os.ReadFile(filepath.Join(native, name+stampArmed)); err != nil || strings.Trim(strings.TrimSpace(string(armed)), "0123456789") != "" || len(strings.TrimSpace(string(armed))) == 0 {
				t.Fatalf("armed stamp = %q, %v; want the timer's pid", armed, err)
			}
		})
	}
}

// The due second is fixed once per boot by the run that first installs the hold: the configured
// bound, or half a minute from now when the hold comes after it.
func TestBootHoldFixesItsDueSecondOnce(t *testing.T) {
	sh, dir, native := shDir(t)
	pl := backstopPlan(t)
	io := holdOptions()
	io.BackstopReady = dir + "/ready"
	var hook strings.Builder
	pl.writeBootHold(&hook, Options{}, io, pl.KillSwitchBackstop(io))
	pre := r8SecondChancePre + "setsid() { return 0; }\n"
	due := func() string {
		raw, _ := os.ReadFile(filepath.Join(native, "ready"+stampDue))
		return strings.TrimSpace(string(raw))
	}
	for _, c := range []struct {
		up, want string
		reset    bool
	}{{"100", "600", true}, {"5000", "600", false}, {"599", "600", true}, {"600", "630", true}, {"5000", "5030", true}} {
		if c.reset {
			_ = os.Remove(filepath.Join(native, "ready"+stampDue))
		}
		if out, err := execCommand(sh, pre+hook.String()+"\ntrue\n", io.BackstopReady, c.up); err != nil {
			t.Fatalf("hold at %s: %v: %s", c.up, err, out)
		}
		if got := due(); got != c.want {
			t.Fatalf("hold at uptime %s (fresh boot %v): due %q, want %q", c.up, c.reset, got, c.want)
		}
	}
}

// Found while fixing round 9 (requirement B): the boot hold wrote its stamps with `: > file`. `:` is a
// special builtin, and a redirection error on one ends a non-interactive POSIX shell, ash included.
// With a tmpfs that takes no file the hook ended at the fill's stamp, before the plane's rules and
// chain, on every run. The stamps are written by `echo` now: the failure is one command's status.
func TestUnwritableStampsDoNotEndTheHook(t *testing.T) {
	sh, dir, native := shDir(t)
	pl := backstopPlan(t)
	io := holdOptions()
	io.FillTool = dir + "/fill"            // not there: the call fails, as a fill that cannot start
	io.BackstopReady = dir + "/gone/ready" // its directory does not exist: no stamp can be written
	io.BootRestore, io.BootLearned = dir+"/restore", dir+"/learned"
	bs := pl.KillSwitchBackstop(io)
	r9Write(t, native, "restore", drainFile(r9Records(bs.ZoneSets4[0], 2)))
	r9Write(t, native, "learned", learnedFile(""))
	var hook strings.Builder
	pl.writeBootHold(&hook, Options{}, io, bs)
	body := hook.String() + renderSecondChanceForTest(t, pl, io)
	if strings.Contains(body, ": > ") {
		t.Fatal("the boot hold writes a stamp with the special builtin `:`")
	}
	pre := r8SecondChancePre + "setsid() { return 0; }\n"
	for _, up := range []string{"100", "700", "2000"} {
		_, _ = execCommand(sh, pre+body+"\necho reached > \"$R.reached\"\n", dir+"/mark", up)
		if !r9Exists(native, "mark.reached") {
			t.Fatalf("uptime %s: the hook ended at a stamp it could not write", up)
		}
		_ = os.Remove(filepath.Join(native, "mark.reached"))
	}
	// The narrow routes went in and the broad hold was taken away all the same.
	ops := r8Ops(t, native, "mark")
	if !strings.Contains(ops, "blackhole 198.51.100.2 table") || !strings.Contains(ops, "route del default") {
		t.Fatalf("without stamps the drain and the lift must still run:\n%s", ops)
	}
}

// Every read of a stamp or state file sends stderr away before it opens the file, so a
// file that is not there (or goes between a test and the open) prints nothing. The form
// `< file 2>/dev/null` opens first and complains first.
func TestStateReadsRedirectStderrBeforeTheFile(t *testing.T) {
	script := backstopPlan(t).RenderKeeneticScript(Options{}, holdOptions())
	if m := regexp.MustCompile(`<\s*/\S+\s+2>\s*/dev/null`).FindString(script); m != "" {
		t.Fatalf("a read opens its file before it redirects stderr: %q", m)
	}
	for _, guard := range []string{"[ -r /tmp/wayhop-backstop.ready.armed ]", "[ -r /tmp/wayhop-backstop.ready.due ]", ".pos ]"} {
		if strings.Contains(script, guard) {
			t.Fatalf("a state read is still test-then-open: %q", guard)
		}
	}
}
