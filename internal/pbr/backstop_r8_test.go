package pbr

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func r8SecondChanceSetup(t *testing.T, name string) (string, string, string, *Plan, IpsetOptions, string) {
	t.Helper()
	sh, dir, native := shDir(t)
	pl := backstopPlan(t)
	io := holdOptions()
	io.FillTool = ""
	io.BackstopReady = dir + "/" + name
	io.BootRestore = dir + "/" + name + ".restore"
	io.BootLearned = dir + "/" + name + ".learned"
	return sh, dir, native, pl, io, renderSecondChanceForTest(t, pl, io)
}

const r8SecondChancePre = `R="$1"; UP="$2"
read() {
	if [ "${2-}" = wr_up ]; then wr_up=$UP; wr_x=0; return 0; fi
	command read "$@"
}
ip() { echo "$*" >> "$R.ops"; return 0; }
`

func r8Ops(t *testing.T, native, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(native, name+".ops"))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// The uncapped hard drain resumes the committed soft-pass position instead of repeating routes.
func TestSecondChanceHardDrainResumesSoftProgress(t *testing.T) {
	sh, _, native, pl, io, body := r8SecondChanceSetup(t, "ready")
	bs := pl.KillSwitchBackstop(io)
	var restore strings.Builder
	for i := 0; i < 70; i++ {
		fmt.Fprintf(&restore, "add %s 198.51.%d.%d -exist\n", bs.ZoneSets4[0], i/256, i%256)
	}
	if err := os.WriteFile(filepath.Join(native, "ready.restore"), drainFile(restore.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(native, "ready.learned"), learnedFile(""), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, up := range []string{"700", "1600"} {
		if out, err := execCommand(sh, r8SecondChancePre+body, io.BackstopReady, up); err != nil {
			t.Fatalf("uptime %s: %v: %s", up, err, out)
		}
	}
	if got := strings.Count(r8Ops(t, native, "ready"), "route replace blackhole"); got != 70 {
		t.Fatalf("soft+hard passes installed %d routes, want each of the 70 exactly once", got)
	}
}

// Unrelated restore records cost a shell read, not one of the route-installing slots.
func TestSecondChanceSoftBudgetCountsOnlyRoutes(t *testing.T) {
	sh, _, native, pl, io, body := r8SecondChanceSetup(t, "ready")
	bs := pl.KillSwitchBackstop(io)
	var restore strings.Builder
	for i := 0; i < 70; i++ {
		fmt.Fprintf(&restore, "add unrelated_4 10.%d.%d.1\n", i/256, i%256)
	}
	fmt.Fprintf(&restore, "add %s 192.0.2.1 -exist\n", bs.ZoneSets4[0])
	for i := 0; i < 70; i++ {
		fmt.Fprintf(&restore, "add another_4 172.%d.%d.1\n", i/256, i%256)
	}
	if err := os.WriteFile(filepath.Join(native, "ready.restore"), drainFile(restore.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(native, "ready.learned"), learnedFile(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := execCommand(sh, r8SecondChancePre+body, io.BackstopReady, "700"); err != nil {
		t.Fatalf("soft pass: %v: %s", err, out)
	}
	if got := strings.Count(r8Ops(t, native, "ready"), "route replace blackhole"); got != 1 {
		t.Fatalf("installed %d routes, want 1 despite the unrelated lines", got)
	}
	if _, err := os.Stat(filepath.Join(native, "ready"+StampLifted)); err != nil {
		t.Fatal("nonmatching records exhausted the soft budget and delayed the lift")
	}
}

// A learned file that has never been created is an empty, complete input.
func TestSecondChanceMissingLearnedFileDoesNotDelayLift(t *testing.T) {
	sh, _, native, pl, io, body := r8SecondChanceSetup(t, "ready")
	bs := pl.KillSwitchBackstop(io)
	restore := fmt.Sprintf("add %s 192.0.2.1 -exist\n", bs.ZoneSets4[0])
	if err := os.WriteFile(filepath.Join(native, "ready.restore"), drainFile(restore), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := execCommand(sh, r8SecondChancePre+body, io.BackstopReady, "700"); err != nil {
		t.Fatalf("soft pass: %v: %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(native, "ready"+StampLifted)); err != nil {
		t.Fatal("an absent learned file delayed the lift")
	}
}

// Missing optional stamp/state files produce no ash redirection diagnostics.
func TestMissingBackstopStateReadsAreSilent(t *testing.T) {
	t.Run("owner and positions", func(t *testing.T) {
		sh, _, native, _, io, body := r8SecondChanceSetup(t, "ready")
		for suffix, data := range map[string][]byte{".restore": drainFile(""), ".learned": learnedFile("")} {
			if err := os.WriteFile(filepath.Join(native, "ready"+suffix), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		// No due stamp, no armed stamp, no positions: every read is of a file that is not there.
		if out, err := execCommand(sh, r8SecondChancePre+body, io.BackstopReady, "700"); err != nil || out != "" {
			t.Fatalf("missing state reads: err %v, output %s", err, out)
		}
	})
	t.Run("armed", func(t *testing.T) {
		sh, dir, _ := shDir(t)
		pl := backstopPlan(t)
		io := holdOptions()
		io.BackstopReady = dir + "/ready"
		var hook strings.Builder
		pl.writeBootHold(&hook, Options{}, io, pl.KillSwitchBackstop(io))
		pre := "R=\"$1\"\nip() { return 0; }\nsetsid() { return 0; }\n"
		out, err := execCommand(sh, pre+hook.String()+"\nwait\n", io.BackstopReady)
		if err != nil {
			t.Fatalf("boot hold: %v: %s", err, out)
		}
		if out != "" {
			t.Fatalf("missing armed stamp printed diagnostics: %s", out)
		}
	})
}

// Every writer ends each line, so a last record without its newline is a cut
// one. It is not installed (round 8 installed it, cut mid-address too) and the file is not whole:
// the records before it are in, the hold stays.
func TestSecondChanceRefusesACutLastRecord(t *testing.T) {
	sh, _, native, pl, io, body := r8SecondChanceSetup(t, "ready")
	bs := pl.KillSwitchBackstop(io)
	restore := fmt.Sprintf("add %s 192.0.2.1 -exist\nadd %s 198.51.100", bs.ZoneSets4[0], bs.ZoneSets4[0])
	if err := os.WriteFile(filepath.Join(native, "ready.restore"), drainFile(restore), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(native, "ready.learned"), learnedFile(""), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := execCommand(sh, r8SecondChancePre+body, io.BackstopReady, "700"); err != nil {
		t.Fatalf("soft pass: %v: %s", err, out)
	}
	ops := r8Ops(t, native, "ready")
	if got := strings.Count(ops, "route replace blackhole"); got != 1 || strings.Contains(ops, "198.51.100") {
		t.Fatalf("installed %d routes, want the whole record only:\n%s", got, ops)
	}
	if _, err := os.Stat(filepath.Join(native, "ready"+StampLifted)); err == nil {
		t.Fatal("a cut restore file counted as complete and lifted the hold")
	}
}
