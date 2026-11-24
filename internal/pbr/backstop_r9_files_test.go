package pbr

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// A progress stamp names the content it describes and counts for nothing under another.
// Before, .pos and .done outlived a rewrite of the file: a position into the old file skipped the
// new file's records and the hold lifted without them.
func TestProgressStampsDieWithTheContentTheyDescribe(t *testing.T) {
	const other = "0123456789abcdef"
	for _, c := range []struct {
		name, pre string
		routes    int
	}{
		{"stale position", `echo "` + other + ` 150" > "$R.restore.pos"`, 2},
		{"stale done", `echo "` + other + `" > "$R.restore.done"`, 2},
		{"unkeyed stamps of an older hook", `echo 150 > "$R.restore.pos"; : > "$R.restore.done"; : > "$R.data"`, 2},
		{"position of this content", "", 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			name := strings.ReplaceAll(c.name, " ", "_")
			sh, _, native, pl, io, body := r8SecondChanceSetup(t, name)
			bs := pl.KillSwitchBackstop(io)
			r9Write(t, native, name+".restore", drainFile(r9Records(bs.ZoneSets4[0], 2)))
			r9Write(t, native, name+".learned", learnedFile(""))
			pre := c.pre + "\n"
			if c.pre == "" {
				pre = r9PosStamp(1+r9HeaderLines, native, name+".restore")
			}
			if out, err := execCommand(sh, r8SecondChancePre+pre+body, io.BackstopReady, "700"); err != nil {
				t.Fatalf("run: %v: %s", err, out)
			}
			ops := r8Ops(t, native, name)
			if got := strings.Count(ops, "route replace blackhole"); got != c.routes {
				t.Fatalf("installed %d routes, want %d:\n%s", got, c.routes, ops)
			}
			if !r9Exists(native, name+StampLifted) {
				t.Fatal("the completed drain did not lift")
			}
		})
	}
	// An Apply replaces the file between two passes of the hook: the second pass starts at the top
	// of the new content instead of at the old position.
	t.Run("file replaced between passes", func(t *testing.T) {
		sh, _, native, pl, io, body := r8SecondChanceSetup(t, "replaced")
		bs := pl.KillSwitchBackstop(io)
		var first strings.Builder
		for i := 0; i < 70; i++ {
			fmt.Fprintf(&first, "add %s 198.51.100.%d -exist\n", bs.ZoneSets4[0], i+1)
		}
		r9Write(t, native, "replaced.restore", drainFile(first.String()))
		r9Write(t, native, "replaced.learned", learnedFile(""))
		if out, err := execCommand(sh, r8SecondChancePre+body, io.BackstopReady, "700"); err != nil {
			t.Fatalf("first pass: %v: %s", err, out)
		}
		if r9Exists(native, "replaced"+StampLifted) {
			t.Fatal("the capped first pass lifted")
		}
		second := fmt.Sprintf("add %s 203.0.113.1 -exist\nadd %s 203.0.113.2 -exist\nadd %s 203.0.113.3 -exist\n", bs.ZoneSets4[0], bs.ZoneSets4[0], bs.ZoneSets4[0])
		r9Write(t, native, "replaced.restore", drainFile(second))
		if out, err := execCommand(sh, r8SecondChancePre+body, io.BackstopReady, "701"); err != nil {
			t.Fatalf("second pass: %v: %s", err, out)
		}
		ops := r8Ops(t, native, "replaced")
		if got := strings.Count(ops, "blackhole 203.0.113."); got != 3 {
			t.Fatalf("the new content got %d of its 3 routes:\n%s", got, ops)
		}
		if !r9Exists(native, "replaced"+StampLifted) {
			t.Fatal("the completed drain of the new content did not lift")
		}
	})
}

// The drain header: a key per content, the number of add lines, written once.
func TestKeyedRestore(t *testing.T) {
	a := KeyedRestore([]byte("create x hash:net\nadd x 192.0.2.0/24 -exist\n  add x 198.51.100.0/24\n# add nothing\n"))
	b := KeyedRestore([]byte("create x hash:net\nadd x 192.0.2.0/24 -exist\n  add x 198.51.101.0/24\n# add nothing\n"))
	fa, fb := strings.Fields(string(a)), strings.Fields(string(b))
	if !HasDrainHeader(a) || fa[0]+" "+fa[1] != drainHeader || fa[3] != "2" {
		t.Fatalf("header: %q", strings.SplitN(string(a), "\n", 2)[0])
	}
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(fa[2]) || fa[2] == fb[2] {
		t.Fatalf("keys %q and %q: want 16 hex digits, different for different contents", fa[2], fb[2])
	}
	if again := KeyedRestore(a); string(again) != string(a) {
		t.Fatalf("keying a keyed file changed it:\n%s", again)
	}
	if empty := KeyedRestore(nil); !regexp.MustCompile(`^# wayhop-key [0-9a-f]{16} 0\n$`).Match(empty) {
		t.Fatalf("empty stream: %q", empty)
	}
	if HasDrainHeader([]byte("add x 192.0.2.1\n")) {
		t.Fatal("a stream without the header was taken for a keyed one")
	}
}

// The restore file exists whenever a kill switch is applied, so a missing one (or one
// an older build wrote, without the header) is a failed drain, not an empty complete input: the hold
// waits for its bound. Round 8 lifted at once. An absent learned file stays complete.
func TestAbsentRestoreFileIsAFailedDrain(t *testing.T) {
	final := strconv.Itoa(600 + BootHoldLiftGrace + BootHoldLiftFinal)
	for _, c := range []struct {
		name    string
		restore []byte
	}{{"absent", nil}, {"without a header", []byte("add wr_list_iplist_4 192.0.2.1 -exist\n")}, {"empty", []byte{}}} {
		t.Run(c.name, func(t *testing.T) {
			name := strings.ReplaceAll(c.name, " ", "_")
			sh, _, native, pl, io, body := r8SecondChanceSetup(t, name)
			bs := pl.KillSwitchBackstop(io)
			if c.restore != nil {
				r9Write(t, native, name+".restore", c.restore)
			}
			r9Write(t, native, name+".learned", learnedFile(fmt.Sprintf("add %s 203.0.113.9 -exist\n", bs.Sets4[0])))
			for _, up := range []string{"700", "1600"} {
				out, err := execCommand(sh, r8SecondChancePre+body, io.BackstopReady, up)
				if err != nil || out != "" {
					t.Fatalf("uptime %s: %v: %q", up, err, out)
				}
				if r9Exists(native, name+StampLifted) {
					t.Fatalf("uptime %s: lifted without the restore file's routes", up)
				}
			}
			ops := r8Ops(t, native, name)
			if strings.Count(ops, "route replace blackhole") != 1 || !strings.Contains(ops, "blackhole 203.0.113.9 table") {
				t.Fatalf("the learned file's route must still go in, and nothing from a file without a header:\n%s", ops)
			}
			if _, err := execCommand(sh, r8SecondChancePre+body, io.BackstopReady, final); err != nil || !r9Exists(native, name+StampLifted) {
				t.Fatalf("the final bound did not lift: %v", err)
			}
		})
	}
}

// A file is whole when it holds as many add lines as its header says and, for the
// learned file, as its trailer says. Fewer (a cut file), a missing trailer or a trailer that
// disagrees: what is there is installed, the file is not complete and the hold stays.
func TestCutOrMiscountedFilesAreNotComplete(t *testing.T) {
	bs := backstopPlan(t).KillSwitchBackstop(holdOptions())
	set, dom := bs.ZoneSets4[0], bs.Sets4[0]
	whole := drainFile(r9Records(set, 3))
	lines := strings.SplitAfter(string(whole), "\n")
	entry := fmt.Sprintf("add %s 203.0.113.9 timeout 3600 -exist\n", dom)
	learned := learnedFile(entry)
	header := strings.SplitAfter(string(learned), "\n")[0]
	for _, c := range []struct {
		name             string
		restore, learned []byte
		routes           int
		lifted           bool
	}{
		{"whole", whole, learned, 4, true},
		{"restore one record short", []byte(strings.Join(lines[:3], "")), learned, 3, false},
		{"learned without its trailer", whole, []byte(header + entry), 4, false},
		{"learned trailer disagrees", whole, []byte(header + entry + LearnedTrailer + "2\n"), 4, false},
		{"learned cut inside its trailer", whole, []byte(header + entry + "# wayhop-lear"), 4, false},
		{"learned cut before its entry", whole, []byte(header), 3, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			name := strings.ReplaceAll(c.name, " ", "_")
			sh, _, native, _, io, body := r8SecondChanceSetup(t, name)
			r9Write(t, native, name+".restore", c.restore)
			r9Write(t, native, name+".learned", c.learned)
			for run := 0; run < 2; run++ { // the second run must not turn "not whole" into "done"
				if out, err := execCommand(sh, r8SecondChancePre+body, io.BackstopReady, "700"); err != nil || out != "" {
					t.Fatalf("run: %v: %q", err, out)
				}
			}
			ops := r8Ops(t, native, name)
			if got := strings.Count(ops, "route replace blackhole"); got < c.routes {
				t.Fatalf("installed %d routes, want the %d that are there:\n%s", got, c.routes, ops)
			}
			if got := r9Exists(native, name+StampLifted); got != c.lifted {
				t.Fatalf("lifted = %v, want %v:\n%s", got, c.lifted, ops)
			}
		})
	}
}
