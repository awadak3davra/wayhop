package pbr

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func holdOptions() IpsetOptions {
	io := bsOptions()
	io.BootRestore = "/opt/etc/ndm/wayhop-policy.ipset"
	io.BootLearned = "/opt/etc/ndm/wayhop-learned.ipset"
	io.BackstopReady = "/tmp/wayhop-backstop.ready"
	io.FillTool, io.BootHoldLift = "/opt/bin/wayhop", 600
	return io
}

// The hold's routes and the backstop's rules come before the set restores and the fill.
// The hold arms its own timer, once per boot, so the lift needs no later hook run.
func TestBootHoldPrecedesRestoreAndFillAndArmsItsTimer(t *testing.T) {
	script := backstopPlan(t).RenderKeeneticScript(Options{}, holdOptions())
	at := func(s string) int { return strings.Index(script, s) }
	hold, armed, rule := at("ip route replace blackhole default table 407"), at("wayhop-backstop.ready.armed"), at("\nip rule add iif br0 fwmark")
	restore, fill, chain := at("ipset restore -!"), at("backstop-fill"), at("iptables")
	if hold < 0 || armed < hold || rule < armed || restore < rule || fill < restore || (chain >= 0 && chain < fill) {
		t.Fatalf("hold@%d armed@%d rule@%d restore@%d fill@%d chain@%d", hold, armed, rule, restore, fill, chain)
	}
	// The due second is fixed by the first run of the boot; the timer waits for it and for the grace
	// from the uptime, and lifts at the second wait whatever its drain did.
	mustContain(t, script, "[ -s /tmp/wayhop-backstop.ready.due ] || { wr_d=600; [ \"${wr_up:-0}\" -lt 600 ] 2>/dev/null || wr_d=$((${wr_up:-0} + 30)); echo \"$wr_d\" > /tmp/wayhop-backstop.ready.due; }")
	mustContain(t, script, "wr_due; wr_wait \"$wr_d\"; wr_drain -1 && wr_lift\n")
	mustContain(t, script, "{ wr_wait $((wr_d + 900)); wr_drain -1; wr_lift; }")
	// No lock; the hook leaves a live timer alone until due+grace+final.
	for _, gone := range []string{".ready.lk", "mkdir ", "rm -rf"} {
		if strings.Contains(script, gone) {
			t.Fatalf("the lift still has a lock: %q", gone)
		}
	}
	mustContain(t, script, "if [ \"$wr_up\" -lt $((wr_d + 1200)) ] 2>/dev/null; then")
	// The timer leaves the hook's session through the pinned shell applet.
	mustContain(t, script, "if command -v setsid >/dev/null 2>&1; then setsid \"${wr_sh:-/opt/bin/sh}\" ${wr_sha:-} -c \"$wr_fns$wr_t\"")
	mustContain(t, script, "\"$wr_bb\" start-stop-daemon -S -b")
	mustContain(t, script, "( trap '' HUP; \"${wr_sh:-/opt/bin/sh}\" ${wr_sha:-} -c \"$wr_fns$wr_t\"")
	// The fallback reads the learned file too.
	mustContain(t, script, "} 2>/dev/null < /opt/etc/ndm/wayhop-learned.ipset || wr_ok=0")
}

// A shared-space throw is not rendered under a kill-switched prefix that contains it (it
// would send that prefix's packets to the main table in every rebuild window), and the lift removes
// the shared throws with the hold.
func TestHoldThrowNeverShadowsAKillSwitchedPrefix(t *testing.T) {
	p := backstopProfile()
	p.RoutingLists[1].Manual = append(p.RoutingLists[1].Manual, "100.64.0.0/10")
	pl, _, err := Compile(p, Options{CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	script := pl.RenderKeeneticScript(Options{}, holdOptions())
	if strings.Contains(script, "replace throw 100.64.0.0/10") {
		t.Fatal("a throw for 100.64.0.0/10 under a kill-switched list that holds that range")
	}
	mustContain(t, script, "\tip route del throw 100.64.0.0/10 table 407 2>/dev/null\n")
	mustContain(t, script, "ip route replace throw 169.254.0.0/16 table 407 && ")
	mustContain(t, script, "ip route del throw 169.254.0.0/16 table 407 2>/dev/null")
}

// The lifted stamp is written only once the hold's default routes are gone; a route that
// is already gone counts.
func TestLiftWritesItsStampOnlyAfterTheHoldIsGone(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	native := t.TempDir()
	out, err := exec.Command(sh, "-c", `cd "$1" && pwd`, "sh", native).Output()
	if err != nil {
		t.Skipf("sh cannot enter the temp dir: %v", err)
	}
	dir := strings.TrimSpace(string(out))
	pl := backstopPlan(t)
	if !strings.Contains(pl.liftCore(Options{}, holdOptions(), pl.KillSwitchBackstop(holdOptions())), "ip -6 route del default") {
		t.Fatal("the plan under test has no v6 hold")
	}
	// A family is judged by read-back, not by the delete's text. A kernel without IPv6
	// routing answers the v6 delete "Operation not supported" and refuses the v6 read: nothing is held
	// there. A v4 default that a read-back still shows (or a v4 read that fails) is not gone.
	for _, c := range []struct {
		name, fail, fail6, show4 string
		show6err                 bool
		lifted                   bool
	}{
		{name: "removed", lifted: true},
		{name: "already gone", fail: "RTNETLINK answers: No such process", lifted: true},
		{name: "refused", fail: "RTNETLINK answers: Operation not permitted", show4: "blackhole default ", lifted: false},
		{name: "refused, read back gone", fail: "RTNETLINK answers: Operation not permitted", lifted: true},
		{name: "v6 refused by the kernel", fail6: "RTNETLINK answers: Operation not supported", show6err: true, lifted: true},
		{name: "v6 refused, still there", fail6: "RTNETLINK answers: Operation not permitted", lifted: false},
	} {
		io := holdOptions()
		io.BackstopReady = dir + "/" + strings.NewReplacer(" ", "_", ",", "").Replace(c.name)
		bs := pl.KillSwitchBackstop(io)
		script := `ip() { f=4; [ "$1" = -6 ] && { f=6; shift; }
case "$f $*" in
"4 route del default"*) [ -n "$FAIL" ] && { echo "$FAIL" >&2; return 2; } ;;
"6 route del default"*) [ -n "$FAIL6" ] && { echo "$FAIL6" >&2; return 2; } ;;
"4 route show"*) echo "$SHOW4" ;;
"6 route show"*) [ -n "$SHOW6ERR" ] && return 1; [ -n "$FAIL6" ] && echo "blackhole default " ;;
esac; return 0; }` + "\n" + pl.liftCore(Options{}, io, bs) + "\n"
		cmd := exec.Command(sh, "-c", script)
		show6 := ""
		if c.show6err {
			show6 = "1"
		}
		cmd.Env = append(os.Environ(), "FAIL="+c.fail, "FAIL6="+c.fail6, "SHOW4="+c.show4, "SHOW6ERR="+show6)
		_ = cmd.Run() // the kernel-log line fails off a router; the stamp is the result
		_, err := os.Stat(filepath.Join(native, strings.NewReplacer(" ", "_", ",", "").Replace(c.name)+StampLifted))
		if (err == nil) != c.lifted {
			t.Fatalf("%s: lifted stamp present=%v, want %v", c.name, err == nil, c.lifted)
		}
	}
}

// The broader case, a kill-switched /8 around the shared /10 (built, not written out).
func TestHoldThrowsUnderABroaderPrefix(t *testing.T) {
	wide := netip.PrefixFrom(netip.MustParsePrefix(holdShared4[0]).Addr(), 8).Masked()
	keep, drop := holdThrows([]netip.Prefix{wide})
	if !slices.Equal(drop, holdShared4[:1]) || !slices.Equal(keep, holdShared4[1:]) {
		t.Fatalf("under %s: keep %v drop %v", wide, keep, drop)
	}
	if keep, drop := holdThrows(nil); len(drop) != 0 || len(keep) != len(holdShared4) {
		t.Fatalf("nothing kill-switched: keep %v drop %v", keep, drop)
	}
}

// The lift and a hook run could cross. The hook passed its stamp check, the lift deleted
// the defaults and wrote .lifted, then the hook's replace put the default back: held until a reboot,
// since every later run skips the hold block on .lifted. A hook run with .lifted and no ready stamp now
// removes the defaults again, and the lift repeats its deletes after stamping (the other order).
func TestLiftAndHookCannotLeaveTheHoldBehindLifted(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	native := t.TempDir()
	out, err := exec.Command(sh, "-c", `cd "$1" && pwd`, "sh", native).Output()
	if err != nil {
		t.Skipf("sh cannot enter the temp dir: %v", err)
	}
	dir := strings.TrimSpace(string(out))
	pl := backstopPlan(t)
	io := holdOptions()
	io.BootHoldLift = 0 // no background timer in a test; the lift is run by the race below
	io.BackstopReady = dir + "/ready"
	bs := pl.KillSwitchBackstop(io)
	var hook strings.Builder
	pl.writeBootHold(&hook, Options{}, io, bs)
	script := `D="$1"
ip() { f=4; [ "$1" = -6 ] && { f=6; shift; }
case "$*" in
"route replace throw"*) [ -e "$D/raced" ] || { : > "$D/raced"; LIFT; } ;;
"route replace blackhole default"*) : > "$D/def$f" ;;
"route del default"*) [ -e "$D/def$f" ] || { echo "RTNETLINK answers: No such process" >&2; return 2; }; rm -f "$D/def$f" ;;
"route show"*) [ -e "$D/def$f" ] && echo "blackhole default " ;;
esac; return 0; }
LIFT() { ` + pl.liftCore(Options{}, io, bs) + `; }
` + hook.String()
	_ = exec.Command(sh, "-c", script, "sh", dir).Run()
	if _, err := os.Stat(filepath.Join(native, "raced")); err != nil {
		t.Fatal("the race was not staged")
	}
	if _, err := os.Stat(filepath.Join(native, "ready"+StampLifted)); err != nil {
		t.Fatal("the lift did not stamp")
	}
	for _, f := range []string{"def4", "def6"} {
		if _, err := os.Stat(filepath.Join(native, f)); err == nil {
			t.Fatalf("%s: the hold came back after .lifted and stayed", f)
		}
	}
	core := pl.liftCore(Options{}, holdOptions(), pl.KillSwitchBackstop(holdOptions()))
	stamp := strings.Index(core, "echo 2>/dev/null > /tmp/wayhop-backstop.ready.lifted")
	if stamp < 0 || !strings.Contains(core[stamp:], "ip route del default table 407") {
		t.Fatal("the lift does not delete the defaults again after stamping")
	}
}

// shDir runs sh in a native temp dir and returns sh, the dir as sh names it, and the native dir.
func shDir(t *testing.T) (string, string, string) {
	t.Helper()
	// WAYHOP_TEST_SH runs the shell tests under another POSIX shell (dash, busybox ash).
	name := os.Getenv("WAYHOP_TEST_SH")
	if name == "" {
		name = "sh"
	}
	sh, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("no %s", name)
	}
	native := t.TempDir()
	out, err := exec.Command(sh, "-c", `cd "$1" && pwd`, "sh", native).Output()
	if err != nil {
		t.Skipf("sh cannot enter the temp dir: %v", err)
	}
	return sh, strings.TrimSpace(string(out)), native
}

// The whole Keenetic program, hold, timer, fill and second chance included, parses as sh.
func TestKeeneticProgramWithHoldParses(t *testing.T) {
	sh, dir, native := shDir(t)
	script := backstopPlan(t).RenderKeeneticScript(Options{}, holdOptions())
	// From a file: a long -c argument with quotes is mangled by the Windows command line.
	if err := os.WriteFile(filepath.Join(native, "hook.sh"), []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(sh, "-n", dir+"/hook.sh").CombinedOutput(); err != nil {
		t.Fatalf("sh -n: %v: %s", err, out)
	}
}
