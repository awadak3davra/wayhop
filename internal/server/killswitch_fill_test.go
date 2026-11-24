package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"wayhop/internal/pbr"
	"wayhop/internal/rtblackhole"
)

// The boot fill: with the restore file and a whole learned file it installs the
// static prefixes and the learned members, writes the ready stamp and takes the broad hold away. With
// the learned file missing or cut it installs what it has and keeps the broad hold.
func TestBackstopFillCompleteAndPartial(t *testing.T) {
	dir := t.TempDir()
	static := filepath.Join(dir, "policy.ipset")
	learned := filepath.Join(dir, "learned.ipset")
	_ = os.WriteFile(static, []byte("create wr_list_tg_4 hash:net family inet -exist\nadd wr_list_tg_4 149.154.160.0/20 -exist\n"+
		"add wr_list_other_4 8.8.8.0/24 -exist\ncreate wr_list_dom_4 hash:net family inet timeout 86400 -exist\n"), 0o644)
	es := []ksEntry{{"wr_list_dom_4", netip.MustParsePrefix("198.51.100.7/32"), 3000}, {"wr_list_dom_4", netip.MustParsePrefix("149.154.167.99/32"), 50}}
	_ = os.WriteFile(learned, renderLearned(es, 100, 1<<20), 0o644)
	sets, domains := []string{"wr_list_dom_4", "wr_list_tg_4"}, []string{"wr_list_dom_4"}
	hold4, hold6 := netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")
	run := func(learnedPath string) (*fakeRouteTable, string, int) {
		table := &fakeRouteTable{routes: map[netip.Prefix]bool{hold4: true, hold6: true}}
		ready := filepath.Join(t.TempDir(), "ready")
		var errb bytes.Buffer
		code := runBackstopFill(table, ready, gatherFill(static, learnedPath, sets, domains), &errb)
		return table, ready, code
	}
	table, ready, code := run(learned)
	if code != 0 || table.routes[hold4] || table.routes[hold6] {
		t.Fatalf("complete fill: code %d routes %v", code, table.routes)
	}
	if !table.routes[netip.MustParsePrefix("149.154.160.0/20")] || !table.routes[netip.MustParsePrefix("198.51.100.7/32")] ||
		table.routes[netip.MustParsePrefix("8.8.8.0/24")] || table.routes[netip.MustParsePrefix("149.154.167.99/32")] {
		t.Fatalf("routes: %v", table.routes)
	}
	if _, err := os.Stat(ready); err != nil {
		t.Fatal("no ready stamp after a complete fill")
	}
	for name, path := range map[string]string{"missing": filepath.Join(dir, "nope"), "cut": func() string {
		p := filepath.Join(dir, "cut.ipset")
		data, _ := os.ReadFile(learned)
		_ = os.WriteFile(p, data[:len(data)/2], 0o644)
		return p
	}()} {
		table, ready, code := run(path)
		if code != ksFillPartial || !table.routes[hold4] || !table.routes[netip.MustParsePrefix("149.154.160.0/20")] {
			t.Fatalf("%s learned file: code %d routes %v", name, code, table.routes)
		}
		if _, err := os.Stat(ready); err == nil {
			t.Fatalf("%s learned file: ready stamp written", name)
		}
		if _, err := os.Stat(ready + pbr.StampPartial); err != nil {
			t.Fatalf("%s learned file: no partial stamp", name)
		}
		if _, err := os.Stat(ready + pbr.StampFilled); err != nil {
			t.Fatalf("%s learned file: no filled stamp", name)
		}
	}
}

// The learned file: capped by count and bytes keeping the newest (longest remaining timeout), the
// trailer counts what is kept, and it reads back.
func TestLearnedFileCapsAndRoundTrips(t *testing.T) {
	var es []ksEntry
	for i := 0; i < 10; i++ {
		es = append(es, ksEntry{"wr_list_dom_4", netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), 32), 100 + i})
	}
	data := renderLearned(es, 3, 1<<20)
	got, err := readLearnedKS(bytes.NewReader(data), []string{"wr_list_dom_4"})
	if err != nil || len(got) != 3 {
		t.Fatalf("read back %v %v\n%s", got, err, data)
	}
	for _, p := range got {
		if p.Addr().As4()[3] < 7 {
			t.Fatalf("an older entry kept over a newer one: %v", got)
		}
	}
	if small := renderLearned(es, 100, 120); bytes.Count(small, []byte("\nadd ")) >= 3 {
		t.Fatalf("byte cap ignored:\n%s", small)
	}
	if e := parseIpsetEntries("s", "Members:\n1.2.3.4 timeout 50\n10.0.0.0/8 timeout 0\n"); len(e) != 1 || e[0].ttl != 50 {
		t.Fatalf("entries: %v", e)
	}
}

// The mirror marks the learned file only when the members change, and the write goes through the
// coalescing writer (at most hourly).
func TestKillSwitchLearnedPersistedOnChangeOnly(t *testing.T) {
	s, _, _ := mirrorServer(t)
	writes := 0
	s.ksl.write = func(path string, data []byte, perm os.FileMode) error {
		writes++
		return os.WriteFile(path, data, perm)
	}
	members := []netip.Prefix{netip.MustParsePrefix("198.51.100.9/32")}
	s.ksb.reader = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(context.Context, string) ([]netip.Prefix, error) { return members, nil }
	}
	ctx := context.Background()
	s.killSwitchMirrorTick(ctx)
	if err := s.learnedWriter().Flush(); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatalf("first change: %d writes", writes)
	}
	data, _ := os.ReadFile(s.ksl.path)
	if !strings.Contains(string(data), "198.51.100.9 timeout") || !strings.Contains(string(data), ksLearnedTrailer+"2") {
		t.Fatalf("file:\n%s", data)
	}
	s.killSwitchMirrorTick(ctx)
	if s.learnedWriter().Pending() {
		t.Fatal("unchanged members marked the writer")
	}
	members = append(members, netip.MustParsePrefix("198.51.100.10/32"))
	s.killSwitchMirrorTick(ctx)
	if !s.learnedWriter().Pending() {
		t.Fatal("a new member did not mark the writer")
	}
	_ = s.learnedWriter().Close()
}

// The hook at boot, run as NDM runs it: the broad hold and the
// backstop rules first, then the sets (static, then learned) and the fill, then the chain. The hold
// arms its own timer: with no further hook run the broad hold is lifted when it is due, the static
// prefixes and the learned members coming from their files by the shell because the fill never
// reported them installed; the lifted stamp stops the next run re-adding the hold.
func TestKeeneticHookBootFillAndBoundedLift(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh to run the hook with")
	}
	// The hold is due liftMargin seconds after the uptime read here. /proc/uptime is read whole seconds
	// down, after readAt, so the due moment is no earlier than readAt + liftMargin - 1 s.
	const liftMargin = 10
	readAt := time.Now()
	dueNoEarlier := readAt.Add((liftMargin - 1) * time.Second)
	up, err := exec.Command(sh, "-c", `read u x < /proc/uptime && echo "${u%%.*}"`).Output()
	if err != nil {
		t.Skip("no /proc/uptime for the hook's timer")
	}
	uptime, err := strconv.Atoi(strings.TrimSpace(string(up)))
	if err != nil {
		t.Skipf("uptime %q", up)
	}
	tools, dir := keeneticHookShims(t, sh)
	// The detached timer now uses the authenticated shell path, so the fixture must record the host's
	// real POSIX shell rather than the router-only default in keeneticPBRTestTools.
	shellPath, err := exec.Command(sh, "-c", "command -v sh").Output()
	if err != nil {
		t.Fatal(err)
	}
	tools.ShellTool.ResolvedPath = strings.TrimSpace(string(shellPath))
	fill := "#!/bin/sh\necho \"wayhop $*\" >> \"$QA_LOG\"\nexit 3\n"
	if err := os.WriteFile(filepath.Join(dir.native, "wayhop"), []byte(fill), 0o755); err != nil {
		t.Fatal(err)
	}
	plan := ksPlan(t, nil)
	io := keeneticPBROptions("eth3")
	io.LANIfaces = []string{"br0"}
	io.BootRestore, io.BackstopReady, io.BootLearned = dir.sh+"/policy.ipset", dir.sh+"/ready", dir.sh+"/learned.ipset"
	io.FillTool, io.BootHoldLift = dir.sh+"/wayhop", uptime+liftMargin
	art, err := buildKeeneticKernelIpsetArtifact(plan, exactKernelOptions(), io, tools)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir.native, "policy.ipset"), keeneticBootRestoreFile(*art), 0o644)
	learnedFile := renderLearned([]ksEntry{{"wr_list_dom_4", netip.MustParsePrefix("198.51.100.7/32"), 3000}}, 100, 1<<20)
	_ = os.WriteFile(filepath.Join(dir.native, "learned.ipset"), learnedFile, 0o644)
	hook, err := renderKeeneticPBRHook(art.Script)
	if err != nil {
		t.Fatal(err)
	}
	calls := runKeeneticHook(t, sh, dir, hook, "mangle", "iptables")
	idx := func(parts ...string) int {
		for i, c := range calls {
			if countCalls([]string{c}, parts...) == 1 {
				return i
			}
		}
		return -1
	}
	// The shim sees no stdin redirect: the static restore, then the learned one.
	static, learned := idx("restore -!"), -1
	if static >= 0 && static+1 < len(calls) && calls[static+1] == "restore -!" {
		learned = static + 1
	}
	hold, fillAt := idx("route replace blackhole default table 407"), idx("wayhop backstop-fill")
	rule, chain := idx("rule add iif br0 fwmark", "table 407 priority"), idx("iptables-restore")
	if hold < 0 || rule < hold || static < rule || learned < static || fillAt < learned || chain < fillAt {
		t.Fatalf("boot order: hold@%d rule@%d static@%d learned@%d fill@%d chain@%d\n%q", hold, rule, static, learned, fillAt, chain, calls)
	}
	if c := calls[fillAt]; !strings.Contains(c, "-sets wr_list_dom_4,wr_list_tg_4,") || !strings.Contains(c, "-domains wr_list_dom_4,wr_list_dom_6") || !strings.Contains(c, "-learned "+io.BootLearned) {
		t.Fatalf("fill call: %s", c)
	}
	// The hook run itself must not lift the hold. Under a loaded full-suite run on Windows the run
	// (dozens of shims through sh) has taken longer than the margin, and then the armed timer lifts it,
	// on time, while the run is still logging; that is not an early lift, and the stamp check below
	// holds it to the due moment either way.
	if countCalls(calls, "route del default table 407") != 0 && time.Now().Before(dueNoEarlier) {
		t.Fatalf("lifted before it was due: %q", calls)
	}
	// No further hook run: the timer armed with the hold lifts it.
	logPath := filepath.Join(dir.native, "hook-mangle-iptables.log")
	lifted := filepath.Join(dir.native, "ready"+pbr.StampLifted)
	deadline := time.Now().Add(60 * time.Second)
	var log string
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(logPath)
		log = string(b)
		if _, err := os.Stat(lifted); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	st, err := os.Stat(lifted)
	if err != nil {
		t.Fatalf("no lift by the timer:\n%s", log)
	}
	// Whoever lifted it (the timer, or a run that found it due), not before it was due. The 100 ms is
	// file-time granularity, far below the one second this could be early by.
	if st.ModTime().Before(dueNoEarlier.Add(-100 * time.Millisecond)) {
		t.Fatalf("lifted at %v, before it was due (no earlier than %v):\n%s", st.ModTime(), dueNoEarlier, log)
	}
	for _, want := range []string{"ip route del default table 407", "ip -6 route del default table 407",
		"ip route replace blackhole 149.154.160.0/20 table 407", "ip route replace blackhole 198.51.100.7 table 407",
		"ip route del throw 100.64.0.0/10 table 407"} {
		if !strings.Contains(log, want) {
			t.Fatalf("lift without %q:\n%s", want, log)
		}
	}
	again := runKeeneticHook(t, sh, dir, hook, "mangle", "iptables")
	if countCalls(again, "blackhole default table 407") != 0 || countCalls(again, "backstop-fill") != 0 {
		t.Fatalf("the broad hold or the fill came back after the lift: %q", again)
	}
}

var _ rtblackhole.Table = (*fakeRouteTable)(nil)

// The fill is bounded: it stops after a run of refusals or past its deadline and exits
// partial, without the filled stamp (the lift's loop then covers the rest).
func TestBackstopFillIsBounded(t *testing.T) {
	var lines strings.Builder
	for i := 0; i < 200; i++ {
		lines.WriteString("add wr_list_tg_4 10." + strconv.Itoa(i/100) + "." + strconv.Itoa(i%100*2) + ".0/24 -exist\n")
	}
	static := filepath.Join(t.TempDir(), "policy.ipset")
	_ = os.WriteFile(static, []byte(lines.String()), 0o644)
	d := func() ksFillData { return gatherFill(static, "", []string{"wr_list_tg_4"}, nil) }
	if n := len(fillRoutes(d())); n < 100 {
		t.Fatalf("fixture aggregated to %d routes", n)
	}
	refusing := &fakeRouteTable{routes: map[netip.Prefix]bool{}, addErr: errors.New("timed out")}
	ready := filepath.Join(t.TempDir(), "ready")
	if code := runBackstopFill(refusing, ready, d(), io.Discard); code != ksFillPartial || refusing.adds != ksFillMaxConsecFail {
		t.Fatalf("refusing kernel: code %d after %d adds", code, refusing.adds)
	}
	if _, err := os.Stat(ready + pbr.StampFilled); err == nil {
		t.Fatal("filled stamp after a cut fill")
	}
	old := ksFillBudget
	ksFillBudget = 5 * time.Millisecond
	defer func() { ksFillBudget = old }()
	slow := &fakeRouteTable{routes: map[netip.Prefix]bool{}, addDelay: 2 * time.Millisecond}
	ready = filepath.Join(t.TempDir(), "ready")
	if code := runBackstopFill(slow, ready, d(), io.Discard); code != ksFillPartial || slow.adds > 10 {
		t.Fatalf("slow kernel: code %d after %d adds", code, slow.adds)
	}
}

// The hold's shared-space throws go with the hold, by the fill and by the daemon.
func TestHoldThrowsGoWithTheHold(t *testing.T) {
	static := filepath.Join(t.TempDir(), "policy.ipset")
	_ = os.WriteFile(static, []byte("add wr_list_tg_4 100.64.0.0/10 -exist\n"), 0o644)
	table := &fakeRouteTable{routes: map[netip.Prefix]bool{netip.MustParsePrefix("0.0.0.0/0"): true}}
	if code := runBackstopFill(table, filepath.Join(t.TempDir(), "ready"), gatherFill(static, "", []string{"wr_list_tg_4"}, nil), io.Discard); code != 0 {
		t.Fatalf("fill: %d", code)
	}
	if !slices.Equal(table.throwDels, pbr.HoldSharedThrows()) {
		t.Fatalf("fill removed throws %v", table.throwDels)
	}
	b := &ksBackstop{ready: filepath.Join(t.TempDir(), "ready")}
	daemon := &fakeRouteTable{routes: map[netip.Prefix]bool{}}
	b.releaseHold(daemon, nil)
	if !slices.Equal(daemon.throwDels, pbr.HoldSharedThrows()) {
		t.Fatalf("daemon removed throws %v", daemon.throwDels)
	}
}

// A learned entry is written with at least ksLearnedMinTTL, so a member dnsmasq re-added
// since the last write does not come back after a reboot with seconds left.
func TestLearnedTimeoutIsFloored(t *testing.T) {
	out := string(renderLearned([]ksEntry{
		{"wr_list_dom_4", netip.MustParsePrefix("198.51.100.7/32"), 90},
		{"wr_list_dom_4", netip.MustParsePrefix("198.51.100.8/32"), 50000},
	}, 100, 1<<20))
	if !strings.Contains(out, "add wr_list_dom_4 198.51.100.7 timeout "+strconv.Itoa(ksLearnedMinTTL)+" -exist\n") ||
		!strings.Contains(out, "add wr_list_dom_4 198.51.100.8 timeout 50000 -exist\n") {
		t.Fatalf("learned file:\n%s", out)
	}
}
