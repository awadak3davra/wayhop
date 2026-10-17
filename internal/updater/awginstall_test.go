package updater

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wayhop/internal/pm"
)

// awgFake is an AWGRunFunc that records what it was asked to run and answers with a canned output.
type awgFake struct {
	argv   []string
	script []byte // what was in the file argv[1] named, read while it existed
	out    AWGOutput
	err    error
	block  bool // wait for the context to end, like a wedged package manager
}

func (f *awgFake) run(ctx context.Context, argv []string) (AWGOutput, error) {
	f.argv = append([]string(nil), argv...)
	if len(argv) > 1 {
		f.script, _ = os.ReadFile(argv[1])
	}
	if f.block {
		<-ctx.Done()
		return AWGOutput{ExitCode: -1}, ctx.Err()
	}
	return f.out, f.err
}

func awgInst(t *testing.T, f *awgFake) AWGInstaller {
	t.Helper()
	return AWGInstaller{Script: []byte("#!/bin/sh\necho test\n"), Dir: t.TempDir(), Run: f.run}
}

// answer is an output whose last stdout line is verdict, after a log line on each stream.
func answer(code int, verdict string) AWGOutput {
	stdout := "checking the feed\n" + verdict + "\n"
	return AWGOutput{Stdout: []byte(stdout), Combined: []byte("checking the feed\nopkg: something on stderr\n" + verdict + "\n"), ExitCode: code}
}

// The seam: the embedded script is written into the run directory, run with sh and the contract's
// flags for each operation, and removed afterwards.
func TestAWGInstallerRunsTheScriptWithTheContractFlags(t *testing.T) {
	for _, c := range []struct {
		name string
		do   func(AWGInstaller) AWGRun
		args []string
	}{
		{"plan, auto", func(i AWGInstaller) AWGRun { return i.Plan(context.Background(), "") }, []string{"--dry-run", "--json"}},
		{"plan, userspace only", func(i AWGInstaller) AWGRun { return i.Plan(context.Background(), AWGPathUserspace) },
			[]string{"--dry-run", "--json", "--mode", "userspace"}},
		{"install kmod", func(i AWGInstaller) AWGRun { return i.Install(context.Background(), AWGPathKmod) },
			[]string{"--yes", "--json", "--mode", "kmod"}},
		{"uninstall", func(i AWGInstaller) AWGRun { return i.Uninstall(context.Background()) },
			[]string{"--uninstall", "--yes", "--json"}},
	} {
		f := &awgFake{out: answer(0, `{"result":"current"}`)}
		inst := awgInst(t, f)
		c.do(inst)
		if len(f.argv) < 2 || f.argv[0] != "sh" {
			t.Fatalf("%s: ran %q, want sh <script> ...", c.name, f.argv)
		}
		if filepath.Dir(f.argv[1]) != inst.Dir || !strings.HasPrefix(filepath.Base(f.argv[1]), "install-awg-") {
			t.Errorf("%s: the script ran from %q, not from the run directory %q", c.name, f.argv[1], inst.Dir)
		}
		if string(f.script) != string(inst.Script) {
			t.Errorf("%s: the file run was %q, not the embedded script", c.name, f.script)
		}
		if got := strings.Join(f.argv[2:], " "); got != strings.Join(c.args, " ") {
			t.Errorf("%s: flags %q, want %q", c.name, got, strings.Join(c.args, " "))
		}
		if _, err := os.Stat(f.argv[1]); !os.IsNotExist(err) {
			t.Errorf("%s: the script was left behind in the run directory", c.name)
		}
	}
}

// An install is only ever on the path the operator approved: no mode, or auto, is refused before
// anything runs.
func TestAWGInstallNeedsAnExplicitPath(t *testing.T) {
	for _, mode := range []string{"", "auto", "kernel"} {
		f := &awgFake{out: answer(0, `{"result":"installed","path":"kmod"}`)}
		run := awgInst(t, f).Install(context.Background(), mode)
		if f.argv != nil || run.Result != AWGFailed || run.OK() {
			t.Errorf("mode %q: ran %q and reported %+v", mode, f.argv, run)
		}
	}
}

// Every verdict the contract defines, and every way a run can fail to give one, classified.
func TestAWGRunClassification(t *testing.T) {
	plan := func(i AWGInstaller) AWGRun { return i.Plan(context.Background(), "") }
	planUserspace := func(i AWGInstaller) AWGRun { return i.Plan(context.Background(), AWGPathUserspace) }
	kmod := func(i AWGInstaller) AWGRun { return i.Install(context.Background(), AWGPathKmod) }
	remove := func(i AWGInstaller) AWGRun { return i.Uninstall(context.Background()) }
	for _, c := range []struct {
		name        string
		do          func(AWGInstaller) AWGRun
		out         AWGOutput
		err         error
		result      string
		ok          bool
		installable bool
		reason      string // a substring the reason must carry
	}{
		{"dry-run kmod", plan, answer(0, `{"result":"dry-run","path":"kmod","packages":["kmod-amneziawg","amneziawg-tools"],"generation":"3.1","flash_free_kib":20480,"mem_total_kib":262144,"profile":"normal"}`),
			nil, AWGDryRun, false, true, ""},
		{"dry-run userspace lowmem", plan, answer(0, `{"result":"dry-run","path":"userspace","packages":["amneziawg-go"],"profile":"lowmem","mem_total_kib":131072,"reason":"no kmod for 6.6.73"}`),
			nil, AWGDryRun, false, true, "no kmod"},
		{"dry-run names no path", plan, answer(0, `{"result":"dry-run"}`), nil, AWGFailed, false, false, "no path"},
		{"dry-run on the kmod path when held to userspace", planUserspace, answer(0, `{"result":"dry-run","path":"kmod"}`),
			nil, AWGFailed, false, false, "only userspace"},
		{"plan: already current", plan, answer(0, `{"result":"current","path":"kmod","generation":"3.1"}`), nil, AWGCurrent, false, false, ""},
		{"plan that claims an install", plan, answer(0, `{"result":"installed","path":"kmod"}`), nil, AWGFailed, false, false, "dry run"},
		{"installed", kmod, answer(0, `{"result":"installed","path":"kmod","packages":["kmod-amneziawg"]}`), nil, AWGInstalled, true, false, ""},
		{"already current", kmod, answer(0, `{"result":"current","path":"kmod"}`), nil, AWGCurrent, true, false, ""},
		{"installed the other path", kmod, answer(0, `{"result":"installed","path":"userspace"}`), nil, AWGFailed, false, false, "kmod was approved"},
		{"installed but exited 1", kmod, answer(1, `{"result":"installed","path":"kmod"}`), nil, AWGFailed, false, false, "exited 1"},
		{"a dry run answering an install", kmod, answer(0, `{"result":"dry-run","path":"kmod"}`), nil, AWGFailed, false, false, "not a dry run"},
		{"refused", kmod, answer(2, `{"result":"refused","reason":"needs 4 MiB on /overlay, 1 MiB free"}`), nil, AWGRefused, false, false, "4 MiB"},
		{"refused without a reason", kmod, answer(2, `{"result":"refused"}`), nil, AWGRefused, false, false, "opkg: something on stderr"},
		{"failed (rolled back)", kmod, answer(1, `{"result":"failed","reason":"modprobe amneziawg failed; rolled back"}`), nil, AWGFailed, false, false, "rolled back"},
		{"failed without a reason", kmod, answer(1, `{"result":"failed"}`), nil, AWGFailed, false, false, "exit 1"},
		{"unknown verdict", kmod, answer(0, `{"result":"maybe"}`), nil, AWGFailed, false, false, "not a verdict"},
		{"garbage", kmod, AWGOutput{Stdout: []byte("Segmentation fault\n"), Combined: []byte("Segmentation fault\n"), ExitCode: 139},
			nil, AWGFailed, false, false, "exit 139"},
		{"broken JSON", kmod, answer(0, `{"result":"installed",`), nil, AWGFailed, false, false, "no verdict"},
		{"JSON not on the last line", kmod, AWGOutput{Stdout: []byte(`{"result":"installed","path":"kmod"}` + "\ndone\n"), ExitCode: 0},
			nil, AWGFailed, false, false, "no verdict"},
		{"exit 0, nothing printed", kmod, AWGOutput{ExitCode: 0}, nil, AWGFailed, false, false, "no verdict"},
		{"exit 2 without JSON", kmod, AWGOutput{Combined: []byte("not enough flash\n"), ExitCode: 2}, nil, AWGRefused, false, false, "not enough flash"},
		{"exit 1 without JSON", kmod, AWGOutput{Combined: []byte("opkg: download failed\n"), ExitCode: 1}, nil, AWGFailed, false, false, "download failed"},
		{"usage error", kmod, AWGOutput{Combined: []byte("usage: install-awg.sh\n"), ExitCode: 3}, nil, AWGFailed, false, false, "exit 3"},
		{"could not be started", kmod, AWGOutput{ExitCode: -1}, errors.New(`exec: "sh": executable file not found in $PATH`),
			AWGFailed, false, false, "could not be run"},
		{"uninstall, removed", remove, answer(0, `{"result":"removed","packages":["kmod-amneziawg"]}`), nil, AWGRemoved, true, false, ""},
		{"uninstall under the install verdict", remove, answer(0, `{"result":"installed"}`), nil, AWGRemoved, true, false, ""},
		{"uninstall refused", remove, answer(2, `{"result":"refused","reason":"an interface still uses the module"}`), nil, AWGRefused, false, false, "interface"},
		{"removed is no install", kmod, answer(0, `{"result":"removed"}`), nil, AWGFailed, false, false, "was an install"},
	} {
		run := c.do(awgInst(t, &awgFake{out: c.out, err: c.err}))
		if run.Result != c.result || run.OK() != c.ok || run.Installable() != c.installable {
			t.Errorf("%s: result %q ok %v installable %v (reason %q), want %q %v %v", c.name, run.Result, run.OK(), run.Installable(), run.Reason, c.result, c.ok, c.installable)
		}
		if c.reason != "" && !strings.Contains(run.Reason, c.reason) {
			t.Errorf("%s: reason %q does not carry %q", c.name, run.Reason, c.reason)
		}
		if run.ExitCode != c.out.ExitCode {
			t.Errorf("%s: exit code %d, want %d", c.name, run.ExitCode, c.out.ExitCode)
		}
	}
}

// The parsed numbers and names survive; what cannot be shown or acted on safely does not.
func TestAWGVerdictIsSanitized(t *testing.T) {
	v := `{"result":"dry-run","path":"kmod","packages":["kmod-amneziawg","--force-depends","x;rm -rf /",""],` +
		`"reason":"feed https://user:tok3n@feed.example.org/private/awg/Packages\u0007 unreachable","generation":"3.1; reboot",` +
		`"flash_free_kib":-5,"mem_total_kib":131072,"profile":"turbo"}`
	run := awgInst(t, &awgFake{out: answer(0, v)}).Plan(context.Background(), "")
	if strings.Join(run.Packages, ",") != "kmod-amneziawg" {
		t.Errorf("packages %q: only valid package names may pass", run.Packages)
	}
	if strings.Contains(run.Reason, "tok3n") || strings.Contains(run.Reason, "private") || !strings.Contains(run.Reason, "https://feed.example.org") {
		t.Errorf("reason %q: a URL must be cut to scheme://host", run.Reason)
	}
	if strings.ContainsRune(run.Reason, '\a') {
		t.Errorf("reason %q keeps a control character", run.Reason)
	}
	if run.Generation != "" || run.Profile != "" || run.FlashFreeKiB != nil {
		t.Errorf("generation %q profile %q flash %v: malformed values must be dropped", run.Generation, run.Profile, run.FlashFreeKiB)
	}
	if run.MemTotalKiB == nil || *run.MemTotalKiB != 131072 {
		t.Errorf("mem_total_kib %v", run.MemTotalKiB)
	}
}

// The log is the tail of both streams, without the verdict, with URLs reduced to their host.
func TestAWGLogTail(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	b.WriteString("Downloading https://downloads.example.org/secret-token/kmod-amneziawg.ipk\n")
	verdict := `{"result":"installed","path":"kmod"}`
	out := AWGOutput{Stdout: []byte(verdict + "\n"), Combined: []byte(b.String() + verdict + "\n"), ExitCode: 0}
	run := awgInst(t, &awgFake{out: out}).Install(context.Background(), AWGPathKmod)
	if len(run.Log) != awgLogLines {
		t.Fatalf("log has %d lines, want the last %d", len(run.Log), awgLogLines)
	}
	last := run.Log[len(run.Log)-1]
	if last != "Downloading https://downloads.example.org" {
		t.Errorf("last log line %q: the verdict must not be repeated and the URL must be cut to its host", last)
	}
	if run.Log[0] != "line 21" {
		t.Errorf("first kept line %q", run.Log[0])
	}
}

// A wedged installer is stopped at the timeout and reported as failed, never as installed - and a
// run the caller abandoned is not called a timeout.
func TestAWGTimeoutAndCancel(t *testing.T) {
	f := &awgFake{block: true}
	inst := awgInst(t, f)
	inst.InstallTimeout = 50 * time.Millisecond
	start := time.Now()
	run := inst.Install(context.Background(), AWGPathKmod)
	if !run.TimedOut || run.Result != AWGFailed || run.OK() || !strings.Contains(run.Reason, "did not finish within 50ms") {
		t.Errorf("timeout: %+v", run)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("the timeout did not stop the run")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	run = awgInst(t, &awgFake{block: true}).Plan(ctx, "")
	if run.TimedOut || run.Result != AWGFailed || !strings.Contains(run.Reason, "stopped before it finished") {
		t.Errorf("cancelled: %+v", run)
	}
}

// Without a script there is nothing to run, and the run says so.
func TestAWGNoScript(t *testing.T) {
	f := &awgFake{}
	run := AWGInstaller{Dir: t.TempDir(), Run: f.run}.Plan(context.Background(), "")
	if f.argv != nil || run.Result != AWGFailed || !strings.Contains(run.Reason, "no AmneziaWG installer") {
		t.Errorf("%+v ran %q", run, f.argv)
	}
}

// The demo answers like a router and installs nothing.
func TestDemoAWGRun(t *testing.T) {
	inst := AWGInstaller{Script: []byte("x"), Dir: t.TempDir(), Run: DemoAWGRun}
	if run := inst.Plan(context.Background(), ""); !run.Installable() || run.Path != AWGPathKmod {
		t.Errorf("demo plan: %+v", run)
	}
	if run := inst.Plan(context.Background(), AWGPathUserspace); !run.Installable() || run.Path != AWGPathUserspace || run.Profile != "lowmem" {
		t.Errorf("demo userspace plan: %+v", run)
	}
	if run := inst.Install(context.Background(), AWGPathUserspace); !run.OK() || run.Path != AWGPathUserspace || lastLogLine(run.Log, "") != "install-awg.sh: demo mode, no package manager was run" {
		t.Errorf("demo install: %+v", run)
	}
	if run := inst.Uninstall(context.Background()); !run.OK() || run.Result != AWGRemoved {
		t.Errorf("demo uninstall: %+v", run)
	}
}

// TestAWGHelperProcess is the child ExecAWGRun runs in the test below; it does nothing otherwise.
func TestAWGHelperProcess(t *testing.T) {
	switch os.Getenv("WAYHOP_AWG_HELPER") {
	case "refused":
		fmt.Println("checking flash")
		fmt.Fprintln(os.Stderr, "not enough flash on /overlay")
		fmt.Println(`{"result":"refused","reason":"not enough flash"}`)
		os.Exit(2)
	case "sleep":
		time.Sleep(time.Minute)
		os.Exit(0)
	}
}

// ExecAWGRun for real: a non-zero exit is an answer with both streams captured, and a context that
// ends stops the process.
func TestExecAWGRun(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Skip("no test executable")
	}
	t.Setenv("WAYHOP_AWG_HELPER", "refused")
	out, err := ExecAWGRun(context.Background(), []string{self, "-test.run=^TestAWGHelperProcess$"})
	if err != nil || out.ExitCode != 2 {
		t.Fatalf("exit %d, err %v", out.ExitCode, err)
	}
	if v, ok := parseAWGVerdict(out.Stdout); !ok || v.Result != AWGRefused {
		t.Errorf("stdout %q: no refused verdict on its last line", out.Stdout)
	}
	if !strings.Contains(string(out.Combined), "not enough flash on /overlay") || !strings.Contains(string(out.Combined), "checking flash") {
		t.Errorf("combined %q is missing a stream", out.Combined)
	}

	t.Setenv("WAYHOP_AWG_HELPER", "sleep")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	out, err = ExecAWGRun(ctx, []string{self, "-test.run=^TestAWGHelperProcess$"})
	if err == nil || out.ExitCode == 0 {
		t.Errorf("a stopped run reported exit %d, err %v", out.ExitCode, err)
	}
	if time.Since(start) > 30*time.Second {
		t.Error("the context did not stop the process")
	}
}

func TestTailBufferKeepsTheEnd(t *testing.T) {
	b := &tailBuffer{max: 8}
	for _, s := range []string{"abc", "defgh", "ijklmno"} {
		_, _ = b.Write([]byte(s))
	}
	if got := string(b.Bytes()); got != "hijklmno" {
		t.Errorf("tail %q", got)
	}
}

// The AmneziaWG packages are asked about only where there is something to find.
func TestAWGPackages(t *testing.T) {
	oldMod, oldLook := awgSysModule, awgLookPath
	t.Cleanup(func() { awgSysModule, awgLookPath = oldMod, oldLook })
	asked := 0
	runner := pmRunnerFunc(func(_ context.Context, name string, args ...string) (string, error) {
		asked++
		switch args[len(args)-1] {
		case "kmod-amneziawg":
			return "Package: kmod-amneziawg\nVersion: 3.1.20260906-r1\n", nil
		case "amneziawg-tools":
			return "Package: amneziawg-tools\nVersion: 3.1.20260812-r1\n", nil
		}
		return "", nil
	})
	u := New(t.TempDir(), "arm64", nil).WithPM(pm.Manager{Kind: pm.Opkg, Runner: runner})

	awgSysModule = filepath.Join(t.TempDir(), "absent")
	awgLookPath = func(string) (string, error) { return "", errors.New("not found") }
	if got := u.AWGPackages(context.Background()); got != nil || asked != 0 {
		t.Errorf("nothing to find: %+v after %d queries", got, asked)
	}
	awgSysModule = t.TempDir()
	awgLookPath = func(string) (string, error) { return "/usr/bin/awg", nil }
	got := u.AWGPackages(context.Background())
	if len(got) != 2 || got[0] != (AWGPackage{"kmod-amneziawg", "3.1.20260906-r1"}) || got[1] != (AWGPackage{"amneziawg-tools", "3.1.20260812-r1"}) {
		t.Errorf("packages %+v", got)
	}
	if New(t.TempDir(), "arm64", nil).WithPM(pm.Manager{Kind: pm.None}).AWGPackages(context.Background()) != nil {
		t.Error("packages without a package manager")
	}
}

type pmRunnerFunc func(ctx context.Context, name string, args ...string) (string, error)

func (f pmRunnerFunc) Run(ctx context.Context, name string, args ...string) (string, error) {
	return f(ctx, name, args...)
}
