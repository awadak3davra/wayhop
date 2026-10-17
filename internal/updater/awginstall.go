package updater

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"wayhop/internal/binstore"
	"wayhop/internal/pm"
)

// awginstall.go is the daemon's half of WayHop's AmneziaWG installer, packaging/awg/install-awg.sh.
//
// The installer is one POSIX script used three ways - by hand, by bootstrap.sh/install.sh
// --with-awg, and from the Components page through this file - so what a router gets is decided in
// one place: the kernel module when the router's release and target have a kmod built for the
// running kernel, userspace amneziawg-go otherwise, or a refusal when neither fits. The daemon
// embeds the script, writes it into the run directory, and runs it three ways:
//
//	--dry-run --json [--mode userspace]   the plan the row shows before anything changes
//	--yes --json --mode kmod|userspace    the install the operator approved, on the path shown
//	--uninstall --yes --json              removal of what the installer put there
//
// The contract (docs/AWG_FULL_INSTALL.md (development repository), "Installer contract"): exit 0 installed or already
// current, 1 failed (rolled back), 2 refused (does not fit / unsupported), 3 usage error; with --json
// the LAST line of stdout is one JSON object. Everything else either stream prints is the log.
//
// Nothing here trusts the script's verdict further than the exit code agrees with it: a run whose
// verdict and exit code disagree, that printed no verdict, or that did not finish in time is
// reported as failed with the reason, never as installed.

// The installer's verdicts.
const (
	AWGInstalled = "installed"
	AWGCurrent   = "current"
	AWGRefused   = "refused"
	AWGFailed    = "failed"
	AWGDryRun    = "dry-run"
	// AWGRemoved is accepted from an --uninstall run. The contract lists no verdict of its own for a
	// removal, so an uninstall that exits 0 is a success under any non-failing verdict; "removed" is
	// the one the daemon reports for it.
	AWGRemoved = "removed"
)

// The two paths the installer can take.
const (
	AWGPathKmod      = "kmod"
	AWGPathUserspace = "userspace"
)

// The installer's exit codes.
const (
	awgExitOK      = 0
	awgExitFailed  = 1
	awgExitRefused = 2
	awgExitUsage   = 3
)

// How long one run may take. A dry run refreshes the feed index over what can be a slow, censored
// link; an install downloads and verifies packages, loads the module and rolls back on failure.
// The bounds exist so a wedged package manager cannot hold the panel - and the lock every other
// package operation waits on - forever.
const (
	AWGPlanTimeout      = 2 * time.Minute
	AWGInstallTimeout   = 10 * time.Minute
	AWGUninstallTimeout = 3 * time.Minute
)

// AWGResult is the installer's one-line JSON verdict.
type AWGResult struct {
	Result   string   `json:"result"`
	Path     string   `json:"path,omitempty"` // kmod | userspace
	Packages []string `json:"packages,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	// Generation is the AmneziaWG generation the run is about ("3.1").
	Generation   string `json:"generation,omitempty"`
	FlashFreeKiB *int64 `json:"flash_free_kib,omitempty"`
	MemTotalKiB  *int64 `json:"mem_total_kib,omitempty"`
	Profile      string `json:"profile,omitempty"` // normal | lowmem
}

// AWGRun is one run of the installer as the daemon reports it: the verdict, checked against the
// exit code, and the tail of what the script printed.
type AWGRun struct {
	AWGResult
	Op       string `json:"op"`             // plan | install | uninstall
	Mode     string `json:"mode,omitempty"` // the --mode the daemon passed, "" for auto
	ExitCode int    `json:"exit_code"`      // -1 when the script did not exit on its own
	TimedOut bool   `json:"timed_out,omitempty"`
	// Log is the last lines the installer printed on stdout and stderr, interleaved, with every URL
	// cut down to its scheme and host: package-manager output repeats the configured repository
	// URLs, and a private feed can carry its token in the path.
	Log []string `json:"log,omitempty"`
}

// OK reports a run that left AmneziaWG installed (or, for an uninstall, removed) as asked.
func (r AWGRun) OK() bool {
	switch r.Result {
	case AWGInstalled, AWGCurrent:
		return r.Op == awgOpInstall
	case AWGRemoved:
		return r.Op == awgOpUninstall
	}
	return false
}

// Installable reports a dry run that names a path the operator can approve as shown.
func (r AWGRun) Installable() bool {
	return r.Op == awgOpPlan && r.Result == AWGDryRun && validAWGPath(r.Path)
}

const (
	awgOpPlan      = "plan"
	awgOpInstall   = "install"
	awgOpUninstall = "uninstall"
)

func validAWGPath(p string) bool { return p == AWGPathKmod || p == AWGPathUserspace }

// AWGOutput is what running the script produced.
type AWGOutput struct {
	Stdout   []byte // read for the verdict on its last line
	Combined []byte // stdout and stderr interleaved, for the log
	ExitCode int    // -1 when the process did not exit on its own (not started, or killed)
}

// AWGRunFunc runs argv and reports its output. A non-zero exit is an answer, not an error: err is
// for a script that could not be started or did not finish (the context ended).
type AWGRunFunc func(ctx context.Context, argv []string) (AWGOutput, error)

// AWGInstaller runs the embedded installer. The zero Run runs it for real (ExecAWGRun); tests and
// the demo pass their own.
type AWGInstaller struct {
	Script []byte     // the embedded install-awg.sh
	Dir    string     // where the script is written to run: the tmpfs run directory
	Run    AWGRunFunc // nil = ExecAWGRun
	// Timeouts override the defaults above; zero keeps them.
	PlanTimeout, InstallTimeout, UninstallTimeout time.Duration
}

// Plan asks what the installer would do here, changing nothing. mode "" lets it choose (auto);
// "userspace" holds it to amneziawg-go (KeeneticOS, where no kmod can be built safely).
func (i AWGInstaller) Plan(ctx context.Context, mode string) AWGRun {
	args := []string{"--dry-run", "--json"}
	if mode != "" {
		args = append(args, "--mode", mode)
	}
	return i.run(ctx, awgOpPlan, mode, pick(i.PlanTimeout, AWGPlanTimeout), args)
}

// Install installs on the path the operator approved. The mode is explicit, never auto: consent was
// given to the path the plan showed, and a re-decision between plan and install must not change it.
func (i AWGInstaller) Install(ctx context.Context, mode string) AWGRun {
	if !validAWGPath(mode) {
		return AWGRun{Op: awgOpInstall, Mode: mode, ExitCode: -1,
			AWGResult: AWGResult{Result: AWGFailed, Reason: fmt.Sprintf("install mode %q is not kmod or userspace", mode)}}
	}
	return i.run(ctx, awgOpInstall, mode, pick(i.InstallTimeout, AWGInstallTimeout),
		[]string{"--yes", "--json", "--mode", mode})
}

// Uninstall removes what the installer installed.
func (i AWGInstaller) Uninstall(ctx context.Context) AWGRun {
	return i.run(ctx, awgOpUninstall, "", pick(i.UninstallTimeout, AWGUninstallTimeout),
		[]string{"--uninstall", "--yes", "--json"})
}

func pick(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// run writes the script into Dir, runs it with sh and classifies what came back.
func (i AWGInstaller) run(parent context.Context, op, mode string, timeout time.Duration, args []string) AWGRun {
	out := AWGRun{Op: op, Mode: mode, ExitCode: -1}
	fail := func(format string, a ...any) AWGRun {
		out.AWGResult = AWGResult{Result: AWGFailed, Reason: fmt.Sprintf(format, a...)}
		return out
	}
	if len(i.Script) == 0 {
		return fail("this build carries no AmneziaWG installer")
	}
	dir := i.Dir
	if dir == "" {
		dir = binstore.DefaultRunDir
	}
	// The run directory is tmpfs on OpenWrt and KeeneticOS: the script never touches flash, and a
	// copy left behind by a crash is gone at the next boot.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fail("could not prepare %s for the installer: %v", dir, err)
	}
	f, err := os.CreateTemp(dir, "install-awg-*.sh")
	if err != nil {
		return fail("could not write the installer into %s: %v", dir, err)
	}
	path := f.Name()
	defer os.Remove(path)
	_, werr := f.Write(i.Script)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		return fail("could not write the installer into %s: %v", dir, errors.Join(werr, cerr))
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fail("could not prepare the installer: %v", err)
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	runner := i.Run
	if runner == nil {
		runner = ExecAWGRun
	}
	res, runErr := runner(ctx, append([]string{"sh", path}, args...))
	out.ExitCode = res.ExitCode
	verdict, parsed := parseAWGVerdict(res.Stdout)
	out.Log = awgLogTail(res.Combined, verdict.line)

	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded) && parent.Err() == nil:
		out.TimedOut = true
		return fail("the installer did not finish within %s and was stopped; the package manager may still hold its lock, so check it before retrying", timeout)
	case ctx.Err() != nil:
		return fail("the installer was stopped before it finished: %v", ctx.Err())
	case runErr != nil:
		return fail("the installer could not be run: %s", scrubErr(runErr))
	}
	return classifyAWG(out, verdict, parsed)
}

// awgVerdict is the parsed last line of stdout, and the line itself (so the log does not repeat it).
type awgVerdict struct {
	AWGResult
	line string
}

// parseAWGVerdict reads the one JSON object on the last non-empty line of stdout. Anything else - no
// output, a last line that is not a JSON object, an object with no result - is not a verdict.
func parseAWGVerdict(stdout []byte) (awgVerdict, bool) {
	lines := strings.Split(strings.ReplaceAll(string(stdout), "\r\n", "\n"), "\n")
	for n := len(lines) - 1; n >= 0; n-- {
		line := strings.TrimSpace(lines[n])
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "{") || !strings.HasSuffix(line, "}") {
			return awgVerdict{}, false
		}
		var v AWGResult
		if err := json.Unmarshal([]byte(line), &v); err != nil || strings.TrimSpace(v.Result) == "" {
			return awgVerdict{}, false
		}
		return awgVerdict{AWGResult: sanitizeAWGResult(v), line: line}, true
	}
	return awgVerdict{}, false
}

var awgGenerationRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

// sanitizeAWGResult keeps only what can be shown and acted on safely: the script runs as root, but
// its verdict ends up in a browser and its package names in a confirmation.
func sanitizeAWGResult(v AWGResult) AWGResult {
	v.Result = strings.TrimSpace(v.Result)
	if !validAWGPath(v.Path) {
		v.Path = ""
	}
	pkgs := make([]string, 0, len(v.Packages))
	for _, p := range v.Packages {
		if pm.ValidPkgName(p) && len(pkgs) < 16 {
			pkgs = append(pkgs, p)
		}
	}
	v.Packages = pkgs
	if len(v.Packages) == 0 {
		v.Packages = nil
	}
	v.Reason = cleanAWGText(v.Reason, 600)
	if !awgGenerationRe.MatchString(v.Generation) {
		v.Generation = ""
	}
	if v.Profile != "normal" && v.Profile != "lowmem" {
		v.Profile = ""
	}
	if v.FlashFreeKiB != nil && *v.FlashFreeKiB < 0 {
		v.FlashFreeKiB = nil
	}
	if v.MemTotalKiB != nil && *v.MemTotalKiB < 0 {
		v.MemTotalKiB = nil
	}
	return v
}

// classifyAWG turns a run into the report: the verdict where the exit code agrees with it, and a
// failure with the disagreement named where it does not.
func classifyAWG(out AWGRun, v awgVerdict, parsed bool) AWGRun {
	code := out.ExitCode
	if !parsed {
		out.AWGResult = AWGResult{Result: AWGFailed}
		switch code {
		case awgExitRefused:
			out.Result = AWGRefused
			out.Reason = lastLogLine(out.Log, "the installer refused (exit 2) without a JSON verdict")
		case awgExitUsage:
			out.Reason = "the installer rejected its arguments (exit 3): this daemon and the installer it embeds disagree about the contract"
		case awgExitOK:
			out.Reason = "the installer exited 0 but printed no verdict, so nothing it did can be confirmed"
		default:
			out.Reason = fmt.Sprintf("the installer failed (exit %d) without a verdict: %s", code,
				lastLogLine(out.Log, "it printed nothing"))
		}
		return out
	}
	out.AWGResult = v.AWGResult
	disagree := func(why string) AWGRun {
		got := out.Result
		out.Result = AWGFailed
		out.Reason = cleanAWGText(fmt.Sprintf("the installer reported %q but %s", got, why), 600)
		return out
	}
	switch out.Result {
	case AWGDryRun:
		if out.Op != awgOpPlan {
			return disagree("this was not a dry run, so nothing can be assumed installed")
		}
		if code != awgExitOK {
			return disagree(fmt.Sprintf("exited %d", code))
		}
		if out.Path == "" {
			return disagree("named no path (kmod or userspace)")
		}
		if out.Mode != "" && out.Path != out.Mode {
			return disagree(fmt.Sprintf("planned the %s path when only %s was allowed", out.Path, out.Mode))
		}
	case AWGInstalled, AWGCurrent, AWGRemoved:
		if code != awgExitOK {
			return disagree(fmt.Sprintf("exited %d", code))
		}
		switch out.Op {
		case awgOpPlan:
			if out.Result != AWGCurrent {
				return disagree("this was a dry run, which must change nothing")
			}
		case awgOpInstall:
			if out.Result == AWGRemoved {
				return disagree("this was an install")
			}
			// Consent was to the path the plan showed. An install that took the other one is not the
			// install that was approved, however well it went.
			if out.Result == AWGInstalled && out.Path != "" && out.Path != out.Mode {
				return disagree(fmt.Sprintf("installed the %s path when %s was approved", out.Path, out.Mode))
			}
		case awgOpUninstall:
			out.Result = AWGRemoved
		}
	case AWGRefused:
		if out.Reason == "" {
			out.Reason = lastLogLine(out.Log, "the installer refused without a reason")
		}
	case AWGFailed:
		if out.Reason == "" {
			out.Reason = fmt.Sprintf("the installer failed (exit %d): %s", code, lastLogLine(out.Log, "no reason given"))
		}
	default:
		return disagree(fmt.Sprintf("that is not a verdict the contract defines (exit %d)", code))
	}
	return out
}

// lastLogLine is the last line of the log, or def when there is none.
func lastLogLine(log []string, def string) string {
	for n := len(log) - 1; n >= 0; n-- {
		if s := strings.TrimSpace(log[n]); s != "" {
			return s
		}
	}
	return def
}

// awgLogLines and awgLogLineMax bound what one run sends to the browser.
const (
	awgLogLines   = 40
	awgLogLineMax = 300
)

// awgLogTail is the last awgLogLines lines of the combined output, without the verdict line.
func awgLogTail(combined []byte, verdictLine string) []string {
	if len(combined) == 0 {
		return nil
	}
	var out []string
	for _, raw := range strings.Split(strings.ReplaceAll(string(combined), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || (verdictLine != "" && line == verdictLine) {
			continue
		}
		out = append(out, cleanAWGText(line, awgLogLineMax))
	}
	if len(out) > awgLogLines {
		out = out[len(out)-awgLogLines:]
	}
	return out
}

var awgURLRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]+`)

// cleanAWGText makes one piece of installer text safe to show: every URL reduced to scheme://host,
// control characters dropped, invalid UTF-8 replaced, and the length capped.
func cleanAWGText(s string, max int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	// Control characters go first: one glued to a URL would make it unparseable, and an unparseable
	// URL is replaced whole rather than shown.
	s = strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = awgURLRe.ReplaceAllStringFunc(s, redactHost)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max-1]) + "…"
	}
	return s
}

// ExecAWGRun runs argv for real. The installer drives opkg/apk, so on Linux it runs in its own
// process group and a timeout signals the whole group (see awgrun_linux.go): stopping only the shell
// would leave the package manager running with its lock held.
func ExecAWGRun(ctx context.Context, argv []string) (AWGOutput, error) {
	if len(argv) == 0 {
		return AWGOutput{ExitCode: -1}, errors.New("nothing to run")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	setAWGProcessGroup(cmd)
	cmd.WaitDelay = 10 * time.Second
	stdout := &tailBuffer{max: 64 << 10}
	combined := &tailBuffer{max: 256 << 10}
	var mu sync.Mutex
	cmd.Stdout = &lockedWriter{mu: &mu, w: io.MultiWriter(stdout, combined)}
	cmd.Stderr = &lockedWriter{mu: &mu, w: combined}
	err := cmd.Run()
	out := AWGOutput{Stdout: stdout.Bytes(), Combined: combined.Bytes(), ExitCode: -1}
	if cmd.ProcessState != nil {
		out.ExitCode = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	var exitErr *exec.ExitError
	if err == nil || errors.As(err, &exitErr) || errors.Is(err, exec.ErrWaitDelay) {
		// A non-zero exit is the script's answer. ErrWaitDelay means it exited and a child it left
		// behind kept the pipes open; the verdict was already printed.
		return out, nil
	}
	return out, err
}

// tailBuffer keeps the last max bytes written to it: a chatty package manager cannot grow the
// daemon's memory, and the verdict is on the last line anyway.
type tailBuffer struct {
	max int
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.max; over > 0 {
		t.buf = append(t.buf[:0], t.buf[over:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) Bytes() []byte { return bytes.Clone(t.buf) }

// lockedWriter serializes the two streams into the shared combined buffer: exec copies stdout and
// stderr from separate goroutines.
type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// WithAWGRunner replaces how the installer is run (tests inject a fake; production leaves it nil and
// the script runs for real). The sibling of WithPM, for the same reason: what this path has to handle
// - a refusal, a timeout, a script printing garbage - cannot be arranged on the machine running the
// test.
func (u *Updater) WithAWGRunner(f AWGRunFunc) *Updater { u.awgRun = f; return u }

// AWGRunner is the injected runner, nil when the installer runs for real.
func (u *Updater) AWGRunner() AWGRunFunc {
	if u == nil {
		return nil
	}
	return u.awgRun
}

// AWGPackage is one AmneziaWG package the package manager has installed.
type AWGPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// awgSysModule is where a loaded amneziawg module shows, and awgLookPath finds awg; variables so
// tests can arrange a router that has them.
var (
	awgSysModule = "/sys/module/amneziawg"
	awgLookPath  = exec.LookPath
)

// AWGPackages lists the AmneziaWG packages the package manager has installed, with their versions:
// the kernel module and the tools the feed installer writes, which the Components row names as the
// source of the kernel path. Asked only where there is something to find - the module loaded, awg on
// PATH - so a router without them pays no package-manager round trip for each page render.
func (u *Updater) AWGPackages(ctx context.Context) []AWGPackage {
	if u == nil || !u.pm.Available() {
		return nil
	}
	var names []string
	if _, err := os.Stat(awgSysModule); err == nil {
		names = append(names, "kmod-amneziawg")
	}
	if _, err := awgLookPath("awg"); err == nil {
		names = append(names, "amneziawg-tools")
	}
	if len(names) == 0 {
		return nil
	}
	u.pmStatusMu.Lock()
	defer u.pmStatusMu.Unlock()
	var out []AWGPackage
	for _, name := range names {
		if v, ok := u.pm.InstalledPackageVersion(ctx, name); ok {
			out = append(out, AWGPackage{Name: name, Version: v})
		}
	}
	return out
}

// DemoAWGRun is the installer as the demo answers it: a router with a matching kmod in WayHop's
// feed, or - held to userspace - the lowmem amneziawg-go path. Like DemoPM it changes nothing and
// says so in its log, and the server opens a demo run's summary with "Demo mode, nothing was
// changed", so nobody reads the outcome as a real install.
func DemoAWGRun(_ context.Context, argv []string) (AWGOutput, error) {
	args := strings.Join(argv, " ")
	line := func(v map[string]any) []byte {
		b, _ := json.Marshal(v)
		return append(b, '\n')
	}
	flash, mem := int64(20480), int64(262144)
	var verdict []byte
	switch {
	case strings.Contains(args, "--uninstall"):
		verdict = line(map[string]any{"result": AWGRemoved})
	case strings.Contains(args, "--dry-run") && strings.Contains(args, "--mode userspace"):
		verdict = line(map[string]any{"result": AWGDryRun, "path": AWGPathUserspace, "packages": []string{"amneziawg-go"},
			"reason": "demo: no kmod is built for this kernel", "generation": "3.1",
			"flash_free_kib": flash, "mem_total_kib": 131072, "profile": "lowmem"})
	case strings.Contains(args, "--dry-run"):
		verdict = line(map[string]any{"result": AWGDryRun, "path": AWGPathKmod,
			"packages": []string{"kmod-amneziawg", "amneziawg-tools"},
			"reason":   "demo: the feed carries a kmod built for the running kernel", "generation": "3.1",
			"flash_free_kib": flash, "mem_total_kib": mem, "profile": "normal"})
	default:
		path := AWGPathKmod
		if strings.Contains(args, "--mode userspace") {
			path = AWGPathUserspace
		}
		verdict = line(map[string]any{"result": AWGInstalled, "path": path, "generation": "3.1",
			"flash_free_kib": flash, "mem_total_kib": mem, "profile": "normal"})
	}
	log := []byte("install-awg.sh: demo mode, no package manager was run\n")
	return AWGOutput{Stdout: verdict, Combined: append(log, verdict...), ExitCode: 0}, nil
}
