package plugin

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"wayhop/internal/model"
)

// run_real_test.go exercises the REAL process paths of the plugin Manager
// (start/stop/Supervise/StopAll for a long-running nfqws2 engine) by building a
// tiny stub executable named like the engine binary and pointing the Manager at
// it. All helpers are prefixed with "pluginrun_" to avoid clashing with
// supervise_test.go / plugin_test.go symbols.

// pluginrun_stubSource blocks forever after a banner, simulating a long-running
// nfqws2 process. It ignores its args; nfqws_test.go holds the Manager to nfqws2's argv.
const pluginrun_stubSource = `package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	fmt.Println("PLUGINRUN-STUB up")
	_ = os.Args
	// Block "forever" via a sleep loop rather than select{} (which would trip Go's
	// deadlock detector and exit on its own). The Manager kills us via Process.Kill().
	for {
		time.Sleep(time.Hour)
	}
}
`

func pluginrun_exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// Resolve Go at package init, before a test empties PATH to prove that only its stub is found.
var pluginrun_goBin = func() string {
	if home, err := os.UserHomeDir(); err == nil {
		cand := filepath.Join(home, "go-toolchain", "go", "bin", "go"+pluginrun_exeSuffix())
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
			return cand
		}
	}
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	return ""
}()

func pluginrun_goTool(t *testing.T) string {
	t.Helper()
	if pluginrun_goBin == "" {
		t.Skip("no Go toolchain available to build the stub executable")
	}
	return pluginrun_goBin
}

// pluginrun_crashStubSource prints a banner then exits immediately, simulating an
// nfqws2 engine that crashes on launch (a true crash loop under Supervise).
const pluginrun_crashStubSource = `package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("PLUGINRUN-CRASHSTUB exiting")
	os.Exit(1)
}
`

// pluginrun_buildStub builds the long-running stub and installs it as the engine
// binary. See pluginrun_buildStubFrom.
func pluginrun_buildStub(t *testing.T, binDir string) {
	t.Helper()
	pluginrun_buildStubFrom(t, binDir, pluginrun_stubSource)
}

// pluginrun_buildStubFrom builds the given stub source and installs it into
// binDir under the engine name ("nfqws2"+GOEXE). It also prepends binDir to PATH so
// the Manager's resolve() finds it on Windows (where resolve()'s binDir os.Stat
// won't match the .exe suffix but exec.LookPath on PATH will). Skips if the build
// is unavailable.
func pluginrun_buildStubFrom(t *testing.T, binDir, src string) {
	t.Helper()
	goBin := pluginrun_goTool(t)

	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("write stub source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module pluginrunstub\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatalf("write stub go.mod: %v", err)
	}

	out := filepath.Join(binDir, "nfqws2"+pluginrun_exeSuffix())
	cmd := exec.Command(goBin, "build", "-o", out, ".")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GO111MODULE=on", "CGO_ENABLED=0")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not build nfqws2 stub (skipping real-process tests): %v\n%s", err, combined)
	}
	if _, err := os.Stat(out); err != nil {
		t.Skipf("nfqws2 stub missing after build: %v", err)
	}

	// Make resolve()'s PATH fallback find it (covers Windows .exe lookup).
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// pluginrun_dsyEndpoint builds an nfqws2 desync endpoint (distinct name from
// supervise_test.go's pluginsup_dsyEndpoint).
func pluginrun_dsyEndpoint(id string) model.Endpoint {
	return model.Endpoint{
		ID: id, Engine: model.EngineNfqws,
		Params: map[string]any{"dpi_desync": "disorder2"},
	}
}

// pluginrun_statusByID indexes a Status slice by id.
func pluginrun_statusByID(ss []Status) map[string]Status {
	m := make(map[string]Status, len(ss))
	for _, s := range ss {
		m[s.ID] = s
	}
	return m
}

// pluginrun_waitFor polls cond until true or the deadline passes.
func pluginrun_waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

// pluginrun_isRunning reads Running for an id under the Manager lock via Status().
func pluginrun_isRunning(m *Manager, id string) bool {
	return pluginrun_statusByID(m.Status())[id].Running
}

// pluginrun_restartsOf reads the internal crash-restart counter under the lock.
func pluginrun_restartsOf(m *Manager, id string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p := m.procs[id]; p != nil {
		return p.restarts
	}
	return 0
}

// pluginrun_waitProcExited blocks until the currently-tracked incarnation of id has
// exited (its done channel closes), so the next Supervise tick deterministically
// observes a dead proc. Returns immediately when nothing live is tracked.
func pluginrun_waitProcExited(t *testing.T, m *Manager, id string) {
	t.Helper()
	m.mu.Lock()
	p := m.procs[id]
	var ch chan struct{}
	running := false
	if p != nil {
		ch, running = p.done, p.running
	}
	m.mu.Unlock()
	if !running || ch == nil {
		return
	}
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s incarnation to exit", id)
	}
}

// TestPluginrun_SuperviseThrottlesCrashLoop is the queue-#12 regression: an nfqws2
// engine that crashes on launch must NOT be relaunched on every Supervise tick.
// Driving N ticks against an always-crashing stub must yield fewer than N relaunches
// (proving backoff kicks in) while still relaunching at least once (resilience).
func TestPluginrun_SuperviseThrottlesCrashLoop(t *testing.T) {
	cfgDir := t.TempDir()
	binDir := t.TempDir()
	pluginrun_buildStubFrom(t, binDir, pluginrun_crashStubSource)

	m := New(cfgDir, binDir)
	t.Cleanup(m.StopAll)

	m.Sync([]Spec{{ID: "dsy1", Endpoint: pluginrun_dsyEndpoint("dsy1"), SOCKSPort: 17901}})

	const ticks = 14
	relaunches := 0
	for i := 0; i < ticks; i++ {
		// Let any live incarnation finish crashing so this tick sees it dead.
		pluginrun_waitProcExited(t, m, "dsy1")
		before := pluginrun_restartsOf(m, "dsy1")
		m.Supervise()
		if pluginrun_restartsOf(m, "dsy1") > before {
			relaunches++
		}
	}

	if relaunches >= ticks {
		t.Fatalf("crash loop not throttled: relaunched on all %d ticks", ticks)
	}
	if relaunches == 0 {
		t.Fatalf("no relaunch at all over %d ticks: resilience lost", ticks)
	}
	// The grace window must let the first few crashes relaunch immediately.
	if relaunches < pluginRestartGrace {
		t.Fatalf("grace window too tight: %d relaunches over %d ticks, want >= %d", relaunches, ticks, pluginRestartGrace)
	}
}

// pluginrun_lateCrashStubSource stays up until the file named by WAYHOP_TEST_DIE_SENTINEL exists,
// then exits 1: a plugin that dies some seconds after each start rather than at once.
const pluginrun_lateCrashStubSource = `package main

import (
	"os"
	"time"
)

func main() {
	p := os.Getenv("WAYHOP_TEST_DIE_SENTINEL")
	for {
		if _, err := os.Stat(p); err == nil {
			os.Exit(1)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
`

// TestPluginrun_SuperviseThrottlesLateCrashLoop is QA-110: a plugin that is still alive on the tick
// after its relaunch and dead on the one after that (a life of 3-6 s) was never throttled. The alive
// tick cleared the crash-loop counters, so every death was the first one, inside the grace, and the
// proc was relaunched every other tick forever. The throttle may clear only once the proc has
// stayed up for the stable window, as the core watchdog's does.
func TestPluginrun_SuperviseThrottlesLateCrashLoop(t *testing.T) {
	cfgDir, binDir := t.TempDir(), t.TempDir()
	pluginrun_buildStubFrom(t, binDir, pluginrun_lateCrashStubSource)
	sentinel := filepath.Join(t.TempDir(), "die")
	t.Setenv("WAYHOP_TEST_DIE_SENTINEL", sentinel)

	m := New(cfgDir, binDir)
	t.Cleanup(m.StopAll)
	m.Sync([]Spec{{ID: "dsy1", Endpoint: pluginrun_dsyEndpoint("dsy1"), SOCKSPort: 17901}})
	if !pluginrun_isRunning(m, "dsy1") {
		t.Fatal("stub did not start")
	}

	const cycles = 12
	relaunches, maxRestarts, maxCooldown := 0, 0, 0
	for i := 0; i < cycles; i++ {
		m.Supervise() // the incarnation is alive on this tick
		if err := os.WriteFile(sentinel, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		pluginrun_waitProcExited(t, m, "dsy1")
		if err := os.Remove(sentinel); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		before := pluginrun_restartsOf(m, "dsy1")
		m.Supervise() // and dead on this one
		m.mu.Lock()
		r, c := m.procs["dsy1"].restarts, m.procs["dsy1"].cooldown
		m.mu.Unlock()
		if r > before {
			relaunches++
		}
		maxRestarts, maxCooldown = max(maxRestarts, r), max(maxCooldown, c)
	}
	t.Logf("cycles=%d relaunches=%d maxRestarts=%d maxCooldown=%d", cycles, relaunches, maxRestarts, maxCooldown)
	if maxRestarts <= pluginRestartGrace || maxCooldown == 0 || relaunches == cycles {
		t.Fatalf("a crash loop with a one-tick life is never throttled: %d/%d immediate relaunches, restarts never above %d, cooldown never above %d",
			relaunches, cycles, maxRestarts, maxCooldown)
	}
}

// TestPluginrun_SyncStartsRealProcess verifies Sync launches the engine stub:
// running=true, needs_binary=false, and a tracked cmd/done exist.
func TestPluginrun_SyncStartsRealProcess(t *testing.T) {
	cfgDir := t.TempDir()
	binDir := t.TempDir()
	pluginrun_buildStub(t, binDir)

	m := New(cfgDir, binDir)
	t.Cleanup(m.StopAll)

	m.Sync([]Spec{{ID: "dsy1", Endpoint: pluginrun_dsyEndpoint("dsy1"), SOCKSPort: 17901}})

	st := pluginrun_statusByID(m.Status())["dsy1"]
	if !st.Running {
		t.Fatalf("dsy1 Running = false after Sync; want true (stub should launch). status=%+v", st)
	}
	if st.NeedsBinary {
		t.Fatalf("dsy1 NeedsBinary = true after Sync with a resolvable binary; want false")
	}

	// The rendered config must be on disk where Supervise would re-launch from.
	if _, err := os.Stat(filepath.Join(cfgDir, "dsy1.nfqws")); err != nil {
		t.Fatalf("dsy1.nfqws config not written: %v", err)
	}

	// Internal: a live cmd + open done channel must be tracked.
	m.mu.Lock()
	p := m.procs["dsy1"]
	m.mu.Unlock()
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		t.Fatal("expected a tracked running cmd for dsy1")
	}
	if procDied(p) {
		t.Fatal("procDied(dsy1) = true immediately after launch; want false")
	}
}

// TestPluginrun_SuperviseRestartsCrashedProc is the supervise contract: after the
// running nfqws2 process dies, Supervise re-launches it from the on-disk config.
func TestPluginrun_SuperviseRestartsCrashedProc(t *testing.T) {
	cfgDir := t.TempDir()
	binDir := t.TempDir()
	pluginrun_buildStub(t, binDir)

	m := New(cfgDir, binDir)
	t.Cleanup(m.StopAll)

	m.Sync([]Spec{{ID: "dsy1", Endpoint: pluginrun_dsyEndpoint("dsy1"), SOCKSPort: 17901}})
	if !pluginrun_isRunning(m, "dsy1") {
		t.Fatal("precondition: dsy1 not running after Sync")
	}

	// Grab the live process and the PID of the first incarnation, then kill it to
	// simulate a crash.
	m.mu.Lock()
	p := m.procs["dsy1"]
	firstProc := p.cmd.Process
	firstDone := p.done
	m.mu.Unlock()
	if firstProc == nil {
		t.Fatal("no live process to kill")
	}
	firstPID := firstProc.Pid

	if err := firstProc.Kill(); err != nil {
		t.Fatalf("kill first nfqws2 process: %v", err)
	}
	// Wait for the exit-tracking goroutine to observe the death (done closes).
	pluginrun_waitFor(t, "first nfqws2 process to be observed dead", func() bool {
		select {
		case <-firstDone:
			return true
		default:
			return false
		}
	})

	// Supervise must detect the dead process and relaunch from the written config.
	m.Supervise()

	pluginrun_waitFor(t, "dsy1 to be running again after Supervise", func() bool {
		return pluginrun_isRunning(m, "dsy1")
	})

	// A genuinely NEW process must be tracked (different PID, fresh done channel).
	m.mu.Lock()
	p2 := m.procs["dsy1"]
	var newPID int
	if p2 != nil && p2.cmd != nil && p2.cmd.Process != nil {
		newPID = p2.cmd.Process.Pid
	}
	sameDone := p2 != nil && p2.done == firstDone
	m.mu.Unlock()

	if newPID == 0 {
		t.Fatal("Supervise did not establish a new tracked process for dsy1")
	}
	if newPID == firstPID {
		t.Fatalf("Supervise reused the dead PID %d; expected a fresh process", firstPID)
	}
	if sameDone {
		t.Fatal("Supervise kept the old (closed) done channel; expected a fresh one")
	}
	if !pluginrun_isRunning(m, "dsy1") {
		t.Fatal("dsy1 not running after Supervise restart")
	}
}

// TestPluginrun_SuperviseNoopWhenAlive verifies Supervise leaves a healthy
// running process untouched (same PID, still running).
func TestPluginrun_SuperviseNoopWhenAlive(t *testing.T) {
	cfgDir := t.TempDir()
	binDir := t.TempDir()
	pluginrun_buildStub(t, binDir)

	m := New(cfgDir, binDir)
	t.Cleanup(m.StopAll)

	m.Sync([]Spec{{ID: "dsy1", Endpoint: pluginrun_dsyEndpoint("dsy1"), SOCKSPort: 17901}})
	pluginrun_waitFor(t, "dsy1 running", func() bool { return pluginrun_isRunning(m, "dsy1") })

	m.mu.Lock()
	pidBefore := m.procs["dsy1"].cmd.Process.Pid
	m.mu.Unlock()

	m.Supervise() // process is alive -> must be a no-op

	m.mu.Lock()
	pidAfter := m.procs["dsy1"].cmd.Process.Pid
	m.mu.Unlock()

	if pidAfter != pidBefore {
		t.Fatalf("Supervise relaunched a healthy process: PID %d -> %d", pidBefore, pidAfter)
	}
	if !pluginrun_isRunning(m, "dsy1") {
		t.Fatal("dsy1 stopped being running after a no-op Supervise")
	}
}

// TestPluginrun_StopAllKillsRealProcess verifies StopAll terminates the live
// process and clears the tracked set.
func TestPluginrun_StopAllKillsRealProcess(t *testing.T) {
	cfgDir := t.TempDir()
	binDir := t.TempDir()
	pluginrun_buildStub(t, binDir)

	m := New(cfgDir, binDir)

	m.Sync([]Spec{{ID: "dsy1", Endpoint: pluginrun_dsyEndpoint("dsy1"), SOCKSPort: 17901}})
	pluginrun_waitFor(t, "dsy1 running", func() bool { return pluginrun_isRunning(m, "dsy1") })

	m.mu.Lock()
	proc := m.procs["dsy1"].cmd.Process
	done := m.procs["dsy1"].done
	m.mu.Unlock()

	m.StopAll()

	if got := m.Status(); len(got) != 0 {
		t.Fatalf("Status() after StopAll = %+v; want empty", got)
	}
	// The killed process's exit goroutine must have completed (done closed).
	select {
	case <-done:
	default:
		t.Fatal("done channel not closed after StopAll; process exit not awaited")
	}
	// The process must actually be gone: a second signal should fail (already dead)
	// on Unix; on Windows Kill on a dead handle also errors. We just assert StopAll
	// awaited the exit above, which is the observable contract.
	_ = proc
}

// TestPluginrun_StopByBinStopsMatchingPlugin: StopByBin stops only the plugin(s) launched from a
// given engine binary (so that binary can be removed/updated without an orphan), and a non-matching
// name is a no-op. This is the plugin-side of the updater's stop-before-mutate.
func TestPluginrun_StopByBinStopsMatchingPlugin(t *testing.T) {
	cfgDir := t.TempDir()
	binDir := t.TempDir()
	pluginrun_buildStub(t, binDir)
	m := New(cfgDir, binDir)
	m.Sync([]Spec{{ID: "dsy1", Endpoint: pluginrun_dsyEndpoint("dsy1"), SOCKSPort: 17911}})
	pluginrun_waitFor(t, "dsy1 running", func() bool { return pluginrun_isRunning(m, "dsy1") })

	if n := m.StopByBin("some-other-binary"); n != 0 {
		t.Errorf("StopByBin(non-matching) = %d, want 0", n)
	}
	if !pluginrun_isRunning(m, "dsy1") {
		t.Fatal("dsy1 must still run after a non-matching StopByBin")
	}

	m.mu.Lock()
	binName := m.procs["dsy1"].binName
	done := m.procs["dsy1"].done
	m.mu.Unlock()
	if n := m.StopByBin(binName); n != 1 {
		t.Errorf("StopByBin(%q) = %d, want 1", binName, n)
	}
	if got := m.Status(); len(got) != 0 {
		t.Errorf("Status() after StopByBin = %+v, want empty", got)
	}
	select {
	case <-done:
	default:
		t.Fatal("process exit not awaited after StopByBin")
	}
	if n := m.StopByBin(binName); n != 0 {
		t.Errorf("second StopByBin = %d, want 0 (already stopped)", n)
	}
}

// TestPluginrun_SyncChangedSpecRestartsProcess verifies that Sync with a CHANGED
// nfqws2 config stops the old process and starts a new one (different PID).
func TestPluginrun_SyncChangedSpecRestartsProcess(t *testing.T) {
	cfgDir := t.TempDir()
	binDir := t.TempDir()
	pluginrun_buildStub(t, binDir)

	m := New(cfgDir, binDir)
	t.Cleanup(m.StopAll)

	m.Sync([]Spec{{ID: "dsy1", Endpoint: pluginrun_dsyEndpoint("dsy1"), SOCKSPort: 17901}})
	pluginrun_waitFor(t, "dsy1 running", func() bool { return pluginrun_isRunning(m, "dsy1") })

	m.mu.Lock()
	pidBefore := m.procs["dsy1"].cmd.Process.Pid
	m.mu.Unlock()

	// Change the desync strategy -> rendered argv differs -> Sync must restart it.
	changed := pluginrun_dsyEndpoint("dsy1")
	changed.Params = map[string]any{"dpi_desync": "fake"}
	m.Sync([]Spec{{ID: "dsy1", Endpoint: changed, SOCKSPort: 17901}})
	pluginrun_waitFor(t, "dsy1 running again after changed Sync", func() bool {
		return pluginrun_isRunning(m, "dsy1")
	})

	m.mu.Lock()
	pidAfter := m.procs["dsy1"].cmd.Process.Pid
	m.mu.Unlock()

	if pidAfter == pidBefore {
		t.Fatalf("changed-spec Sync did not restart the process (PID stayed %d)", pidBefore)
	}
}
