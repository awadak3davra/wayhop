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
// (start/stop/Supervise/StopAll for a long-running olcRTC engine) by building a
// tiny stub executable named like the engine binary and pointing the Manager at
// it. All helpers are prefixed with "pluginrun_" to avoid clashing with
// supervise_test.go / plugin_test.go symbols.

// pluginrun_stubSource blocks forever after a banner, simulating a long-running
// olcRTC process. SingBox-style invocation is `<bin> -config <path>`; the stub
// ignores its args.
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

// pluginrun_goTool locates the Go binary (repo ~/go-toolchain first, then PATH).
func pluginrun_goTool(t *testing.T) string {
	t.Helper()
	if home, err := os.UserHomeDir(); err == nil {
		cand := filepath.Join(home, "go-toolchain", "go", "bin", "go"+pluginrun_exeSuffix())
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
			return cand
		}
	}
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	t.Skip("no Go toolchain available to build the stub executable")
	return ""
}

// pluginrun_crashStubSource prints a banner then exits immediately, simulating an
// olcRTC engine that crashes on launch (a true crash loop under Supervise).
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

// pluginrun_buildOlcStub builds the long-running stub and installs it as the engine
// binary. See pluginrun_buildOlcStubFrom.
func pluginrun_buildOlcStub(t *testing.T, binDir string) {
	t.Helper()
	pluginrun_buildOlcStubFrom(t, binDir, pluginrun_stubSource)
}

// pluginrun_buildOlcStubFrom builds the given stub source and installs it into
// binDir under the engine name ("olcrtc"+GOEXE). It also prepends binDir to PATH so
// the Manager's resolve() finds it on Windows (where resolve()'s binDir os.Stat
// won't match the .exe suffix but exec.LookPath on PATH will). Skips if the build
// is unavailable.
func pluginrun_buildOlcStubFrom(t *testing.T, binDir, src string) {
	t.Helper()
	goBin := pluginrun_goTool(t)

	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("write stub source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module pluginrunstub\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatalf("write stub go.mod: %v", err)
	}

	out := filepath.Join(binDir, "olcrtc"+pluginrun_exeSuffix())
	cmd := exec.Command(goBin, "build", "-o", out, ".")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GO111MODULE=on")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not build olcrtc stub (skipping real-process tests): %v\n%s", err, combined)
	}
	if _, err := os.Stat(out); err != nil {
		t.Skipf("olcrtc stub missing after build: %v", err)
	}

	// Make resolve()'s PATH fallback find it (covers Windows .exe lookup).
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// pluginrun_olcEndpoint builds an olcRTC endpoint (distinct name from
// supervise_test.go's pluginsup_olcEndpoint).
func pluginrun_olcEndpoint(id string) model.Endpoint {
	return model.Endpoint{
		ID: id, Engine: model.EngineOlcRTC, Protocol: model.ProtoOlcRTC,
		Server: "meet.x", Port: 443,
		Params: map[string]any{
			"provider": "telemost", "room": "https://telemost.yandex.ru/j/1",
			"key": "KEY", "transport": "vp8channel",
		},
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

// TestPluginrun_SuperviseThrottlesCrashLoop is the queue-#12 regression: an olcRTC
// engine that crashes on launch must NOT be relaunched on every Supervise tick.
// Driving N ticks against an always-crashing stub must yield fewer than N relaunches
// (proving backoff kicks in) while still relaunching at least once (resilience).
func TestPluginrun_SuperviseThrottlesCrashLoop(t *testing.T) {
	cfgDir := t.TempDir()
	binDir := t.TempDir()
	pluginrun_buildOlcStubFrom(t, binDir, pluginrun_crashStubSource)

	m := New(cfgDir, binDir)
	t.Cleanup(m.StopAll)

	m.Sync([]Spec{{ID: "olc1", Endpoint: pluginrun_olcEndpoint("olc1"), SOCKSPort: 17901}})

	const ticks = 14
	relaunches := 0
	for i := 0; i < ticks; i++ {
		// Let any live incarnation finish crashing so this tick sees it dead.
		pluginrun_waitProcExited(t, m, "olc1")
		before := pluginrun_restartsOf(m, "olc1")
		m.Supervise()
		if pluginrun_restartsOf(m, "olc1") > before {
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

// TestPluginrun_SyncStartsRealOlcProcess verifies Sync launches the olcRTC stub:
// running=true, needs_binary=false, and a tracked cmd/done exist.
func TestPluginrun_SyncStartsRealOlcProcess(t *testing.T) {
	cfgDir := t.TempDir()
	binDir := t.TempDir()
	pluginrun_buildOlcStub(t, binDir)

	m := New(cfgDir, binDir)
	t.Cleanup(m.StopAll)

	m.Sync([]Spec{{ID: "olc1", Endpoint: pluginrun_olcEndpoint("olc1"), SOCKSPort: 17901}})

	st := pluginrun_statusByID(m.Status())["olc1"]
	if !st.Running {
		t.Fatalf("olc1 Running = false after Sync; want true (stub should launch). status=%+v", st)
	}
	if st.NeedsBinary {
		t.Fatalf("olc1 NeedsBinary = true after Sync with a resolvable binary; want false")
	}

	// The rendered config must be on disk where Supervise would re-launch from.
	if _, err := os.Stat(filepath.Join(cfgDir, "olc1.yaml")); err != nil {
		t.Fatalf("olc1.yaml config not written: %v", err)
	}

	// Internal: a live cmd + open done channel must be tracked.
	m.mu.Lock()
	p := m.procs["olc1"]
	m.mu.Unlock()
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		t.Fatal("expected a tracked running cmd for olc1")
	}
	if procDied(p) {
		t.Fatal("procDied(olc1) = true immediately after launch; want false")
	}
}

// TestPluginrun_SuperviseRestartsCrashedOlc is the supervise contract: after the
// running olcRTC process dies, Supervise re-launches it from the on-disk config.
func TestPluginrun_SuperviseRestartsCrashedOlc(t *testing.T) {
	cfgDir := t.TempDir()
	binDir := t.TempDir()
	pluginrun_buildOlcStub(t, binDir)

	m := New(cfgDir, binDir)
	t.Cleanup(m.StopAll)

	m.Sync([]Spec{{ID: "olc1", Endpoint: pluginrun_olcEndpoint("olc1"), SOCKSPort: 17901}})
	if !pluginrun_isRunning(m, "olc1") {
		t.Fatal("precondition: olc1 not running after Sync")
	}

	// Grab the live process and the PID of the first incarnation, then kill it to
	// simulate a crash.
	m.mu.Lock()
	p := m.procs["olc1"]
	firstProc := p.cmd.Process
	firstDone := p.done
	m.mu.Unlock()
	if firstProc == nil {
		t.Fatal("no live process to kill")
	}
	firstPID := firstProc.Pid

	if err := firstProc.Kill(); err != nil {
		t.Fatalf("kill first olc process: %v", err)
	}
	// Wait for the exit-tracking goroutine to observe the death (done closes).
	pluginrun_waitFor(t, "first olc process to be observed dead", func() bool {
		select {
		case <-firstDone:
			return true
		default:
			return false
		}
	})

	// Supervise must detect the dead process and relaunch from the written config.
	m.Supervise()

	pluginrun_waitFor(t, "olc1 to be running again after Supervise", func() bool {
		return pluginrun_isRunning(m, "olc1")
	})

	// A genuinely NEW process must be tracked (different PID, fresh done channel).
	m.mu.Lock()
	p2 := m.procs["olc1"]
	var newPID int
	if p2 != nil && p2.cmd != nil && p2.cmd.Process != nil {
		newPID = p2.cmd.Process.Pid
	}
	sameDone := p2 != nil && p2.done == firstDone
	m.mu.Unlock()

	if newPID == 0 {
		t.Fatal("Supervise did not establish a new tracked process for olc1")
	}
	if newPID == firstPID {
		t.Fatalf("Supervise reused the dead PID %d; expected a fresh process", firstPID)
	}
	if sameDone {
		t.Fatal("Supervise kept the old (closed) done channel; expected a fresh one")
	}
	if !pluginrun_isRunning(m, "olc1") {
		t.Fatal("olc1 not running after Supervise restart")
	}
}

// TestPluginrun_SuperviseNoopWhenAlive verifies Supervise leaves a healthy
// running process untouched (same PID, still running).
func TestPluginrun_SuperviseNoopWhenAlive(t *testing.T) {
	cfgDir := t.TempDir()
	binDir := t.TempDir()
	pluginrun_buildOlcStub(t, binDir)

	m := New(cfgDir, binDir)
	t.Cleanup(m.StopAll)

	m.Sync([]Spec{{ID: "olc1", Endpoint: pluginrun_olcEndpoint("olc1"), SOCKSPort: 17901}})
	pluginrun_waitFor(t, "olc1 running", func() bool { return pluginrun_isRunning(m, "olc1") })

	m.mu.Lock()
	pidBefore := m.procs["olc1"].cmd.Process.Pid
	m.mu.Unlock()

	m.Supervise() // process is alive -> must be a no-op

	m.mu.Lock()
	pidAfter := m.procs["olc1"].cmd.Process.Pid
	m.mu.Unlock()

	if pidAfter != pidBefore {
		t.Fatalf("Supervise relaunched a healthy process: PID %d -> %d", pidBefore, pidAfter)
	}
	if !pluginrun_isRunning(m, "olc1") {
		t.Fatal("olc1 stopped being running after a no-op Supervise")
	}
}

// TestPluginrun_StopAllKillsRealProcess verifies StopAll terminates the live
// process and clears the tracked set.
func TestPluginrun_StopAllKillsRealProcess(t *testing.T) {
	cfgDir := t.TempDir()
	binDir := t.TempDir()
	pluginrun_buildOlcStub(t, binDir)

	m := New(cfgDir, binDir)

	m.Sync([]Spec{{ID: "olc1", Endpoint: pluginrun_olcEndpoint("olc1"), SOCKSPort: 17901}})
	pluginrun_waitFor(t, "olc1 running", func() bool { return pluginrun_isRunning(m, "olc1") })

	m.mu.Lock()
	proc := m.procs["olc1"].cmd.Process
	done := m.procs["olc1"].done
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
	pluginrun_buildOlcStub(t, binDir)
	m := New(cfgDir, binDir)
	m.Sync([]Spec{{ID: "olc1", Endpoint: pluginrun_olcEndpoint("olc1"), SOCKSPort: 17911}})
	pluginrun_waitFor(t, "olc1 running", func() bool { return pluginrun_isRunning(m, "olc1") })

	if n := m.StopByBin("some-other-binary"); n != 0 {
		t.Errorf("StopByBin(non-matching) = %d, want 0", n)
	}
	if !pluginrun_isRunning(m, "olc1") {
		t.Fatal("olc1 must still run after a non-matching StopByBin")
	}

	m.mu.Lock()
	binName := m.procs["olc1"].binName
	done := m.procs["olc1"].done
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
// olcRTC config stops the old process and starts a new one (different PID).
func TestPluginrun_SyncChangedSpecRestartsProcess(t *testing.T) {
	cfgDir := t.TempDir()
	binDir := t.TempDir()
	pluginrun_buildOlcStub(t, binDir)

	m := New(cfgDir, binDir)
	t.Cleanup(m.StopAll)

	m.Sync([]Spec{{ID: "olc1", Endpoint: pluginrun_olcEndpoint("olc1"), SOCKSPort: 17901}})
	pluginrun_waitFor(t, "olc1 running", func() bool { return pluginrun_isRunning(m, "olc1") })

	m.mu.Lock()
	pidBefore := m.procs["olc1"].cmd.Process.Pid
	m.mu.Unlock()

	// Change the SOCKS port -> rendered config differs -> Sync must restart it.
	m.Sync([]Spec{{ID: "olc1", Endpoint: pluginrun_olcEndpoint("olc1"), SOCKSPort: 18888}})
	pluginrun_waitFor(t, "olc1 running again after changed Sync", func() bool {
		return pluginrun_isRunning(m, "olc1")
	})

	m.mu.Lock()
	pidAfter := m.procs["olc1"].cmd.Process.Pid
	m.mu.Unlock()

	if pidAfter == pidBefore {
		t.Fatalf("changed-spec Sync did not restart the process (PID stayed %d)", pidBefore)
	}
}
