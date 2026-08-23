package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// lifecycle_real_test.go exercises the REAL process-lifecycle paths of SingBox
// (Start/Stop/Reload/Alive/Desired/StartedAt + the exit-tracking goroutine + the
// ringLog fed from real child output) by building a tiny stub executable at test
// time and pointing core.New(...) at it. All helpers are prefixed with
// "corelifecycle_" to avoid clashing with singbox_test.go symbols.

// corelifecycle_stubSource is a self-contained Go program built into an .exe at
// test time. Behaviour:
//   - With env CORELIFECYCLE_CRASH=1 it prints a line and exits non-zero
//     immediately (simulates a crash).
//   - Otherwise it prints a startup banner to stdout (so the ringLog captures it)
//     and blocks forever. SingBox launches it as `<bin> run -c <config>`; the stub
//     ignores its args.
const corelifecycle_stubSource = `package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	if os.Getenv("CORELIFECYCLE_CRASH") == "1" {
		fmt.Println("CORELIFECYCLE-STUB crashing on purpose")
		os.Exit(3)
	}
	fmt.Println("CORELIFECYCLE-STUB up and running")
	// Block "forever" via a sleep loop. A bare select{} would trip Go's
	// all-goroutines-asleep deadlock detector and make the stub exit on its own,
	// so we keep a sleeping goroutine alive instead. The supervisor kills us via
	// Process.Kill().
	for {
		time.Sleep(time.Hour)
	}
}
`

// corelifecycle_buildStub writes the stub source into a fresh temp dir and builds
// it into an executable for the host OS. It t.Skip()s if the toolchain or build is
// unavailable so the suite stays green in constrained CI.
func corelifecycle_buildStub(t *testing.T) string {
	t.Helper()

	goBin := corelifecycle_goTool(t)

	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte(corelifecycle_stubSource), 0o600); err != nil {
		t.Fatalf("write stub source: %v", err)
	}
	// A standalone module so `go build` doesn't try to attach the stub to the wayhop
	// module (the temp dir is outside the repo, but be explicit).
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module corelifecyclestub\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatalf("write stub go.mod: %v", err)
	}

	out := filepath.Join(dir, "stub"+corelifecycle_exeSuffix())
	cmd := exec.Command(goBin, "build", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GO111MODULE=on")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not build stub executable (skipping real-process tests): %v\n%s", err, combined)
	}
	if _, err := os.Stat(out); err != nil {
		t.Skipf("stub executable missing after build: %v", err)
	}
	return out
}

// corelifecycle_goTool locates the Go binary used to build the stub. It honours
// the repo's documented ~/go-toolchain location, then falls back to PATH.
func corelifecycle_goTool(t *testing.T) string {
	t.Helper()
	if home, err := os.UserHomeDir(); err == nil {
		cand := filepath.Join(home, "go-toolchain", "go", "bin", "go"+corelifecycle_exeSuffix())
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

func corelifecycle_exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// corelifecycle_waitFor polls cond until it returns true or the deadline passes.
// Generous timeout keeps it deterministic on a slow/loaded CI box.
func corelifecycle_waitFor(t *testing.T, what string, cond func() bool) {
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

// corelifecycle_hasLine reports whether any captured log line contains substr.
func corelifecycle_hasLine(lines []string, substr string) bool {
	for _, l := range lines {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

// TestCorelifecycle_StartRunStop drives the happy path against a real child:
// Start -> Alive/Desired/StartedAt set + banner captured -> Stop -> not alive.
func TestCorelifecycle_StartRunStop(t *testing.T) {
	stub := corelifecycle_buildStub(t)
	s := New(stub, filepath.Join(t.TempDir(), "config.json"))
	t.Cleanup(func() { _ = s.Stop() })

	before := time.Now()
	if err := s.Start(); err != nil {
		t.Fatalf("Start() error = %v; want nil", err)
	}

	corelifecycle_waitFor(t, "process to become Alive", s.Alive)

	if !s.Alive() {
		t.Fatal("Alive() = false after Start; want true")
	}
	if !s.Running() {
		t.Fatal("Running() = false after Start; want true")
	}
	if !s.Desired() {
		t.Fatal("Desired() = false after Start; want true")
	}
	at := s.StartedAt()
	if at.IsZero() {
		t.Fatal("StartedAt() = zero after Start; want non-zero")
	}
	if at.Before(before) {
		t.Fatalf("StartedAt() = %v is before Start was called (%v)", at, before)
	}

	// The child's stdout banner must surface through io.MultiWriter -> ringLog.
	corelifecycle_waitFor(t, "stub banner in LogLines", func() bool {
		return corelifecycle_hasLine(s.LogLines(), "CORELIFECYCLE-STUB up and running")
	})

	if err := s.Stop(); err != nil {
		t.Fatalf("Stop() error = %v; want nil", err)
	}
	if s.Alive() {
		t.Fatal("Alive() = true after Stop; want false")
	}
	if s.Running() {
		t.Fatal("Running() = true after Stop; want false")
	}
	if s.Desired() {
		t.Fatal("Desired() = true after Stop; want false (Stop clears watchdog intent)")
	}
}

// TestCorelifecycle_StartIdempotentWhileAlive verifies that a second Start while
// the process is already alive does not spawn a new process: StartedAt is
// unchanged and the same child keeps running.
func TestCorelifecycle_StartIdempotentWhileAlive(t *testing.T) {
	stub := corelifecycle_buildStub(t)
	s := New(stub, filepath.Join(t.TempDir(), "config.json"))
	t.Cleanup(func() { _ = s.Stop() })

	if err := s.Start(); err != nil {
		t.Fatalf("first Start() error = %v", err)
	}
	corelifecycle_waitFor(t, "process to become Alive", s.Alive)
	first := s.StartedAt()

	// Small spacing so a re-launch would yield a strictly later StartedAt.
	time.Sleep(20 * time.Millisecond)

	if err := s.Start(); err != nil {
		t.Fatalf("second Start() (already alive) error = %v; want nil", err)
	}
	if got := s.StartedAt(); !got.Equal(first) {
		t.Fatalf("StartedAt() changed after a no-op Start: %v -> %v (must not relaunch a live process)", first, got)
	}
	if !s.Alive() || !s.Desired() {
		t.Fatal("process must stay Alive() and Desired() after idempotent Start")
	}
}

// TestCorelifecycle_ReloadRestarts verifies Reload stops the current process and
// starts a fresh one: it stays Alive/Desired and StartedAt advances.
func TestCorelifecycle_ReloadRestarts(t *testing.T) {
	stub := corelifecycle_buildStub(t)
	s := New(stub, filepath.Join(t.TempDir(), "config.json"))
	t.Cleanup(func() { _ = s.Stop() })

	if err := s.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	corelifecycle_waitFor(t, "process to become Alive", s.Alive)
	first := s.StartedAt()

	time.Sleep(20 * time.Millisecond)

	if err := s.Reload(); err != nil {
		t.Fatalf("Reload() error = %v; want nil", err)
	}
	corelifecycle_waitFor(t, "process Alive after Reload", s.Alive)

	if !s.Desired() {
		t.Fatal("Desired() = false after Reload; want true")
	}
	second := s.StartedAt()
	if !second.After(first) {
		t.Fatalf("StartedAt() did not advance across Reload: %v -> %v", first, second)
	}

	if err := s.Stop(); err != nil {
		t.Fatalf("Stop() after Reload error = %v", err)
	}
	if s.Alive() {
		t.Fatal("Alive() = true after final Stop; want false")
	}
}

// TestCorelifecycle_CrashFlipsAliveButKeepsDesired is the watchdog contract: when
// the child exits on its own, Alive() goes false (the exit-tracking goroutine
// closed done) while Desired() stays true so a watchdog would restart it.
func TestCorelifecycle_CrashFlipsAliveButKeepsDesired(t *testing.T) {
	stub := corelifecycle_buildStub(t)
	s := New(stub, filepath.Join(t.TempDir(), "config.json"))
	t.Cleanup(func() { _ = s.Stop() })

	// Make this launch crash immediately. exec.Command inherits the parent env,
	// so setting it on the test process propagates to the child.
	t.Setenv("CORELIFECYCLE_CRASH", "1")

	if err := s.Start(); err != nil {
		t.Fatalf("Start() error = %v; want nil (Start succeeds, the process exits later)", err)
	}
	// Start marks desired immediately, before the child may have exited.
	if !s.Desired() {
		t.Fatal("Desired() = false right after Start; want true")
	}

	// The crashing child exits on its own -> exit goroutine closes done -> Alive false.
	corelifecycle_waitFor(t, "crashed process to flip Alive()=false", func() bool {
		return !s.Alive()
	})

	if s.Alive() {
		t.Fatal("Alive() = true after the child crashed; want false")
	}
	if s.Running() {
		t.Fatal("Running() = true after the child crashed; want false")
	}
	// The crash must NOT clear the watchdog intent.
	if !s.Desired() {
		t.Fatal("Desired() = false after a crash; want true (watchdog must still want it up)")
	}
	// The crash banner should have been captured before exit.
	corelifecycle_waitFor(t, "crash banner in LogLines", func() bool {
		return corelifecycle_hasLine(s.LogLines(), "crashing on purpose")
	})
}

// TestCorelifecycle_StartAfterCrashRelaunches verifies the watchdog-style
// recovery: after a crash (Alive false, Desired true) a fresh Start launches a
// new, healthy process.
func TestCorelifecycle_StartAfterCrashRelaunches(t *testing.T) {
	stub := corelifecycle_buildStub(t)
	cfg := filepath.Join(t.TempDir(), "config.json")
	s := New(stub, cfg)
	t.Cleanup(func() { _ = s.Stop() })

	// First launch crashes.
	t.Setenv("CORELIFECYCLE_CRASH", "1")
	if err := s.Start(); err != nil {
		t.Fatalf("crashing Start() error = %v", err)
	}
	corelifecycle_waitFor(t, "first process to die", func() bool { return !s.Alive() })
	if !s.Desired() {
		t.Fatal("Desired() = false after crash; want true")
	}

	// Now clear the crash env and re-Start (what a watchdog would do).
	if err := os.Unsetenv("CORELIFECYCLE_CRASH"); err != nil {
		t.Fatalf("unset crash env: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("recovery Start() error = %v; want nil", err)
	}
	corelifecycle_waitFor(t, "recovered process Alive", s.Alive)

	if !s.Alive() || !s.Desired() {
		t.Fatal("after recovery Start the process must be Alive() and Desired()")
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop() after recovery error = %v", err)
	}
}
