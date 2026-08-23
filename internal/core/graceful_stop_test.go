package core

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// gracefulstop_build compiles a one-file stub from src into the test's temp dir,
// reusing the toolchain locator from lifecycle_real_test.go (same package).
func gracefulstop_build(t *testing.T, src string) string {
	t.Helper()
	goBin := corelifecycle_goTool(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("write stub: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module gracefulstub\n\ngo 1.22\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	out := filepath.Join(dir, "stub"+corelifecycle_exeSuffix())
	cmd := exec.Command(goBin, "build", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GO111MODULE=on")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not build stub (skipping): %v\n%s", err, combined)
	}
	return out
}

// A stub that CATCHES and ignores SIGTERM and never exits on its own. Stop() must
// still terminate it via the SIGKILL fallback after the grace window.
const gracefulstop_ignoreSrc = `package main
import ("fmt";"os";"os/signal";"syscall";"time")
func main(){
	c:=make(chan os.Signal,1); signal.Notify(c,syscall.SIGTERM)
	fmt.Println("IGNORE-STUB up"); go func(){ for range c {} }()
	for { time.Sleep(time.Hour) }
}`

// A stub that EXITS cleanly on SIGTERM, printing a marker first so the ringLog
// proves SIGTERM was actually delivered (the graceful path).
const gracefulstop_handleSrc = `package main
import ("fmt";"os";"os/signal";"syscall")
func main(){
	c:=make(chan os.Signal,1); signal.Notify(c,syscall.SIGTERM)
	fmt.Println("HANDLE-STUB up"); <-c
	fmt.Println("HANDLE-STUB got-sigterm"); os.Exit(0)
}`

// TestGracefulStop_TerminatesSIGTERMIgnoringChild: even a child that swallows
// SIGTERM must be killed by Stop() (the SIGKILL fallback). Cross-platform.
func TestGracefulStop_TerminatesSIGTERMIgnoringChild(t *testing.T) {
	stub := gracefulstop_build(t, gracefulstop_ignoreSrc)
	old := stopGrace
	stopGrace = 300 * time.Millisecond
	defer func() { stopGrace = old }()

	s := New(stub, filepath.Join(t.TempDir(), "config.json"))
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	corelifecycle_waitFor(t, "child alive", s.Alive)
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if s.Alive() {
		t.Fatal("child still alive after Stop() — SIGKILL fallback did not fire")
	}
}

// TestGracefulStop_DeliversSIGTERMFirst proves Stop() sends SIGTERM before
// killing: the child exits cleanly on SIGTERM and logs a marker. Skipped on
// Windows, which has no SIGTERM delivery (Stop() falls straight to Kill there).
func TestGracefulStop_DeliversSIGTERMFirst(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no SIGTERM on windows; Stop() force-kills instead")
	}
	stub := gracefulstop_build(t, gracefulstop_handleSrc)
	s := New(stub, filepath.Join(t.TempDir(), "config.json"))
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	corelifecycle_waitFor(t, "child up banner", func() bool {
		return corelifecycle_hasLine(s.LogLines(), "HANDLE-STUB up")
	})
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !corelifecycle_hasLine(s.LogLines(), "got-sigterm") {
		t.Fatalf("child did not receive SIGTERM before kill; log=%v", s.LogLines())
	}
}
