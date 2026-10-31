//go:build linux

package core

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// deathsig_helperEnv names the directory the helper "daemon" works in; set only for the helper.
const deathsig_helperEnv = "WAYHOP_TEST_CORE_DAEMON_DIR"

// init turns this test binary into the helper "daemon" TestCoreDiesWithTheDaemon kills, when it is
// started as one: it starts a core through the real supervisor, records the core's pid and waits to
// be killed. An init rather than a skipping Test function keeps the skip manifest out of it.
func init() {
	dir := os.Getenv(deathsig_helperEnv)
	if dir == "" {
		return
	}
	sb := New(filepath.Join(dir, "sing-box"), filepath.Join(dir, "singbox.json"))
	if err := sb.Start(); err != nil {
		fmt.Println("helper start:", err)
		os.Exit(3)
	}
	sb.mu.Lock()
	pid := sb.cmd.Process.Pid
	sb.mu.Unlock()
	if err := os.WriteFile(filepath.Join(dir, "core.pid"), []byte(strconv.Itoa(pid)), 0o600); err != nil {
		os.Exit(4)
	}
	time.Sleep(time.Hour) // until the test kills this daemon
}

// deathsig_alive reports whether pid is a live process: neither gone nor a zombie waiting for init.
func deathsig_alive(pid int) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return false
	}
	state := s[i+2]
	return state != 'Z' && state != 'X'
}

// QA-109. A daemon that dies without running Shutdown (an OOM kill, a kill -9, a Go fatal error)
// must not leave its core running: the orphan kept routing by the old config with no supervisor,
// and it held the cache-file lock and the ports, so the next daemon's core died at every start.
func TestCoreDiesWithTheDaemon(t *testing.T) {
	dir := t.TempDir()
	// The stand-in core ignores its `run -c <config>` and sleeps; exec keeps the pid the supervisor
	// started, which is the process that must die with the daemon.
	if err := os.WriteFile(filepath.Join(dir, "sing-box"), []byte("#!/bin/sh\nexec sleep 300\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "singbox.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	daemon := exec.Command(os.Args[0], "-test.run=^$")
	daemon.Env = append(os.Environ(), deathsig_helperEnv+"="+dir)
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = daemon.Process.Kill(); _ = daemon.Wait() })

	pid := 0
	for deadline := time.Now().Add(10 * time.Second); pid == 0 && time.Now().Before(deadline); {
		if b, err := os.ReadFile(filepath.Join(dir, "core.pid")); err == nil {
			pid, _ = strconv.Atoi(string(b))
		}
		if pid == 0 {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if pid == 0 || !deathsig_alive(pid) {
		t.Fatalf("the helper daemon never started its core (pid %d)", pid)
	}
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })

	_ = daemon.Process.Kill() // the daemon dies uncleanly: nothing runs Shutdown
	_ = daemon.Wait()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if !deathsig_alive(pid) {
			return
		}
	}
	t.Fatalf("the core (pid %d) outlived the daemon that started it", pid)
}
