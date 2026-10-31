//go:build linux

package server

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// QA-109. A sing-box that an earlier daemon left running (an OOM kill, kill -9, a Go fatal error)
// still holds the cache-file lock, the Clash and mixed ports and the TUN, so the core this daemon
// starts dies at every start with "initialize cache-file: timeout" and the watchdog restarts it in a
// loop. The reaper for exactly that (core.SingBox.ReapStrays) lost its only caller with the old
// exact core adapter. Boot must end such a process before anything starts the new core.
//
// The stray is a shell whose argv[0] is the configured core binary and whose arguments name the
// configured core config: what /proc shows for `sing-box run -c <config>`, and all the reaper reads.
func TestStartApply_ReapsACoreAnEarlierDaemonLeftRunning(t *testing.T) {
	s, _ := applytest_server(t)
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("no sh to stand in for the orphaned core: %v", err)
	}
	cfg := s.config().SingBox
	stray := &exec.Cmd{Path: sh, Args: []string{cfg.Bin, "-c", "while :; do sleep 1; done", "sing-box", "run", "-c", cfg.Config}}
	if err := stray.Start(); err != nil {
		t.Fatalf("start the stand-in core: %v", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- stray.Wait() }()
	t.Cleanup(func() { _ = stray.Process.Kill() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // converge and the loops return at once; the reap must not depend on them
	s.StartApply(ctx, filepath.Join(s.applyStateDir, "config.json"))

	select {
	case err := <-exited:
		t.Logf("the orphaned core ended: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("StartApply left a core from an earlier daemon running on this daemon's config")
	}
}
