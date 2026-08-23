package server

import (
	"strings"
	"testing"
	"time"

	"wayhop/internal/core"
)

// TestVerifySingboxLive_DeadCoreDetected is the P0 regression guard: Reload()/Start() return as soon
// as the process is SPAWNED, so a config that passes `sing-box check` but aborts at runtime would
// otherwise let Apply report success and advance the applied revision over a dead core. A core that
// is not running must yield a non-empty diagnostic — and must do so PROMPTLY (the poll exits on the
// first dead observation; it must not burn the whole settle window).
func TestVerifySingboxLive_DeadCoreDetected(t *testing.T) {
	s := &Server{singbox: core.New(t.TempDir()+"/no-such-sing-box", t.TempDir()+"/config.json")}
	if s.singbox.Running() {
		t.Fatal("test setup broken: a never-started core must not report Running")
	}

	start := time.Now()
	msg := s.verifySingboxLive()
	elapsed := time.Since(start)

	if msg == "" {
		t.Fatal("a dead core must produce a diagnostic, got empty (Apply would falsely report success)")
	}
	if !strings.Contains(msg, "NOT running") {
		t.Errorf("diagnostic should say the core is not running, got %q", msg)
	}
	// Dead is observed on the first poll iteration — no reason to wait out the settle window.
	if elapsed >= singboxSettleWindow {
		t.Errorf("dead core must be detected promptly, took %v (settle window %v)", elapsed, singboxSettleWindow)
	}
}
