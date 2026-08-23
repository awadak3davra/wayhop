package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wayhop/internal/pm"
)

// TestUninstall_SerializesDeleteWithApply is the LOOP-024 guard. handleUpdaterUninstall stops the
// engine and then deletes its binary; handleApply, which restarts the core, takes applyMu end-to-end.
// If the delete runs OUTSIDE applyMu, a concurrent Apply can restart the core onto the binary between
// the stop and the unlink, and the uninstall then reports removed while the old inode keeps running.
// The delete must be serialized with Apply.
//
// The test simulates an in-flight Apply by holding applyMu, then fires an uninstall: it must BLOCK
// (not delete the binary) until the lock is released. Proven to FAIL against the old code, whose
// delete path never touched applyMu — the uninstall completed, and the binary vanished, while the
// lock was held.
func TestUninstall_SerializesDeleteWithApply(t *testing.T) {
	s, _ := routing_newServer(t)
	if s.updater == nil {
		t.Fatal("test harness built no updater")
	}
	// Force "no package manager" so UninstallPrecheck takes the panel-installed (GitHub) path — the
	// case a direct uninstall is FOR — instead of whatever PM the build host happens to carry. Without
	// this the Debian test image's own tooling makes the ownership probe answer 409 before the lock.
	s.updater.WithPM(pm.Manager{Kind: pm.None})

	// Panel-install a fake engine binary in the updater's BinDir (the dir of the configured sing-box
	// binary — see server.New). xray is a real registry engine, not source-only, and no package
	// manager exists on the test host, so UninstallPrecheck accepts it.
	binDir := filepath.Dir(s.cfg.SingBox.Bin)
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bindir: %v", err)
	}
	binPath := filepath.Join(binDir, "xray")
	if err := os.WriteFile(binPath, []byte("fake-xray"), 0o755); err != nil {
		t.Fatalf("seed binary: %v", err)
	}

	uninstall := func() int {
		req := httptest.NewRequest(http.MethodDelete, "/api/updater/xray", strings.NewReader(`{}`))
		req.SetPathValue("id", "xray")
		rec := httptest.NewRecorder()
		s.handleUpdaterUninstall(rec, req)
		return rec.Code
	}

	// Simulate an Apply in flight.
	s.applyMu.Lock()

	done := make(chan int, 1)
	go func() { done <- uninstall() }()

	// While the Apply holds applyMu, the uninstall must not complete — it is blocked acquiring the
	// same lock before it can delete. A qualitative distinction: the new code blocks indefinitely, the
	// old code (delete never under applyMu) completes in microseconds, so the window is not a guess.
	select {
	case code := <-done:
		s.applyMu.Unlock()
		t.Fatalf("uninstall completed (status %d) while an Apply held applyMu — the delete is not serialized (LOOP-024)", code)
	case <-time.After(300 * time.Millisecond):
	}
	if _, err := os.Stat(binPath); err != nil {
		s.applyMu.Unlock()
		t.Fatalf("the binary was deleted while applyMu was held: %v", err)
	}

	// Release the Apply; the uninstall now proceeds and removes the binary.
	s.applyMu.Unlock()
	if code := <-done; code != http.StatusOK {
		t.Fatalf("uninstall status = %d after the lock was released, want 200", code)
	}
	if _, err := os.Stat(binPath); !os.IsNotExist(err) {
		t.Errorf("binary still present after uninstall (stat err = %v)", err)
	}
}
