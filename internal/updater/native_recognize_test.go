package updater

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/pm"
)

// pmMock is a pm.Runner returning canned output for opkg/apk queries.
type pmMock struct{ out string }

func (m pmMock) Run(ctx context.Context, name string, args ...string) (string, error) {
	return m.out, nil
}

// errRunner simulates a PM whose database is locked (every query fails).
type errRunner struct{}

func (errRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	return "Could not lock /opt/tmp/opkg.lock\n", errors.New("exit status 255")
}

// TestNativeManaged_RefusesInstallAndUninstall: when the engine's binary exists AND opkg reports a
// package owns that path, both Install and Uninstall must REFUSE (defer to opkg) rather than clobber
// the packaged binary / orphan its DB entry.
func TestNativeManaged_RefusesInstallAndUninstall(t *testing.T) {
	binDir := t.TempDir()
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}
	if err := os.WriteFile(filepath.Join(binDir, e.BinName), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := New(binDir, "arm64", nil).WithPM(pm.Manager{Kind: pm.Opkg, Runner: pmMock{out: "sing-box-go - 1.12.22-r1\n"}})

	if _, err := u.Install(context.Background(), e, "v1.12.22"); err == nil || !strings.Contains(err.Error(), "managed by opkg") {
		t.Errorf("Install over a PM-owned binary must refuse with 'managed by opkg', got %v", err)
	}
	if err := u.Uninstall(e); err == nil || !strings.Contains(err.Error(), "managed by opkg") {
		t.Errorf("Uninstall of a PM-owned binary must refuse with 'managed by opkg', got %v", err)
	}
}

// TestNativeManaged_NoPM_DoesNotRefuse: with no package manager, recognition is a pure no-op, so the
// direct-download path is unaffected (dev/CI hosts included).
func TestNativeManaged_NoPM_DoesNotRefuse(t *testing.T) {
	binDir := t.TempDir()
	e := Engine{ID: "sing-box", BinName: "sing-box"}
	_ = os.WriteFile(filepath.Join(binDir, e.BinName), []byte("x"), 0o755)
	u := New(binDir, "arm64", nil).WithPM(pm.Manager{Kind: pm.None})
	if _, yes, err := u.nativeManaged(e); yes || err != nil {
		t.Error("no PM must never report native-managed")
	}
	if u.NativeManaged(e) {
		t.Error("NativeManaged must be false with no PM")
	}
}

// TestNativeManaged_AbsentBinary_NotManaged: an engine with no binary in BinDir NOR on PATH is not
// "managed" — there is nothing to clobber, and no PM exec is spent probing it.
func TestNativeManaged_AbsentBinary_NotManaged(t *testing.T) {
	e := Engine{ID: "sing-box", BinName: "wayhop-test-no-such-binary-xyz"} // guaranteed not on PATH either
	u := New(t.TempDir(), "arm64", nil).WithPM(pm.Manager{Kind: pm.Opkg, Runner: pmMock{out: "sing-box-go - 1\n"}})
	if _, yes, err := u.nativeManaged(e); yes || err != nil {
		t.Error("an absent binary must not be reported native-managed")
	}
}

// TestNativeManaged_FailsClosedOnPMError: when the PM can't answer (db locked by a concurrent
// opkg/apk run), the MUTATING paths refuse instead of proceeding as if unowned — otherwise the
// clobber guard silently disappears exactly when the PM is busy installing.
func TestNativeManaged_FailsClosedOnPMError(t *testing.T) {
	binDir := t.TempDir()
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}
	if err := os.WriteFile(filepath.Join(binDir, e.BinName), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	locked := pm.Manager{Kind: pm.Opkg, Runner: errRunner{}}
	u := New(binDir, "arm64", nil).WithPM(locked)
	if _, err := u.Install(context.Background(), e, "v1.12.22"); err == nil || !strings.Contains(err.Error(), "could not verify") {
		t.Errorf("Install must fail closed on a PM query error, got %v", err)
	}
	if err := u.Uninstall(e); err == nil || !strings.Contains(err.Error(), "could not verify") {
		t.Errorf("Uninstall must fail closed on a PM query error, got %v", err)
	}
	var nm *NativeManagedError
	if err := u.UninstallPrecheck(e); !errors.As(err, &nm) {
		t.Errorf("the fail-closed refusal must be a NativeManagedError (409), got %T %v", err, err)
	}
	if u.NativeManaged(e) {
		t.Error("the advisory UI bool reads false on a PM error (no false badge)")
	}
}

// TestUninstallPrecheck_AbsentIsRefusedNotSuccess: a binary the panel never installed (absent in
// BinDir) must refuse with an explanation, NOT report success — 'removed' for an untouched binary
// misleads the operator (it may exist elsewhere on PATH, PM-owned).
func TestUninstallPrecheck_AbsentIsRefusedNotSuccess(t *testing.T) {
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "wayhop-test-no-such-binary-xyz"}
	u := New(t.TempDir(), "arm64", nil).WithPM(pm.Manager{Kind: pm.None})
	if err := u.UninstallPrecheck(e); err == nil || !strings.Contains(err.Error(), "no panel-installed binary") {
		t.Errorf("absent binary must refuse the uninstall, got %v", err)
	}
	if err := u.Uninstall(e); err == nil {
		t.Error("Uninstall of an absent binary must NOT report success")
	}
}

// TestSelfManaged_RefusesSelfUpdate: when wayhop's own binary is opkg-owned (feed-installed),
// SelfUpdate must REFUSE the self-swap and defer to the PM (red-team R5 — no racing restart / DB
// desync). The refuse fires before any network lookup. No PM -> the normal GitHub path is unaffected.
func TestSelfManaged_RefusesSelfUpdate(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "wayhop")
	if err := os.WriteFile(exe, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := New(dir, "arm64", nil).WithPM(pm.Manager{Kind: pm.Opkg, Runner: pmMock{out: "wayhop - 0.4.0-r1\n"}})
	if _, err := u.SelfUpdate(context.Background(), "", "latest", exe); err == nil || !strings.Contains(err.Error(), "managed by opkg") {
		t.Errorf("SelfUpdate of a PM-owned wayhop must refuse with 'managed by opkg', got %v", err)
	}
	if New(dir, "arm64", nil).WithPM(pm.Manager{Kind: pm.None}).SelfManaged(exe) {
		t.Error("SelfManaged must be false with no PM")
	}
}

// TestBinaryRunnable: the post-install probe distinguishes "won't execute" (wrong arch/corrupt ->
// error) from "ran but exited non-zero / no version" (fine), and no-ops without VersionArgs.
func TestBinaryRunnable(t *testing.T) {
	if v, err := binaryRunnable("/nonexistent", nil); err != nil || v != "" {
		t.Errorf("no VersionArgs must be a no-op, got %q,%v", v, err)
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("\x00\x01not a real binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := binaryRunnable(bad, []string{"version"}); err == nil {
		t.Error("a non-executable file must fail the runnable check")
	}
	// The test binary itself IS runnable; a no-match filter makes it run and exit without recursing.
	if _, err := binaryRunnable(os.Args[0], []string{"-test.run=NoSuchTestXYZ"}); err != nil {
		t.Errorf("a runnable binary must not be flagged non-executable: %v", err)
	}
}
