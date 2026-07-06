package keenetic

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCutover_SuccessThenRollback(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"outbounds":[{"tag":"orig-hy2"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	hookPath := filepath.Join(dir, "40-wayhop.sh")
	run := &recRunner{}
	var kApplied, kTorndown bool

	o := CutoverOptions{
		SingboxConfig:  map[string]any{"inbounds": []any{}, "outbounds": []any{}},
		Netfilter:      NetfilterHookOptions{Path: hookPath},
		Stage:          SingboxStageOptions{ConfigPath: cfgPath},
		ApplyKernel:    func() error { kApplied = true; return nil },
		TeardownKernel: func() error { kTorndown = true; return nil },
	}
	rollback, err := Cutover(run, o)
	if err != nil {
		t.Fatal(err)
	}

	// Forward: old stack retired, hook installed, config staged+snapshotted, restarted, kernel applied.
	fwd := strings.Join(run.calls, "\n")
	if !strings.Contains(fwd, "chmod -x /opt/etc/init.d/S80keen-pbr") {
		t.Error("old stack not retired")
	}
	if !strings.Contains(fwd, "/opt/etc/init.d/S99sing-box restart") {
		t.Error("sing-box not restarted")
	}
	if !kApplied {
		t.Error("kernel plane not applied")
	}
	if _, e := os.Stat(hookPath); e != nil {
		t.Error("netfilter hook not installed")
	}
	if snap, _ := os.ReadFile(cfgPath + ".wr-orig"); !strings.Contains(string(snap), "orig-hy2") {
		t.Error("original sing-box config not snapshotted")
	}
	if cur, _ := os.ReadFile(cfgPath); strings.Contains(string(cur), "orig-hy2") {
		t.Error("sing-box config not replaced with the new one")
	}

	// Rollback restores EVERYTHING.
	mark := len(run.calls)
	if err := rollback(); err != nil {
		t.Fatal(err)
	}
	if back, _ := os.ReadFile(cfgPath); !strings.Contains(string(back), "orig-hy2") {
		t.Error("rollback did not restore the original sing-box config")
	}
	if _, e := os.Stat(hookPath); !os.IsNotExist(e) {
		t.Error("rollback did not remove the netfilter hook")
	}
	if !kTorndown {
		t.Error("rollback did not tear down the kernel plane")
	}
	if !strings.Contains(strings.Join(run.calls[mark:], "\n"), "/opt/etc/init.d/S80keen-pbr start") {
		t.Error("rollback did not restart the old stack")
	}
}

func TestCutover_RollsBackOnStepFailure(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	_ = os.WriteFile(cfgPath, []byte(`{"tag":"orig"}`), 0o644)
	run := &recRunner{}
	var torndown bool

	o := CutoverOptions{
		SingboxConfig:  map[string]any{"x": 1},
		Netfilter:      NetfilterHookOptions{Path: filepath.Join(dir, "hook.sh")},
		Stage:          SingboxStageOptions{ConfigPath: cfgPath},
		ApplyKernel:    func() error { return errors.New("kernel apply boom") },
		TeardownKernel: func() error { torndown = true; return nil },
	}
	rb, err := Cutover(run, o)
	if err == nil || !strings.Contains(err.Error(), "apply kernel plane") {
		t.Fatalf("want kernel-apply failure, got err=%v", err)
	}
	if rb != nil {
		t.Error("a failed cutover must return a nil rollback (it already rolled back)")
	}
	// Auto-rolled-back: config restored, kernel torn down, old stack restarted.
	if back, _ := os.ReadFile(cfgPath); !strings.Contains(string(back), "orig") {
		t.Error("config not restored after the failed cutover")
	}
	if !torndown {
		t.Error("kernel not torn down after the failed cutover")
	}
	if !strings.Contains(strings.Join(run.calls, "\n"), "/opt/etc/init.d/S80keen-pbr start") {
		t.Error("old stack not restored after the failed cutover")
	}
}
