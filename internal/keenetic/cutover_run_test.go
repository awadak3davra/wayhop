package keenetic

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wayhop/internal/failsafe"
)

func TestCutoverCheck(t *testing.T) {
	// Exit IP is a VPN exit (≠ raw WAN) → healthy.
	if ok := CutoverCheck(func() (string, error) { return "203.0.113.10", nil }, "172.20.7.173"); !ok() {
		t.Error("a VPN exit IP must pass the check")
	}
	// Exit IP == raw WAN IP → leaking → FAIL.
	if leak := CutoverCheck(func() (string, error) { return "172.20.7.173", nil }, "172.20.7.173"); leak() {
		t.Error("exit IP equal to the raw WAN IP must FAIL (leak)")
	}
	// Probe error → FAIL (don't commit on an unknown state).
	if bad := CutoverCheck(func() (string, error) { return "", errors.New("x") }, "172.20.7.173"); bad() {
		t.Error("a probe error must FAIL the check")
	}
}

// checkFailRunner records calls and fails ONLY the `sing-box check` command, to exercise the
// config-check gate: a bad staged config must trip Cutover's rollback before the restart/apply.
type checkFailRunner struct{ calls []string }

func (r *checkFailRunner) Run(stdin, name string, args ...string) (string, error) {
	cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
	r.calls = append(r.calls, cmd)
	if strings.Contains(cmd, "check -c") {
		return "", errors.New("sing-box: decode config: dns detour to unknown outbound")
	}
	return "", nil
}

// TestRunCutover_BadConfigCheckRollsBack: when the staged sing-box config fails `sing-box check`,
// the cutover rolls back (original config restored) WITHOUT restarting onto / applying the kernel
// default — no LAN black-hole — and the failsafe is NOT armed.
func TestRunCutover_BadConfigCheckRollsBack(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"outbounds":[{"tag":"orig"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	run := &checkFailRunner{}
	in := PrepareInputs{
		KeenPBRConfig:     []byte(kpFixture),
		LocalListFiles:    map[string][]string{"/opt/etc/keen-pbr/local.lst": {"lampa.mx"}},
		RunningConfig:     rcFixture,
		LiveSingboxConfig: []byte(`{"outbounds":[{"type":"hysteria2","tag":"hy2-main","server":"9.9.9.9","server_port":8444,"password":"P","tls":{"enabled":true}},{"type":"vless","tag":"vless-main","server":"9.9.9.9","server_port":443,"uuid":"U","tls":{"enabled":true}}]}`),
		WanGateway:        "172.20.0.1",
		Fetch:             func(string) ([]string, error) { return []string{"149.154.160.0/20"}, nil },
		Stage:             SingboxStageOptions{ConfigPath: cfgPath},
		Netfilter:         NetfilterHookOptions{Path: filepath.Join(dir, "40-wayhop.sh")},
	}
	mgr := failsafe.New(failsafe.Durations{Grace: time.Hour, Interval: time.Hour, RollbackAfter: time.Hour, RebootAfter: time.Hour, KeepWindow: time.Hour})

	_, err := RunCutover(run, in, mgr, func() bool { return true }, func() {}, false)
	if err == nil {
		t.Fatal("RunCutover must fail when the staged config fails sing-box check")
	}
	if !strings.Contains(err.Error(), "check sing-box config") {
		t.Errorf("error should name the failed check step: %v", err)
	}
	if b, _ := os.ReadFile(cfgPath); !strings.Contains(string(b), "orig") {
		t.Errorf("rollback must restore the original sing-box config, got %s", b)
	}
	if strings.Contains(strings.Join(run.calls, "\n"), "ip route replace default dev wr-tun") {
		t.Error("kernel default must NOT be applied after a failed config check")
	}
	if mgr.Status().Pending {
		t.Error("failsafe must NOT be armed after a failed cutover")
	}
}

func TestRunCutover_AppliesAndArms(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"outbounds":[{"tag":"orig"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	run := &recRunner{}
	in := PrepareInputs{
		KeenPBRConfig:     []byte(kpFixture),
		LocalListFiles:    map[string][]string{"/opt/etc/keen-pbr/local.lst": {"lampa.mx"}},
		RunningConfig:     rcFixture,
		LiveSingboxConfig: []byte(`{"outbounds":[{"type":"hysteria2","tag":"hy2-main","server":"9.9.9.9","server_port":8444,"password":"P","tls":{"enabled":true}},{"type":"vless","tag":"vless-main","server":"9.9.9.9","server_port":443,"uuid":"U","tls":{"enabled":true}}]}`),
		WanGateway:        "172.20.0.1",
		Fetch:             func(string) ([]string, error) { return []string{"149.154.160.0/20"}, nil },
		Stage:             SingboxStageOptions{ConfigPath: cfgPath},
		Netfilter:         NetfilterHookOptions{Path: filepath.Join(dir, "40-wayhop.sh")},
	}
	mgr := failsafe.New(failsafe.Durations{Grace: time.Hour, Interval: time.Hour, RollbackAfter: time.Hour, RebootAfter: time.Hour, KeepWindow: time.Hour})

	warns, err := RunCutover(run, in, mgr, func() bool { return true }, func() {}, false)
	if err != nil {
		t.Fatalf("RunCutover: %v (warns %v)", err, warns)
	}

	// Cutover ran: old stack retired + kernel default applied.
	got := strings.Join(run.calls, "\n")
	if !strings.Contains(got, "chmod -x /opt/etc/init.d/S80keen-pbr") {
		t.Error("old stack not retired")
	}
	if !strings.Contains(got, "ip route replace default dev wr-tun metric 50") {
		t.Error("kernel default→wr-tun not applied")
	}
	// New sing-box config staged (the original is snapshotted).
	if snap, _ := os.ReadFile(cfgPath + ".wr-orig"); !strings.Contains(string(snap), "orig") {
		t.Error("original sing-box config not snapshotted")
	}
	// Failsafe armed.
	if !mgr.Status().Pending {
		t.Error("failsafe must be armed after a successful cutover")
	}
	mgr.Confirm() // stop the armed goroutine
}
