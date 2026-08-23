package keenetic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- bug #12: IPv6 bypass/local-direct routes must use the IPv6 WAN gateway + `ip -6`, never the
// IPv4 gateway (which iproute2 rejects, aborting the whole cutover). ---

func TestKernelPlaneAddCommands_IPv6UsesV6Gateway(t *testing.T) {
	o := KernelPlaneOptions{
		WanIface: "eth3", WanGateway: "172.20.0.1", WanGateway6: "fe80::1",
		BypassIPs:   []string{"203.0.113.10", "2001:db8::1"},
		LocalDirect: []string{"2001:db8:aaaa::/48"},
	}
	cmds, err := kernelPlaneAddCommands(o)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(cmds, "\n")
	if !strings.Contains(got, "ip route replace 203.0.113.10 via 172.20.0.1 dev eth3 metric 50") {
		t.Errorf("v4 bypass form changed:\n%s", got)
	}
	if !strings.Contains(got, "ip -6 route replace 2001:db8::1 via fe80::1 dev eth3 metric 50") {
		t.Errorf("v6 bypass must use `ip -6` + the v6 gateway:\n%s", got)
	}
	if !strings.Contains(got, "ip -6 route replace 2001:db8:aaaa::/48 via fe80::1 dev eth3 metric 100") {
		t.Errorf("v6 local-direct must use `ip -6` + the v6 gateway:\n%s", got)
	}
	if strings.Contains(got, "2001:db8::1 via 172.20.0.1") {
		t.Errorf("a v6 dest must NEVER be paired with the IPv4 gateway:\n%s", got)
	}
}

func TestKernelPlaneAddCommands_IPv6SkippedWithoutV6Gateway(t *testing.T) {
	o := KernelPlaneOptions{
		WanIface: "eth3", WanGateway: "172.20.0.1", // no WanGateway6 (no IPv6 WAN)
		BypassIPs: []string{"203.0.113.10", "2001:db8::1"},
	}
	cmds, err := kernelPlaneAddCommands(o)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(cmds, "\n")
	if strings.Contains(got, "2001:db8::1") {
		t.Errorf("without a v6 WAN gateway the v6 bypass must be SKIPPED, not emitted broken (which would abort the cutover):\n%s", got)
	}
	if !strings.Contains(got, "ip route replace 203.0.113.10 via 172.20.0.1 dev eth3 metric 50") {
		t.Errorf("the v4 bypass must still be emitted:\n%s", got)
	}
}

func TestKernelPlaneDelCommands_IPv6UsesV6Family(t *testing.T) {
	o := KernelPlaneOptions{TunIface: "wr-tun", BypassIPs: []string{"203.0.113.10", "2001:db8::1"}}
	got := strings.Join(kernelPlaneDelCommands(o), "\n")
	if !strings.Contains(got, "ip route del 203.0.113.10") {
		t.Errorf("v4 teardown missing:\n%s", got)
	}
	if !strings.Contains(got, "ip -6 route del 2001:db8::1") {
		t.Errorf("v6 teardown must use `ip -6`:\n%s", got)
	}
}

// v6gwRunner answers the v4/v6 default-gateway discovery so ApplyKernelPlane can be exercised offline.
type v6gwRunner struct{ calls []string }

func (r *v6gwRunner) Run(stdin, name string, args ...string) (string, error) {
	cmd := strings.Join(args, " ")
	r.calls = append(r.calls, name+" "+cmd)
	switch {
	case strings.Contains(cmd, "ip -6 route show default"):
		return "fe80::1\n", nil
	case strings.Contains(cmd, "ip route show default"):
		return "172.20.0.1\n", nil
	}
	return "", nil
}

func TestApplyKernelPlane_DiscoversV6Gateway(t *testing.T) {
	run := &v6gwRunner{}
	o := KernelPlaneOptions{BypassIPs: []string{"2001:db8::1"}} // a v6 target triggers v6 discovery
	if err := ApplyKernelPlane(run, o); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(run.calls, "\n")
	if !strings.Contains(got, "ip -6 route replace 2001:db8::1 via fe80::1") {
		t.Errorf("v6 bypass not applied via the discovered v6 gateway:\n%s", got)
	}
}

// --- bug #13: an existing-but-UNREADABLE original config.json must ABORT staging, not be overwritten
// without a rollback snapshot (which would make RestoreSingboxConfig a permanent no-op). ---

func TestStageSingboxConfig_UnreadableOriginalAborts(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	// Make config.json a DIRECTORY: os.Stat succeeds (it exists) but os.ReadFile fails with a
	// non-ENOENT error, exercising the "original exists but is unreadable" branch portably.
	if err := os.Mkdir(cfgPath, 0o755); err != nil {
		t.Fatal(err)
	}
	err := StageSingboxConfig(map[string]any{"inbounds": []any{}}, SingboxStageOptions{ConfigPath: cfgPath})
	if err == nil {
		t.Fatal("staging must ABORT when the original config exists but is unreadable (else it overwrites with no rollback snapshot)")
	}
	if _, serr := os.Stat(cfgPath + ".wr-orig"); !os.IsNotExist(serr) {
		t.Errorf("no snapshot must be written when the original is unreadable")
	}
}
