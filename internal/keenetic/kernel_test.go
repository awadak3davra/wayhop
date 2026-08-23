package keenetic

import (
	"strings"
	"testing"
)

func TestKernelPlaneAddCommands(t *testing.T) {
	o := KernelPlaneOptions{
		TunIface: "wr-tun", WanIface: "eth3", WanGateway: "172.20.0.1",
		BypassIPs:   []string{"203.0.113.10", "198.51.100.20"},
		LocalDirect: []string{"109.254.0.0/16"},
		MgmtReverse: []string{"10.0.0.0/24"},
	}
	cmds, err := kernelPlaneAddCommands(o)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(cmds, "\n")
	for _, w := range []string{
		"ip route replace 203.0.113.10 via 172.20.0.1 dev eth3 metric 50", // anti-loop bypass
		"ip route replace 198.51.100.20 via 172.20.0.1 dev eth3 metric 50",
		"ip route replace 109.254.0.0/16 via 172.20.0.1 dev eth3 metric 100", // local DNR direct
		"ip route replace 10.0.0.0/24 dev nwg2",                              // mgmt-reverse
		"ip route replace default dev wr-tun metric 50",                      // general → sing-box
	} {
		if !strings.Contains(got, w) {
			t.Errorf("missing kernel route %q\n--- got ---\n%s", w, got)
		}
	}

	// No WAN gateway → error (must be discovered first).
	if _, err := kernelPlaneAddCommands(KernelPlaneOptions{}); err == nil {
		t.Error("missing WAN gateway must error")
	}
}

func TestKernelPlaneDelCommands(t *testing.T) {
	o := KernelPlaneOptions{TunIface: "wr-tun", BypassIPs: []string{"203.0.113.10"}, MgmtReverse: []string{"10.0.0.0/24"}}
	got := strings.Join(kernelPlaneDelCommands(o), "\n")
	for _, w := range []string{
		"ip route del default dev wr-tun metric 50",
		"ip route del 10.0.0.0/24 dev nwg2",
		"ip route del 203.0.113.10",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("missing teardown %q\n%s", w, got)
		}
	}
}

func TestApplyKernelPlane(t *testing.T) {
	run := &recRunner{}
	o := KernelPlaneOptions{WanGateway: "172.20.0.1", BypassIPs: []string{"203.0.113.10"}}
	if err := ApplyKernelPlane(run, o); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(run.calls, "\n")
	if !strings.Contains(got, "ip route replace 203.0.113.10 via 172.20.0.1 dev eth3 metric 50") {
		t.Errorf("bypass route not applied via runner\n%s", got)
	}
	if !strings.Contains(got, "ip route replace default dev wr-tun metric 50") {
		t.Errorf("default→wr-tun not applied\n%s", got)
	}
}
