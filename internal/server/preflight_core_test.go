package server

import (
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/platform"
)

// Found by a hunter on an emulated OpenWrt: sing-box installed from Components lands at the configured
// /opt/sbin/sing-box, off the daemon's PATH. Health said the core was running, and the review still
// listed every proxy protocol as "requires the sing-box core, which is not installed".
func TestPreflightCountsTheConfiguredCore(t *testing.T) {
	s := opshandlers_server(t)
	c := config.Default()
	prof := dnsDefaultFixture()
	onPath := platform.Capabilities{Platform: "openwrt", SingboxRequired: []string{"vless", "socks"}}

	protocolFindings := func(caps platform.Capabilities) int {
		n := 0
		for _, u := range s.preflightFor(*c, prof, caps, platform.OffloadState{}) {
			if strings.HasPrefix(u.Setting, "protocol:") {
				n++
			}
		}
		return n
	}
	if protocolFindings(onPath) != 1 {
		t.Fatal("fixture: with no core anywhere the vless connection should need one")
	}
	if n := protocolFindings(withConfiguredCore(onPath, true)); n != 0 {
		t.Fatalf("a runnable configured core still produced %d missing-core findings", n)
	}

	runnable := platform.Evaluate(onPath, platform.RuntimeFacts{SingboxRunnable: true, SingboxVersion: "1.14.4"})
	if !s.planCapabilities(runnable).SingboxPresent {
		t.Fatal("the plan's preflight ignored the runnable configured core")
	}
}
