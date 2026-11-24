package server

import (
	"context"
	"os"
	"strings"
	"testing"
)

// The WAN was read once, at capture. After an uplink failover the artifact's `-o <wan>`
// MASQUERADE names the old uplink. The mirror re-probes the WAN after each rebuild and flags a
// mismatch in Diagnostics until an Apply records the new one.
func TestKillSwitchMirrorFlagsAStaleWAN(t *testing.T) {
	s, _, stamp := mirrorServer(t)
	k := &s.applyState.rec.Committed.Materialization.Kernel
	k.Ipset.WANIface = "eth3"
	wan := "eth3"
	s.ksb.probeWAN = func() (string, error) { return wan, nil }
	ctx := context.Background()
	s.killSwitchMirrorTick(ctx)
	if got := s.wanDriftCheck(ctx); got.Status != "pass" {
		t.Fatalf("same WAN: %+v", got)
	}
	wan = "ppp0"
	_ = os.WriteFile(stamp, nil, 0o644)
	s.killSwitchMirrorTick(ctx)
	if got := s.wanDriftCheck(ctx); got.Status != "warn" || !strings.Contains(got.Summary, "ppp0") {
		t.Fatalf("changed WAN not flagged: %+v", got)
	}
}
