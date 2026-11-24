package server

import (
	"context"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

func scopedKSPlan(t *testing.T) *pbr.Plan {
	return ksPlan(t, func(p *model.Profile) {
		p.Rules = []model.Rule{{ID: "tv", Outbound: "grp", SourceMAC: []string{"aa:bb:cc:dd:ee:01"}, IPCIDR: []string{"198.51.100.0/24"}}}
	})
}

// The Apply's own refusal covered LAN interfaces, the DNS listener and the cap, not a
// kill-switched zone scoped to some devices; only the review preflight refused it.
func TestKeeneticKillSwitchRefusesAScopedZone(t *testing.T) {
	pl := scopedKSPlan(t)
	if len(pl.KillSwitchScopedZones()) == 0 {
		t.Fatal("the plan under test has no scoped kill-switched zone")
	}
	io := pbr.IpsetOptions{LANIfaces: []string{"br0"}, KillSwitchDNS: "127.0.0.1#5353"}
	if err := keeneticKillSwitchRefusal(pl, io, config.Config{}); err == nil || !strings.Contains(err.Error(), "some devices") {
		t.Fatalf("a scoped kill-switched zone was not refused: %v", err)
	}
}

// A plane committed before the refusal existed shows in Diagnostics.
func TestKillSwitchDiagnosticsFlagsAScopedPlane(t *testing.T) {
	s, _, _ := mirrorServer(t)
	s.applyState.rec.Committed.Materialization.Kernel.Plan = scopedKSPlan(t)
	row := s.killSwitchBootCheck(context.Background())
	if row.Status != "fail" || !strings.Contains(row.Summary, "some devices") {
		t.Fatalf("row %+v", row)
	}
}
