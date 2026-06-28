package server

import (
	"testing"

	"wakeroute/internal/model"
	"wakeroute/internal/pbr"
)

// TestApplyPBR_SkipsUnchangedPlan (QW3): re-applying a deep-equal plan must be a no-op — no
// teardown/apply commands hit the kernel — so a config save that doesn't change routing can't
// open a routing gap (drop calls / stall flows). A genuinely changed plan still applies.
func TestApplyPBR_SkipsUnchangedPlan(t *testing.T) {
	s, rr := pbrApplyServer(t)
	prof := &model.Profile{
		Endpoints:    []model.Endpoint{pbr_extEndpoint("ru-awg1", "awg1", "198.51.100.20")},
		RoutingLists: []model.RoutingList{pbr_list("l", "198.51.100.0/24", "ru-awg1")},
	}
	plan, _, err := pbr.Compile(prof, pbr.Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if err := s.applyPBR(plan); err != nil {
		t.Fatalf("first applyPBR: %v", err)
	}
	n1 := len(rr.Calls)
	if n1 == 0 {
		t.Fatal("first applyPBR ran no kernel commands")
	}

	// Re-apply a deep-equal plan (same profile recompiled) → idempotent skip, zero new commands.
	plan2, _, err := pbr.Compile(prof, pbr.Options{})
	if err != nil {
		t.Fatalf("Compile (re): %v", err)
	}
	if err := s.applyPBR(plan2); err != nil {
		t.Fatalf("re-applyPBR: %v", err)
	}
	if len(rr.Calls) != n1 {
		t.Errorf("re-applying an unchanged plan ran %d extra kernel commands, want 0 (idempotent skip)", len(rr.Calls)-n1)
	}

	// A genuinely changed plan must still apply.
	prof2 := &model.Profile{
		Endpoints:    []model.Endpoint{pbr_extEndpoint("ru-awg1", "awg1", "198.51.100.20")},
		RoutingLists: []model.RoutingList{pbr_list("l", "8.8.8.0/24", "ru-awg1")},
	}
	plan3, _, err := pbr.Compile(prof2, pbr.Options{})
	if err != nil {
		t.Fatalf("Compile (changed): %v", err)
	}
	if err := s.applyPBR(plan3); err != nil {
		t.Fatalf("changed applyPBR: %v", err)
	}
	if len(rr.Calls) == n1 {
		t.Error("a changed plan should have run apply commands, but none ran")
	}
}
