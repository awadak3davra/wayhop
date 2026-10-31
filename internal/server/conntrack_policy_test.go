package server

import (
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// A flow routed by a KeeneticOS access policy carries the policy's slot in its connmark; the
// per-exit traffic view names the policy instead of counting it as "direct" (gap 6 review).
func TestMarkExitResolverNamesAnAccessPolicy(t *testing.T) {
	s, _ := applytest_server(t)
	s.cfg.RoutingMode = "hybrid"
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "rl-policy", Name: "Telegram", Enabled: true,
		Outbound: "ndm-policy:Policy1", Manual: []string{"198.51.100.0/24"}}); err != nil {
		t.Fatal(err)
	}
	p := s.store.Profile()
	plan, _, err := pbr.Compile(&p, pbr.Options{NDMPolicies: map[string]uint32{"Policy1": 0x0ffffaab}})
	if err != nil || len(plan.Zones) != 1 {
		t.Fatalf("plan %+v err %v", plan, err)
	}
	s.applyState.mu.Lock()
	rec := s.stateLocked()
	rec.Live = &appliedRevision{Rev: "rev-1", Materialization: executionMaterializationV1{
		Kernel: executionKernelArtifactV1{Action: ExecutionEnsurePresent, Plan: plan}}}
	s.applyState.mu.Unlock()

	resolve := s.computeMarkExitResolver()
	if got := resolve(plan.Zones[0].Mark); got != "ndm-policy:Policy1" {
		t.Errorf("the policy's slot resolves to %q, want ndm-policy:Policy1", got)
	}
	if got := resolve(0); got != "direct" {
		t.Errorf("an unmarked flow resolves to %q", got)
	}
}
