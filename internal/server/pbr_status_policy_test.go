package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// Once a list sent to a KeeneticOS access policy is applied, the status compares like for like - the
// installed plan's policy marks compile the profile again - so it does not read "stale - Apply to
// activate" forever, which no Apply could clear (gap 6 review).
func TestPBRStatusIsCurrentAfterApplyingAPolicyList(t *testing.T) {
	s, _ := applytest_server(t)
	s.cfg.RoutingMode = "hybrid"
	if err := s.store.UpsertRoutingList(model.RoutingList{ID: "rl-policy", Name: "Telegram", Enabled: true,
		Outbound: "ndm-policy:Policy1", Manual: []string{"198.51.100.0/24"}}); err != nil {
		t.Fatal(err)
	}
	p := s.store.Profile()
	// The plan Apply installs: compiled with the marks the capture read.
	plan, _, err := pbr.Compile(&p, pbr.Options{NDMPolicies: map[string]uint32{"Policy1": 0x0ffffaab}})
	if err != nil || len(plan.Zones) != 1 {
		t.Fatalf("plan %+v err %v", plan, err)
	}
	s.applyState.mu.Lock()
	rec := s.stateLocked()
	rec.Live = &appliedRevision{Rev: "rev-1", Materialization: executionMaterializationV1{
		Kernel: executionKernelArtifactV1{Action: ExecutionEnsurePresent, Plan: plan}}}
	s.applyState.mu.Unlock()

	w := httptest.NewRecorder()
	s.handlePBRStatus(w, httptest.NewRequest(http.MethodGet, "/api/pbr/status", nil))
	var st map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if st["stale"] == true {
		t.Errorf("an Apply that installed exactly the current profile reports stale: zones=%v compiled_zones=%v", st["zones"], st["compiled_zones"])
	}
}
