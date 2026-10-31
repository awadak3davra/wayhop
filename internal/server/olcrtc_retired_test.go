package server

import (
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// olcRTC was removed, but a profile saved by an older build can still hold an olcRTC connection.
// It must load and review; while enabled it blocks Apply and says what to do, and once disabled it
// is inert.
func TestEndpointFindings_RetiredOlcRTCBlocksApplyOnlyWhileEnabled(t *testing.T) {
	s, _ := applytest_server(t)
	olc := model.Endpoint{ID: "olc", Name: "Meet tunnel", Engine: model.EngineOlcRTC, Protocol: model.ProtoOlcRTC, Enabled: true}

	got := s.endpointFindings(model.Profile{Endpoints: []model.Endpoint{olc}}, platform.CapabilitySet{})
	if len(got) != 1 || got[0].ID != "endpoint.engine.olcrtc" || got[0].Blocks != platform.BlocksApply ||
		!strings.Contains(got[0].Remedy, "Delete this connection") {
		t.Fatalf("findings = %+v, want one Apply-blocking finding telling the operator to delete it", got)
	}

	olc.Enabled = false
	if got := s.endpointFindings(model.Profile{Endpoints: []model.Endpoint{olc}}, platform.CapabilitySet{}); len(got) != 0 {
		t.Fatalf("a disabled olcRTC connection raised %+v, want nothing", got)
	}
}

func TestEndpointCapabilityRequirements_RetiredOlcRTCCannotBeEnabled(t *testing.T) {
	_, err := endpointCapabilityRequirements(model.Endpoint{Engine: model.EngineOlcRTC, Protocol: model.ProtoOlcRTC})
	if err == nil || !strings.Contains(err.Error(), "no longer supported") {
		t.Fatalf("err = %v, want the retired-olcRTC refusal", err)
	}
}
