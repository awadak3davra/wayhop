package server

import (
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// An enabled nfqws connection cannot be applied (the executor has no path for a packet modifier with
// no exit), so the review says so and blocks Apply - it used to promise that installing nfqws2 would
// fix it, and said nothing at all once the binary was there (QA-055).
func TestEndpointFindings_NfqwsIsNotRunnableByThisBuild(t *testing.T) {
	s, _ := sharehandlers_server(t)
	prof := model.Profile{Endpoints: []model.Endpoint{{ID: "dpi", Name: "Desync", Enabled: true, Engine: model.EngineNfqws}}}
	for _, f := range s.endpointFindings(prof, platform.CapabilitySet{}) {
		if f.ID == "endpoint.engine.nfqws" {
			if f.Blocks != platform.BlocksApply || f.Reason != platform.ReasonBackendNotWired {
				t.Errorf("finding = %+v, want an Apply blocker naming the missing executor", f)
			}
			return
		}
	}
	t.Error("no finding for an enabled nfqws connection")
}
