package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"wayhop/internal/platform"
)

func TestNativeCapabilitiesIncludesOperationLevelRoutingChoices(t *testing.T) {
	s := applyhealth_server(t)
	req := httptest.NewRequest(http.MethodGet, "/api/native/capabilities", nil)
	w := httptest.NewRecorder()
	s.handleNativeCapabilities(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var body struct {
		CapabilitySet platform.CapabilitySet `json:"capability_set"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.CapabilitySet.Rev == "" || body.CapabilitySet.Items == nil {
		t.Fatalf("evaluated capability set missing from response: %+v", body.CapabilitySet)
	}
	for _, id := range []string{
		platform.CapRoutingModeMixed,
		platform.CapRoutingModeTun,
		platform.CapRoutingModeHybrid,
		platform.CapRoutingModeFast,
		platform.CapOffloadSW,
		platform.CapOffloadHW,
	} {
		item, ok := body.CapabilitySet.Items[id]
		if !ok || item.ID != id || item.State == "" {
			t.Errorf("capability %q missing or incomplete: %+v", id, item)
		}
	}
}

// K6 compares PPE experiments through this endpoint. The API must therefore use the same bounded
// observer as strict Apply and state the sample limit/errors instead of silently falling back to the
// legacy whole-file conntrack read.
func TestNativeCapabilitiesPublishesBoundedOffloadObservation(t *testing.T) {
	s := applyhealth_server(t)
	called := 0
	s.offloadObserver = func(ctx context.Context, requested, table string) (platform.OffloadState, []string) {
		called++
		if ctx == nil || requested != s.config().Offload || table != pbrKernelTable {
			t.Fatalf("observer inputs: ctx=%v requested=%q table=%q", ctx, requested, table)
		}
		return platform.OffloadState{
			Requested: requested, Configured: "unknown", Effective: "off", KnobsKnown: true,
			FlowsKnown: true, PPEEnabled: true, FlowsTotal: applyHostConntrackLines,
		}, []string{applyHostFlowtableError}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/native/capabilities", nil)
	w := httptest.NewRecorder()
	s.handleNativeCapabilities(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var body struct {
		OffloadState platform.OffloadState `json:"offload_state"`
		OffloadProbe struct {
			SchemaVersion        int      `json:"schema_version"`
			ConntrackSampleLimit int      `json:"conntrack_sample_limit"`
			Errors               []string `json:"errors"`
		} `json:"offload_probe"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if called != 1 {
		t.Fatalf("observer calls = %d, want exactly one", called)
	}
	if body.OffloadState.FlowsTotal != applyHostConntrackLines || !body.OffloadState.PPEEnabled {
		t.Fatalf("offload state = %+v", body.OffloadState)
	}
	if body.OffloadProbe.SchemaVersion != 1 || body.OffloadProbe.ConntrackSampleLimit != applyHostConntrackLines {
		t.Fatalf("probe contract = %+v", body.OffloadProbe)
	}
	if len(body.OffloadProbe.Errors) != 1 || body.OffloadProbe.Errors[0] != applyHostFlowtableError {
		t.Fatalf("probe errors = %v", body.OffloadProbe.Errors)
	}
}
