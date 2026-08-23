package store

import (
	"testing"

	"wayhop/internal/model"
)

// TestUpsertEndpoints_BatchInsertReplace: the batch upsert inserts new endpoints and replaces
// existing ones by ID in a SINGLE publish (the O(N) replacement for the O(N^2) per-endpoint loop),
// and reports empty-ID inputs as skipped rather than persisting an id-less endpoint.
func TestUpsertEndpoints_BatchInsertReplace(t *testing.T) {
	st, _ := storemodelconfig_newStore(t)
	ep := func(id, server string) model.Endpoint {
		return model.Endpoint{
			ID: id, Name: id, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
			Server: server, Port: 443, Enabled: true, Params: map[string]any{"uuid": "u-" + id},
		}
	}
	if err := st.UpsertEndpoint(ep("a", "1.1.1.1")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Batch: replace a (new server), insert b and c, and one empty-ID (must be skipped).
	skipped, err := st.UpsertEndpoints([]model.Endpoint{
		ep("a", "9.9.9.9"), ep("b", "2.2.2.2"), ep("", "x"), ep("c", "3.3.3.3"),
	})
	if err != nil {
		t.Fatalf("UpsertEndpoints: %v", err)
	}
	if len(skipped) != 1 || skipped[0] != 2 {
		t.Fatalf("skipped=%v, want [2] (the empty-ID input at index 2)", skipped)
	}
	p := st.Profile()
	if len(p.Endpoints) != 3 {
		t.Fatalf("got %d endpoints, want 3 (a replaced in place, b+c inserted, empty skipped)", len(p.Endpoints))
	}
	if e := p.EndpointByID("a"); e == nil || e.Server != "9.9.9.9" {
		t.Fatalf("a not replaced by ID: %+v", e)
	}
	if p.EndpointByID("b") == nil || p.EndpointByID("c") == nil {
		t.Fatal("b/c not inserted")
	}
	// A no-op batch must not error.
	if _, err := st.UpsertEndpoints(nil); err != nil {
		t.Fatalf("empty batch errored: %v", err)
	}
}
