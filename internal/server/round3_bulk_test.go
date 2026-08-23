package server

import (
	"encoding/json"
	"fmt"
	"testing"

	"wayhop/internal/model"
)

// TestBulkEndpoints_ManyDistinct persists a large batch of DISTINCT endpoints in one call. The fix
// replaced the per-endpoint UpsertEndpoint loop (O(N^2) whole-profile rewrites + fsyncs, a stall +
// flash-wear hazard) with a single UpsertEndpoints batch write; this asserts the batch stays correct
// — every distinct endpoint is saved, the counts are right, and all land in the profile.
func TestBulkEndpoints_ManyDistinct(t *testing.T) {
	s, _ := sharehandlers_server(t)
	const n = 200
	eps := make([]model.Endpoint, 0, n)
	for i := 0; i < n; i++ {
		e := profilehandlers_endpoint(fmt.Sprintf("e-%d", i), fmt.Sprintf("E%d", i))
		e.Server = fmt.Sprintf("10.%d.%d.%d", i/256, i%256, (i*7)%256) // distinct content
		e.Params = map[string]any{"uuid": fmt.Sprintf("uuid-%d", i)}
		eps = append(eps, e)
	}
	body, _ := json.Marshal(map[string]any{"endpoints": eps})
	w := profilehandlers_post(s.handleBulkEndpoints, string(body))
	if w.Code != 200 {
		t.Fatalf("bulk: got %d (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Saved      int `json:"saved"`
		Duplicates int `json:"duplicates"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Saved != n || resp.Duplicates != 0 {
		t.Fatalf("saved=%d duplicates=%d, want %d/0", resp.Saved, resp.Duplicates, n)
	}
	if got := len(s.store.Profile().Endpoints); got != n {
		t.Fatalf("persisted %d, want %d", got, n)
	}
}

// TestBulkEndpoints_Duplicates: content-identical re-imports collapse (DedupeNew), so re-POSTing the
// same set adds nothing — the single-write path preserves the dedup semantics.
func TestBulkEndpoints_Duplicates(t *testing.T) {
	s, _ := sharehandlers_server(t)
	a := profilehandlers_endpoint("a", "A")
	a.Server = "1.1.1.1"
	a.Params = map[string]any{"uuid": "ua"}
	b := profilehandlers_endpoint("b", "B")
	b.Server = "2.2.2.2"
	b.Params = map[string]any{"uuid": "ub"}
	post := func(eps []model.Endpoint) (saved, dupes int) {
		body, _ := json.Marshal(map[string]any{"endpoints": eps})
		w := profilehandlers_post(s.handleBulkEndpoints, string(body))
		var r struct {
			Saved      int `json:"saved"`
			Duplicates int `json:"duplicates"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &r)
		return r.Saved, r.Duplicates
	}
	if sv, _ := post([]model.Endpoint{a, b}); sv != 2 {
		t.Fatalf("first import saved=%d, want 2", sv)
	}
	// A re-fetched subscription re-parses the SAME content under FRESH IDs; those are content
	// duplicates and must not pile up (DedupeNew drops them; same-ID would be an in-place update).
	a2, b2 := a, b
	a2.ID, b2.ID = "a-new", "b-new"
	if _, dup := post([]model.Endpoint{a2, b2}); dup != 2 {
		t.Fatalf("re-import (fresh IDs, same content) duplicates=%d, want 2", dup)
	}
	if got := len(s.store.Profile().Endpoints); got != 2 {
		t.Fatalf("profile has %d endpoints after re-import, want 2", got)
	}
}
