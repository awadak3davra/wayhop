package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"wayhop/internal/model"
)

// The routing-catalog handler must serve the catalog with a content ETag, honor
// If-None-Match with a 304 (no body), and still serve the full body on a mismatch.
func TestRoutingCatalogETag(t *testing.T) {
	s := &Server{} // handler reads no Server fields

	// First request: 200 + ETag + full body matching model.RoutingPresets().
	rec := httptest.NewRecorder()
	s.handleRoutingCatalog(rec, httptest.NewRequest(http.MethodGet, "/api/routing/catalog", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("first GET status = %d, want 200", rec.Code)
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("first GET set no ETag")
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var got, want []model.RoutingPreset
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	want = model.RoutingPresets()
	if len(got) != len(want) || len(got) == 0 {
		t.Fatalf("catalog length = %d, want %d (non-zero)", len(got), len(want))
	}

	// Conditional request with the matching ETag: 304, empty body.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/routing/catalog", nil)
	req2.Header.Set("If-None-Match", etag)
	s.handleRoutingCatalog(rec2, req2)
	if rec2.Code != http.StatusNotModified {
		t.Fatalf("conditional GET status = %d, want 304", rec2.Code)
	}
	if rec2.Body.Len() != 0 {
		t.Errorf("304 response carried a body of %d bytes", rec2.Body.Len())
	}
	if rec2.Header().Get("ETag") != etag {
		t.Error("304 response did not echo the ETag")
	}

	// Stale/mismatched ETag: full 200 body again.
	rec3 := httptest.NewRecorder()
	req3 := httptest.NewRequest(http.MethodGet, "/api/routing/catalog", nil)
	req3.Header.Set("If-None-Match", `W/"cat-deadbeef"`)
	s.handleRoutingCatalog(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("mismatched-ETag GET status = %d, want 200", rec3.Code)
	}
	if rec3.Body.Len() == 0 {
		t.Error("mismatched-ETag GET returned an empty body")
	}
}
