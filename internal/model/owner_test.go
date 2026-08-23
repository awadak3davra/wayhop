package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestOwnsResource locks the never-destroy-external invariant: only a WayHop-owned resource may be
// destroyed. External / imported / unknown must all report false so a future destructive native op
// (interface down, teardown, uninstall) refuses to touch them.
func TestOwnsResource(t *testing.T) {
	cases := []struct {
		owner Owner
		owns  bool
	}{
		{OwnerWayHop, true},
		{Owner(""), true}, // empty defaults to WayHop-managed (no migration for old profiles)
		{OwnerExternal, false},
		{OwnerImported, false},
		{OwnerUnknown, false},
	}
	for _, c := range cases {
		if got := (Endpoint{Owner: c.owner}).OwnsResource(); got != c.owns {
			t.Errorf("Endpoint{Owner:%q}.OwnsResource() = %v, want %v", c.owner, got, c.owns)
		}
	}
}

// TestOwnerOmitEmpty: a WayHop-owned (default) endpoint serializes WITHOUT an owner key, so existing
// stored profiles round-trip unchanged and deserialize back to OwnerWayHop.
func TestOwnerOmitEmpty(t *testing.T) {
	b, err := json.Marshal(Endpoint{ID: "x", Owner: OwnerWayHop})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"owner"`) {
		t.Errorf("default-owner endpoint must omit the owner field, got %s", b)
	}
	// An external endpoint serializes the field, and round-trips.
	b2, _ := json.Marshal(Endpoint{ID: "y", Owner: OwnerExternal})
	if !strings.Contains(string(b2), `"owner":"external"`) {
		t.Errorf("external endpoint must serialize owner, got %s", b2)
	}
	var back Endpoint
	if err := json.Unmarshal([]byte(`{"id":"z"}`), &back); err != nil {
		t.Fatal(err)
	}
	if back.Owner != OwnerWayHop || !back.OwnsResource() {
		t.Errorf("legacy endpoint (no owner key) must decode to OwnerWayHop, got %q", back.Owner)
	}
}
