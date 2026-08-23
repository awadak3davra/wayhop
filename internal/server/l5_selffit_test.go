package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"wayhop/internal/updater"
)

// TestSelfFitIsAnswerable (L5): the panel cannot warn about a self-update that will not fit unless
// it can ASK, and /api/updater/{id}/fit resolved its id through the engine catalogue — which has no
// wayhop entry. So WayHop's own row offered "Update now" with no idea whether the router had room,
// and the refusal arrived only after the click.
//
// That is not academic on a small-flash box: on a live AX3000T (OpenWrt, /overlay 13 MiB
// free) a self-update needs ~27 MiB — the new binary plus the mandatory rollback backup plus slack —
// so refusing is the routine outcome there.
//
// This pins the ROUTING, not the network call: "self" must reach a real measurement rather than the
// 404 the engine lookup gave it. The measurement itself needs a release source, which a unit test
// has no business reaching, so a failure to look one up is an acceptable answer here — a 404 is not.
func TestSelfFitIsAnswerable(t *testing.T) {
	s := dnsSeed(t)
	// The shared harness builds a Server with only the fields its own subject needs, and this handler
	// reaches the updater. Production New() always wires one, so the gap is the harness's, not the
	// handler's — give it one rather than making the handler defensive about a state that cannot
	// occur. The repo is unreachable from a test, which is fine: this pins the ROUTING.
	s.updater = updater.New(t.TempDir(), "aarch64", nil)

	r := httptest.NewRequest(http.MethodGet, "/api/updater/self/fit", nil)
	r.SetPathValue("id", "self")
	w := httptest.NewRecorder()
	s.handleUpdaterFit(w, r)
	if w.Code == http.StatusNotFound {
		t.Fatalf("the self row cannot ask whether an update fits: %d %s", w.Code, w.Body)
	}

	// And an unknown id must still be a 404 — the special case must not swallow typos.
	r2 := httptest.NewRequest(http.MethodGet, "/api/updater/not-an-engine/fit", nil)
	r2.SetPathValue("id", "not-an-engine")
	w2 := httptest.NewRecorder()
	s.handleUpdaterFit(w2, r2)
	if w2.Code != http.StatusNotFound {
		t.Errorf("an unknown engine must still be 404, got %d %s", w2.Code, w2.Body)
	}
}
