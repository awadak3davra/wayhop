package server

import (
	"testing"

	"wayhop/internal/model"
)

// The native-only verdict cache must: (1) match the authoritative datapathNativeOnly on a
// cold call, (2) actually serve a cached value (a hit skips the recompute), and (3) recompute
// when EITHER the store generation OR the routing mode changes. We distinguish a hit from a
// miss by poisoning the cached value with the impossible opposite and seeing which wins.
func TestNativeOnlyCached(t *testing.T) {
	s := metrics_server(t) // store + cfg, empty profile

	// (1) cold call matches the direct computation and populates the cache.
	v1 := s.nativeOnlyCached()
	p := s.store.Profile()
	if want := s.datapathNativeOnly(s.config(), &p); v1 != want {
		t.Fatalf("cold verdict = %v, want %v", v1, want)
	}
	if !s.nativeOnlyOK || s.nativeOnlyGen != s.store.Gen() {
		t.Fatalf("cache not populated: ok=%v gen=%d storeGen=%d", s.nativeOnlyOK, s.nativeOnlyGen, s.store.Gen())
	}

	// (2) poison the value without touching gen/mode → a hit returns the poison.
	s.nativeOnlyVal = !v1
	if got := s.nativeOnlyCached(); got != !v1 {
		t.Fatalf("expected a cache HIT returning poisoned %v, got %v (it recomputed)", !v1, got)
	}

	// (3a) a store mutation bumps gen → recompute, ignoring the poison.
	if err := s.store.UpsertEndpoint(model.Endpoint{ID: "e1", Name: "E1", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "1.1.1.1", Port: 443, Enabled: true}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	p = s.store.Profile()
	wantAfterMut := s.datapathNativeOnly(s.config(), &p)
	if got := s.nativeOnlyCached(); got != wantAfterMut {
		t.Fatalf("after mutation verdict = %v, want fresh %v", got, wantAfterMut)
	}

	// (3b) a routing-mode change with UNCHANGED gen must also invalidate. Poison first so
	// only a mode-keyed miss can override it.
	s.nativeOnlyVal = !s.nativeOnlyVal
	cur := s.routingMode(s.config())
	newMode := "fast"
	if cur == newMode {
		newMode = "mixed"
	}
	s.cfg.RoutingMode = newMode
	p = s.store.Profile()
	wantAfterMode := s.datapathNativeOnly(s.config(), &p)
	if got := s.nativeOnlyCached(); got != wantAfterMode {
		t.Fatalf("after mode change (%s→%s) verdict = %v, want fresh %v", cur, newMode, got, wantAfterMode)
	}
	if s.nativeOnlyMode != newMode {
		t.Fatalf("cache mode key not updated: %q, want %q", s.nativeOnlyMode, newMode)
	}
}
