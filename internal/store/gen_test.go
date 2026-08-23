package store

import (
	"path/filepath"
	"testing"

	"wayhop/internal/model"
)

// Gen must advance on every durable mutation (so a gen-keyed cache invalidates) and stay
// put across pure reads (so a hit is actually a hit).
func TestGen(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	g0 := s.Gen()

	// A read must not move the generation.
	_ = s.Profile()
	if s.Gen() != g0 {
		t.Fatalf("Profile() bumped gen: %d -> %d", g0, s.Gen())
	}

	ep := model.Endpoint{ID: "e1", Name: "E1", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "1.1.1.1", Port: 443, Enabled: true}
	if err := s.UpsertEndpoint(ep); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	g1 := s.Gen()
	if g1 == g0 {
		t.Fatalf("UpsertEndpoint did not bump gen (still %d)", g0)
	}

	// A second distinct mutation bumps again.
	if err := s.UpsertEndpoint(model.Endpoint{ID: "e2", Name: "E2", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "2.2.2.2", Port: 443, Enabled: true}); err != nil {
		t.Fatalf("UpsertEndpoint e2: %v", err)
	}
	if s.Gen() == g1 {
		t.Fatalf("second mutation did not bump gen (still %d)", g1)
	}

	// Replace is a mutation too.
	before := s.Gen()
	if err := s.Replace(model.Profile{}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if s.Gen() == before {
		t.Fatalf("Replace did not bump gen (still %d)", before)
	}
}
