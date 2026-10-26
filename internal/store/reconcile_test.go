package store

import (
	"path/filepath"
	"testing"

	"wayhop/internal/model"
)

// Reconcile writes only when its function reports a change, and then durably.
func TestReconcile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertEndpoint(model.Endpoint{ID: "a", Engine: model.EngineExternal, Params: map[string]any{"interface": "wg0"}}); err != nil {
		t.Fatal(err)
	}
	gen := s.Gen()
	if err := s.Reconcile(func(p *model.Profile) bool { return false }); err != nil || s.Gen() != gen {
		t.Fatalf("an unchanged reconcile must not publish: err %v gen %d -> %d", err, gen, s.Gen())
	}
	if err := s.Reconcile(func(p *model.Profile) bool {
		p.Endpoints[0].Name = "renamed"
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if s.Gen() != gen+1 || s.Profile().Endpoints[0].Name != "renamed" {
		t.Fatalf("a changed reconcile must publish once: gen %d name %q", s.Gen(), s.Profile().Endpoints[0].Name)
	}
	again, err := Open(path)
	if err != nil || again.Profile().Endpoints[0].Name != "renamed" {
		t.Fatalf("the change must be persisted: %v", err)
	}
}
