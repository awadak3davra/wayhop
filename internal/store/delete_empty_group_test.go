package store

import (
	"path/filepath"
	"testing"

	"velinx/internal/model"
)

// #14: deleting an endpoint that is the SOLE member of a group must be refused —
// otherwise the group is left with zero members and the profile fails Validate(),
// blocking every Apply.
func TestDeleteEndpointRefusesEmptyingGroup(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "p.json"))
	if err != nil {
		t.Fatal(err)
	}
	ep := func(id string) model.Endpoint {
		return model.Endpoint{ID: id, Name: id, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "h", Port: 443, Enabled: true}
	}
	_ = s.UpsertEndpoint(ep("e1"))
	_ = s.UpsertGroup(model.Group{ID: "g", Name: "G", Type: model.GroupURLTest, Members: []string{"e1"}})

	if err := s.DeleteEndpoint("e1"); err == nil {
		t.Fatal("deleting the sole member of a group must be refused")
	}
	if len(s.Profile().Endpoints) != 1 {
		t.Fatal("a refused delete must not remove the endpoint")
	}

	// With a second member, the delete prunes e1 and leaves a valid group.
	_ = s.UpsertEndpoint(ep("e2"))
	_ = s.UpsertGroup(model.Group{ID: "g", Name: "G", Type: model.GroupURLTest, Members: []string{"e1", "e2"}})
	if err := s.DeleteEndpoint("e1"); err != nil {
		t.Fatalf("delete with a remaining member should succeed: %v", err)
	}
	if p := s.Profile(); p.Validate() != nil {
		t.Fatalf("profile must be Validate-clean after the pruning delete: %v", p.Validate())
	}
}
