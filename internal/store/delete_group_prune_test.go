package store

import (
	"path/filepath"
	"reflect"
	"testing"

	"wayhop/internal/model"
)

// TestDeleteGroupPrunesNestedMembers: deleting a group must remove its id from
// any group that listed it as a nested member (Group.Members may hold group IDs),
// keeping the profile Validate-clean — symmetric with DeleteEndpoint.
func TestDeleteGroupPrunesNestedMembers(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertEndpoint(model.Endpoint{ID: "e1", Name: "E1", Server: "1.1.1.1", Port: 443, Protocol: model.ProtoVLESS, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertGroup(model.Group{ID: "inner", Name: "Inner", Type: model.GroupURLTest, Members: []string{"e1"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertGroup(model.Group{ID: "outer", Name: "Outer", Type: model.GroupSelector, Members: []string{"inner", "e1"}}); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteGroup("inner"); err != nil {
		t.Fatalf("DeleteGroup(inner): %v", err)
	}

	p := s.Profile()
	var outer *model.Group
	for i := range p.Groups {
		if p.Groups[i].ID == "outer" {
			outer = &p.Groups[i]
		}
	}
	if outer == nil {
		t.Fatal("outer group missing after delete")
	}
	if !reflect.DeepEqual(outer.Members, []string{"e1"}) {
		t.Fatalf("outer.Members: want [e1] after pruning inner, got %v", outer.Members)
	}
	// No dangling reference -> profile validates clean.
	if err := p.Validate(); err != nil {
		t.Fatalf("profile should be Validate-clean after DeleteGroup, got: %v", err)
	}
}
