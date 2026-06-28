package generator

import (
	"testing"

	"wakeroute/internal/model"
)

// TestGroupInterruptOnSwitch: the opt-in InterruptOnSwitch flag emits sing-box's
// interrupt_exist_connections on both urltest/fallback and selector groups, and is a byte-identical
// no-op when unset (default).
func TestGroupInterruptOnSwitch(t *testing.T) {
	// Default (unset): the key must be ABSENT — existing profiles render identically.
	base := groupOutbound(&model.Group{ID: "g", Type: model.GroupFallback, Members: []string{"a", "b"}})
	if _, ok := base["interrupt_exist_connections"]; ok {
		t.Fatal("default group must NOT emit interrupt_exist_connections")
	}

	cases := []struct {
		name    string
		typ     model.GroupType
		wantTyp string
	}{
		{"urltest", model.GroupURLTest, "urltest"},
		{"fallback", model.GroupFallback, "urltest"},
		{"selector", model.GroupSelector, "selector"},
	}
	for _, c := range cases {
		ob := groupOutbound(&model.Group{ID: "g", Type: c.typ, Members: []string{"a", "b"}, InterruptOnSwitch: true})
		if ob["interrupt_exist_connections"] != true {
			t.Errorf("%s: interrupt_exist_connections=%v, want true", c.name, ob["interrupt_exist_connections"])
		}
		if ob["type"] != c.wantTyp {
			t.Errorf("%s: type=%v, want %s", c.name, ob["type"], c.wantTyp)
		}
	}
}
