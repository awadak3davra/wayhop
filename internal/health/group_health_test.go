package health

import (
	"testing"

	"wakeroute/internal/model"
)

// TestGroupHealthFromMembers: a group's health is derived from its members — alive if any member is
// alive, down only if a member is down and none alive, and Unknown when every member is still
// Unknown (e.g. before the first probe). The last case is the fix: all-Unknown members must NOT
// render the group as a misleading "down".
func TestGroupHealthFromMembers(t *testing.T) {
	ep := func(id, name string) model.Endpoint {
		return model.Endpoint{ID: id, Name: name, Protocol: model.ProtoVLESS, Server: "1.2.3.4", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u"}}
	}
	p := model.Profile{
		Endpoints: []model.Endpoint{ep("e-alive", "A"), ep("e-down", "D"), ep("e-unk", "U")},
		Groups: []model.Group{
			{ID: "g-alive", Name: "GA", Type: model.GroupSelector, Members: []string{"e-down", "e-alive"}},
			{ID: "g-down", Name: "GD", Type: model.GroupSelector, Members: []string{"e-down"}},
			{ID: "g-unk", Name: "GU", Type: model.GroupSelector, Members: []string{"e-unk"}},
		},
	}
	m := NewMonitor(nil, health_newStore(t, p), nil, false)
	now := nowMS()
	m.record("e-alive", "A", "endpoint", Alive, 10, now)
	// flapThreshold=2: two consecutive Down observations are needed to flip Unknown->Down.
	m.record("e-down", "D", "endpoint", Down, 0, now)
	m.record("e-down", "D", "endpoint", Down, 0, now)
	// e-unk: intentionally unrecorded -> Unknown.

	byID := map[string]string{}
	for _, v := range m.Snapshot() {
		byID[v.ID] = v.State
	}
	if byID["g-alive"] != string(Alive) {
		t.Errorf("g-alive = %q, want alive (a member is alive)", byID["g-alive"])
	}
	if byID["g-down"] != string(Down) {
		t.Errorf("g-down = %q, want down (a member down, none alive)", byID["g-down"])
	}
	if byID["g-unk"] != string(Unknown) {
		t.Errorf("g-unk = %q, want unknown — all-Unknown members must not be a misleading down", byID["g-unk"])
	}
}
