package health

import (
	"testing"

	"velinx/internal/model"
)

// TestGroupTrafficFromMembers: a kernel group (no Clash chain → its own view reads zero) has its
// traffic filled by summing its members' iface-accounted bytes/rates. A group that already shows
// traffic (sing-box, via clash chains) is left untouched.
func TestGroupTrafficFromMembers(t *testing.T) {
	ep := func(id, name string) model.Endpoint {
		return model.Endpoint{ID: id, Name: name, Protocol: model.ProtoVLESS, Server: "1.2.3.4", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u"}}
	}
	p := model.Profile{
		Endpoints: []model.Endpoint{ep("e1", "E1"), ep("e2", "E2")},
		Groups:    []model.Group{{ID: "g", Name: "G", Type: model.GroupSelector, Members: []string{"e1", "e2"}}},
	}
	m := NewMonitor(nil, health_newStore(t, p), nil, false)
	now := nowMS()
	m.record("e1", "E1", "endpoint", Alive, 5, now)
	m.record("e2", "E2", "endpoint", Alive, 5, now)
	// Members carry traffic (as if iface-accounted); the group's own stat has none.
	m.stats["e1"].totalUp, m.stats["e1"].totalDown, m.stats["e1"].rateUp, m.stats["e1"].rateDown = 100, 1000, 10, 100
	m.stats["e2"].totalUp, m.stats["e2"].totalDown, m.stats["e2"].rateUp, m.stats["e2"].rateDown = 200, 2000, 20, 200

	var gv View
	for _, v := range m.Snapshot() {
		if v.ID == "g" {
			gv = v
		}
	}
	if gv.BytesUp != 300 || gv.BytesDown != 3000 || gv.RateUpBps != 30 || gv.RateDownBps != 300 {
		t.Errorf("group traffic = up:%d/%d down:%d/%d, want bytes 300/3000 rate 30/300",
			gv.BytesUp, gv.RateUpBps, gv.BytesDown, gv.RateDownBps)
	}
}
