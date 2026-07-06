package generator

import (
	"reflect"
	"testing"

	"wayhop/internal/model"
)

// TestGroupOutboundManagedEmitsSelector pins F4b slice 1: a Managed group is emitted as a plain
// sing-box `selector` (so sing-box's own urltest prober can't fight the daemon control loop),
// regardless of its Type, and carries NO urltest url/interval/tolerance/idle_timeout. Its members
// and the opt-in interrupt flag round-trip. An UNMANAGED group is byte-identical to before.
func TestGroupOutboundManagedEmitsSelector(t *testing.T) {
	for _, gt := range []model.GroupType{model.GroupURLTest, model.GroupFallback, model.GroupSelector} {
		g := &model.Group{ID: "g", Type: gt, Members: []string{"a", "b"}, Managed: true,
			Test: &model.Health{URL: "http://x/204", Interval: 30, Tolerance: 80}}
		ob := groupOutbound(g)
		if ob["type"] != "selector" {
			t.Errorf("managed %s: type=%v, want selector", gt, ob["type"])
		}
		for _, k := range []string{"url", "interval", "tolerance", "idle_timeout"} {
			if _, ok := ob[k]; ok {
				t.Errorf("managed %s: unexpected urltest key %q on a selector: %v", gt, k, ob[k])
			}
		}
		if !reflect.DeepEqual(ob["outbounds"], []string{"a", "b"}) {
			t.Errorf("managed %s: outbounds=%v, want members in order", gt, ob["outbounds"])
		}
	}

	// A managed group NEVER emits the static interrupt_exist_connections flag — even with
	// InterruptOnSwitch set — because the daemon control loop interrupts DECISION-AWARE (F11:
	// hard-cut on an emergency switch, drain on a graceful failback). A static "interrupt on every
	// switch" would wrongly kill connections on a graceful failback.
	gi := &model.Group{ID: "g", Type: model.GroupURLTest, Members: []string{"a"}, Managed: true, InterruptOnSwitch: true}
	if _, ok := groupOutbound(gi)["interrupt_exist_connections"]; ok {
		t.Errorf("managed group must not emit static interrupt_exist_connections (daemon controls it)")
	}

	// UNMANAGED urltest is unchanged: still type urltest with the urltest knobs.
	gu := &model.Group{ID: "g", Type: model.GroupURLTest, Members: []string{"a"}}
	ob := groupOutbound(gu)
	if ob["type"] != "urltest" {
		t.Errorf("unmanaged urltest: type=%v, want urltest (byte-identical)", ob["type"])
	}
	if _, ok := ob["idle_timeout"]; !ok {
		t.Errorf("unmanaged urltest: missing idle_timeout (regressed F2)")
	}
}
