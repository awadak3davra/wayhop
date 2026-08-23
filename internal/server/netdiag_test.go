package server

import (
	"testing"

	"wayhop/internal/model"
)

// egressIfaceIn resolves an exit tag to the kernel interface an iface-bound
// reachability probe binds to: an ENABLED external endpoint's interface, a group's
// first interface-backed member (recursively, skipping proxy + disabled members), or
// "" for proxies / unknown tags / cyclic graphs. This is the core of the fix for the
// "tunnels always unreachable" bug — the Clash API can't see kernel interfaces.
func TestEgressIfaceIn(t *testing.T) {
	prof := &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "nl", Engine: model.EngineExternal, Enabled: true, Params: map[string]any{"interface": "nwg1"}},
			{ID: "ru", Engine: model.EngineExternal, Enabled: true, Params: map[string]any{"interface": "nwg0"}},
			{ID: "hy2", Engine: model.EngineSingBox, Enabled: true},                                                // sing-box proxy: no interface
			{ID: "off", Engine: model.EngineExternal, Enabled: false, Params: map[string]any{"interface": "nwg9"}}, // disabled: not a live egress
		},
		Groups: []model.Group{
			{ID: "vpn", Members: []string{"nl", "ru"}},       // tunnels → first interface
			{ID: "tier", Members: []string{"hy2", "nl"}},     // proxy primary → skip to nl's iface
			{ID: "proxies", Members: []string{"hy2"}},        // all-proxy group → ""
			{ID: "nested", Members: []string{"vpn"}},         // nested group recurses
			{ID: "offfirst", Members: []string{"off", "nl"}}, // disabled member skipped → nl's iface
			{ID: "cyc1", Members: []string{"cyc2"}},          // cycle: depth guard → ""
			{ID: "cyc2", Members: []string{"cyc1"}},
		},
	}
	for _, c := range []struct{ tag, want string }{
		{"nl", "nwg1"}, {"ru", "nwg0"}, {"hy2", ""}, {"off", ""},
		{"vpn", "nwg1"}, {"tier", "nwg1"}, {"proxies", ""},
		{"nested", "nwg1"}, {"offfirst", "nwg1"}, {"cyc1", ""}, {"unknown", ""},
	} {
		if got := egressIfaceIn(prof, c.tag, 0); got != c.want {
			t.Errorf("egressIfaceIn(%q) = %q, want %q", c.tag, got, c.want)
		}
	}
}
