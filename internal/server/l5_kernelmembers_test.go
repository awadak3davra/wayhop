package server

import (
	"path/filepath"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/store"
)

// TestKernelElectableMembers (L5): a group can hold more names than the kernel plane can route to,
// and the Failover card must be told which.
//
// A live AX3000T runs group-failover = [tunnel-a (kernel link awg1), proxy-member (socks through
// sing-box)] with four routing lists on it. electMember skips a member with no kernel link, so when
// awg1 dies there is no candidate at all: the table keeps a route through a dead interface, the
// fwmark lookup finds nothing usable and falls through to main — the provider. Meanwhile the card
// counted both members and printed "2 exits deep".
//
// The answer is deliberately about CAPABILITY, not health: engine kind does not change while a
// tunnel is down, and a guarantee that redraws itself every time a member blinks teaches nobody
// anything.
func TestKernelElectableMembers(t *testing.T) {
	mixed := model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "native", Enabled: true, Engine: model.EngineExternal, Params: map[string]any{"interface": "awg1"}},
			{ID: "socks", Enabled: true, Engine: model.EngineSingBox, Protocol: "socks", Server: "198.51.100.7", Port: 1080},
		},
		Groups: []model.Group{{ID: "grp", Name: "Mixed", Type: "fallback", Members: []string{"native", "socks"}}},
		RoutingLists: []model.RoutingList{{ID: "l", Name: "L", Outbound: "grp", Enabled: true,
			Manual: []string{"203.0.113.0/24"}}},
	}

	got := serverFor(t, mixed).kernelElectableMembers()
	members, ok := got["grp"]
	if !ok {
		t.Fatalf("a group the kernel routes must be reported: %v", got)
	}
	if len(members) != 1 || members[0] != "native" {
		t.Errorf("only the member with a kernel link is electable, got %v", members)
	}

	// A group whose members are ALL kernel-routable has nothing to correct, and the card must be able
	// to tell that apart from the mixed case — it renders nothing when the counts agree.
	allNative := mixed
	allNative.Endpoints = []model.Endpoint{
		{ID: "native", Enabled: true, Engine: model.EngineExternal, Params: map[string]any{"interface": "awg1"}},
		{ID: "native2", Enabled: true, Engine: model.EngineExternal, Params: map[string]any{"interface": "awg2"}},
	}
	allNative.Groups = []model.Group{{ID: "grp", Name: "Both", Type: "fallback", Members: []string{"native", "native2"}}}
	if m := serverFor(t, allNative).kernelElectableMembers()["grp"]; len(m) != 2 {
		t.Errorf("both native members must be electable, got %v", m)
	}

	// A list carrying only NAMES gives the kernel no zone, so no table and no claim to make. Reporting
	// a group here would put a kernel caveat on a card whose traffic the core carries end to end.
	namesOnly := mixed
	namesOnly.RoutingLists = []model.RoutingList{{ID: "l", Name: "L", Outbound: "grp", Enabled: true,
		Manual: []string{"example.com"}}}
	if got := serverFor(t, namesOnly).kernelElectableMembers(); len(got) != 0 {
		t.Errorf("a group the kernel does not route must not be reported, got %v", got)
	}
}

// TestKernelElectableMembersIgnoresHealth (L5): the same answer whether members are up or down.
// listFailoverTargets already drops a group with no HEALTHY kernel member, which is why the card
// cannot be built on it: the moment awg1 died the group would vanish from the report and the caveat
// with it, exactly when the operator needs to read it.
func TestKernelElectableMembersIgnoresHealth(t *testing.T) {
	p := model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "native", Enabled: true, Engine: model.EngineExternal, Params: map[string]any{"interface": "awg1"}},
			{ID: "socks", Enabled: true, Engine: model.EngineSingBox, Protocol: "socks", Server: "198.51.100.7", Port: 1080},
		},
		Groups: []model.Group{{ID: "grp", Name: "Mixed", Type: "fallback", Members: []string{"native", "socks"}}},
		RoutingLists: []model.RoutingList{{ID: "l", Name: "L", Outbound: "grp", Enabled: true,
			Manual: []string{"203.0.113.0/24"}}},
	}
	s := serverFor(t, p)
	// No health has ever been recorded for either member here — the monitor is untouched. The answer
	// must still name the native member.
	if m := s.kernelElectableMembers()["grp"]; len(m) != 1 || m[0] != "native" {
		t.Errorf("capability must not depend on measured health, got %v", m)
	}
}

// serverFor builds a Server around one profile, with the pieces kernelElectableMembers reads.
func serverFor(t *testing.T, p model.Profile) *Server {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Replace(p); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	cfg := config.Config{RoutingMode: "fast"}
	return &Server{cfg: &cfg, store: st}
}
