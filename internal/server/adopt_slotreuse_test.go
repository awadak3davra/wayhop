package server

import (
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/store"

	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/netvpn"
	"wayhop/internal/platform"
)

// The tunnel dies and the operator makes a new one in the router's own UI: KeeneticOS hands it the
// same WireguardN slot, with another key. Everything WayHop does from there, in order.
const adoptCap = "native.operation.amneziawg.adopt"

func TestAdoptedTunnelReplacedInTheSameSlot(t *testing.T) {
	old := endpointFromDiscovered(netvpn.DiscoveredVPN{Iface: "nwg0", NDMName: "Wireguard0", Type: "amneziawg",
		Name: "ProviderVPN", PublicKey: "OLDKEY", Source: netvpn.SourceNDM})
	old.Enabled = true
	fresh := netvpn.DiscoveredVPN{Iface: "nwg0", NDMName: "Wireguard0", Type: "amneziawg",
		Name: "AWG3.1_RU", PublicKey: "NEWKEY", Source: netvpn.SourceNDM}
	disc := netvpn.Discovery{VPNs: []netvpn.DiscoveredVPN{fresh}, NDM: true}

	// 1. The old record is reported deleted, not silently re-pointed at the new tunnel.
	missing := missingAdoptedTunnels([]model.Endpoint{old}, disc, nil)
	if len(missing) != 1 || !missing[0].Deleted {
		t.Fatalf("old endpoint not reported as deleted: %+v", missing)
	}
	// 2. Adopting the new tunnel mints its own record beside the old one (rules still use the old).
	newID := resolveAdoptedIDAmong([]model.Endpoint{old}, fresh, disc.VPNs)
	if newID == old.ID {
		t.Fatalf("new tunnel took over the old record %q", newID)
	}
	ep := endpointFromDiscovered(fresh)
	ep.ID = newID
	ep.Enabled = true
	// 3. Both claim nwg0: the plan is refused naming both, with the way out.
	facts := nativeplan.HostFacts{
		Platform: platform.Keenetic,
		Capabilities: platform.CapabilitySet{Items: map[string]platform.Capability{
			adoptCap: {ID: adoptCap, State: platform.CapSupported, HostSupport: platform.VerdictYes,
				WayHopSupport: platform.VerdictYes, RuntimeState: platform.VerdictYes, Blocks: platform.BlocksNothing},
		}},
		AdoptInterfaces:    map[string]string{old.ID: "nwg0", ep.ID: "nwg0"},
		AdoptNDMNames:      map[string]string{old.ID: "Wireguard0", ep.ID: "Wireguard0"},
		OccupiedInterfaces: map[string]bool{},
	}
	_, err := nativeplan.Compile(&model.Profile{Endpoints: []model.Endpoint{old, ep}}, facts)
	if err == nil || !strings.Contains(err.Error(), old.ID) || !strings.Contains(err.Error(), ep.ID) {
		t.Fatalf("two records on one interface: %v", err)
	}
	t.Logf("compile error: %v", err)

	// 4. The operator deletes the stale record and moves what used it onto the new tunnel, in one step
	// (the Connections delete dialog, ?replace_with=). The plan then compiles.
	st, serr := store.Open(filepath.Join(t.TempDir(), "profile.json"))
	if serr != nil {
		t.Fatal(serr)
	}
	for _, e := range []model.Endpoint{old, ep} {
		if err := st.UpsertEndpoint(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.UpsertGroup(model.Group{ID: "g", Name: "G", Type: model.GroupURLTest, Members: []string{old.ID}}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertRoutingList(model.RoutingList{ID: "l", Name: "L", Outbound: old.ID, Enabled: true, Manual: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteEndpointReplacing(old.ID, ep.ID); err != nil {
		t.Fatalf("move and delete: %v", err)
	}
	p := st.Profile()
	if p.RoutingLists[0].Outbound != ep.ID || p.GroupByID("g").Members[0] != ep.ID {
		t.Fatalf("dependents not moved: list %q group %v", p.RoutingLists[0].Outbound, p.GroupByID("g").Members)
	}
	delete(facts.AdoptInterfaces, old.ID)
	delete(facts.AdoptNDMNames, old.ID)
	if _, err := nativeplan.Compile(&p, facts); err != nil {
		t.Fatalf("after the stale record is gone: %v", err)
	}
}

// "Replace tunnel": the same record, the new tunnel's identity, nothing of the dead one's left behind.
func TestReplacedTunnelEndpointKeepsTheRecordAndDropsTheOldIdentity(t *testing.T) {
	old := endpointFromDiscovered(netvpn.DiscoveredVPN{Iface: "nwg0", NDMName: "Wireguard0", Type: "amneziawg",
		Name: "Old", PublicKey: "OLDKEY", Source: netvpn.SourceNDM,
		Peers: []netvpn.Peer{{PublicKey: "p", Endpoint: "198.51.100.1:51820"}}})
	old.Enabled = false
	old.Name = "My Finland exit" // renamed by the operator
	fresh := netvpn.DiscoveredVPN{Iface: "nwg7", NDMName: "Wireguard7", Type: "amneziawg",
		Name: "New", PublicKey: "NEWKEY", Source: netvpn.SourceNDM}
	got := replacedTunnelEndpoint(old, fresh, 0)
	if got.ID != old.ID || got.Name != "My Finland exit" {
		t.Fatalf("record not kept: %q %q", got.ID, got.Name)
	}
	if got.Params["interface"] != "nwg7" || got.Params["ndm_name"] != "Wireguard7" || got.Params["public_key"] != "NEWKEY" {
		t.Fatalf("new identity missing: %v", got.Params)
	}
	if _, stale := got.Params["endpoint_ip"]; stale {
		t.Fatalf("the dead tunnel's peer address survived: %v", got.Params)
	}
}
