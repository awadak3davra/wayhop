package server

import (
	"errors"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/netvpn"
)

func ndmTunnel(n, label, key string) netvpn.DiscoveredVPN {
	return netvpn.DiscoveredVPN{
		Iface: "nwg" + n, NDMName: "Wireguard" + n, Type: "amneziawg", Name: label,
		PublicKey: key, Source: netvpn.SourceNDM,
	}
}

// legacyNDMEndpoint is an endpoint adopted before the sync existed: no key, no source, no label.
func legacyNDMEndpoint(n, label string, enabled bool) model.Endpoint {
	return model.Endpoint{
		ID: "external-nwg" + n, Name: label + " (native)", Engine: model.EngineExternal,
		Protocol: "amneziawg", Owner: model.OwnerExternal, Enabled: enabled,
		Params: map[string]any{"interface": "nwg" + n, "ndm_name": "Wireguard" + n, "discovered": true},
	}
}

func endpointByID(p model.Profile, id string) (model.Endpoint, bool) {
	for _, e := range p.Endpoints {
		if e.ID == id {
			return e, true
		}
	}
	return model.Endpoint{}, false
}

// A Keenetic as found on 2026-10-19: Wireguard5 was deleted in the Keenetic web UI and three
// tunnels were added, while an Entware awg tunnel also runs. The deleted tunnel's endpoint was off
// and unused, so it goes; the adopted Wireguard4 learns its key and stays.
func TestSyncAdoptedTunnels_KeeneticDeletedAndAddedTunnels(t *testing.T) {
	p := model.Profile{
		Endpoints: []model.Endpoint{
			legacyNDMEndpoint("4", "Exit_Belarus", true),
			legacyNDMEndpoint("5", "VPS_main", false),
		},
		Groups: []model.Group{{ID: "grp-main", Members: []string{"external-nwg4"}}},
	}
	d := netvpn.Discovery{NDM: true, VPNs: []netvpn.DiscoveredVPN{
		ndmTunnel("0", "Exit_Cyprus", "K0"),
		ndmTunnel("4", "Exit_Belarus", "K4"),
		ndmTunnel("6", "RU_exit", "K6"),
		{Iface: "awg1", Type: "amneziawg", PublicKey: "KA", Source: netvpn.SourceRuntime},
	}}
	missing, removed, changed := syncAdoptedTunnels(&p, d, nil)
	if !changed {
		t.Fatal("the profile must change")
	}
	if len(missing) != 0 {
		t.Fatalf("nothing in use is gone, got missing %+v", missing)
	}
	if len(removed) != 1 || removed[0].EndpointID != "external-nwg5" || !removed[0].Deleted {
		t.Fatalf("the deleted, unused tunnel's endpoint must be removed: %+v", removed)
	}
	if _, ok := endpointByID(p, "external-nwg5"); ok {
		t.Fatal("external-nwg5 is still in the profile")
	}
	e, ok := endpointByID(p, "external-nwg4")
	if !ok || !e.Enabled || e.Params["public_key"] != "K4" || e.Params["source"] != netvpn.SourceNDM ||
		e.Name != "Exit_Belarus (native)" {
		t.Fatalf("external-nwg4 must be refreshed in place and keep its state: %+v", e)
	}
	if len(p.Groups[0].Members) != 1 {
		t.Fatalf("the group was touched: %+v", p.Groups)
	}
	// The new tunnels are not adopted behind the operator's back.
	if len(p.Endpoints) != 1 {
		t.Fatalf("want only external-nwg4 left, got %+v", p.Endpoints)
	}
	for _, v := range d.VPNs {
		id, _ := nativeAdoption(p.Endpoints, v)
		if want := map[string]string{"nwg4": "external-nwg4"}[v.Iface]; id != want {
			t.Errorf("%s adopted by %q, want %q", v.Iface, id, want)
		}
	}

	// A second look changes nothing.
	if _, _, again := syncAdoptedTunnels(&p, d, nil); again {
		t.Fatal("a sync with nothing new must not write")
	}
}

// A deleted tunnel that something still routes through is reported, never removed.
func TestSyncAdoptedTunnels_DeletedButInUseIsKept(t *testing.T) {
	for name, p := range map[string]model.Profile{
		"enabled": {Endpoints: []model.Endpoint{legacyNDMEndpoint("5", "VPS", true)}},
		"rule": {Endpoints: []model.Endpoint{legacyNDMEndpoint("5", "VPS", false)},
			Rules: []model.Rule{{ID: "r1", Outbound: "external-nwg5"}}},
		"group member": {Endpoints: []model.Endpoint{legacyNDMEndpoint("5", "VPS", false)},
			Groups: []model.Group{{ID: "g", Members: []string{"x", "external-nwg5"}}}},
		"routing list": {Endpoints: []model.Endpoint{legacyNDMEndpoint("5", "VPS", false)},
			RoutingLists: []model.RoutingList{{ID: "l", DownloadVia: "external-nwg5"}}},
		"dns detour": {Endpoints: []model.Endpoint{legacyNDMEndpoint("5", "VPS", false)},
			DNS: &model.DNSSettings{Servers: []model.DNSServer{{Tag: "d", Detour: "external-nwg5"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			missing, removed, changed := syncAdoptedTunnels(&p, netvpn.Discovery{NDM: true}, nil)
			if changed || len(removed) != 0 {
				t.Fatalf("an endpoint in use must stay: changed %v removed %+v", changed, removed)
			}
			if len(missing) != 1 || !missing[0].Deleted {
				t.Fatalf("it must be reported as deleted on the router: %+v", missing)
			}
		})
	}
}

// KeeneticOS reuses a freed WireguardN slot. A new tunnel in the old one's slot has another key, so
// it is a new tunnel: the old endpoint is reported deleted and the new tunnel is offered under an ID
// of its own instead of inheriting the old rules.
func TestSyncAdoptedTunnels_ReusedNDMSlotIsANewTunnel(t *testing.T) {
	old := legacyNDMEndpoint("5", "VPS", false)
	old.Params["public_key"] = "K-OLD"
	p := model.Profile{Endpoints: []model.Endpoint{old}, Rules: []model.Rule{{ID: "r", Outbound: old.ID}}}
	fresh := ndmTunnel("5", "Office", "K-NEW")
	missing, _, _ := syncAdoptedTunnels(&p, netvpn.Discovery{NDM: true, VPNs: []netvpn.DiscoveredVPN{fresh}}, nil)
	if len(missing) != 1 || missing[0].EndpointID != old.ID || !missing[0].Deleted {
		t.Fatalf("the old tunnel is gone: %+v", missing)
	}
	if e, _ := endpointByID(p, old.ID); e.Params["public_key"] != "K-OLD" || e.Name != "VPS (native)" {
		t.Fatalf("the old endpoint must not take the new tunnel's identity: %+v", e)
	}
	if id, _ := nativeAdoption(p.Endpoints, fresh); id != "" {
		t.Fatalf("the new tunnel must be offered for adoption, but %q claims it", id)
	}
	if id := resolveAdoptedID(p.Endpoints, fresh); id != "external-nwg5-2" {
		t.Fatalf("adopting the new tunnel must not reuse the old ID, got %q", id)
	}
}

// A label changed on the router renames an endpoint WayHop named, never one the operator named.
func TestSyncAdoptedTunnels_LabelFollowsRouterOnlyForAutoNames(t *testing.T) {
	auto := endpointFromDiscovered(ndmTunnel("1", "Finland", "K1"))
	custom := endpointFromDiscovered(ndmTunnel("2", "LAN", "K2"))
	custom.Name = "Office LAN"
	p := model.Profile{Endpoints: []model.Endpoint{auto, custom}}
	d := netvpn.Discovery{NDM: true, VPNs: []netvpn.DiscoveredVPN{
		ndmTunnel("1", "Finland_2", "K1"), ndmTunnel("2", "LAN_2", "K2"),
	}}
	if _, _, changed := syncAdoptedTunnels(&p, d, nil); !changed {
		t.Fatal("the new labels must be recorded")
	}
	if p.Endpoints[0].Name != "Finland_2 (native)" {
		t.Errorf("auto-named endpoint = %q, want the new label", p.Endpoints[0].Name)
	}
	if p.Endpoints[1].Name != "Office LAN" || p.Endpoints[1].Params["native_label"] != "LAN_2" {
		t.Errorf("custom-named endpoint = %q / %v, want its own name kept", p.Endpoints[1].Name, p.Endpoints[1].Params["native_label"])
	}
}

// What cannot be seen is not judged: a failed probe, an unread NDM listing, a runtime-only tunnel.
func TestSyncAdoptedTunnels_UncertainAbsenceRemovesNothing(t *testing.T) {
	runtimeOnly := endpointFromDiscovered(netvpn.DiscoveredVPN{Iface: "awg1", PublicKey: "KA", Source: netvpn.SourceRuntime})
	ndm := legacyNDMEndpoint("5", "VPS", false)
	base := model.Profile{Endpoints: []model.Endpoint{runtimeOnly, ndm}}

	p := base
	p.Endpoints = append([]model.Endpoint(nil), base.Endpoints...)
	missing, removed, changed := syncAdoptedTunnels(&p, netvpn.Discovery{NDM: true, Err: errors.New("awg show all dump: exit status 1")}, nil)
	if changed || len(missing)+len(removed) != 0 {
		t.Fatalf("a failed look concludes nothing: changed %v missing %+v removed %+v", changed, missing, removed)
	}

	p.Endpoints = append([]model.Endpoint(nil), base.Endpoints...)
	missing, removed, changed = syncAdoptedTunnels(&p, netvpn.Discovery{}, nil) // ndmc absent
	if changed || len(removed) != 0 {
		t.Fatalf("nothing may be removed: changed %v removed %+v", changed, removed)
	}
	if len(missing) != 1 || missing[0].EndpointID != runtimeOnly.ID || missing[0].Deleted {
		t.Fatalf("only the runtime tunnel is reported, and only as not running: %+v", missing)
	}
}

// On OpenWrt a uci-backed tunnel deleted from the network config goes like an NDM one; while it is
// only down it is still listed, so it stays adopted.
func TestSyncAdoptedTunnels_OpenWrtUCI(t *testing.T) {
	down := netvpn.DiscoveredVPN{Iface: "wg1", Type: "wireguard", PublicKey: "K1", Source: netvpn.SourceUCI}
	deleted := endpointFromDiscovered(netvpn.DiscoveredVPN{Iface: "wg2", Type: "wireguard", PublicKey: "K2", Source: netvpn.SourceUCI})
	p := model.Profile{Endpoints: []model.Endpoint{endpointFromDiscovered(down), deleted}}
	missing, removed, _ := syncAdoptedTunnels(&p, netvpn.Discovery{UCI: true, VPNs: []netvpn.DiscoveredVPN{down}}, nil)
	if len(missing) != 0 || len(removed) != 1 || removed[0].EndpointID != deleted.ID {
		t.Fatalf("want wg2 removed and wg1 kept: missing %+v removed %+v", missing, removed)
	}
}

// A dismissed drift warning keeps its endpoint: the operator said it is expected.
func TestSyncAdoptedTunnels_IgnoredIsKept(t *testing.T) {
	p := model.Profile{Endpoints: []model.Endpoint{legacyNDMEndpoint("5", "VPS", false)}}
	missing, removed, changed := syncAdoptedTunnels(&p, netvpn.Discovery{NDM: true}, []string{"external-nwg5"})
	if changed || len(missing)+len(removed) != 0 {
		t.Fatalf("an ignored endpoint is neither reported nor removed: %v %+v %+v", changed, missing, removed)
	}
}
