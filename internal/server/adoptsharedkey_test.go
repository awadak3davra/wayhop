package server

import (
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/netvpn"
)

func uciTunnel(iface, key, peer string) netvpn.DiscoveredVPN {
	return netvpn.DiscoveredVPN{
		Iface: iface, Type: "amneziawg", PublicKey: key, Source: netvpn.SourceUCI,
		Peers: []netvpn.Peer{{Endpoint: peer + ":51820"}},
	}
}

func adoptedEndpoint(id, iface, key string, enabled bool) model.Endpoint {
	return model.Endpoint{
		ID: id, Name: id, Engine: model.EngineExternal, Protocol: "amneziawg", Owner: model.OwnerExternal,
		Enabled: enabled, Params: map[string]any{"interface": iface, "public_key": key, "discovered": true},
	}
}

// Two interfaces built from one private key share a public key. A live test router had awg1 to one exit
// and awg_b to another under one key; matching by key first re-pointed the enabled "RU (awg1)" at
// awg_b whichever came first in the listing, and the next Apply sent every RU list there.
func TestSyncAdoptedTunnelsKeepsEachEndpointOnItsOwnInterfaceUnderASharedKey(t *testing.T) {
	for name, order := range map[string][]netvpn.DiscoveredVPN{
		"awg_b listed first": {uciTunnel("awg_b", "K", "198.51.100.2"), uciTunnel("awg1", "K", "203.0.113.14")},
		"awg1 listed first":  {uciTunnel("awg1", "K", "203.0.113.14"), uciTunnel("awg_b", "K", "198.51.100.2")},
	} {
		p := model.Profile{Endpoints: []model.Endpoint{
			adoptedEndpoint("ru-exit", "awg1", "K", true),
			adoptedEndpoint("external-awg_b", "awg_b", "K", false),
		}}
		syncAdoptedTunnels(&p, netvpn.Discovery{UCI: true, VPNs: order}, nil)
		ru, _ := endpointByID(p, "ru-exit")
		second, _ := endpointByID(p, "external-awg_b")
		if endpointIface(ru) != "awg1" || ru.Params["endpoint_ip"] != "203.0.113.14" {
			t.Errorf("%s: ru-exit moved to %q (%v)", name, endpointIface(ru), ru.Params["endpoint_ip"])
		}
		if endpointIface(second) != "awg_b" {
			t.Errorf("%s: external-awg_b moved to %q", name, endpointIface(second))
		}
		for _, v := range order {
			if id, _ := nativeAdoptionAmong(p.Endpoints, v, order); id != map[string]string{"awg1": "ru-exit", "awg_b": "external-awg_b"}[v.Iface] {
				t.Errorf("%s: %s is shown as adopted by %q", name, v.Iface, id)
			}
			if id := resolveAdoptedIDAmong(p.Endpoints, v, order); id != map[string]string{"awg1": "ru-exit", "awg_b": "external-awg_b"}[v.Iface] {
				t.Errorf("%s: re-adopting %s resolves to %q", name, v.Iface, id)
			}
		}
	}
}

// The key still follows a renamed tunnel, but only when it names exactly one tunnel: with the old
// name gone and two tunnels under the key, the endpoint is not guessed onto either.
func TestAdoptedTunnelForRenameAndAmbiguousKey(t *testing.T) {
	e := adoptedEndpoint("ru", "awg9", "K", true)
	if v, ok := adoptedTunnelFor(e, []netvpn.DiscoveredVPN{uciTunnel("awg3", "K", "203.0.113.1")}); !ok || v.Iface != "awg3" {
		t.Errorf("a renamed tunnel was not followed: %v %v", v.Iface, ok)
	}
	if v, ok := adoptedTunnelFor(e, []netvpn.DiscoveredVPN{uciTunnel("awg3", "K", "203.0.113.1"), uciTunnel("awg4", "K", "203.0.113.2")}); ok {
		t.Errorf("an ambiguous key picked %s", v.Iface)
	}
	// A name reused by another tunnel (another key) is not this endpoint's tunnel.
	if v, ok := adoptedTunnelFor(e, []netvpn.DiscoveredVPN{uciTunnel("awg9", "OTHER", "203.0.113.1")}); ok {
		t.Errorf("a reused name with another key matched %s", v.Iface)
	}
}
