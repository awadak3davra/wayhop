package generator

import (
	"encoding/json"
	"testing"
)

// The OpenWrt kill-switch guard lets traffic through by the TUN's device name; it
// guessed "tun*". The generator now states the name it is asked for, and TunFacts reads it back from
// the config as generated, so an operator's override that renames the device is followed too.
func TestTunInboundStatesItsNameAndTunFactsReadsItBack(t *testing.T) {
	res, err := Generate(probeProfile(), Options{MixedPort: 7890, TunEnabled: true, Hybrid: true, TunName: CoreTunName})
	if err != nil {
		t.Fatal(err)
	}
	if tun := tunInbound(t, res.Config); tun["interface_name"] != "whtun0" {
		t.Fatalf("tun inbound: %v", tun)
	}
	if name, v6, found := TunFacts(res.Config); name != "whtun0" || v6 || !found {
		t.Fatalf("TunFacts = %q, %v, %v; a hybrid TUN without a kill switch over names stays IPv4-only", name, v6, found)
	}
	// The config as the core reads it (after a JSON round trip) says the same.
	raw, _ := json.Marshal(res.Config)
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if name, _, found := TunFacts(decoded); name != "whtun0" || !found {
		t.Fatalf("TunFacts on the decoded config = %q, %v", name, found)
	}
	// No name asked for: none stated (the core picks), which the guard treats as the old wildcard.
	res, err = Generate(probeProfile(), Options{MixedPort: 7890, TunEnabled: true, Hybrid: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, named := tunInbound(t, res.Config)["interface_name"]; named {
		t.Fatal("a name nobody asked for")
	}
	if name, _, found := TunFacts(res.Config); name != "" || !found {
		t.Fatalf("TunFacts = %q, %v", name, found)
	}
	// An override that renames the device is what the core will run, and what is read.
	res, err = Generate(probeProfile(), Options{MixedPort: 7890, TunEnabled: true, Hybrid: true, TunName: CoreTunName,
		CoreOverride: `{"inbounds":[{"type":"tun","tag":"tun-in","interface_name":"mytun","address":["172.31.3.1/30"],"auto_route":true,"auto_redirect":true}]}`})
	if err != nil {
		t.Fatal(err)
	}
	if name, _, found := TunFacts(res.Config); name != "mytun" || !found {
		t.Fatalf("TunFacts after an override = %q, %v", name, found)
	}
	// No TUN at all (fast mode).
	res, err = Generate(probeProfile(), Options{MixedPort: 7890, Hybrid: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, found := TunFacts(res.Config); found {
		t.Fatal("a TUN in a config without one")
	}
}

// With a kill switch over names the hybrid TUN carries IPv6 as well: the kernel plane
// cannot match a name, and IPv6 that passes beside the core would take a kill-switched name's AAAA
// to the provider, which used to be "solved" by dropping all of the LAN's IPv6.
func TestHybridTunCarriesIPv6UnderAKillSwitchOverNames(t *testing.T) {
	res, err := Generate(probeProfile(), Options{MixedPort: 7890, TunEnabled: true, Hybrid: true, TunV6: true,
		KernelExcludeV4: []string{"203.0.113.0/24"}, KernelExcludeV6: []string{"2001:db8:6::/48"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, v6, _ := TunFacts(res.Config); !v6 {
		t.Fatalf("the TUN has no IPv6 address: %v", tunInbound(t, res.Config))
	}
	// What the kernel plane routes stays out of the TUN in both families.
	raw, _ := json.Marshal(tunInbound(t, res.Config)["route_exclude_address"])
	if string(raw) != `["203.0.113.0/24","2001:db8:6::/48"]` {
		t.Fatalf("route_exclude_address = %s", raw)
	}
}
