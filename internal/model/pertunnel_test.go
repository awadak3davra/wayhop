package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// pertunnel_wgProfile builds a valid single-endpoint WG profile that we can
// decorate with per-tunnel link tunables (MTU / PersistentKeepalive). A group +
// default rule keep the profile otherwise structurally sound.
func pertunnel_wgProfile() Profile {
	return Profile{
		Endpoints: []Endpoint{{
			ID: "wg", Name: "wg", Engine: EngineSingBox, Protocol: ProtoWireGuard,
			Server: "1.2.3.4", Port: 51820, Enabled: true,
			Params: map[string]any{"private_key": "k", "peer_public_key": "pk"},
		}},
		Groups: []Group{
			{ID: "g1", Name: "G1", Type: GroupURLTest, Members: []string{"wg"}},
		},
		Rules: []Rule{
			{ID: "r1", Default: true, Outbound: "g1"},
		},
	}
}

// TestPerTunnelFieldsOmitWhenUnset: an Endpoint with MTU/PersistentKeepalive at
// their zero value and a Group with KillSwitch false must marshal WITHOUT the new
// keys, so existing profiles/JSON stay byte-identical (omitempty contract).
func TestPerTunnelFieldsOmitWhenUnset(t *testing.T) {
	e := Endpoint{
		ID: "e", Name: "e", Engine: EngineSingBox, Protocol: ProtoVLESS,
		Server: "1.1.1.1", Port: 443, Enabled: true,
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal endpoint: %v", err)
	}
	js := string(b)
	for _, key := range []string{"mtu", "persistent_keepalive"} {
		if strings.Contains(js, key) {
			t.Errorf("unset endpoint must omit %q, got: %s", key, js)
		}
	}

	g := Group{ID: "g", Name: "g", Type: GroupURLTest, Members: []string{"e"}}
	gb, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal group: %v", err)
	}
	if strings.Contains(string(gb), "kill_switch") {
		t.Errorf("unset group must omit kill_switch, got: %s", gb)
	}
}

// TestPerTunnelJSONTags pins the exact JSON keys (the SHARED-SPEC names that the
// UI/importer/generator align on). A rename here would silently break round-trips.
func TestPerTunnelJSONTags(t *testing.T) {
	e := Endpoint{
		ID: "e", Name: "e", Engine: EngineSingBox, Protocol: ProtoVLESS,
		Server: "1.1.1.1", Port: 443, Enabled: true,
		MTU: 1420, PersistentKeepalive: 25,
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(b)
	if !strings.Contains(js, `"mtu":1420`) {
		t.Errorf(`expected "mtu":1420 in %s`, js)
	}
	if !strings.Contains(js, `"persistent_keepalive":25`) {
		t.Errorf(`expected "persistent_keepalive":25 in %s`, js)
	}

	g := Group{ID: "g", Name: "g", Type: GroupURLTest, Members: []string{"e"}, KillSwitch: true}
	gb, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal group: %v", err)
	}
	if !strings.Contains(string(gb), `"kill_switch":true`) {
		t.Errorf(`expected "kill_switch":true in %s`, gb)
	}
}

// TestPerTunnelRoundTrip: a profile carrying the new fields survives a
// marshal→unmarshal cycle with the values intact.
func TestPerTunnelRoundTrip(t *testing.T) {
	p := pertunnel_wgProfile()
	p.Endpoints[0].MTU = 1280
	p.Endpoints[0].PersistentKeepalive = 15
	p.Groups[0].KillSwitch = true

	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got Profile
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Endpoints[0].MTU != 1280 {
		t.Errorf("MTU round-trip: want 1280, got %d", got.Endpoints[0].MTU)
	}
	if got.Endpoints[0].PersistentKeepalive != 15 {
		t.Errorf("PersistentKeepalive round-trip: want 15, got %d", got.Endpoints[0].PersistentKeepalive)
	}
	if !got.Groups[0].KillSwitch {
		t.Error("KillSwitch round-trip: want true, got false")
	}
}

// TestValidateMTUBounds: an out-of-range MTU (when SET) is rejected; an unset (0)
// or in-range MTU passes. The check is protocol-agnostic.
func TestValidateMTUBounds(t *testing.T) {
	cases := []struct {
		name string
		mtu  int
		ok   bool
	}{
		{"unset-zero", 0, true},
		{"min-boundary", minMTU, true},
		{"max-boundary", maxMTU, true},
		{"typical-wg", 1420, true},
		{"keenetic-1280", 1280, true},
		{"below-min", minMTU - 1, false},
		{"above-max", maxMTU + 1, false},
		{"negative", -1, false},
		{"absurd-high", 100000, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := pertunnel_wgProfile()
			p.Endpoints[0].MTU = c.mtu
			err := p.Validate()
			if c.ok && err != nil {
				t.Fatalf("mtu %d should be accepted, got: %v", c.mtu, err)
			}
			if !c.ok && err == nil {
				t.Fatalf("mtu %d should be rejected", c.mtu)
			}
		})
	}
}

// TestValidateKeepaliveBounds: an out-of-range PersistentKeepalive (when SET) is
// rejected; an unset (0) or 1..65535 value passes.
func TestValidateKeepaliveBounds(t *testing.T) {
	cases := []struct {
		name string
		ka   int
		ok   bool
	}{
		{"unset-zero", 0, true},
		{"min-one", 1, true},
		{"typical-25", 25, true},
		{"max-65535", 65535, true},
		{"above-max", 65536, false},
		{"negative", -1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := pertunnel_wgProfile()
			p.Endpoints[0].PersistentKeepalive = c.ka
			err := p.Validate()
			if c.ok && err != nil {
				t.Fatalf("keepalive %d should be accepted, got: %v", c.ka, err)
			}
			if !c.ok && err == nil {
				t.Fatalf("keepalive %d should be rejected", c.ka)
			}
		})
	}
}

// TestValidateKillSwitchNoConstraint: KillSwitch has no value bounds — both
// true and false must validate (it's a pure routing-behavior flag).
func TestValidateKillSwitchNoConstraint(t *testing.T) {
	for _, ks := range []bool{false, true} {
		p := pertunnel_wgProfile()
		p.Groups[0].KillSwitch = ks
		if err := p.Validate(); err != nil {
			t.Fatalf("KillSwitch=%v should validate, got: %v", ks, err)
		}
	}
}

// TestValidatePerTunnelOnExternalEndpoint: the MTU/keepalive bound checks run
// before the external short-circuit, so a stray bad value on an external endpoint
// is still caught (defense-in-depth), while a sane value passes.
func TestValidatePerTunnelOnExternalEndpoint(t *testing.T) {
	mk := func(mtu int) *Profile {
		return &Profile{Endpoints: []Endpoint{{
			ID: "x", Name: "x", Engine: EngineExternal, Protocol: ProtoWireGuard,
			Enabled: true, MTU: mtu,
			Params: map[string]any{"interface": "awg0"},
		}}}
	}
	if err := mk(maxMTU + 1).Validate(); err == nil {
		t.Fatal("external endpoint with an out-of-range MTU must be rejected")
	}
	if err := mk(1420).Validate(); err != nil {
		t.Fatalf("external endpoint with a sane MTU must validate, got: %v", err)
	}
	if err := mk(0).Validate(); err != nil {
		t.Fatalf("external endpoint with unset MTU must validate, got: %v", err)
	}
}
