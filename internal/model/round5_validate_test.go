package model

import (
	"strings"
	"testing"
)

// TestValidate_RejectsBuiltinOutboundIDs: an endpoint/group id equal to a builtin outbound tag
// (direct/block) would collide with the generator's always-emitted builtin outbound, producing a
// DUPLICATE outbound tag that FATALs sing-box and bricks every Apply. Validate must reject it.
func TestValidate_RejectsBuiltinOutboundIDs(t *testing.T) {
	ep := func(id string) Endpoint {
		return Endpoint{ID: id, Name: id, Engine: EngineSingBox, Protocol: ProtoVLESS, Server: "1.2.3.4", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u"}}
	}
	// Both exact-case (direct/block) AND case-differing variants (Direct/BLOCK) must be rejected:
	// canonicalOutbound lowercases a reference, so a case-differing id silently folds to the builtin.
	for _, id := range []string{OutboundDirect, OutboundBlock, "Direct", "BLOCK", "Block", "DIRECT"} {
		pe := Profile{Endpoints: []Endpoint{ep(id)}}
		if err := pe.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate id") {
			t.Errorf("endpoint id %q must be rejected as a builtin-tag collision, got %v", id, err)
		}
		g := Profile{
			Endpoints: []Endpoint{ep("e1")},
			Groups:    []Group{{ID: id, Name: id, Type: GroupURLTest, Members: []string{"e1"}}},
		}
		if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate id") {
			t.Errorf("group id %q must be rejected as a builtin-tag collision, got %v", id, err)
		}
	}
	// A normal id still validates (regression guard that the reservation doesn't over-block).
	pok := Profile{Endpoints: []Endpoint{ep("nl-1")}}
	if err := pok.Validate(); err != nil {
		t.Errorf("a normal endpoint id must still validate: %v", err)
	}
}

// TestValidateDeviceGroup_RejectsNon48BitMAC: net.ParseMAC also accepts 8-byte EUI-64 / 20-byte
// InfiniBand forms, but the kernel planes render `ether saddr`/`--mac-source`, which accept only a
// 6-byte EUI-48 — a longer address fails the whole nft/iptables apply device-wide, so it must be
// rejected at the CRUD boundary.
func TestValidateDeviceGroup_RejectsNon48BitMAC(t *testing.T) {
	if err := ValidateDeviceGroup(DeviceGroup{ID: "g", Name: "g", Members: []DeviceMember{{MAC: "aa:bb:cc:dd:ee:ff"}}}); err != nil {
		t.Fatalf("a 6-byte MAC must be accepted: %v", err)
	}
	for _, bad := range []string{
		"aa:bb:cc:dd:ee:ff:00:11",                                     // 8-byte EUI-64
		"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33", // 20-byte InfiniBand
	} {
		if err := ValidateDeviceGroup(DeviceGroup{ID: "g", Name: "g", Members: []DeviceMember{{MAC: bad}}}); err == nil {
			t.Errorf("non-6-byte MAC %q must be rejected (kernel accepts only EUI-48)", bad)
		}
	}
}
