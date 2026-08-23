package model

import (
	"strings"
	"testing"
)

// TestValidateAllowsDirectGroupMember: `direct` (WAN) is a valid, always-reachable failover /
// WAN-fallback member — needed for the Keenetic all-VPN-down→WAN posture (an ordered urltest
// [vpn…, direct] that only reaches WAN when every VPN tier is dead). `block` is a route
// action (reject) in sing-box ≥1.12, not an outbound, so it stays rejected as a member.
func TestValidateAllowsDirectGroupMember(t *testing.T) {
	p := storemodelconfig_goodProfile()
	p.Groups = []Group{{ID: "g1", Name: "G1", Type: GroupURLTest, Members: []string{"e1", "e2", OutboundDirect}}}
	if err := p.Validate(); err != nil {
		t.Errorf("group with a `direct` member must validate, got: %v", err)
	}

	p.Groups = []Group{{ID: "g1", Name: "G1", Type: GroupURLTest, Members: []string{"e1", OutboundBlock}}}
	err := p.Validate()
	if err == nil || !strings.Contains(err.Error(), "route action") {
		t.Errorf("group with a `block` member must be rejected as a route action, got: %v", err)
	}

	// Bogus members still rejected.
	p.Groups = []Group{{ID: "g1", Name: "G1", Type: GroupURLTest, Members: []string{"e1", "nope"}}}
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "does not resolve") {
		t.Errorf("unknown member must still be rejected, got: %v", err)
	}
}
