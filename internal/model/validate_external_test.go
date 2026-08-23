package model

import (
	"strings"
	"testing"
)

// TestValidateExternalEndpoint_NoInterface: an external endpoint with no
// params.interface must fail Validate with a message containing
// "needs params.interface".
func TestValidateExternalEndpoint_NoInterface(t *testing.T) {
	p := &Profile{Endpoints: []Endpoint{{
		ID:      "ext-1",
		Name:    "no-iface",
		Engine:  EngineExternal,
		Enabled: true,
		// Params intentionally absent
	}}}
	err := p.Validate()
	if err == nil {
		t.Fatal("external endpoint without params.interface must fail Validate")
	}
	if !strings.Contains(err.Error(), "needs params.interface") {
		t.Fatalf("expected error to contain %q, got: %v", "needs params.interface", err)
	}
}

// TestValidateExternalEndpoint_WithInterface: an external endpoint that supplies
// params.interface must pass Validate even without Server, Port, or Protocol —
// those fields do not apply to external-engine endpoints.
func TestValidateExternalEndpoint_WithInterface(t *testing.T) {
	p := &Profile{Endpoints: []Endpoint{{
		ID:      "ext-1",
		Name:    "with-iface",
		Engine:  EngineExternal,
		Enabled: true,
		Params:  map[string]any{"interface": "awg0"},
		// No Server, Port, or Protocol — must not be required
	}}}
	if err := p.Validate(); err != nil {
		t.Fatalf("external endpoint with params.interface should validate, got: %v", err)
	}
}

// TestValidateExternalEndpoint_WithEndpointIP: endpoint_ip is an optional param
// for external endpoints; supplying it alongside interface must not cause
// Validate to reject the endpoint.
func TestValidateExternalEndpoint_WithEndpointIP(t *testing.T) {
	p := &Profile{Endpoints: []Endpoint{{
		ID:      "ext-1",
		Name:    "with-endpoint-ip",
		Engine:  EngineExternal,
		Enabled: true,
		Params: map[string]any{
			"interface":   "awg0",
			"endpoint_ip": "10.8.0.1",
		},
	}}}
	if err := p.Validate(); err != nil {
		t.Fatalf("external endpoint with interface + endpoint_ip should validate, got: %v", err)
	}
}

// TestValidateExternalEndpoint_EmptyInterface: a params.interface value that is
// all whitespace is treated the same as absent (strings.TrimSpace == ""); Validate
// must reject it with the same "needs params.interface" error.
func TestValidateExternalEndpoint_EmptyInterface(t *testing.T) {
	p := &Profile{Endpoints: []Endpoint{{
		ID:      "ext-1",
		Name:    "blank-iface",
		Engine:  EngineExternal,
		Enabled: true,
		Params:  map[string]any{"interface": "   "},
	}}}
	err := p.Validate()
	if err == nil {
		t.Fatal("external endpoint with whitespace-only params.interface must fail Validate")
	}
	if !strings.Contains(err.Error(), "needs params.interface") {
		t.Fatalf("expected error to contain %q, got: %v", "needs params.interface", err)
	}
}

// TestValidateExternalEndpoint_DisabledNoInterface: Validate checks ALL
// endpoints regardless of their Enabled flag; a disabled external endpoint that
// is missing params.interface must still be rejected. (Unlike regular endpoints
// whose identity-field checks are gated on Enabled, the interface requirement is
// unconditional — the name is referenced in routing even when disabled.)
func TestValidateExternalEndpoint_DisabledNoInterface(t *testing.T) {
	p := &Profile{Endpoints: []Endpoint{{
		ID:      "ext-1",
		Name:    "disabled-no-iface",
		Engine:  EngineExternal,
		Enabled: false, // disabled
		// No params.interface
	}}}
	err := p.Validate()
	if err == nil {
		t.Fatal("disabled external endpoint without params.interface must still fail Validate")
	}
	if !strings.Contains(err.Error(), "needs params.interface") {
		t.Fatalf("expected error to contain %q, got: %v", "needs params.interface", err)
	}
}

// TestValidateExternalEndpoint_RoutingListPointsToDisabled: a routing list whose
// outbound targets a disabled EngineExternal endpoint is rejected by Validate —
// Validate enforces that routing list outbounds resolve to an ENABLED id (or a
// builtin), because the generator omits disabled endpoints and a dangling tag
// would cause sing-box to reject the entire config.
func TestValidateExternalEndpoint_RoutingListPointsToDisabled(t *testing.T) {
	p := &Profile{
		Endpoints: []Endpoint{{
			ID:      "ext-1",
			Name:    "disabled-ext",
			Engine:  EngineExternal,
			Enabled: false,
			Params:  map[string]any{"interface": "awg0"},
		}},
		RoutingLists: []RoutingList{{
			ID:       "rl-1",
			Name:     "my-list",
			Manual:   []string{"example.com"},
			Outbound: "ext-1",
			Enabled:  true,
		}},
	}
	// A disabled endpoint is not emitted by the generator; the routing list
	// would reference a missing outbound tag, so Validate rejects this.
	if err := p.Validate(); err == nil {
		t.Fatal("routing list pointing at a disabled external endpoint must fail Validate")
	}

	// Enabling the endpoint fixes the profile.
	p.Endpoints[0].Enabled = true
	if err := p.Validate(); err != nil {
		t.Fatalf("routing list pointing at an enabled external endpoint should validate, got: %v", err)
	}
}

// TestValidateExternalEndpoint_StableID: endpoint IDs beginning with "external-"
// (the adoption prefix used by handleVPNAdopt) are accepted by Validate; the ID
// namespace has no reserved prefixes.
func TestValidateExternalEndpoint_StableID(t *testing.T) {
	for _, id := range []string{"external-awg0", "external-wg1", "external-vpn"} {
		p := &Profile{Endpoints: []Endpoint{{
			ID:      id,
			Name:    "adopted-" + id,
			Engine:  EngineExternal,
			Enabled: true,
			Params:  map[string]any{"interface": "awg0"},
		}}}
		if err := p.Validate(); err != nil {
			t.Errorf("external endpoint with id %q should validate, got: %v", id, err)
		}
	}
}
