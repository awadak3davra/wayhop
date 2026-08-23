package model

import "testing"

// TestValidate_ExternalEndpoint: external endpoints validate on params.interface
// alone — server/port/protocol do not apply — and are rejected without it.
func TestValidate_ExternalEndpoint(t *testing.T) {
	ok := &Profile{Endpoints: []Endpoint{{
		ID: "x", Engine: EngineExternal, Enabled: true, Params: map[string]any{"interface": "awg1"},
	}}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("external endpoint with interface should validate: %v", err)
	}

	bad := &Profile{Endpoints: []Endpoint{{ID: "x", Engine: EngineExternal, Enabled: true}}}
	if err := bad.Validate(); err == nil {
		t.Fatal("external endpoint without params.interface must fail validation")
	}

	// No server/port must NOT trip the normal endpoint checks.
	noSrv := &Profile{Endpoints: []Endpoint{{ID: "x", Engine: EngineExternal, Params: map[string]any{"interface": "awg0"}}}}
	if err := noSrv.Validate(); err != nil {
		t.Fatalf("external endpoint must not require server/port: %v", err)
	}
}
