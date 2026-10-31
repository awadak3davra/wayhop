package server

import (
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// ByeDPI is run by the plugin manager; whatever protocol a stored connection carries does not change that.
func TestByeDPIExecutesAsPlugin(t *testing.T) {
	for _, proto := range []model.Protocol{"", model.ProtoSOCKS} {
		if got := classifyExecutionEndpoint(model.EngineByeDPI, proto); got != executionEndpointPlugin {
			t.Errorf("byedpi/%q classified %v, want plugin", proto, got)
		}
	}
}

// Enabling a ByeDPI connection needs the core that carries its SOCKS outbound, not a sing-box
// protocol client of its own: the first save from the panel was refused as "protocol socks requires
// the sing-box compatibility add-on".
func TestByeDPICapabilityRequirements(t *testing.T) {
	req, err := endpointCapabilityRequirements(model.Endpoint{ID: "bye", Engine: model.EngineByeDPI, Protocol: model.ProtoSOCKS})
	if err != nil || len(req) != 2 || req[0] != platform.CapEngineSingbox {
		t.Errorf("requirements = %v, %v", req, err)
	}
	if _, err := endpointCapabilityRequirements(model.Endpoint{ID: "x", Engine: model.EngineXray, Protocol: model.ProtoSOCKS}); err == nil {
		t.Error("another non-sing-box engine on a proxy protocol is still refused")
	}
}
