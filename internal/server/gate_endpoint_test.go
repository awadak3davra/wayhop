package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

func gateSeed(t *testing.T, capabilities ...platform.Capability) *Server {
	t.Helper()
	s := dnsSeed(t)
	items := make(map[string]platform.Capability, len(capabilities))
	for _, capability := range capabilities {
		items[capability.ID] = capability
	}
	s.caps.mu.Lock()
	s.caps.set = platform.CapabilitySet{Items: items, ProbedAt: time.Now()}
	s.caps.mu.Unlock()
	return s
}

func gateCapability(id string, state platform.CapState) platform.Capability {
	return platform.Capability{ID: id, State: state, Detail: "fixture detail", Remedy: "fixture remedy"}
}

func gateEndpointOf(proto string, enabled bool) model.Endpoint {
	return model.Endpoint{ID: "e1", Name: "e1", Engine: model.EngineSingBox,
		Protocol: model.Protocol(proto), Server: "198.51.100.10", Port: 443, Enabled: enabled}
}

func gateProxyServer(t *testing.T, proto string, engineState, protocolState platform.CapState) *Server {
	t.Helper()
	return gateSeed(t,
		gateCapability(platform.CapEngineSingbox, engineState),
		gateCapability(platform.CapProtocolPrefix+proto, protocolState),
	)
}

func TestGateEndpointDisabledDraftIsAlwaysAllowed(t *testing.T) {
	s := gateSeed(t)
	if code, msg := s.gateEndpoint(context.Background(), gateEndpointOf("future-protocol", false)); code != 0 {
		t.Errorf("disabled draft refused with %d (%s)", code, msg)
	}
}

func TestGateEndpointDemoDoesNotPretendToActivateRouterCapabilities(t *testing.T) {
	s := applyhealth_server(t)
	if code, msg := s.gateEndpoint(context.Background(), gateEndpointOf("vless", true)); code != 0 {
		t.Fatalf("demo fixture refused with %d (%s)", code, msg)
	}
}

func TestGateEndpointProxyRequiresCoreAndProtocol(t *testing.T) {
	for _, tc := range []struct {
		name          string
		engine, proto platform.CapState
	}{
		{"engine unavailable", platform.CapUnsupportedPlatform, platform.CapSupported},
		{"protocol unavailable", platform.CapSupported, platform.CapUnsupportedFirmware},
		{"engine not installed", platform.CapAvailableAfterInstall, platform.CapSupported},
		{"protocol dependency blocked", platform.CapSupported, platform.CapBlockedByDependency},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := gateProxyServer(t, "vless", tc.engine, tc.proto)
			code, msg := s.gateEndpoint(context.Background(), gateEndpointOf("vless", true))
			if code != http.StatusUnprocessableEntity || !strings.Contains(msg, "Save it disabled") {
				t.Fatalf("code=%d msg=%q, want 422 with disabled-draft remedy", code, msg)
			}
		})
	}
}

func TestGateEndpointProxySupported(t *testing.T) {
	s := gateProxyServer(t, "anytls", platform.CapSupported, platform.CapSupported)
	if code, msg := s.gateEndpoint(context.Background(), gateEndpointOf("anytls", true)); code != 0 {
		t.Fatalf("supported AnyTLS refused with %d (%s)", code, msg)
	}
}

func TestGateEndpointUnknownOrMissingCapabilityAsksAgain(t *testing.T) {
	for _, s := range []*Server{
		gateProxyServer(t, "vless", platform.CapSupported, platform.CapUnknown),
		gateSeed(t, gateCapability(platform.CapEngineSingbox, platform.CapSupported)),
	} {
		code, msg := s.gateEndpoint(context.Background(), gateEndpointOf("vless", true))
		if code != http.StatusServiceUnavailable || !strings.Contains(msg, "not verified") {
			t.Fatalf("code=%d msg=%q, want fail-closed 503", code, msg)
		}
	}
}

func TestGateEndpointNativeRequiresCreateAndRollbackAuthority(t *testing.T) {
	create := platform.NativeOperationCapabilityID("wireguard", platform.NativeCreate)
	remove := platform.NativeOperationCapabilityID("wireguard", platform.NativeRemove)
	ep := gateEndpointOf("wireguard", true)

	t.Run("both supported", func(t *testing.T) {
		s := gateSeed(t, gateCapability(create, platform.CapSupported), gateCapability(remove, platform.CapSupported))
		if code, msg := s.gateEndpoint(context.Background(), ep); code != 0 {
			t.Fatalf("native endpoint refused with %d (%s)", code, msg)
		}
	})
	t.Run("carry is not create authority", func(t *testing.T) {
		carry := platform.NativeOperationCapabilityID("wireguard", platform.NativeCarry)
		s := gateSeed(t, gateCapability(carry, platform.CapSupported), gateCapability(remove, platform.CapSupported))
		if code, _ := s.gateEndpoint(context.Background(), ep); code != http.StatusServiceUnavailable {
			t.Fatalf("code=%d, want 503 for unevaluated create authority", code)
		}
	})
	t.Run("remove unavailable", func(t *testing.T) {
		s := gateSeed(t, gateCapability(create, platform.CapSupported), gateCapability(remove, platform.CapUnsupportedPlatform))
		if code, _ := s.gateEndpoint(context.Background(), ep); code != http.StatusUnprocessableEntity {
			t.Fatalf("code=%d, want 422 without rollback authority", code)
		}
	})
}

func TestGateEndpointExternalBindingDoesNotRequireCore(t *testing.T) {
	s := gateSeed(t)
	ep := gateEndpointOf("wireguard", true)
	ep.Engine = model.EngineExternal
	ep.Owner = model.OwnerExternal
	ep.Params = map[string]any{"interface": "awg0", "discovered": true}
	if code, msg := s.gateEndpoint(context.Background(), ep); code != 0 {
		t.Fatalf("external binding refused with %d (%s)", code, msg)
	}
}

func TestGateEndpointUnsupportedPairFailsClosed(t *testing.T) {
	for _, ep := range []model.Endpoint{
		gateEndpointOf("future-protocol", true),
		{ID: "olc", Engine: model.EngineOlcRTC, Protocol: model.ProtoOlcRTC, Enabled: true},
		{ID: "bad", Engine: model.EngineAmneziaWG, Protocol: model.ProtoVLESS, Enabled: true},
	} {
		s := gateSeed(t, gateCapability(platform.CapEngineOlcRTC, platform.CapUnsupportedPlatform))
		if code, _ := s.gateEndpoint(context.Background(), ep); code != http.StatusUnprocessableEntity {
			t.Errorf("%s/%s code=%d, want 422", ep.Engine, ep.Protocol, code)
		}
	}
}
