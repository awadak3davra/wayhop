package server

import (
	"testing"

	"wayhop/internal/model"
)

// TestAuthFieldMissing (L5): a connection that can never authenticate must not be silent.
//
// Measured on the demo: Add connection → Manual → trojan, server and port filled, password left
// empty. The panel answered "Added Manual probe" in the success style, stored it enabled, and the
// review verdict was "ready". Nothing on any screen said the server would refuse it.
//
// model.Validate is right not to block: missingProtoParam covers only the fields whose absence
// hard-rejects the whole sing-box config, and an empty trojan password loads fine. That makes this a
// DEGRADED report, not a blocker — one exit will not come up, and nothing else changes.
func TestAuthFieldMissing(t *testing.T) {
	cases := []struct {
		proto model.Protocol
		key   string
		want  string
	}{
		{model.ProtoTrojan, "password", "password"},
		{model.ProtoHysteria2, "password", "password"},
		{model.ProtoVLESS, "uuid", "uuid"},
		{model.ProtoVMess, "uuid", "uuid"},
	}
	for _, c := range cases {
		empty := model.Endpoint{ID: "e", Enabled: true, Engine: model.EngineSingBox, Protocol: c.proto}
		if got := authFieldMissing(empty); got != c.want {
			t.Errorf("%s with no %s must be reported, got %q", c.proto, c.key, got)
		}
		filled := model.Endpoint{ID: "e", Enabled: true, Engine: model.EngineSingBox, Protocol: c.proto,
			Params: map[string]any{c.key: "something"}}
		if got := authFieldMissing(filled); got != "" {
			t.Errorf("%s with a %s must not be reported, got %q", c.proto, c.key, got)
		}
		// Whitespace is not a credential. A field holding " " reads as filled to a human skimming the
		// dialog and is refused by the server exactly like an empty one.
		blank := model.Endpoint{ID: "e", Enabled: true, Engine: model.EngineSingBox, Protocol: c.proto,
			Params: map[string]any{c.key: "   "}}
		if got := authFieldMissing(blank); got != c.want {
			t.Errorf("%s with a whitespace %s must be reported, got %q", c.proto, c.key, got)
		}
	}

	// The protocols model.Validate ALREADY blocks are left alone here: a degraded note beside a
	// blocker about the same field is two answers to one question.
	ss := model.Endpoint{ID: "e", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoShadowsocks}
	if got := authFieldMissing(ss); got != "" {
		t.Errorf("shadowsocks is covered by Validate and must not be reported twice, got %q", got)
	}
	wg := model.Endpoint{ID: "e", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoWireGuard}
	if got := authFieldMissing(wg); got != "" {
		t.Errorf("wireguard is covered by Validate and must not be reported twice, got %q", got)
	}
}
