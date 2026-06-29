package exporter

import (
	"encoding/json"
	"testing"

	"velinx/internal/model"
)

// extEndpoint is the canonical adopted-native-tunnel endpoint: EngineExternal,
// egress = an existing OS-owned interface, no server/port/keys of its own.
func extEndpoint() model.Endpoint {
	return model.Endpoint{
		ID:       "ext-awg0",
		Name:     "awg0 (native)",
		Engine:   model.EngineExternal,
		Protocol: model.ProtoAmneziaWG, // descriptive only; export must not act on it
		Params: map[string]any{
			"interface":   "awg0",
			"endpoint_ip": "203.0.113.7", // synthetic (RFC5737) peer endpoint
			"discovered":  true,
		},
		Enabled: true,
	}
}

// An EngineExternal endpoint is device-local and has nothing to share, so
// share-link export must degrade gracefully: ok=false, no panic, no malformed
// link, no leaked identifier.
func TestExportExternalNotShareable(t *testing.T) {
	e := extEndpoint()

	res, ok := Export(e)
	if ok {
		t.Fatalf("Export(EngineExternal) should not be ok; got %+v", res)
	}
	if res.Text != "" || res.Kind != "" || res.Filename != "" {
		t.Errorf("Export(EngineExternal) should be a zero Result; got %+v", res)
	}

	link, ok := ShareLink(e)
	if ok {
		t.Fatalf("ShareLink(EngineExternal) should not be ok; got %q", link)
	}
	if link != "" {
		t.Errorf("ShareLink(EngineExternal) should be empty; got %q", link)
	}
}

// Even a malformed/empty EngineExternal endpoint must not panic or leak.
func TestExportExternalEmptyParamsSafe(t *testing.T) {
	e := model.Endpoint{ID: "ext-empty", Engine: model.EngineExternal}
	if _, ok := Export(e); ok {
		t.Fatalf("Export(empty EngineExternal) should not be ok")
	}
	if _, ok := ShareLink(e); ok {
		t.Fatalf("ShareLink(empty EngineExternal) should not be ok")
	}
}

// EngineExternal is excluded from share-link export but must survive a
// profile-JSON marshal/unmarshal unchanged (that is the persistence path that
// stores adopted native tunnels). Engine + Params["interface"] are load-bearing.
func TestExternalProfileJSONRoundTrip(t *testing.T) {
	in := model.Profile{Endpoints: []model.Endpoint{extEndpoint()}}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}
	var out model.Profile
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal profile: %v", err)
	}

	if len(out.Endpoints) != 1 {
		t.Fatalf("endpoint count = %d, want 1", len(out.Endpoints))
	}
	got := out.Endpoints[0]
	if got.Engine != model.EngineExternal {
		t.Errorf("Engine = %q, want %q", got.Engine, model.EngineExternal)
	}
	if iface, _ := got.Params["interface"].(string); iface != "awg0" {
		t.Errorf("Params[interface] = %v, want awg0", got.Params["interface"])
	}
	if ip, _ := got.Params["endpoint_ip"].(string); ip != "203.0.113.7" {
		t.Errorf("Params[endpoint_ip] = %v, want 203.0.113.7", got.Params["endpoint_ip"])
	}
	// JSON has no bool/number distinction issue here: "discovered" stays a bool.
	if d, _ := got.Params["discovered"].(bool); !d {
		t.Errorf("Params[discovered] = %v, want true", got.Params["discovered"])
	}
}
