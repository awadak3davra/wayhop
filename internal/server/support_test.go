package server

import (
	"encoding/json"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestSupportBundle_RedactsSecrets: the diagnostics bundle summarizes endpoints (id/protocol/
// enabled/has_server) but NEVER leaks a secret — no Params (keys/passwords), no server address.
func TestSupportBundle_RedactsSecrets(t *testing.T) {
	s, _ := backup_newServer(t)

	const secret = "SUPER-SECRET-PRIVATE-KEY-abc123"
	const server = "203.0.113.9"
	if err := s.store.UpsertEndpoint(model.Endpoint{
		ID: "ep1", Name: "NL", Engine: model.EngineExternal, Server: server, Port: 51820, Enabled: true,
		Params: map[string]any{"interface": "awg9", "private_key": secret, "password": "hunter2"},
	}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}

	b := s.buildSupportBundle()
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(data)

	for _, leak := range []string{secret, "hunter2", server, "private_key", "params", "interface"} {
		if strings.Contains(js, leak) {
			t.Errorf("support bundle LEAKED %q:\n%s", leak, js)
		}
	}

	// The endpoint is present as a redacted summary.
	var found *supportEndpoint
	for i := range b.Profile.Endpoints {
		if b.Profile.Endpoints[i].ID == "ep1" {
			found = &b.Profile.Endpoints[i]
			break
		}
	}
	if found == nil {
		t.Fatal("redacted endpoint ep1 missing from the bundle")
	}
	if found.Protocol == "" && found.Engine == "" {
		t.Error("redacted endpoint should keep protocol/engine")
	}
	if !found.Enabled || !found.HasServer || found.Port != 51820 {
		t.Errorf("redacted endpoint summary wrong: %+v", *found)
	}
	if b.WayHopSupport != supportBundleSchema {
		t.Errorf("schema marker = %d, want %d", b.WayHopSupport, supportBundleSchema)
	}
}
