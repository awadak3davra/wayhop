package server

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// A Hysteria2 connection with gecko obfuscation on a pre-1.14 core is applied without gecko (the
// shared config must still load) and the review says that exit will not come up - degraded, not an
// Apply blocker. On a 1.14 core there is nothing to say.
func TestEndpointFindings_GeckoOnAnOlderCore(t *testing.T) {
	s, _ := sharehandlers_server(t)
	bin := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(bin, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.cfg.SingBox.Bin = bin
	answer := "sing-box version 1.13.21\n"
	s.coreVersionOf = func(context.Context, string) (string, error) { return answer, nil }
	hy := model.Endpoint{ID: "hy", Name: "Gecko node", Enabled: true, Engine: model.EngineSingBox,
		Protocol: model.ProtoHysteria2, Server: "192.0.2.4", Port: 8443,
		Params: map[string]any{"password": "pw", "obfs": "gecko", "obfs_password": "o"}}
	prof := model.Profile{Endpoints: []model.Endpoint{hy}}

	find := func() *PlanFinding {
		for _, f := range s.endpointFindings(prof, platform.CapabilitySet{}) {
			if f.ID == "endpoint.hysteria2.gecko" {
				return &f
			}
		}
		return nil
	}
	f := find()
	if f == nil || f.Severity != platform.SeverityDegraded || f.Blocks != platform.BlocksFeature || f.Item != "Gecko node" {
		t.Fatalf("1.13 core: finding = %+v, want a degraded, feature-only finding naming the connection", f)
	}
	// A new binary is a new probe (the cache keys on size and mtime).
	if err := os.WriteFile(bin, []byte("v2-longer"), 0o755); err != nil {
		t.Fatal(err)
	}
	answer = "sing-box version 1.14.4\n"
	if f := find(); f != nil {
		t.Fatalf("1.14 core: unexpected finding %+v", f)
	}
}
