package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"wayhop/internal/generator"
	"wayhop/internal/model"
)

// coreVersionProfile has a remote rule-set, which is what the 1.14+ schema renders differently: its
// download_detour (which 1.15 refuses at the first fetch) becomes an http_client.
func coreVersionProfile() model.Profile {
	return model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "p", Name: "P", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
			Server: "192.0.2.10", Port: 443, Enabled: true,
			Params: map[string]any{"uuid": "11111111-2222-3333-4444-555555555555"},
		}},
		RoutingLists: []model.RoutingList{{ID: "l", Name: "L", Source: "https://example.com/x.srs", Outbound: "p", Enabled: true}},
	}
}

// coreVersionShape renders the profile with opts and reports whether it came out in the 1.14+
// schema, failing the test when it is neither shape cleanly.
func coreVersionShape(t *testing.T, opts generator.Options) (modern bool, raw string) {
	t.Helper()
	p := coreVersionProfile()
	res, err := generator.Generate(&p, opts)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	b, _ := json.Marshal(res.Config)
	route, _ := res.Config["route"].(map[string]any)
	sets, _ := route["rule_set"].([]map[string]any)
	if len(sets) != 1 {
		t.Fatalf("want one rule-set, got %v", route["rule_set"])
	}
	_, legacyField := sets[0]["download_detour"]
	_, clients := res.Config["http_clients"]
	if legacyField == clients {
		t.Fatalf("mixed schema: download_detour=%v http_clients=%v", legacyField, clients)
	}
	return clients, string(b)
}

// TestGenOptionsCoreVersionFollowsTheProbedCore: Generate and the preview render for the sing-box the
// daemon is configured with. A 1.14+ core gets the 1.14 schema; a 1.12 core, a probe that fails and
// a binary that is not there all get the old one, byte for byte. The binary is asked again only when
// it changes.
func TestGenOptionsCoreVersionFollowsTheProbedCore(t *testing.T) {
	s, _ := sharehandlers_server(t)
	bin := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(bin, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.cfg.SingBox.Bin = bin
	answer, probes := "", 0
	var probeErr error
	s.coreVersionOf = func(_ context.Context, got string) (string, error) {
		probes++
		if got != bin {
			t.Errorf("probed %q, want the configured %q", got, bin)
		}
		return answer, probeErr
	}
	p := coreVersionProfile()
	opts := func() generator.Options {
		o, _ := s.genOptionsWithPlan(&p, s.config())
		return o
	}

	answer = "sing-box version 1.12.17\n\nEnvironment: go1.24.4 linux/arm64\nTags: with_quic\n"
	old := opts()
	if old.CoreVersion == "" {
		t.Fatal("the probed 1.12 version was not passed to the generator")
	}
	if modern, _ := coreVersionShape(t, old); modern {
		t.Fatal("a 1.12 core got the 1.14 schema")
	}
	_, unknownRaw := coreVersionShape(t, generator.Options{MixedPort: old.MixedPort, ProbePort: old.ProbePort, ClashAddr: old.ClashAddr,
		ClashSecret: old.ClashSecret, CacheFile: old.CacheFile, TunEnabled: old.TunEnabled,
		TunMTU: old.TunMTU, TunAddr: old.TunAddr})
	if _, oldRaw := coreVersionShape(t, old); oldRaw != unknownRaw {
		t.Fatal("a 1.12 core must render exactly what an unknown core renders")
	}
	opts()
	if probes != 1 {
		t.Fatalf("an unchanged binary was asked %d times, want once", probes)
	}

	// The updater replaces the binary: a new identity, asked again, and the new schema.
	if err := os.WriteFile(bin, []byte("v1.14"), 0o755); err != nil {
		t.Fatal(err)
	}
	answer = "sing-box version 1.14.3\n\nEnvironment: go1.25.1 linux/arm64\n"
	if modern, _ := coreVersionShape(t, opts()); !modern || probes != 2 {
		t.Fatalf("a 1.14 core: modern=%v after %d probes, want the 1.14 schema after 2", modern, probes)
	}
	if err := os.WriteFile(bin, []byte("v1.15.0-beta"), 0o755); err != nil {
		t.Fatal(err)
	}
	answer = "sing-box version 1.15.0-beta.2\n"
	if modern, _ := coreVersionShape(t, opts()); !modern {
		t.Fatal("a 1.15 pre-release got the old schema, which it refuses to start")
	}

	// A binary that does not answer: unknown, the old schema.
	if err := os.WriteFile(bin, []byte("broken"), 0o755); err != nil {
		t.Fatal(err)
	}
	answer, probeErr = "", errors.New("exec format error")
	if o := opts(); o.CoreVersion != "" {
		t.Fatalf("a failed probe passed %q", o.CoreVersion)
	} else if _, raw := coreVersionShape(t, o); raw != unknownRaw {
		t.Fatal("a failed probe must render the unknown-core config")
	}

	// No binary at all, and a demo daemon: unknown without running anything.
	before := probes
	s.cfg.SingBox.Bin = filepath.Join(t.TempDir(), "absent")
	if o := opts(); o.CoreVersion != "" {
		t.Fatalf("a missing binary passed %q", o.CoreVersion)
	}
	s.cfg.SingBox.Bin, s.cfg.Demo = bin, true
	probeErr, answer = nil, "sing-box version 1.14.3\n"
	if o := opts(); o.CoreVersion != "" {
		t.Fatalf("a demo daemon passed %q; its config must not depend on the host's sing-box", o.CoreVersion)
	}
	if probes != before {
		t.Fatalf("a missing binary or a demo daemon ran the probe (%d -> %d)", before, probes)
	}
}

// TestMaterializeRendersForTheSnapshotCore: an Apply renders the config for the core its host
// snapshot identified, not for whatever a later probe would say.
func TestMaterializeRendersForTheSnapshotCore(t *testing.T) {
	desired := DesiredSnapshot{Profile: coreVersionProfile()}
	desired.Config.RoutingMode = "mixed"
	desired.Config.Ports.Mixed = 7890
	render := func(core CoreRunnableIdentityV1) (bool, string) {
		t.Helper()
		var got generator.Options
		host := HostSnapshotV1{Core: core}
		_, _, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host},
			generate: func(p *model.Profile, o generator.Options) (*generator.Result, error) {
				got = o
				return generator.Generate(p, o)
			}})
		if err != nil {
			t.Fatalf("materialize: %v", err)
		}
		return coreVersionShape(t, got)
	}
	ready := func(v string) CoreRunnableIdentityV1 {
		return CoreRunnableIdentityV1{Version: v, Present: true, Runnable: true, State: coreStateReady}
	}
	if modern, _ := render(ready("sing-box version 1.14.3")); !modern {
		t.Error("a 1.14 core in the snapshot got the old schema")
	}
	_, unknown := render(CoreRunnableIdentityV1{})
	for name, core := range map[string]CoreRunnableIdentityV1{
		"1.12 core":           ready("sing-box version 1.12.17"),
		"identity incomplete": {Version: "sing-box version 1.14.3", State: coreStateProbeFailed},
	} {
		if modern, raw := render(core); modern || raw != unknown {
			t.Errorf("%s: modern=%v, want the unknown-core config byte for byte", name, modern)
		}
	}
}
