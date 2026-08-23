package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// A backup is most often carried BETWEEN routers, which is where a mode this host cannot run
// arrives: hybrid from a box with a kernel plane, restored onto one without. The restore used to
// adopt whatever the bundle named.

func gateRestoreServer(t *testing.T, hybrid platform.CapState) (*Server, *httptest.Server) {
	t.Helper()
	srv, h := backup_newServer(t)
	// The bundled fixture is a demo instance, where the gate deliberately stands aside. This case is
	// about a real one, so say so — otherwise the test would pass without the gate ever running.
	srv.cfgMu.Lock()
	srv.cfg.Demo = false
	srv.cfgMu.Unlock()
	srv.caps.mu.Lock()
	srv.caps.set = platform.CapabilitySet{
		Items: map[string]platform.Capability{
			platform.CapRoutingModeMixed: {ID: platform.CapRoutingModeMixed, State: platform.CapSupported},
			platform.CapRoutingModeHybrid: {ID: platform.CapRoutingModeHybrid, State: hybrid,
				Detail: "this firmware has no nftables"},
		},
		ProbedAt: time.Now(),
	}
	srv.caps.mu.Unlock()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return srv, ts
}

func gateRestoreBundle(mode string) []byte {
	b, _ := json.Marshal(backupBundle{
		Schema:      backupSchemaVersion,
		RoutingMode: mode,
		Profile: model.Profile{Endpoints: []model.Endpoint{{
			ID: "ep-restored", Name: "restored", Engine: model.EngineSingBox,
			Protocol: model.ProtoTrojan, Server: "198.51.100.70", Port: 443,
			Enabled: true, Params: map[string]any{"password": "x"},
		}}},
	})
	return b
}

func TestGateRestoreMode_AModeThisHostCannotRunIsDeclinedWithoutLosingTheRestore(t *testing.T) {
	srv, ts := gateRestoreServer(t, platform.CapUnsupportedFirmware)
	before := srv.config().RoutingMode

	code, out := backup_post(t, ts, "/api/backup/restore", gateRestoreBundle("hybrid"))
	if code != http.StatusOK {
		t.Fatalf("got %d, want 200 — refusing the whole restore would take the operator's exits with it (%s)", code, out)
	}
	var resp struct {
		Endpoints int    `json:"endpoints"`
		Declined  string `json:"routing_mode_declined"`
		Note      string `json:"routing_mode_note"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("response: %v", err)
	}
	if resp.Endpoints != 1 {
		t.Errorf("endpoints = %d, want the bundle restored", resp.Endpoints)
	}
	if now := srv.config().RoutingMode; now != before {
		t.Errorf("the mode was adopted anyway: %q -> %q", before, now)
	}
	if resp.Declined != "hybrid" || resp.Note == "" {
		t.Errorf("the answer does not say which mode was declined or why: %+v", resp)
	}
	var restored bool
	for _, e := range srv.store.Profile().Endpoints {
		if e.ID == "ep-restored" {
			restored = true
		}
	}
	if !restored {
		t.Error("the profile was not restored")
	}
}

// A mode this host CAN run is carried over exactly as before.
func TestGateRestoreMode_ARunnableModeIsStillAdopted(t *testing.T) {
	srv, ts := gateRestoreServer(t, platform.CapSupported)

	code, out := backup_post(t, ts, "/api/backup/restore", gateRestoreBundle("hybrid"))
	if code != http.StatusOK {
		t.Fatalf("got %d, want 200 (%s)", code, out)
	}
	if now := srv.config().RoutingMode; now != "hybrid" {
		t.Errorf("RoutingMode = %q, want hybrid — the gate declined a mode this host runs", now)
	}
	if got := string(out); len(got) > 0 && jsonHasKey(got, "routing_mode_declined") {
		t.Errorf("the answer reports a decline that did not happen: %s", got)
	}
}

func jsonHasKey(body, key string) bool {
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return false
	}
	_, ok := m[key]
	return ok
}
