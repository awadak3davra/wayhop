package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// applystate_server builds an isolated *Server whose apply-state.json lives in the temp config
// dir (next to config.json, as StartApply arranges on a router).
func applystate_server(t *testing.T) *Server {
	t.Helper()
	s, cfgPath := sharehandlers_server(t)
	s.cfg.DataDir = filepath.Dir(cfgPath)
	s.cfg.SingBox.Config = filepath.Join(filepath.Dir(cfgPath), "singbox.json")
	s.applyStateDir = filepath.Dir(cfgPath)
	return s
}

// applystate_demoMaterialization is a materialization whose every plane is a demo no-op.
func applystate_demoMaterialization() executionMaterializationV1 {
	return executionMaterializationV1{
		SchemaVersion: ExecutionSnapshotSchemaV1, Backend: executionBackendGeneric,
		Core:         executionCoreArtifactV1{Action: ExecutionDemoNoop},
		Kernel:       executionKernelArtifactV1{Action: ExecutionDemoNoop},
		PluginAction: ExecutionDemoNoop, Plugins: []executionPluginSpecV1{},
	}
}

// applystate_apply records the CURRENT saved state as applied (save=true → committed, false → live),
// the way a successful Apply does.
func applystate_apply(t *testing.T, s *Server, save bool) *appliedRevision {
	t.Helper()
	desired, err := s.captureDesiredSnapshot()
	if err != nil {
		t.Fatalf("desired: %v", err)
	}
	rev := &appliedRevision{
		Rev: desired.DesiredRev, At: 1,
		Desired:         &appliedDesired{Profile: desired.Profile, Config: desired.Config},
		Materialization: applystate_demoMaterialization(),
	}
	s.recordApplied(save, rev)
	return rev
}

// applystate_stateBody drives GET /api/state and returns the decoded body.
func applystate_stateBody(t *testing.T, s *Server) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	rec := httptest.NewRecorder()
	s.handleState(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/state: status %d (%s)", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode /api/state: %v (%s)", err, rec.Body.String())
	}
	return m
}

func TestApplyState_SaveLoadRoundTrip(t *testing.T) {
	s := applystate_server(t)
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v1", "NL")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	live := applystate_apply(t, s, false)
	s.setAcks([]string{"kernel_plane.fallback"}, true)
	if got := s.appliedBaseline(); got == nil || got.Rev != live.Rev {
		t.Fatalf("baseline = %+v, want the live revision", got)
	}

	// A fresh Server over the same directory reads the same record back.
	again := &Server{cfg: s.cfg, store: s.store, applyStateDir: s.applyStateDir}
	rec, saveErr := again.applyStateSnapshot()
	if saveErr != "" {
		t.Fatalf("save error after a healthy write: %q", saveErr)
	}
	if rec.Schema != applyStateSchema || rec.Live == nil || rec.Live.Rev != live.Rev || rec.Committed != nil {
		t.Fatalf("reloaded record = %+v", rec)
	}
	if !again.isAcked("kernel_plane.fallback") {
		t.Error("acknowledgements must survive a reload")
	}
	if rec.Live.Desired == nil || len(rec.Live.Desired.Profile.Endpoints) != 1 {
		t.Errorf("the desired snapshot must round-trip: %+v", rec.Live.Desired)
	}
	info, err := os.Stat(filepath.Join(s.applyStateDir, applyStateFileName))
	if err != nil {
		t.Fatalf("record not written: %v", err)
	}
	if info.Size() == 0 {
		t.Error("empty record written")
	}
}

func TestApplyState_CommitAndRollbackTransitions(t *testing.T) {
	s := applystate_server(t)
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v1", "NL")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	committed := applystate_apply(t, s, true)
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v2", "DE")); err != nil {
		t.Fatalf("edit: %v", err)
	}
	live := applystate_apply(t, s, false)
	if b := s.appliedBaseline(); b.Rev != live.Rev {
		t.Fatalf("baseline while a window is open = %s, want live %s", b.Rev, live.Rev)
	}
	if c := s.committedRevision(); c.Rev != committed.Rev {
		t.Fatalf("committed moved during a Test: %s", c.Rev)
	}
	// Rollback drops live; committed stays.
	s.recordRollback()
	if s.liveRevision() != nil || s.appliedBaseline().Rev != committed.Rev {
		t.Fatal("rollback must drop the live revision and expose committed again")
	}
	// Test again, then Keep: live becomes committed.
	live = applystate_apply(t, s, false)
	s.recordCommit()
	if s.liveRevision() != nil || s.committedRevision().Rev != live.Rev {
		t.Fatal("commit must promote live to committed")
	}
	// A saving Apply closes any open window.
	applystate_apply(t, s, false)
	saved := applystate_apply(t, s, true)
	if s.liveRevision() != nil || s.committedRevision().Rev != saved.Rev {
		t.Fatal("a saving Apply must replace committed and close the window")
	}
}

func TestApplyState_CorruptRecordIsToleratedAndInFlightDiscardedOnBoot(t *testing.T) {
	s := applystate_server(t)
	path := filepath.Join(s.applyStateDir, applyStateFileName)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b := s.appliedBaseline(); b != nil {
		t.Fatalf("a corrupt record must read as empty, got %+v", b)
	}
	// Apply still works over a corrupt record.
	rev := applystate_apply(t, s, true)
	if s.committedRevision() == nil || s.committedRevision().Rev != rev.Rev {
		t.Fatal("recording after a corrupt record failed")
	}

	// A crash mid-Apply leaves in_flight + maybe a live state; the next boot discards both.
	s.setInFlight(false, "abc")
	applystate_apply(t, s, false)
	again := &Server{cfg: s.cfg, store: s.store, applyStateDir: s.applyStateDir}
	if !again.discardLiveOnBoot() {
		t.Fatal("boot must report the discarded live/in-flight state")
	}
	rec, _ := again.applyStateSnapshot()
	if rec.Live != nil || rec.InFlight != nil || rec.Committed == nil || rec.Committed.Rev != rev.Rev {
		t.Fatalf("after boot: %+v", rec)
	}
	third := &Server{cfg: s.cfg, store: s.store, applyStateDir: s.applyStateDir}
	if third.discardLiveOnBoot() {
		t.Fatal("a second boot has nothing to discard")
	}
}

func TestApplyState_Acks(t *testing.T) {
	s := applystate_server(t)
	s.setAcks([]string{"a", "b", ""}, true)
	if !s.isAcked("a") || !s.isAcked("b") || s.isAcked("") {
		t.Fatalf("acks = %v", s.ackedIDs())
	}
	s.setAcks([]string{"a"}, false)
	if s.isAcked("a") || !s.isAcked("b") {
		t.Fatalf("unack: %v", s.ackedIDs())
	}
	if got := s.ackedIDs(); len(got) != 1 || got[0] != "b" {
		t.Fatalf("ackedIDs = %v", got)
	}
}

// TestApplyState_MigratesPreviousLedger fabricates the previous stack's apply-ledger-v1 directory
// (checkpoint + manifest + blob envelope) and checks its committed materialization is imported.
func TestApplyState_MigratesPreviousLedger(t *testing.T) {
	s := applystate_server(t)
	root := filepath.Join(s.applyStateDir, "apply-ledger-v1")
	if err := os.MkdirAll(filepath.Join(root, "manifests"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "blobs"), 0o755); err != nil {
		t.Fatal(err)
	}
	desiredRev := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	manifestRev := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	blobRev := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	// The previous stack's materialization shape carried fields this record no longer has; they
	// must be ignored, not rejected.
	payload := []byte(`{"schema_version":1,"backend":"generic",
		"inputs":{"desired_rev":"` + desiredRev + `","host_rev":"h","capability_rev":"c","kernel_plan_rev":"k"},
		"core":{"action":"ensure_present","binary_path":"/opt/bin/sing-box","config_path":"/opt/etc/wayhop/singbox.json","host_identity":{"configured_path":"/opt/bin/sing-box","present":true,"runnable":true,"state":"ready"},"config":"eyJsb2ciOnt9fQ=="},
		"kernel":{"action":"ensure_absent","nft_tool":{},"ip_tool":{},"plan":null,"nft":"","ip":[],"offload":"","teardown":[],"retire":[]},
		"plugin_action":"ensure_absent","plugins":[],"retire_plugins":[],"external_bindings":[],
		"awg_plugin":{"state":"","ip_tool":{},"awg_tool":{}},"awg_interfaces":[]}`)
	envelope, _ := json.Marshal(map[string]any{"schema_version": 1, "media_type": "application/json", "payload": payload})
	if err := os.WriteFile(filepath.Join(root, "blobs", blobRev+".json"), envelope, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := []byte(`{"schema_version":1,"descriptor":{"schema_version":1,"desired_rev":"` + desiredRev + `","backend":"generic"},"execution_blob_rev":"` + blobRev + `"}`)
	if err := os.WriteFile(filepath.Join(root, "manifests", manifestRev+".json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	checkpoint := []byte(`{"schema_version":1,"initialized":true,"current":{"state":"known","manifest_rev":"` + manifestRev + `"},"committed":{"state":"known","manifest_rev":"` + manifestRev + `"},"window_baseline":{"state":"none"}}`)
	if err := os.WriteFile(filepath.Join(root, "checkpoint.json"), checkpoint, 0o600); err != nil {
		t.Fatal(err)
	}
	// The pre-ledger applied snapshot supplies the review baseline for the imported state.
	prof := model.Profile{Endpoints: []model.Endpoint{profilehandlers_endpoint("v1", "NL")}}
	snap, _ := json.Marshal(legacyAppliedSnapshot{Hash: "legacy", Config: *config.Default(), Profile: prof})
	if err := os.WriteFile(s.legacyAppliedSnapshotPath(), snap, 0o600); err != nil {
		t.Fatal(err)
	}

	committed := s.committedRevision()
	if committed == nil {
		t.Fatal("the previous ledger's committed state was not imported")
	}
	if committed.Rev != desiredRev {
		t.Errorf("rev = %s, want the manifest's desired_rev", committed.Rev)
	}
	if !committed.Materialization.known() || committed.Materialization.Core.Action != ExecutionEnsurePresent ||
		string(committed.Materialization.Core.Config) != `{"log":{}}` {
		t.Errorf("materialization not decoded: %+v", committed.Materialization.Core)
	}
	if committed.Desired == nil || len(committed.Desired.Profile.Endpoints) != 1 {
		t.Errorf("the legacy applied snapshot must supply the diff baseline: %+v", committed.Desired)
	}
	if s.liveRevision() != nil {
		t.Error("an import never creates a live window")
	}
	// The import is persisted as the new record.
	if _, err := os.Stat(filepath.Join(s.applyStateDir, applyStateFileName)); err != nil {
		t.Errorf("imported record not persisted: %v", err)
	}
}

// TestApplyState_MigratesLegacySnapshotAlone: without a ledger, the pre-ledger snapshot becomes a
// diff-only baseline whose materialization is unknown (nothing to converge or roll back to).
func TestApplyState_MigratesLegacySnapshotAlone(t *testing.T) {
	s := applystate_server(t)
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v1", "NL")); err != nil {
		t.Fatal(err)
	}
	// The pre-ledger stack persisted the exact saved inputs it applied.
	snap, _ := json.Marshal(legacyAppliedSnapshot{Hash: "legacy", Config: s.config(), Profile: s.store.Profile()})
	if err := os.WriteFile(s.legacyAppliedSnapshotPath(), snap, 0o600); err != nil {
		t.Fatal(err)
	}
	committed := s.committedRevision()
	if committed == nil || committed.Desired == nil {
		t.Fatalf("legacy snapshot not imported: %+v", committed)
	}
	if committed.Materialization.known() {
		t.Error("a pre-ledger baseline cannot know what it installed")
	}
	// The imported rev is in the current desired-rev scheme, so an unchanged saved config reads
	// as not pending.
	desired, err := s.captureDesiredSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if view := s.pendingView(desired); view.Pending {
		t.Errorf("unchanged saved config after import must not be pending: %+v", view)
	}
}

// TestApplyState_HandleStateJSON pins the /api/state contract the Apply banner consumes.
func TestApplyState_HandleStateJSON(t *testing.T) {
	s := applystate_server(t)

	// Nothing configured, nothing applied: not pending, nothing_configured.
	m := applystate_stateBody(t, s)
	if m["pending"] != false || m["nothing_configured"] != true {
		t.Errorf("empty install: pending=%v nothing_configured=%v, want false/true", m["pending"], m["nothing_configured"])
	}
	for _, key := range []string{"saved_hash", "applied_hash", "applied_at", "pending", "nothing_configured", "lifecycle", "effective", "effective_reason", "window_open"} {
		if _, ok := m[key]; !ok {
			t.Errorf("/api/state lacks %q", key)
		}
	}
	if m["effective"] != effectiveUnknown {
		t.Errorf("nothing applied must be effective=unknown, got %v", m["effective"])
	}

	// Configure something: pending, applied_hash empty.
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v1", "NL")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	m = applystate_stateBody(t, s)
	if m["pending"] != true || m["nothing_configured"] != false {
		t.Errorf("configured, unapplied: pending=%v nothing_configured=%v", m["pending"], m["nothing_configured"])
	}
	if m["applied_hash"] != "" {
		t.Errorf("applied_hash should be empty when nothing is on record, got %v", m["applied_hash"])
	}

	// Apply (Test) → not pending, window open, hashes equal.
	applystate_apply(t, s, false)
	m = applystate_stateBody(t, s)
	if m["pending"] != false || m["window_open"] != true || m["saved_hash"] != m["applied_hash"] {
		t.Errorf("after a Test apply: %v", m)
	}

	// Edit → pending true, hashes differ.
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v2", "DE")); err != nil {
		t.Fatalf("edit: %v", err)
	}
	m = applystate_stateBody(t, s)
	if m["pending"] != true || m["saved_hash"] == m["applied_hash"] {
		t.Errorf("after edit: %v", m)
	}

	// A config-only edit must ALSO flip pending (all apply-relevant inputs are in the rev).
	applystate_apply(t, s, true)
	s.cfg.Offload = "hw"
	m = applystate_stateBody(t, s)
	if m["pending"] != true {
		t.Errorf("after a config-only edit pending = %v, want true", m["pending"])
	}
	// A rev that never touches the applied inputs must not: CIDRRefreshed churn is not a change.
	s.cfg.Offload = ""
	applystate_apply(t, s, true)
	m = applystate_stateBody(t, s)
	if m["pending"] != false {
		t.Errorf("re-applied: pending = %v", m["pending"])
	}
}

// TestApplyState_SurfacesPersistError: after a successful Apply the record is written best-effort.
// When that write FAILS the datapath is applied and must NOT be rolled back, but /api/state carries
// state_persistence_error so the UI can show a recovery action instead of an unqualified success.
func TestApplyState_SurfacesPersistError(t *testing.T) {
	s := applystate_server(t)
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v1", "NL")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	applystate_apply(t, s, true)
	if _, ok := applystate_stateBody(t, s)["state_persistence_error"]; ok {
		t.Fatal("/api/state carried a persistence error on a healthy Apply")
	}
	// A record path whose PARENT is a regular file makes the atomic write fail.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.applyState.mu.Lock()
	s.applyState.path = filepath.Join(blocker, "sub", applyStateFileName)
	s.applyState.mu.Unlock()
	applystate_apply(t, s, true)
	if body := applystate_stateBody(t, s); body["state_persistence_error"] == nil {
		t.Fatalf("/api/state does not surface the persistence failure: %v", body)
	}
	// Recovery: once the path is writable again the next record write clears the error.
	s.applyState.mu.Lock()
	s.applyState.path = filepath.Join(s.applyStateDir, applyStateFileName)
	s.applyState.mu.Unlock()
	applystate_apply(t, s, true)
	if _, ok := applystate_stateBody(t, s)["state_persistence_error"]; ok {
		t.Fatal("/api/state still carries a persistence error after a clean write")
	}
}

func TestDesiredProfileRequestsNoDatapathCoversEveryProfileField(t *testing.T) {
	if !desiredProfileRequestsNoDatapath(model.Profile{}) {
		t.Fatal("a zero profile asks for a datapath")
	}
	// A clean install carries no baseline, so anything that reports a datapath here turns into "You
	// have unapplied changes" over a config nobody has touched. Each field is checked on its own: a
	// predicate that missed one would under-report a real pending change.
	cases := map[string]model.Profile{
		"endpoint":     {Endpoints: []model.Endpoint{{ID: "e1"}}},
		"group":        {Groups: []model.Group{{ID: "g1"}}},
		"rule":         {Rules: []model.Rule{{}}},
		"routing list": {RoutingLists: []model.RoutingList{{ID: "l1"}}},
		"device group": {DeviceGroups: []model.DeviceGroup{{ID: "d1"}}},
		"dns plane":    {DNS: &model.DNSSettings{}},
	}
	for name, profile := range cases {
		if desiredProfileRequestsNoDatapath(profile) {
			t.Fatalf("a profile carrying one %s reported no datapath", name)
		}
	}
}
