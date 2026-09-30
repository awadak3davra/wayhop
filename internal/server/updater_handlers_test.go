package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/updater"
)

// updaterinstall_serverWithUpdater builds a *Server via the shared sharehandlers_server
// helper and wires in a real *updater.Updater rooted entirely in a temp BinDir with a
// fixed arch and direct (no-mirror) source. The updater handlers under test
// (handleUpdaterEngines / handleUpdaterVersions / handleUpdaterInstall) all dereference
// s.updater, which the shared helper leaves nil, so every test must set it.
//
// arch picks the wayhop arch token. BinDir is a fresh t.TempDir(); since no engine binary is
// ever written there (and none of the registry bin names exist on PATH in CI), Installed()
// reports Present=false for every engine — which keeps handleUpdaterEngines offline and
// deterministic.
func updaterinstall_serverWithUpdater(t *testing.T, arch string) *Server {
	t.Helper()
	s, _ := sharehandlers_server(t)
	// Direct source (mirrors nil -> New normalizes to {""}); BinDir is an empty temp dir.
	s.updater = updater.New(t.TempDir(), arch, nil)
	return s
}

// updaterinstall_get issues a GET to handler h.
func updaterinstall_get(h http.HandlerFunc) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/updater/engines", nil)
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

// updaterinstall_postWithID issues a POST to handler h with the path value "id" set and
// the given JSON body.
func updaterinstall_postWithID(h http.HandlerFunc, id, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/updater/"+id+"/install", strings.NewReader(body))
	req.SetPathValue("id", id)
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

// --- handleUpdaterEngines --------------------------------------------------

// TestUpdaterinstall_EnginesListsRegistry asserts the engines handler echoes the
// configured arch + mirrors and returns one item per registry Engine, each carrying its
// id/name/repo/bin_name and an "installed" object. With a fresh empty BinDir (and no
// engine binaries on PATH) every engine reports installed.present=false.
func TestUpdaterinstall_EnginesListsRegistry(t *testing.T) {
	// Hermetic: updater.Installed() falls back to PATH, so a host with real engine
	// binaries on PATH (xray/hysteria/olcrtc on the self-hosted CI runner) would
	// report them "installed" despite the empty BinDir. Empty PATH keeps it clean.
	t.Setenv("PATH", t.TempDir())
	s := updaterinstall_serverWithUpdater(t, "amd64")

	w := updaterinstall_get(s.handleUpdaterEngines)
	if w.Code != http.StatusOK {
		t.Fatalf("handleUpdaterEngines: got %d, want 200 (%s)", w.Code, w.Body.String())
	}

	var resp struct {
		Arch    string   `json:"arch"`
		Mirrors []string `json:"mirrors"`
		Engines []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Repo      string `json:"repo"`
			BinName   string `json:"bin_name"`
			Installed struct {
				Present bool   `json:"present"`
				Version string `json:"version"`
				Path    string `json:"path"`
			} `json:"installed"`
		} `json:"engines"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}

	if resp.Arch != "amd64" {
		t.Errorf("arch = %q, want amd64", resp.Arch)
	}
	// New() normalizes an empty mirror list to a single direct entry ("").
	if len(resp.Mirrors) != 1 || resp.Mirrors[0] != "" {
		t.Errorf("mirrors = %v, want [\"\"]", resp.Mirrors)
	}

	// One item per registry engine, ids preserved and unique.
	if len(resp.Engines) != len(updater.Engines) {
		t.Fatalf("engines len = %d, want %d (registry size)", len(resp.Engines), len(updater.Engines))
	}
	seen := map[string]bool{}
	for i, e := range resp.Engines {
		want := updater.Engines[i]
		if e.ID != want.ID || e.Name != want.Name || e.Repo != want.Repo || e.BinName != want.BinName {
			t.Errorf("engine[%d] = %+v, want id/name/repo/bin from %+v", i, e, want)
		}
		if e.ID == "" {
			t.Errorf("engine[%d] has empty id", i)
		}
		if seen[e.ID] {
			t.Errorf("duplicate engine id %q", e.ID)
		}
		seen[e.ID] = true
		// Nothing installed in a fresh temp BinDir.
		if e.Installed.Present {
			t.Errorf("engine %q reported installed.present=true in an empty BinDir (path=%q)", e.ID, e.Installed.Path)
		}
	}
	// Spot-check a couple of well-known engines are present.
	for _, id := range []string{"sing-box", "amneziawg-go"} {
		if !seen[id] {
			t.Errorf("expected engine %q in the list; ids=%v", id, seen)
		}
	}
}

// --- handleUpdaterVersions (input validation) ------------------------------

// TestUpdaterinstall_VersionsUnknownEngine404 asserts an id that is not in the registry
// is rejected with 404 before any network call.
func TestUpdaterinstall_VersionsUnknownEngine404(t *testing.T) {
	s := updaterinstall_serverWithUpdater(t, "amd64")
	req := httptest.NewRequest(http.MethodGet, "/api/updater/no-such-engine/versions", nil)
	req.SetPathValue("id", "no-such-engine")
	w := httptest.NewRecorder()
	s.handleUpdaterVersions(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown engine versions: got %d, want 404 (%s)", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if !strings.Contains(resp["error"], "unknown engine") {
		t.Errorf("error = %q, want it to mention unknown engine", resp["error"])
	}
}

// TestUpdaterinstall_VersionsEmptyID404 asserts a missing/empty path value is also unknown.
func TestUpdaterinstall_VersionsEmptyID404(t *testing.T) {
	s := updaterinstall_serverWithUpdater(t, "amd64")
	req := httptest.NewRequest(http.MethodGet, "/api/updater//versions", nil)
	// No SetPathValue -> r.PathValue("id") == "" -> EngineByID("") == nil.
	w := httptest.NewRecorder()
	s.handleUpdaterVersions(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("empty id versions: got %d, want 404 (%s)", w.Code, w.Body.String())
	}
}

// --- handleUpdaterInstall (input validation) -------------------------------

// TestUpdaterinstall_InstallUnknownEngine404 asserts an unknown engine id is rejected
// with 404 before the body is even consumed.
func TestUpdaterinstall_InstallUnknownEngine404(t *testing.T) {
	s := updaterinstall_serverWithUpdater(t, "amd64")
	w := updaterinstall_postWithID(s.handleUpdaterInstall, "no-such-engine", `{"version":"1.2.3"}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown engine install: got %d, want 404 (%s)", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if !strings.Contains(resp["error"], "unknown engine") {
		t.Errorf("error = %q, want it to mention unknown engine", resp["error"])
	}
}

// TestUpdaterinstall_InstallMissingVersion400 asserts that a known engine with an empty
// (or absent) version is rejected with 400 "version required" before any network call.
func TestUpdaterinstall_InstallMissingVersion400(t *testing.T) {
	s := updaterinstall_serverWithUpdater(t, "amd64")

	// Empty version field.
	w := updaterinstall_postWithID(s.handleUpdaterInstall, "sing-box", `{"version":""}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty version: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if !strings.Contains(resp["error"], "version required") {
		t.Errorf("error = %q, want it to mention version required", resp["error"])
	}

	// Absent version field (decode succeeds, Version stays "").
	w2 := updaterinstall_postWithID(s.handleUpdaterInstall, "sing-box", `{}`)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("missing version: got %d, want 400 (%s)", w2.Code, w2.Body.String())
	}

	// Garbage body: the decode error is intentionally ignored, so Version stays ""
	// and the handler still 400s on "version required" (not a JSON 400).
	w3 := updaterinstall_postWithID(s.handleUpdaterInstall, "sing-box", `not json`)
	if w3.Code != http.StatusBadRequest {
		t.Fatalf("garbage body: got %d, want 400 (%s)", w3.Code, w3.Body.String())
	}
	var resp3 map[string]string
	_ = json.Unmarshal(w3.Body.Bytes(), &resp3)
	if !strings.Contains(resp3["error"], "version required") {
		t.Errorf("garbage-body error = %q, want version required (decode error is swallowed)", resp3["error"])
	}
}

// withSourceOnlyEngine adds a source-only engine to the catalogue for one test. amneziawg-go was the
// catalogue's only such engine until WayHop began building it (it is now a companion of WayHop's own
// releases), and the handlers' source-only branch still has to answer for the next one.
func withSourceOnlyEngine(t *testing.T) string {
	t.Helper()
	saved := updater.Engines
	updater.Engines = append(append([]updater.Engine(nil), saved...), updater.Engine{
		ID: "src-only", Name: "Source-only engine", Repo: "example/src-only", BinName: "src-only",
		Role: "standalone", SourceOnly: true, Note: "No prebuilt releases; build from source on-device.",
	})
	t.Cleanup(func() { updater.Engines = saved })
	return "src-only"
}

// TestUpdaterinstall_InstallSourceOnlyEngineIsNotAGatewayFailure drives Install on a SourceOnly
// engine. Install() short-circuits with a "no prebuilt releases" error BEFORE any network access.
//
// This asserted 502 BadGateway, and the status was in the test's own name. It changed deliberately:
// 502 says an upstream failed, and no upstream was ever contacted — the answer is a permanent
// property of the engine, known before the request. Worse, the 502 branch persists the message as
// the engine's last_error, so the operator's Updater page carried "Install failed:" for a build that
// was never going to be downloaded, with no action that could clear it. 422 says what is true: the
// request cannot be satisfied for this engine, and nothing is wrong with the router or the network.
func TestUpdaterinstall_InstallSourceOnlyEngineIsNotAGatewayFailure(t *testing.T) {
	s := updaterinstall_serverWithUpdater(t, "amd64")
	id := withSourceOnlyEngine(t)

	w := updaterinstall_postWithID(s.handleUpdaterInstall, id, `{"version":"v0.2.13"}`)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("source-only install: got %d, want 422 (%s)", w.Code, w.Body.String())
	}
	// And it must NOT be filed as an install failure: nothing failed, and nothing could clear it.
	if got := s.updErr(id); got != "" {
		t.Errorf("the refusal was persisted as last_error (%q) — the row would show a permanent "+
			"'Install failed' the operator cannot clear", got)
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if !strings.Contains(resp["error"], "no prebuilt releases") {
		t.Errorf("error = %q, want it to mention no prebuilt releases", resp["error"])
	}
	// The error must name the engine id (the Install error format is "<id> has no...").
	if !strings.Contains(resp["error"], id) {
		t.Errorf("error = %q, want it to name the engine id", resp["error"])
	}
}

// TestUpdaterinstall_VersionsSourceOnlyShapeWithoutNetwork documents that for a SourceOnly
// engine the Versions handler ALWAYS returns 200 with source_only=true and the engine's
// note + installed version, even when the upstream tag lookup fails (it folds the failure
// into an "error" field rather than a non-200). We force the lookup to fail offline by
// pointing the updater at an unreachable mirror, so the test never touches the real
// network yet still exercises the source_only branch end to end.
func TestUpdaterinstall_VersionsSourceOnlyShapeWithoutNetwork(t *testing.T) {
	s, _ := sharehandlers_server(t)
	id := withSourceOnlyEngine(t)
	// Unreachable mirror -> Tags() fails fast; the handler still returns 200.
	s.updater = updater.New(t.TempDir(), "amd64", []string{"http://127.0.0.1:0"})

	req := httptest.NewRequest(http.MethodGet, "/api/updater/"+id+"/versions", nil)
	req.SetPathValue("id", id)
	w := httptest.NewRecorder()
	s.handleUpdaterVersions(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("source-only versions: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if so, _ := resp["source_only"].(bool); !so {
		t.Errorf("source_only = %v, want true", resp["source_only"])
	}
	// The engine's note is echoed.
	note, _ := resp["note"].(string)
	if !strings.Contains(note, "build from source") {
		t.Errorf("note = %q, want the engine's source note", note)
	}
	// The failed lookup is reported via an "error" field (not a non-200), and no
	// versions/latest were produced.
	if _, ok := resp["error"]; !ok {
		t.Errorf("expected an \"error\" field when the tag lookup fails offline; got %v", resp)
	}
	if _, ok := resp["versions"]; ok {
		t.Errorf("did not expect \"versions\" when the lookup failed; got %v", resp["versions"])
	}
}

// A Nightly engine (olcRTC) publishes only prerelease nightlies: "latest" is the newest nightly TAG
// (picker + install target), and the handler ALSO surfaces "latest_version" = the build DATE parsed
// from the newest release NAME, so the UI can compare it to the installed binary's stamped date.
func TestUpdaterinstall_VersionsNightlySurfacesLatestDate(t *testing.T) {
	s, _ := sharehandlers_server(t)
	// Mock mirror: any path returns a dated nightly prerelease list (newest first), as olcRTC publishes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[
			{"tag_name":"nightly-2f2db04","name":"olcRTC nightly 2026.07.23 (2f2db04)","prerelease":true},
			{"tag_name":"nightly-6fa08e7","name":"olcRTC nightly 2026.07.22 (6fa08e7)","prerelease":true}
		]`))
	}))
	defer srv.Close()
	s.updater = updater.New(t.TempDir(), "amd64", []string{srv.URL})

	req := httptest.NewRequest(http.MethodGet, "/api/updater/olcrtc/versions", nil)
	req.SetPathValue("id", "olcrtc")
	w := httptest.NewRecorder()
	s.handleUpdaterVersions(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("olcrtc versions: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if got, _ := resp["latest"].(string); got != "nightly-2f2db04" {
		t.Errorf("latest = %q, want the newest nightly tag nightly-2f2db04", got)
	}
	if got, _ := resp["latest_version"].(string); got != "2026.07.23" {
		t.Errorf("latest_version = %q, want 2026.07.23 (date parsed from the newest release name)", got)
	}
}
