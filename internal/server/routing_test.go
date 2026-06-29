package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"velinx/internal/clash"
	"velinx/internal/config"
	"velinx/internal/core"
	"velinx/internal/health"
	"velinx/internal/serverstore"
	"velinx/internal/store"
	"velinx/internal/traffic"
	"velinx/web"
)

// These tests live in package server, so the real exported constructor New and
// the real Server type are referenced directly (unqualified) — no self-import.

// routing_newServer builds a FULL *Server through the real server.New
// constructor, wiring every dependency the way cmd/velinx/main.go does but rooted in
// t.TempDir() so the suite stays entirely offline and leaves nothing behind.
//
// Key choices that keep it offline + deterministic:
//   - Demo = true, so handlers take the no-real-core path.
//   - cfg.SingBox.Bin points at a file that does NOT exist, so core.Available()
//     is false and nothing is ever spawned.
//   - cfg's unexported path is set via config.Load on a temp file (Default()
//     alone has no path, which would make Save() fail), matching the prompt.
//   - clash.Client points at a loopback controller that is never dialed by the
//     routes exercised here.
//
// It returns the constructed *Server and its mounted http.Handler.
func routing_newServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	dir := t.TempDir()

	// Start from Default() but give cfg a real backing path by loading a temp
	// file (Load writes the defaults out and records the path for Save()).
	cfgPath := filepath.Join(dir, "config.json")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cfg.Demo = true
	// Non-existent binary + a temp config target: Available() must be false.
	cfg.SingBox.Bin = filepath.Join(dir, "sbin", "no-such-sing-box")
	cfg.SingBox.Config = filepath.Join(dir, "etc", "singbox.json")

	hub := traffic.NewHub(50)

	cl, err := clash.New(cfg.Clash.Controller, cfg.Clash.Secret)
	if err != nil {
		t.Fatalf("clash.New: %v", err)
	}

	sb := core.New(cfg.SingBox.Bin, cfg.SingBox.Config)
	if sb.Available() {
		t.Fatalf("test setup broken: sing-box reports available at %q", cfg.SingBox.Bin)
	}

	st, err := store.Open(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	mon := health.NewMonitor(cl, st, sb, cfg.Demo)

	ss, err := serverstore.Open(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatalf("serverstore.Open: %v", err)
	}

	srv := New(cfg, hub, cl, sb, st, mon, ss, web.FS())
	return srv, srv.Handler()
}

// routing_do issues a request against an httptest.Server backed by the mounted
// handler and returns status, body and Content-Type. Using a real server (not
// just ResponseRecorder) exercises the full mux + logRequests wrapper + the
// embedded FileServer exactly as production does.
func routing_do(t *testing.T, ts *httptest.Server, method, path string) (int, string, string) {
	t.Helper()
	req, err := http.NewRequest(method, ts.URL+path, nil)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, path, err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body %s %s: %v", method, path, err)
	}
	return resp.StatusCode, string(body), resp.Header.Get("Content-Type")
}

func TestRouting_HealthOK(t *testing.T) {
	_, h := routing_newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	code, body, ct := routing_do(t, ts, http.MethodGet, "/api/health")
	if code != http.StatusOK {
		t.Fatalf("GET /api/health: got %d, want 200 (%s)", code, body)
	}
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var resp struct {
		Status  string `json:"status"`
		Version string `json:"version"`
		Demo    bool   `json:"demo"`
		SingBox struct {
			Available bool `json:"available"`
			Running   bool `json:"running"`
		} `json:"singbox"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, body)
	}
	if resp.Status != "ok" {
		t.Errorf("status = %q, want ok", resp.Status)
	}
	if !resp.Demo {
		t.Errorf("demo = false, want true (cfg.Demo set)")
	}
	// Non-existent binary -> not available, not running.
	if resp.SingBox.Available || resp.SingBox.Running {
		t.Errorf("singbox available=%v running=%v, want both false", resp.SingBox.Available, resp.SingBox.Running)
	}
}

func TestRouting_ProfileOK(t *testing.T) {
	_, h := routing_newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	code, body, ct := routing_do(t, ts, http.MethodGet, "/api/profile")
	if code != http.StatusOK {
		t.Fatalf("GET /api/profile: got %d, want 200 (%s)", code, body)
	}
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	// A fresh profile decodes as a JSON object (not null / not an array).
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		t.Fatalf("profile is not a JSON object: %v (%s)", err, body)
	}
}

func TestRouting_ServerOptionsOK(t *testing.T) {
	_, h := routing_newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	code, body, ct := routing_do(t, ts, http.MethodGet, "/api/server/options")
	if code != http.StatusOK {
		t.Fatalf("GET /api/server/options: got %d, want 200 (%s)", code, body)
	}
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	// The catalog is a non-empty JSON array of provisionable protocol options.
	var opts []map[string]any
	if err := json.Unmarshal([]byte(body), &opts); err != nil {
		t.Fatalf("options is not a JSON array: %v (%s)", err, body)
	}
	if len(opts) == 0 {
		t.Error("server options catalog is empty")
	}
}

func TestRouting_IndexServesEmbeddedUI(t *testing.T) {
	_, h := routing_newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	code, body, ct := routing_do(t, ts, http.MethodGet, "/")
	if code != http.StatusOK {
		t.Fatalf("GET /: got %d, want 200 (%s)", code, body)
	}
	// The embedded FileServer serves dist/index.html at the root with an HTML
	// content type.
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	// Content fingerprints from web/dist/index.html prove the embedded UI (not a
	// fallback / error page) was served.
	if !strings.Contains(body, "<!doctype html>") {
		t.Errorf("response is not the index doctype: %.120q", body)
	}
	if !strings.Contains(body, "Velinx") {
		t.Errorf("response does not contain the UI title: %.200q", body)
	}
	if !strings.Contains(body, `src="app.js"`) {
		t.Errorf("response does not reference app.js: %.200q", body)
	}
}

func TestRouting_IndexServesStaticAsset(t *testing.T) {
	_, h := routing_newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	// A named embedded asset is also served by the catch-all FileServer.
	code, body, ct := routing_do(t, ts, http.MethodGet, "/app.js")
	if code != http.StatusOK {
		t.Fatalf("GET /app.js: got %d, want 200 (%s)", code, body)
	}
	if !strings.Contains(ct, "javascript") {
		t.Errorf("Content-Type = %q, want a javascript type", ct)
	}
}

func TestRouting_UnknownAPIPath404(t *testing.T) {
	_, h := routing_newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	// /api/does-not-exist matches no API route. The catch-all FileServer at "/"
	// has no such embedded file, so it returns 404 (NOT the index).
	code, body, _ := routing_do(t, ts, http.MethodGet, "/api/does-not-exist")
	if code != http.StatusNotFound {
		t.Fatalf("GET /api/does-not-exist: got %d, want 404 (%s)", code, body)
	}
	// Must not have fallen through to serving the SPA index.
	if strings.Contains(body, "Velinx") {
		t.Errorf("unknown api path leaked the UI index: %.200q", body)
	}
}

// TestRouting_WrongMethodOnMethodScopedRoute documents the ACTUAL current
// behaviour of a wrong method on a method-scoped API route.
//
// /api/server/options is registered as "GET /api/server/options". Ordinarily Go
// 1.22's mux answers a method mismatch with 405. But this Handler also mounts a
// method-agnostic catch-all `mux.Handle("/", FileServer)`. Because that "/"
// pattern ALSO matches the request path, the mux has a matching handler for the
// POST and serves it (instead of reporting 405) — the FileServer then 404s
// because no such embedded file exists. So the observable result is 404, not 405.
func TestRouting_WrongMethodOnMethodScopedRoute(t *testing.T) {
	_, h := routing_newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/server/options", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// The catch-all "/" FileServer swallows the method mismatch and 404s.
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("POST /api/server/options: got %d, want 404 (catch-all fallthrough) (%s)",
			resp.StatusCode, string(body))
	}
	// It must NOT have served the SPA index in place of a 404.
	if strings.Contains(string(body), "Velinx") {
		t.Errorf("wrong-method request leaked the UI index: %.200q", string(body))
	}
}

// TestRouting_WrongMethodOnDeleteScopedRoute confirms the same fallthrough for a
// path-wildcard method route: /api/endpoints/{id} is registered only for DELETE.
// A GET on it does not 405; the catch-all "/" FileServer matches and 404s
// (there is no embedded file at that path).
func TestRouting_WrongMethodOnDeleteScopedRoute(t *testing.T) {
	_, h := routing_newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	code, body, _ := routing_do(t, ts, http.MethodGet, "/api/endpoints/some-id")
	if code != http.StatusNotFound {
		t.Fatalf("GET /api/endpoints/{id}: got %d, want 404 (catch-all fallthrough) (%s)", code, body)
	}
}
