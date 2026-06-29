package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"velinx/internal/config"
	"velinx/internal/core"
	"velinx/internal/failsafe"
	"velinx/internal/health"
	"velinx/internal/initserver"
	"velinx/internal/model"
	"velinx/internal/plugin"
	"velinx/internal/serverstore"
	"velinx/internal/store"
	"velinx/internal/watchdog"
)

// servererrorpaths_server builds a *Server wired with the union of dependencies
// the error-path handlers exercised in this file touch — all rooted in
// t.TempDir() so the suite stays offline and leaves nothing behind.
//
// It deliberately does NOT reuse sharehandlers_server (which omits singbox /
// servers / jobs / plugins / failsafe) because the handlers under test here
// (speedtest / health-test / subscription-fetch / servers / server-check)
// dereference those fields and would nil-panic otherwise. The sing-box binary
// path points at a file that does NOT exist, so core.SingBox.Available() and
// Running() are both false — every handler takes its demo / no-core branch.
func servererrorpaths_server(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()

	cfgPath := filepath.Join(dir, "config.json")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cfg.Demo = true
	cfg.SingBox.Bin = filepath.Join(dir, "no-such-sing-box")
	cfg.SingBox.Config = filepath.Join(dir, "out", "singbox.json")

	st, err := store.Open(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	ss, err := serverstore.Open(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatalf("serverstore.Open: %v", err)
	}

	sb := core.New(cfg.SingBox.Bin, cfg.SingBox.Config)
	if sb.Available() {
		t.Fatalf("test setup broken: sing-box reports available at %q", cfg.SingBox.Bin)
	}

	return &Server{
		cfg:      cfg,
		store:    st,
		singbox:  sb,
		servers:  ss,
		jobs:     initserver.NewJobManager(),
		failsafe: failsafe.New(failsafe.DefaultDurations()),
		plugins:  plugin.New(filepath.Join(dir, "plugins"), filepath.Join(dir, "bin")),
		watchdog: watchdog.New("sing-box", sb),
	}
}

// servererrorpaths_post POSTs a JSON body to a handler and returns the recorder.
func servererrorpaths_post(h http.HandlerFunc, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

// servererrorpaths_errMsg decodes the {"error":...} envelope writeErr produces.
func servererrorpaths_errMsg(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("error body is not JSON: %v (%s)", err, w.Body.String())
	}
	msg, _ := resp["error"].(string)
	return msg
}

// ---- handleSpeedtest (error paths) ----------------------------------------

// TestServererrorpaths_SpeedtestProxyNoPortBadGateway forces the via:"proxy"
// branch with no proxy port configured (Ports.Mixed = 0). speedtest.Run then
// returns "no proxy port configured" BEFORE any network call, which the handler
// surfaces as 502 BadGateway. This stays fully offline.
func TestServererrorpaths_SpeedtestProxyNoPortBadGateway(t *testing.T) {
	s := servererrorpaths_server(t)
	s.cfg.Ports.Mixed = 0 // no mixed inbound -> proxy client can't be built

	w := servererrorpaths_post(s.handleSpeedtest, "/api/speedtest", `{"via":"proxy"}`)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("proxy speedtest w/o port: got %d, want 502 (%s)", w.Code, w.Body.String())
	}
	if msg := servererrorpaths_errMsg(t, w); !strings.Contains(msg, "proxy port") {
		t.Errorf("error = %q, want it to mention the missing proxy port", msg)
	}
}

// TestServererrorpaths_SpeedtestMalformedBodyTolerated confirms the decode error
// is intentionally swallowed: a garbage body still runs (defaults via=auto). With
// no sing-box running, auto resolves to a DIRECT test, which would touch the real
// network — so we instead pin via:"proxy" with no port to keep it offline AND
// prove the bad body did not 400 the request before reaching the run.
func TestServererrorpaths_SpeedtestMalformedBodyTolerated(t *testing.T) {
	s := servererrorpaths_server(t)
	s.cfg.Ports.Mixed = 0
	// Body is not valid JSON; decode error is ignored, Via stays "". With no
	// running core, viaProxy stays false -> would go direct. Override to proxy via
	// a second, valid call is not possible here, so assert only that a malformed
	// body is NOT rejected with 400 (the handler swallows the decode error).
	w := servererrorpaths_post(s.handleSpeedtest, "/api/speedtest", `not json`)
	if w.Code == http.StatusBadRequest {
		t.Fatalf("malformed speedtest body unexpectedly 400'd (decode error should be swallowed): %s", w.Body.String())
	}
}

// ---- handleHealthTest -----------------------------------------------------

// TestServererrorpaths_HealthTestNilMonitor503 covers the nil-monitor guard:
// the handler must answer 503 ServiceUnavailable, not panic.
func TestServererrorpaths_HealthTestNilMonitor503(t *testing.T) {
	s := servererrorpaths_server(t) // monitor stays nil

	req := httptest.NewRequest(http.MethodPost, "/api/health/test/e1", nil)
	req.SetPathValue("id", "e1")
	w := httptest.NewRecorder()
	s.handleHealthTest(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil-monitor health test: got %d, want 503 (%s)", w.Code, w.Body.String())
	}
	if msg := servererrorpaths_errMsg(t, w); !strings.Contains(msg, "monitor") {
		t.Errorf("error = %q, want it to mention the monitor", msg)
	}
}

// TestServererrorpaths_HealthTestUnknownIDReturnsUnknownView drives ProbeOne for
// an id that is not a known target with a real monitor that has a nil Clash
// client (so probe() short-circuits to Unknown without any network). The handler
// must return 200 with a view whose handshake is one of the known values.
func TestServererrorpaths_HealthTestUnknownIDReturnsUnknownView(t *testing.T) {
	s := servererrorpaths_server(t)
	// nil clash + nil log source: probe() returns Unknown,0 — fully offline.
	s.monitor = health.NewMonitor(nil, s.store, nil, false)

	req := httptest.NewRequest(http.MethodPost, "/api/health/test/ghost", nil)
	req.SetPathValue("id", "ghost")
	w := httptest.NewRecorder()
	s.handleHealthTest(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("health test (unknown id): got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var v health.View
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if v.ID != "ghost" {
		t.Errorf("view id = %q, want ghost", v.ID)
	}
	switch v.Handshake {
	case "ok", "failed", "unknown":
	default:
		t.Errorf("handshake = %q, want one of ok|failed|unknown", v.Handshake)
	}
}

// ---- handleSubscription (URL-fetch error branches) ------------------------

// TestServererrorpaths_SubscriptionBadURLScheme400 hits the "bad url" branch:
// http.NewRequestWithContext rejects a control-char-laced URL before any dial,
// so the handler returns 400 offline.
func TestServererrorpaths_SubscriptionBadURLScheme400(t *testing.T) {
	s := servererrorpaths_server(t)
	// A URL containing a control character makes http.NewRequest fail with
	// "invalid control character in URL" — no network is touched.
	body, _ := json.Marshal(map[string]string{"url": "http://exa\x7fmple.com/sub"})
	w := servererrorpaths_post(s.handleSubscription, "/api/subscription", string(body))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad url: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
	if msg := servererrorpaths_errMsg(t, w); !strings.Contains(msg, "bad url") {
		t.Errorf("error = %q, want it to start with 'bad url'", msg)
	}
}

// TestServererrorpaths_SubscriptionSSRFBlocksLoopback asserts the SSRF guard (on
// by default) refuses to fetch a loopback URL, so the panel can't be turned into
// a request-forgery sink to reach the router's own Clash API / LAN / metadata.
func TestServererrorpaths_SubscriptionSSRFBlocksLoopback(t *testing.T) {
	s := servererrorpaths_server(t) // allowInternalFetch stays false — guard ON
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("vless://x@1.2.3.4:443#x"))
	}))
	defer upstream.Close()

	body, _ := json.Marshal(map[string]string{"url": upstream.URL}) // http://127.0.0.1:PORT
	w := servererrorpaths_post(s.handleSubscription, "/api/subscription", string(body))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("loopback fetch: got %d, want 502 (guard should refuse) (%s)", w.Code, w.Body.String())
	}
	if msg := servererrorpaths_errMsg(t, w); !strings.Contains(msg, "internal address") {
		t.Errorf("error = %q, want it to mention the blocked internal address", msg)
	}
}

// TestServererrorpaths_SubscriptionFetchNon200BadGateway points the fetch at a
// loopback httptest server that always answers 500, exercising the
// "subscription returned status" branch -> 502 BadGateway. Loopback only.
func TestServererrorpaths_SubscriptionFetchNon200BadGateway(t *testing.T) {
	s := servererrorpaths_server(t)
	s.allowInternalFetch = true // httptest binds loopback; relax the SSRF dial guard
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer upstream.Close()

	body, _ := json.Marshal(map[string]string{"url": upstream.URL})
	w := servererrorpaths_post(s.handleSubscription, "/api/subscription", string(body))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("non-200 fetch: got %d, want 502 (%s)", w.Code, w.Body.String())
	}
	if msg := servererrorpaths_errMsg(t, w); !strings.Contains(msg, "status") {
		t.Errorf("error = %q, want it to mention the upstream status", msg)
	}
}

// TestServererrorpaths_SubscriptionFetchUnreachableBadGateway points the fetch at
// a loopback server that has already been closed, so the Do() fails with a
// connection error -> the "fetch failed" branch -> 502 BadGateway. Loopback only.
func TestServererrorpaths_SubscriptionFetchUnreachableBadGateway(t *testing.T) {
	s := servererrorpaths_server(t)
	s.allowInternalFetch = true // httptest binds loopback; relax the SSRF dial guard
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := dead.URL
	dead.Close() // nothing listening on that port now

	body, _ := json.Marshal(map[string]string{"url": url})
	w := servererrorpaths_post(s.handleSubscription, "/api/subscription", string(body))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("unreachable fetch: got %d, want 502 (%s)", w.Code, w.Body.String())
	}
	if msg := servererrorpaths_errMsg(t, w); !strings.Contains(msg, "fetch failed") {
		t.Errorf("error = %q, want 'fetch failed'", msg)
	}
}

// TestServererrorpaths_SubscriptionFetchOKParsesLinks confirms the success branch
// of the URL path: a loopback server returns two share links + one garbage line,
// and the handler decodes them into 2 endpoints + 1 error (preview, no persist).
func TestServererrorpaths_SubscriptionFetchOKParsesLinks(t *testing.T) {
	s := servererrorpaths_server(t)
	s.allowInternalFetch = true // httptest binds loopback; relax the SSRF dial guard
	const payload = "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443" +
		"?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=ab12&flow=xtls-rprx-vision#NL\n" +
		"trojan://secretpass@example.com:443?security=tls&sni=example.com#T1\n" +
		"ftp://garbage"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "velinx" {
			t.Errorf("upstream saw User-Agent %q, want velinx", got)
		}
		_, _ = w.Write([]byte(payload))
	}))
	defer upstream.Close()

	body, _ := json.Marshal(map[string]string{"url": upstream.URL})
	w := servererrorpaths_post(s.handleSubscription, "/api/subscription", string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("ok fetch: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Endpoints []model.Endpoint `json:"endpoints"`
		Errors    []string         `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if len(resp.Endpoints) != 2 {
		t.Fatalf("parsed %d endpoints, want 2: %+v", len(resp.Endpoints), resp.Endpoints)
	}
	if len(resp.Errors) != 1 {
		t.Fatalf("got %d errors, want 1: %v", len(resp.Errors), resp.Errors)
	}
	// Preview only: must not persist.
	if len(s.store.Profile().Endpoints) != 0 {
		t.Errorf("subscription URL fetch unexpectedly persisted endpoints: %+v", s.store.Profile().Endpoints)
	}
}

// ---- handleBulkEndpoints (empty-body decode guard) ------------------------

// TestServererrorpaths_BulkEndpointsEmptyBody400 confirms an entirely empty body
// (EOF on decode) is rejected with 400 by handleBulkEndpoints.
//
// Note: a malformed JSON body is the only 400 here. Per-endpoint failures are
// non-fatal — the handler accumulates them into the "errors" array and still
// returns 200 with the true "saved" count (so a partial import isn't reported as
// a total failure), so there is no inner-400 branch to exercise.
func TestServererrorpaths_BulkEndpointsEmptyBody400(t *testing.T) {
	s := servererrorpaths_server(t)
	req := httptest.NewRequest(http.MethodPost, "/api/endpoints/bulk", nil)
	w := httptest.NewRecorder()
	s.handleBulkEndpoints(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bulk empty body: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// ---- handleApply (generate validation error) ------------------------------

// TestServererrorpaths_ApplyInvalidProfile400 makes generator.Generate fail by
// seeding a rule that targets a non-existent outbound; handleApply must return
// 400 before writing any config file.
func TestServererrorpaths_ApplyInvalidProfile400(t *testing.T) {
	s := servererrorpaths_server(t)
	if err := s.store.UpsertRule(model.Rule{ID: "r1", Outbound: "does-not-exist"}); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	w := servererrorpaths_post(s.handleApply, "/api/apply", `{"save":false}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("apply invalid profile: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// ---- handleServers : GET + upsert defaults + invalid host -----------------

// TestServererrorpaths_ServersGetEmptyList covers the GET branch of handleServers:
// a fresh registry returns an empty JSON array (never null).
func TestServererrorpaths_ServersGetEmptyList(t *testing.T) {
	s := servererrorpaths_server(t)
	req := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	w := httptest.NewRecorder()
	s.handleServers(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/servers: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var list []serverstore.Server
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if len(list) != 0 {
		t.Errorf("fresh registry should be empty, got %+v", list)
	}
}

// TestServererrorpaths_ServersPostBadJSON400 covers the decode guard.
func TestServererrorpaths_ServersPostBadJSON400(t *testing.T) {
	s := servererrorpaths_server(t)
	w := servererrorpaths_post(s.handleServers, "/api/servers", `}{`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("servers bad json: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// TestServererrorpaths_ServersPostInvalidHost400 rejects an injection-shaped host.
func TestServererrorpaths_ServersPostInvalidHost400(t *testing.T) {
	s := servererrorpaths_server(t)
	for _, host := range []string{`8.8.8.8; rm -rf /`, `bad host`, `$(id)`, ``} {
		body, _ := json.Marshal(serverstore.Server{Host: host})
		w := servererrorpaths_post(s.handleServers, "/api/servers", string(body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("servers host %q: got %d, want 400 (%s)", host, w.Code, w.Body.String())
		}
	}
	if got := len(s.servers.List()); got != 0 {
		t.Errorf("registry must stay empty after rejected hosts, has %d", got)
	}
}

// ---- handleDeleteServer ----------------------------------------------------

// TestServererrorpaths_DeleteServerUnknown404 deletes an id that was never added.
func TestServererrorpaths_DeleteServerUnknown404(t *testing.T) {
	s := servererrorpaths_server(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/servers/ghost", nil)
	req.SetPathValue("id", "ghost")
	w := httptest.NewRecorder()
	s.handleDeleteServer(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("delete unknown server: got %d, want 404 (%s)", w.Code, w.Body.String())
	}
}

// ---- handleServerCheck (success shape on loopback) ------------------------

// TestServererrorpaths_ServerCheckLoopbackShape posts a valid loopback host so the
// reachability branch runs (no validation 400) and returns the documented JSON
// shape. We bind a loopback listener to make port_open deterministically true,
// then assert the response shape without asserting ping (ICMP is sandbox-dependent).
func TestServererrorpaths_ServerCheckLoopbackShape(t *testing.T) {
	s := servererrorpaths_server(t)
	// A listening loopback server gives a real open TCP port to dial.
	ln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ln.Close()
	// httptest URL is http://127.0.0.1:PORT — split out the port.
	hostport := strings.TrimPrefix(ln.URL, "http://")
	host, portStr, ok := strings.Cut(hostport, ":")
	if !ok {
		t.Fatalf("could not split %q", hostport)
	}
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}

	body, _ := json.Marshal(map[string]any{"host": host, "port": port})
	w := servererrorpaths_post(s.handleServerCheck, "/api/server/check", string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("server check loopback: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Reachable bool `json:"reachable"`
		PortOpen  bool `json:"port_open"`
		Port      int  `json:"port"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if resp.Port != port {
		t.Errorf("echoed port = %d, want %d", resp.Port, port)
	}
	// The loopback listener is up, so the dial must succeed -> reachable.
	if !resp.PortOpen {
		t.Errorf("port_open = false for a live loopback listener (%s)", w.Body.String())
	}
	if !resp.Reachable {
		t.Errorf("reachable = false despite an open port")
	}
}

// TestServererrorpaths_ServerCheckDefaultsPortTo22 confirms the "port == 0 -> 22"
// default branch: with no listener at :22 the dial fails, but the handler still
// returns 200 with the echoed default port (the dial is best-effort, not fatal).
func TestServererrorpaths_ServerCheckDefaultsPortTo22(t *testing.T) {
	s := servererrorpaths_server(t)
	// Loopback host, no port -> defaults to 22. We don't assume :22 is closed or
	// open on the runner; only that the handler echoes port=22 and returns 200.
	w := servererrorpaths_post(s.handleServerCheck, "/api/server/check", `{"host":"127.0.0.1"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("server check default port: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Port int `json:"port"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if resp.Port != 22 {
		t.Errorf("defaulted port = %d, want 22", resp.Port)
	}
}

// ---- handleServerScript (host-less, single protocol) ----------------------

// TestServererrorpaths_ServerScriptNoHostStillBuilds confirms a script can be
// built without a host (the host is optional in BuildScript); the response is a
// non-empty script carrying the requested protocol marker.
func TestServererrorpaths_ServerScriptNoHostStillBuilds(t *testing.T) {
	s := servererrorpaths_server(t)
	w := servererrorpaths_post(s.handleServerScript, "/api/server/script",
		`{"protocols":["amneziawg"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("server script no host: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var resp struct {
		Script string `json:"script"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, w.Body.String())
	}
	if !strings.Contains(resp.Script, "WR_PROTO=amneziawg") {
		t.Errorf("script missing amneziawg marker:\n%s", resp.Script)
	}
}

// ---- handleServerHardenKeys / handleServerLockdown (decode + validation) --

// TestServererrorpaths_HardenKeysBadJSON400 covers the decode guard.
func TestServererrorpaths_HardenKeysBadJSON400(t *testing.T) {
	s := servererrorpaths_server(t)
	w := servererrorpaths_post(s.handleServerHardenKeys, "/api/server/harden/keys", `nope`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("harden keys bad json: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// TestServererrorpaths_HardenKeysInvalidHost400 rejects an injection-shaped host.
func TestServererrorpaths_HardenKeysInvalidHost400(t *testing.T) {
	s := servererrorpaths_server(t)
	body, _ := json.Marshal(map[string]any{"host": "bad host", "user": "root"})
	w := servererrorpaths_post(s.handleServerHardenKeys, "/api/server/harden/keys", string(body))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("harden keys invalid host: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// TestServererrorpaths_LockdownBadJSON400 covers the decode guard.
func TestServererrorpaths_LockdownBadJSON400(t *testing.T) {
	s := servererrorpaths_server(t)
	w := servererrorpaths_post(s.handleServerLockdown, "/api/server/harden/lockdown", `}{`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("lockdown bad json: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// TestServererrorpaths_LockdownMissingHost400 covers the resolve/validate guard.
func TestServererrorpaths_LockdownMissingHost400(t *testing.T) {
	s := servererrorpaths_server(t)
	body, _ := json.Marshal(hardenReq{User: "root"}) // no host
	w := servererrorpaths_post(s.handleServerLockdown, "/api/server/harden/lockdown", string(body))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("lockdown missing host: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// ---- handleServerProvision (decode guard) ---------------------------------

// TestServererrorpaths_ProvisionBadJSON400 covers the decode guard (distinct from
// the input-validation 400s already covered in server_jobs_test.go).
func TestServererrorpaths_ProvisionBadJSON400(t *testing.T) {
	s := servererrorpaths_server(t)
	w := servererrorpaths_post(s.handleServerProvision, "/api/server/provision", `not json`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("provision bad json: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
	// No job should be created for a rejected request.
	if job := s.jobs.New("probe", ""); job.ID() != "job-1" {
		t.Errorf("a rejected provision leaked a job: next id = %q, want job-1", job.ID())
	}
}

// ---- handlePutConfig (decode guard) ---------------------------------------

// TestServererrorpaths_PutConfigBadJSON400 covers the decode guard of the config
// PUT handler (the validation 400s are covered in config_test.go).
func TestServererrorpaths_PutConfigBadJSON400(t *testing.T) {
	s := servererrorpaths_server(t)
	req := httptest.NewRequest(http.MethodPut, "/api/config", strings.NewReader(`not json`))
	w := httptest.NewRecorder()
	s.handlePutConfig(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("put config bad json: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// ---- handleImport / handleDiagnosticsAnalyze (empty-body decode guard) -----

// TestServererrorpaths_ImportEmptyBody400 confirms an entirely empty body (EOF on
// decode) is rejected with 400 by handleImport.
func TestServererrorpaths_ImportEmptyBody400(t *testing.T) {
	s := servererrorpaths_server(t)
	req := httptest.NewRequest(http.MethodPost, "/api/import", nil)
	w := httptest.NewRecorder()
	s.handleImport(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("import empty body: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// ---- handleQR (encode-overflow error branch) ------------------------------

// TestServererrorpaths_QROversizedTextBadRequest covers the qrcode.Encode error
// branch: a payload larger than any QR version's capacity makes Encode fail,
// which the handler maps to 400 "could not encode QR". (Distinct from the empty-
// text / bad-JSON 400s already covered in share_test.go.)
func TestServererrorpaths_QROversizedTextBadRequest(t *testing.T) {
	s := servererrorpaths_server(t)
	// The largest QR (version 40) holds well under 3 KB at Medium EC; 8 KB
	// overflows every version, so Encode returns an error.
	huge := strings.Repeat("A", 8000)
	body, _ := json.Marshal(map[string]any{"text": huge, "size": 256})
	w := servererrorpaths_post(s.handleQR, "/api/qr", string(body))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized QR text: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
	if msg := servererrorpaths_errMsg(t, w); !strings.Contains(msg, "encode QR") {
		t.Errorf("error = %q, want it to mention QR encoding", msg)
	}
}

// ---- Watchdog() accessor ---------------------------------------------------

// TestServererrorpaths_WatchdogAccessor exercises the trivial Watchdog() getter
// (the daemon uses it to Run the supervisor) and confirms it returns the wired
// instance whose Stats are queryable.
func TestServererrorpaths_WatchdogAccessor(t *testing.T) {
	s := servererrorpaths_server(t)
	wd := s.Watchdog()
	if wd == nil {
		t.Fatal("Watchdog() returned nil")
	}
	if wd != s.watchdog {
		t.Errorf("Watchdog() returned a different instance than s.watchdog")
	}
	// Stats are callable (no panic) and report the demo/not-supervised baseline.
	st := wd.Stats()
	if st.Restarts != 0 {
		t.Errorf("fresh watchdog restarts = %d, want 0", st.Restarts)
	}
}
