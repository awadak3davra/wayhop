package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"velinx/internal/config"
	"velinx/internal/initserver"
	"velinx/internal/plugin"
	"velinx/internal/serverstore"
	"velinx/internal/store"
)

// serverjobs_newServer builds a fully-wired DEMO *Server for exercising the
// server-jobs HTTP layer end to end: a Demo config, a profile store, a server
// registry, a job manager, and a plugin manager — every field the
// servers/options/provision/harden/plugins handlers touch. Everything is backed
// by t.TempDir() so nothing leaks between tests.
//
// It does NOT reuse sharehandlers_server (which omits servers/jobs/plugins) on
// purpose: the job handlers would nil-panic without those. The name is prefixed
// to avoid clashing with the other server-package test files.
func serverjobs_newServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	ss, err := serverstore.Open(filepath.Join(dir, "servers.json"))
	if err != nil {
		t.Fatalf("serverstore.Open: %v", err)
	}
	return &Server{
		cfg:     &config.Config{Demo: true},
		store:   st,
		servers: ss,
		jobs:    initserver.NewJobManager(),
		plugins: plugin.New(filepath.Join(dir, "plugins"), filepath.Join(dir, "bin")),
	}
}

// serverjobs_do runs a single request straight through the given handler with a
// fresh recorder and returns the recorder. Path wildcards (e.g. {id}) must be set
// by the caller via req.SetPathValue before this is called, matching how Go 1.22
// routing would populate them.
func serverjobs_do(t *testing.T, h http.HandlerFunc, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

// serverjobs_jsonReq builds a POST request whose body is the JSON encoding of v.
func serverjobs_jsonReq(t *testing.T, method, target string, v any) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(v); err != nil {
		t.Fatalf("encode body: %v", err)
	}
	return httptest.NewRequest(method, target, &buf)
}

// serverjobs_decode unmarshals a recorder body into v, failing on bad JSON.
func serverjobs_decode(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("invalid JSON (%d): %v\nbody: %s", w.Code, err, w.Body.String())
	}
}

// serverjobs_pollJob polls GET /api/server/job/{id} through handleServerJob until
// the snapshot reports done, returning the final decoded view. It mirrors what the
// UI does. Fails (rather than hangs) if the job never finishes.
func serverjobs_pollJob(t *testing.T, s *Server, id string) initserver.JobView {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		req := httptest.NewRequest(http.MethodGet, "/api/server/job/"+id, nil)
		req.SetPathValue("id", id)
		w := serverjobs_do(t, s.handleServerJob, req)
		if w.Code != http.StatusOK {
			t.Fatalf("handleServerJob(%s): got %d, want 200 (%s)", id, w.Code, w.Body.String())
		}
		var v initserver.JobView
		serverjobs_decode(t, w, &v)
		if v.Done {
			return v
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("job %s never reported done via the HTTP poller", id)
	return initserver.JobView{}
}

// ---- /api/servers : list / upsert / delete ----

// TestServerjobs_PostServerAddsAndDefaults posts a bare server (only host set) and
// asserts the handler fills in the port/user/id/name defaults, persists it, and
// that a follow-up GET lists exactly that record.
func TestServerjobs_PostServerAddsAndDefaults(t *testing.T) {
	s := serverjobs_newServer(t)

	req := serverjobs_jsonReq(t, http.MethodPost, "/api/servers",
		serverstore.Server{Host: "203.0.113.10"})
	w := serverjobs_do(t, s.handleServers, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/servers: got %d, want 200 (%s)", w.Code, w.Body.String())
	}

	var created serverstore.Server
	serverjobs_decode(t, w, &created)
	if created.Port != 22 {
		t.Errorf("default port = %d, want 22", created.Port)
	}
	if created.User != "root" {
		t.Errorf("default user = %q, want root", created.User)
	}
	if want := "srv-203-0-113-10"; created.ID != want {
		t.Errorf("default id = %q, want %q", created.ID, want)
	}
	if created.Name != "203.0.113.10" {
		t.Errorf("default name = %q, want host", created.Name)
	}

	// GET lists exactly the one record we just added.
	greq := httptest.NewRequest(http.MethodGet, "/api/servers", nil)
	gw := serverjobs_do(t, s.handleServers, greq)
	if gw.Code != http.StatusOK {
		t.Fatalf("GET /api/servers: got %d, want 200", gw.Code)
	}
	var list []serverstore.Server
	serverjobs_decode(t, gw, &list)
	if len(list) != 1 {
		t.Fatalf("server list len = %d, want 1: %+v", len(list), list)
	}
	if list[0].ID != created.ID || list[0].Host != "203.0.113.10" {
		t.Errorf("listed server = %+v, want the one we added", list[0])
	}
}

// TestServerjobs_PostServerInvalidHost rejects a host that fails ValidTarget with
// a 400 and adds nothing to the registry.
func TestServerjobs_PostServerInvalidHost(t *testing.T) {
	s := serverjobs_newServer(t)

	// A space is not allowed by the validTarget regex.
	req := serverjobs_jsonReq(t, http.MethodPost, "/api/servers",
		serverstore.Server{Host: "bad host"})
	w := serverjobs_do(t, s.handleServers, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid host: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
	if got := len(s.servers.List()); got != 0 {
		t.Errorf("registry should stay empty after a rejected host, has %d", got)
	}
}

// TestServerjobs_PostServerMalformedJSON returns 400 on a body that is not JSON.
func TestServerjobs_PostServerMalformedJSON(t *testing.T) {
	s := serverjobs_newServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/servers", strings.NewReader("not json"))
	w := serverjobs_do(t, s.handleServers, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// TestServerjobs_DeleteServer removes an existing server (200) and reports 404 for
// an id that was never there.
func TestServerjobs_DeleteServer(t *testing.T) {
	s := serverjobs_newServer(t)
	if err := s.servers.Upsert(serverstore.Server{
		ID: "srv-del", Name: "doomed", Host: "198.51.100.5", Port: 22, User: "root",
	}); err != nil {
		t.Fatal(err)
	}

	// Delete the real one.
	dreq := httptest.NewRequest(http.MethodDelete, "/api/servers/srv-del", nil)
	dreq.SetPathValue("id", "srv-del")
	dw := serverjobs_do(t, s.handleDeleteServer, dreq)
	if dw.Code != http.StatusOK {
		t.Fatalf("DELETE existing: got %d, want 200 (%s)", dw.Code, dw.Body.String())
	}
	var resp map[string]any
	serverjobs_decode(t, dw, &resp)
	if resp["deleted"] != "srv-del" {
		t.Errorf("deleted echo = %v, want srv-del", resp["deleted"])
	}
	if _, ok := s.servers.Get("srv-del"); ok {
		t.Error("server still present after delete")
	}

	// Deleting again (now absent) is a 404.
	dreq2 := httptest.NewRequest(http.MethodDelete, "/api/servers/srv-del", nil)
	dreq2.SetPathValue("id", "srv-del")
	dw2 := serverjobs_do(t, s.handleDeleteServer, dreq2)
	if dw2.Code != http.StatusNotFound {
		t.Errorf("DELETE missing: got %d, want 404 (%s)", dw2.Code, dw2.Body.String())
	}
}

// ---- /api/server/options : the provisionable catalog ----

// TestServerjobs_OptionsCatalog returns the catalog with both shipped protocols,
// their human names, ports, and transports, and marks them recommended.
func TestServerjobs_OptionsCatalog(t *testing.T) {
	s := serverjobs_newServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/server/options", nil)
	w := serverjobs_do(t, s.handleServerOptions, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/server/options: got %d, want 200 (%s)", w.Code, w.Body.String())
	}

	var opts []struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Summary     string   `json:"summary"`
		Details     []string `json:"details"`
		Port        int      `json:"port"`
		Transport   string   `json:"transport"`
		Recommended bool     `json:"recommended"`
	}
	serverjobs_decode(t, w, &opts)
	// AmneziaWG + VLESS-Reality + sing-box (VMess/Trojan/Shadowsocks/Hysteria2/TUIC) +
	// plain WireGuard. Asserted by ID below, so adding a protocol won't break this on the
	// raw count alone — only a regression that drops one will.
	if len(opts) < 8 {
		t.Fatalf("catalog len = %d, want >=8: %+v", len(opts), opts)
	}

	byID := map[string]struct {
		name, transport string
		port            int
		recommended     bool
		details         int
	}{}
	for _, o := range opts {
		byID[o.ID] = struct {
			name, transport string
			port            int
			recommended     bool
			details         int
		}{o.Name, o.Transport, o.Port, o.Recommended, len(o.Details)}
	}

	for _, id := range []string{
		initserver.ProtoVMess, initserver.ProtoTrojan, initserver.ProtoShadowsocks,
		initserver.ProtoHysteria2, initserver.ProtoTUIC, initserver.ProtoWireGuard,
	} {
		if _, present := byID[id]; !present {
			t.Errorf("catalog missing protocol %q", id)
		}
	}

	awg, ok := byID[initserver.ProtoAmneziaWG]
	if !ok {
		t.Fatalf("catalog missing %q", initserver.ProtoAmneziaWG)
	}
	if awg.name != "AmneziaWG" || awg.port != 51820 || awg.transport != "udp" {
		t.Errorf("amneziawg option = %+v, want AmneziaWG/51820/udp", awg)
	}
	if !awg.recommended || awg.details == 0 {
		t.Errorf("amneziawg option should be recommended with details: %+v", awg)
	}

	vless, ok := byID[initserver.ProtoReality]
	if !ok {
		t.Fatalf("catalog missing %q", initserver.ProtoReality)
	}
	if vless.name != "VLESS-Reality" || vless.port != 443 || vless.transport != "tcp" {
		t.Errorf("vless option = %+v, want VLESS-Reality/443/tcp", vless)
	}
	if !vless.recommended || vless.details == 0 {
		t.Errorf("vless option should be recommended with details: %+v", vless)
	}
}

// ---- /api/server/provision -> poll /api/server/job/{id} ----

// TestServerjobs_ProvisionFlowAddsEndpoints drives the real HTTP provisioning
// path: POST /api/server/provision returns a job_id immediately, then the UI polls
// GET /api/server/job/{id} until done. On completion both demo client configs must
// be parsed and added to Connections with correctly-labelled names, the job result
// must echo the request, and the saved-server record must exist.
func TestServerjobs_ProvisionFlowAddsEndpoints(t *testing.T) {
	s := serverjobs_newServer(t)

	body := provisionReq{
		Name:      "edge",
		Host:      "203.0.113.7",
		Port:      22,
		User:      "root",
		Protocols: []string{initserver.ProtoAmneziaWG, initserver.ProtoReality},
	}
	req := serverjobs_jsonReq(t, http.MethodPost, "/api/server/provision", body)
	w := serverjobs_do(t, s.handleServerProvision, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST provision: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var start struct {
		JobID string `json:"job_id"`
	}
	serverjobs_decode(t, w, &start)
	if start.JobID == "" {
		t.Fatal("provision did not return a job_id")
	}

	v := serverjobs_pollJob(t, s, start.JobID)
	if !v.OK {
		t.Fatalf("provision job finished not-ok: %+v", v)
	}
	if v.Kind != "provision" {
		t.Errorf("job kind = %q, want provision", v.Kind)
	}

	// Two endpoints landed, one per protocol, with the host-derived server and the
	// "<name> · <label>" naming convention.
	eps := s.store.Profile().Endpoints
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints in store, got %d: %+v", len(eps), eps)
	}
	names := map[string]bool{}
	for _, ep := range eps {
		names[ep.Name] = true
		if ep.Server != "203.0.113.7" {
			t.Errorf("endpoint %q server = %q, want 203.0.113.7", ep.Name, ep.Server)
		}
	}
	if !names["edge · AmneziaWG"] {
		t.Errorf("missing AmneziaWG-labelled endpoint; have %v", names)
	}
	if !names["edge · VLESS-Reality"] {
		t.Errorf("missing VLESS-Reality-labelled endpoint; have %v", names)
	}

	// Job result echoes the request.
	if v.Result == nil {
		t.Fatal("finished provision job has no result")
	}
	if got, _ := v.Result["server_id"].(string); got != "srv-203-0-113-7" {
		t.Errorf("result server_id = %q, want srv-203-0-113-7", got)
	}
	added, _ := v.Result["added_endpoints"].([]any)
	if len(added) != 2 {
		t.Errorf("result added_endpoints = %v, want 2 ids", v.Result["added_endpoints"])
	}

	// The saved server was recorded for redundancy.
	sv, ok := s.servers.Get("srv-203-0-113-7")
	if !ok {
		t.Fatalf("provisioned server not saved to registry")
	}
	if sv.Host != "203.0.113.7" || sv.User != "root" {
		t.Errorf("saved server addressing wrong: %+v", sv)
	}
	if len(sv.Installed) != 2 {
		t.Errorf("saved installed = %v, want both protocols", sv.Installed)
	}
	if sv.LastJob != start.JobID {
		t.Errorf("saved last_job = %q, want %q", sv.LastJob, start.JobID)
	}

	// Console has at least one create-client step per protocol label.
	wantSteps := []string{"Create client: AmneziaWG", "Create client: VLESS-Reality"}
	have := map[string]bool{}
	for _, st := range v.Steps {
		have[st.Name] = true
	}
	for _, want := range wantSteps {
		if !have[want] {
			t.Errorf("missing console step %q; steps=%v", want, serverjobs_stepNames(v.Steps))
		}
	}
}

// TestServerjobs_ProvisionUsesSavedServerAddressing verifies that posting only a
// server_id (no host) resolves the host/port/user from the saved record before
// running. The endpoints created must carry that resolved host.
func TestServerjobs_ProvisionUsesSavedServerAddressing(t *testing.T) {
	s := serverjobs_newServer(t)
	const id = "srv-saved"
	if err := s.servers.Upsert(serverstore.Server{
		ID: id, Name: "saved-box", Host: "192.0.2.200", Port: 2222, User: "admin",
	}); err != nil {
		t.Fatal(err)
	}

	body := provisionReq{
		ServerID:  id,
		Protocols: []string{initserver.ProtoReality},
		// No Host/User/Port: must come from the saved record.
	}
	req := serverjobs_jsonReq(t, http.MethodPost, "/api/server/provision", body)
	w := serverjobs_do(t, s.handleServerProvision, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST provision (saved): got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var start struct {
		JobID string `json:"job_id"`
	}
	serverjobs_decode(t, w, &start)

	v := serverjobs_pollJob(t, s, start.JobID)
	if !v.OK {
		t.Fatalf("provision job (saved) finished not-ok: %+v", v)
	}
	eps := s.store.Profile().Endpoints
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}
	if eps[0].Server != "192.0.2.200" {
		t.Errorf("endpoint server = %q, want the saved host 192.0.2.200", eps[0].Server)
	}
	// Name falls back to the saved server name since the request omitted Name.
	if eps[0].Name != "saved-box · VLESS-Reality" {
		t.Errorf("endpoint name = %q, want 'saved-box · VLESS-Reality'", eps[0].Name)
	}
}

// TestServerjobs_ProvisionRejectsBadInput covers the synchronous 400 guards of the
// provision handler: missing host/user, no protocols, and an unknown option id.
func TestServerjobs_ProvisionRejectsBadInput(t *testing.T) {
	s := serverjobs_newServer(t)

	cases := []struct {
		name string
		body provisionReq
	}{
		{"missing host", provisionReq{User: "root", Protocols: []string{initserver.ProtoReality}}},
		{"missing user", provisionReq{Host: "203.0.113.7", Protocols: []string{initserver.ProtoReality}}},
		// A leading-hyphen user is SSH argument injection (CWE-88 → RCE): it must be rejected
		// up front, exactly as the other SSH handlers reject it via resolveHardenTarget.
		{"argument-injection user", provisionReq{Host: "203.0.113.7", User: "-oProxyCommand=touch /tmp/pwned", Protocols: []string{initserver.ProtoReality}}},
		{"no protocols", provisionReq{Host: "203.0.113.7", User: "root"}},
		{"unknown option", provisionReq{Host: "203.0.113.7", User: "root", Protocols: []string{"wireguard-classic"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := serverjobs_jsonReq(t, http.MethodPost, "/api/server/provision", c.body)
			w := serverjobs_do(t, s.handleServerProvision, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400 (%s)", w.Code, w.Body.String())
			}
		})
	}
	// No job should have been created for any rejected request: the next New() is
	// the first job id.
	job := s.jobs.New("probe", "")
	if job.ID() != "job-1" {
		t.Errorf("a rejected provision leaked a job: next id = %q, want job-1", job.ID())
	}
}

// TestServerjobs_JobNotFound returns 404 for an unknown job id.
func TestServerjobs_JobNotFound(t *testing.T) {
	s := serverjobs_newServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/server/job/job-999", nil)
	req.SetPathValue("id", "job-999")
	w := serverjobs_do(t, s.handleServerJob, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown job: got %d, want 404 (%s)", w.Code, w.Body.String())
	}
}

// ---- /api/server/harden/keys ----

// TestServerjobs_HardenKeysFlow drives the harden-keys HTTP path: POST returns a
// job_id, polling the job to completion yields a result carrying a PEM private key,
// a public key, and a host-derived download filename.
func TestServerjobs_HardenKeysFlow(t *testing.T) {
	s := serverjobs_newServer(t)

	body := hardenReq{Host: "192.0.2.40", Port: 22, User: "root"}
	req := serverjobs_jsonReq(t, http.MethodPost, "/api/server/harden/keys", body)
	w := serverjobs_do(t, s.handleServerHardenKeys, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST harden/keys: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var start struct {
		JobID string `json:"job_id"`
	}
	serverjobs_decode(t, w, &start)
	if start.JobID == "" {
		t.Fatal("harden/keys did not return a job_id")
	}

	v := serverjobs_pollJob(t, s, start.JobID)
	if !v.OK {
		t.Fatalf("harden-keys job finished not-ok: %+v", v)
	}
	if v.Kind != "harden-keys" {
		t.Errorf("job kind = %q, want harden-keys", v.Kind)
	}
	if v.Result == nil {
		t.Fatal("harden-keys result is nil")
	}
	priv, _ := v.Result["private_key"].(string)
	if !strings.Contains(priv, "PRIVATE KEY") {
		t.Errorf("result private_key does not look like a PEM key: %q", priv)
	}
	if _, ok := v.Result["public_key"].(string); !ok {
		t.Error("harden-keys result missing public_key")
	}
	if fn, _ := v.Result["filename"].(string); fn != "velinx-192-0-2-40-ed25519" {
		t.Errorf("filename = %q, want velinx-192-0-2-40-ed25519", fn)
	}
}

// TestServerjobs_HardenKeysRejectsBadInput: missing host/user is a synchronous 400.
func TestServerjobs_HardenKeysRejectsBadInput(t *testing.T) {
	s := serverjobs_newServer(t)
	req := serverjobs_jsonReq(t, http.MethodPost, "/api/server/harden/keys",
		hardenReq{User: "root"}) // no host
	w := serverjobs_do(t, s.handleServerHardenKeys, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("harden/keys missing host: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// ---- /api/server/harden/lockdown ----

// TestServerjobs_LockdownFlow drives the lockdown HTTP path against a saved server
// and asserts the job finishes ok, the result carries hardened=true, and the saved
// server record gets its hardened flag + last_job set. In demo mode no key is
// required (the b.Key guard only applies to non-demo).
func TestServerjobs_LockdownFlow(t *testing.T) {
	s := serverjobs_newServer(t)
	const id = "srv-lock"
	if err := s.servers.Upsert(serverstore.Server{
		ID: id, Name: "lockbox", Host: "192.0.2.77", Port: 22, User: "root",
	}); err != nil {
		t.Fatal(err)
	}

	body := hardenReq{ServerID: id, Host: "192.0.2.77", Port: 22, User: "root"}
	req := serverjobs_jsonReq(t, http.MethodPost, "/api/server/harden/lockdown", body)
	w := serverjobs_do(t, s.handleServerLockdown, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST harden/lockdown: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	var start struct {
		JobID string `json:"job_id"`
	}
	serverjobs_decode(t, w, &start)
	if start.JobID == "" {
		t.Fatal("harden/lockdown did not return a job_id")
	}

	v := serverjobs_pollJob(t, s, start.JobID)
	if !v.OK {
		t.Fatalf("lockdown job finished not-ok: %+v", v)
	}
	if v.Kind != "lockdown" {
		t.Errorf("job kind = %q, want lockdown", v.Kind)
	}
	if hardened, _ := v.Result["hardened"].(bool); !hardened {
		t.Errorf("lockdown result hardened = %v, want true", v.Result["hardened"])
	}

	sv, ok := s.servers.Get(id)
	if !ok {
		t.Fatalf("server %q missing after lockdown", id)
	}
	if !sv.Hardened {
		t.Error("saved server hardened flag not set")
	}
	if sv.LastJob != start.JobID {
		t.Errorf("saved last_job = %q, want %q", sv.LastJob, start.JobID)
	}
}

// TestServerjobs_LockdownRejectsBadInput: missing host/user is a synchronous 400.
// (The Key-required guard does NOT apply in demo mode, so that branch is not
// exercised here — see the source: `if b.Key == "" && !s.cfg.Demo`.)
func TestServerjobs_LockdownRejectsBadInput(t *testing.T) {
	s := serverjobs_newServer(t)
	req := serverjobs_jsonReq(t, http.MethodPost, "/api/server/harden/lockdown",
		hardenReq{Port: 22}) // no host, no user
	w := serverjobs_do(t, s.handleServerLockdown, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("lockdown missing host: got %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// ---- /api/plugins ----

// TestServerjobs_PluginsEmptyByDefault: a freshly-built plugin manager has no
// running plugins, so the handler returns an empty JSON array (never null).
func TestServerjobs_PluginsEmptyByDefault(t *testing.T) {
	s := serverjobs_newServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/plugins", nil)
	w := serverjobs_do(t, s.handlePlugins, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/plugins: got %d, want 200 (%s)", w.Code, w.Body.String())
	}
	// Status() returns make([]Status, 0, ...) so the body is "[]", not "null".
	if got := strings.TrimSpace(w.Body.String()); got != "[]" {
		t.Errorf("plugins body = %q, want []", got)
	}
	var statuses []plugin.Status
	serverjobs_decode(t, w, &statuses)
	if len(statuses) != 0 {
		t.Errorf("expected 0 plugin statuses, got %d: %+v", len(statuses), statuses)
	}
}

// serverjobs_stepNames extracts step names for diagnostics in failure messages.
func serverjobs_stepNames(steps []initserver.Step) []string {
	out := make([]string, 0, len(steps))
	for _, st := range steps {
		out = append(out, st.Name)
	}
	sort.Strings(out)
	return out
}
