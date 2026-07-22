package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/clash"
	"wayhop/internal/config"
	"wayhop/internal/core"
	"wayhop/internal/health"
	"wayhop/internal/model"
	"wayhop/internal/serverstore"
	"wayhop/internal/store"
	"wayhop/internal/traffic"
	"wayhop/web"
)

// backup_newServer builds a full *Server rooted in t.TempDir(), like
// routing_newServer, but returns the concrete *Server too so a test can seed the
// store / serverstore / config and assert on them after a restore. Offline +
// deterministic: Demo=true, a non-existent sing-box binary, a loopback Clash
// controller that is never dialed.
func backup_newServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	dir := t.TempDir()

	cfgPath := filepath.Join(dir, "config.json")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cfg.Demo = true
	cfg.SingBox.Bin = filepath.Join(dir, "sbin", "no-such-sing-box")
	cfg.SingBox.Config = filepath.Join(dir, "etc", "singbox.json")

	hub := traffic.NewHub(50)
	cl, err := clash.New(cfg.Clash.Controller, cfg.Clash.Secret)
	if err != nil {
		t.Fatalf("clash.New: %v", err)
	}
	sb := core.New(cfg.SingBox.Bin, cfg.SingBox.Config)
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

// sampleProfile is a small, Validate-clean profile: one enabled vless endpoint
// (a valid uuid) and a selector group over it.
func sampleProfile() model.Profile {
	return model.Profile{
		Endpoints: []model.Endpoint{{
			ID:       "ep1",
			Name:     "NL",
			Protocol: model.ProtoVLESS,
			Server:   "nl.example.com",
			Port:     443,
			Enabled:  true,
			Params:   map[string]any{"uuid": "11111111-2222-3333-4444-555555555555"},
		}},
		Groups: []model.Group{{
			ID:      "grp1",
			Name:    "Main",
			Type:    model.GroupSelector,
			Members: []string{"ep1"},
		}},
	}
}

func backup_get(t *testing.T, ts *httptest.Server, path string) (int, []byte, http.Header) {
	t.Helper()
	resp, err := ts.Client().Get(ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, resp.Header
}

func backup_post(t *testing.T, ts *httptest.Server, path string, body []byte) (int, []byte) {
	t.Helper()
	resp, err := ts.Client().Post(ts.URL+path, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func TestBackupExport(t *testing.T) {
	srv, h := backup_newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	if err := srv.store.Replace(sampleProfile()); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	if err := srv.servers.Upsert(serverstore.Server{ID: "s1", Name: "vps", Host: "1.2.3.4", Port: 22, User: "root"}); err != nil {
		t.Fatalf("seed server: %v", err)
	}
	if err := srv.restoreConfig("hybrid", true); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	code, body, hdr := backup_get(t, ts, "/api/backup")
	if code != http.StatusOK {
		t.Fatalf("GET /api/backup: got %d, want 200 (%s)", code, body)
	}
	if cd := hdr.Get("Content-Disposition"); !strings.Contains(cd, `filename="wayhop-backup.json"`) {
		t.Errorf("Content-Disposition = %q, want attachment filename", cd)
	}
	if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var b backupBundle
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatalf("invalid bundle JSON: %v (%s)", err, body)
	}
	if b.Schema != backupSchemaVersion {
		t.Errorf("wayhop_backup = %d, want %d", b.Schema, backupSchemaVersion)
	}
	if b.Version == "" {
		t.Errorf("version is empty, want the build version")
	}
	if len(b.Profile.Endpoints) != 1 || b.Profile.Endpoints[0].ID != "ep1" {
		t.Errorf("profile endpoints = %+v, want one ep1", b.Profile.Endpoints)
	}
	if len(b.Servers) != 1 || b.Servers[0].ID != "s1" {
		t.Errorf("servers = %+v, want one s1", b.Servers)
	}
	if b.RoutingMode != "hybrid" {
		t.Errorf("routing_mode = %q, want hybrid", b.RoutingMode)
	}
	if !b.Gateway {
		t.Errorf("gateway = false, want true")
	}
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	// Server A: seed + export.
	srvA, hA := backup_newServer(t)
	tsA := httptest.NewServer(hA)
	defer tsA.Close()
	if err := srvA.store.Replace(sampleProfile()); err != nil {
		t.Fatalf("seed A profile: %v", err)
	}
	if err := srvA.servers.Upsert(serverstore.Server{ID: "s1", Name: "vps", Host: "1.2.3.4", Port: 22, User: "root"}); err != nil {
		t.Fatalf("seed A server: %v", err)
	}
	if err := srvA.restoreConfig("fast", false); err != nil {
		t.Fatalf("seed A config: %v", err)
	}
	_, bundle, _ := backup_get(t, tsA, "/api/backup")

	// Server B starts empty; set an access-critical field BEFORE restore to prove
	// it is PRESERVED (not overwritten by the bundle).
	srvB, hB := backup_newServer(t)
	tsB := httptest.NewServer(hB)
	defer tsB.Close()
	const sentinelToken = "keep-me-token"
	const sentinelHost = "panel.lan"
	srvB.cfgMu.Lock()
	srvB.cfg.Subscription.Token = sentinelToken
	srvB.cfg.AllowedHosts = []string{sentinelHost}
	srvB.cfgMu.Unlock()

	// Send the request with Host == the allowed sentinel so hostAllowGuard (which is
	// active because we set AllowedHosts above to prove preservation) lets it through —
	// the client still dials tsB's loopback addr, only the Host header changes.
	req, _ := http.NewRequest(http.MethodPost, tsB.URL+"/api/backup/restore", bytes.NewReader(bundle))
	req.Host = sentinelHost
	req.Header.Set("Content-Type", "application/json")
	resp, err := tsB.Client().Do(req)
	if err != nil {
		t.Fatalf("POST restore: %v", err)
	}
	out, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST restore: got %d, want 200 (%s)", resp.StatusCode, out)
	}
	var summary struct {
		Restored  bool   `json:"restored"`
		Endpoints int    `json:"endpoints"`
		Groups    int    `json:"groups"`
		Servers   int    `json:"servers"`
		Note      string `json:"note"`
	}
	if err := json.Unmarshal(out, &summary); err != nil {
		t.Fatalf("invalid summary JSON: %v (%s)", err, out)
	}
	if !summary.Restored || summary.Endpoints != 1 || summary.Groups != 1 || summary.Servers != 1 {
		t.Errorf("summary = %+v, want restored 1/1/1", summary)
	}
	if summary.Note == "" {
		t.Errorf("summary note is empty, want a review-and-Apply hint")
	}

	// Profile restored on B.
	pB := srvB.store.Profile()
	if len(pB.Endpoints) != 1 || pB.Endpoints[0].ID != "ep1" {
		t.Errorf("B endpoints = %+v, want ep1", pB.Endpoints)
	}
	if len(pB.Groups) != 1 || pB.Groups[0].ID != "grp1" {
		t.Errorf("B groups = %+v, want grp1", pB.Groups)
	}
	// Server record restored on B.
	if _, ok := srvB.servers.Get("s1"); !ok {
		t.Errorf("server s1 not restored on B")
	}
	// routing_mode applied; access-critical config PRESERVED.
	cfgB := srvB.config()
	if cfgB.RoutingMode != "fast" {
		t.Errorf("B routing_mode = %q, want fast (from bundle)", cfgB.RoutingMode)
	}
	if cfgB.Subscription.Token != sentinelToken {
		t.Errorf("B subscription token = %q, want preserved %q", cfgB.Subscription.Token, sentinelToken)
	}
	if len(cfgB.AllowedHosts) != 1 || cfgB.AllowedHosts[0] != sentinelHost {
		t.Errorf("B allowed_hosts = %v, want preserved [%q]", cfgB.AllowedHosts, sentinelHost)
	}
}

func TestBackupRestoreRejectsWrongSchema(t *testing.T) {
	srv, h := backup_newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	if err := srv.store.Replace(sampleProfile()); err != nil {
		t.Fatalf("seed: %v", err)
	}

	bad, _ := json.Marshal(backupBundle{Schema: 99, Profile: sampleProfile()})
	code, out := backup_post(t, ts, "/api/backup/restore", bad)
	if code != http.StatusBadRequest {
		t.Fatalf("wrong-schema restore: got %d, want 400 (%s)", code, out)
	}
	// Profile unchanged (still the seeded one, not wiped).
	if p := srv.store.Profile(); len(p.Endpoints) != 1 {
		t.Errorf("profile changed by a rejected restore: %+v", p.Endpoints)
	}
}

func TestBackupRestoreRejectsInvalidProfile(t *testing.T) {
	srv, h := backup_newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	seed := sampleProfile()
	if err := srv.store.Replace(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// An ENABLED TUIC endpoint with a malformed uuid fails Validate (TUIC parses
	// the uuid strictly — see model.invalidProtoParam).
	bad := backupBundle{
		Schema: backupSchemaVersion,
		Profile: model.Profile{
			Endpoints: []model.Endpoint{{
				ID:       "bad",
				Name:     "broken",
				Protocol: model.ProtoTUIC,
				Server:   "x.example.com",
				Port:     443,
				Enabled:  true,
				Params:   map[string]any{"uuid": "not-a-valid-uuid", "password": "p"},
			}},
		},
	}
	body, _ := json.Marshal(bad)
	code, out := backup_post(t, ts, "/api/backup/restore", body)
	if code != http.StatusBadRequest {
		t.Fatalf("invalid-profile restore: got %d, want 400 (%s)", code, out)
	}
	// Profile unchanged.
	p := srv.store.Profile()
	if len(p.Endpoints) != 1 || p.Endpoints[0].ID != "ep1" {
		t.Errorf("profile changed by a rejected restore: %+v", p.Endpoints)
	}
}

// TestBackupRestoreRejectsBadRoutingMode: a bundle whose profile + servers are perfectly valid
// but whose routing_mode is out of enum must change NOTHING. Before the pre-commit config
// validation, this passed profile-validate + store.Replace + the server upserts and only THEN
// failed on restoreConfig — leaving the profile and server registry overwritten despite the 400.
func TestBackupRestoreRejectsBadRoutingMode(t *testing.T) {
	srv, h := backup_newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	// Seed a DISTINCT profile + server so a rejected restore is provably a no-op.
	seed := sampleProfile()
	seed.Endpoints[0].ID = "seeded"
	seed.Groups[0].Members = []string{"seeded"}
	if err := srv.store.Replace(seed); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	if err := srv.servers.Upsert(serverstore.Server{ID: "seeded-srv", Name: "old", Host: "9.9.9.9", Port: 22, User: "root"}); err != nil {
		t.Fatalf("seed server: %v", err)
	}

	bundle := backupBundle{
		Schema:      backupSchemaVersion,
		Profile:     sampleProfile(), // valid, carries ep1
		Servers:     []serverstore.Server{{ID: "s1", Name: "vps", Host: "1.2.3.4", Port: 22, User: "root"}},
		RoutingMode: "not-a-mode", // out of {"",tun,hybrid,fast,mixed} → config.Validate fails
	}
	body, _ := json.Marshal(bundle)
	code, out := backup_post(t, ts, "/api/backup/restore", body)
	if code != http.StatusBadRequest {
		t.Fatalf("bad-routing-mode restore: got %d, want 400 (%s)", code, out)
	}

	// Profile unchanged: still the seeded endpoint, NOT the bundle's ep1.
	if p := srv.store.Profile(); len(p.Endpoints) != 1 || p.Endpoints[0].ID != "seeded" {
		t.Errorf("profile was overwritten by a rejected restore: %+v", p.Endpoints)
	}
	// Server registry unchanged: seeded server intact, the bundle's NOT upserted.
	if _, ok := srv.servers.Get("seeded-srv"); !ok {
		t.Errorf("seeded server was lost by a rejected restore")
	}
	if _, ok := srv.servers.Get("s1"); ok {
		t.Errorf("bundle server s1 was upserted despite the restore being rejected")
	}
}
