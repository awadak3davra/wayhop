package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/config"
)

// cfgFileServer builds a *Server whose config is backed by a fresh file (so
// Save() works) seeded with defaults.
func cfgFileServer(t *testing.T) *Server {
	t.Helper()
	cfg, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	return &Server{cfg: cfg}
}

func getRec(t *testing.T, h http.HandlerFunc, url string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	w := httptest.NewRecorder()
	h(w, req)
	return w
}

// TestApplyConfigFields_CopiesEveryExportedField is the guard against the
// silently-dropped-field class (gateway, then offload): every exported config
// field except Subscription must be copied by applyConfigFields.
func TestApplyConfigFields_CopiesEveryExportedField(t *testing.T) {
	in := &config.Config{
		Listen: ":9999", DataDir: "/x", Demo: true, Gateway: true,
		GatewayMTU: 1280, GatewayAddr: "172.19.0.1/30", RoutingMode: "fast",
		Offload: "sw", OffloadDevices: []string{"wan", "br-lan"},
		Ports:        config.Ports{UI: 1, Clash: 2, DNS: 3, Mixed: 4},
		Clash:        config.Clash{Controller: "127.0.0.1:9090", Secret: "s"},
		SingBox:      config.SingBox{Bin: "/b", Config: "/c"},
		Updater:      config.Updater{Arch: "arm64", Mirrors: []string{"m"}, SelfRepo: "o/r", AutoUpdate: true},
		FailSafe:     config.FailSafe{Target: "8.8.8.8", AutoReboot: true},
		Watchdog:     config.Watchdog{NotifyURL: "https://x"},
		Subscription: config.Subscription{Token: "tok"},
		AllowedHosts: []string{"router.lan"},
		Features:     map[string]config.FeatureConfig{"iptv": {Enabled: true}},
		Backup:       config.Backup{AutoHours: 6, KeepN: 5, Dir: "/bk"},
	}
	dst := &config.Config{}
	applyConfigFields(dst, in)

	vIn, vDst := reflect.ValueOf(*in), reflect.ValueOf(*dst)
	tp := vIn.Type()
	for i := 0; i < tp.NumField(); i++ {
		f := tp.Field(i)
		if !f.IsExported() {
			continue
		}
		gotIn := vIn.Field(i).Interface()
		gotDst := vDst.Field(i).Interface()
		if f.Name == "Subscription" {
			if !reflect.DeepEqual(gotDst, config.Subscription{}) {
				t.Errorf("Subscription must NOT be copied (token protection), got %+v", gotDst)
			}
			continue
		}
		if f.Name == "Features" {
			// Features must NOT be copied by the bulk PUT — toggled via /api/features/{id}.
			if dst.Features != nil {
				t.Errorf("Features must NOT be copied (per-plugin toggles via /api/features), got %+v", dst.Features)
			}
			continue
		}
		if !reflect.DeepEqual(gotIn, gotDst) {
			t.Errorf("applyConfigFields did not copy field %s: in=%v dst=%v", f.Name, gotIn, gotDst)
		}
	}
}

func TestRestartNeeded(t *testing.T) {
	base := *config.Default()
	cases := []struct {
		name string
		mut  func(*config.Config)
		want bool
	}{
		{"no change", func(*config.Config) {}, false},
		{"listen", func(c *config.Config) { c.Listen = ":9000" }, true},
		{"ui port", func(c *config.Config) { c.Ports.UI = 9001 }, true},
		{"singbox bin", func(c *config.Config) { c.SingBox.Bin = "/x" }, true},
		{"clash secret", func(c *config.Config) { c.Clash.Secret = "x" }, true},
		{"demo", func(c *config.Config) { c.Demo = !c.Demo }, true},
		{"failsafe target (hot)", func(c *config.Config) { c.FailSafe.Target = "9.9.9.9" }, false},
		{"watchdog url (hot)", func(c *config.Config) { c.Watchdog.NotifyURL = "https://x" }, false},
		{"routing mode (apply)", func(c *config.Config) { c.RoutingMode = "fast" }, false},
		{"allowed hosts (hot)", func(c *config.Config) { c.AllowedHosts = []string{"x"} }, false},
		{"updater mirrors (hot)", func(c *config.Config) { c.Updater.Mirrors = []string{"x"} }, false},
	}
	for _, tc := range cases {
		nw := base
		tc.mut(&nw)
		if got := restartNeeded(base, nw); got != tc.want {
			t.Errorf("%s: restartNeeded=%v want %v", tc.name, got, tc.want)
		}
	}
}

// TestPutConfig_PersistsOffload covers the confirmed bug: the old handler dropped
// Offload/OffloadDevices, so fast-mode flow-offload was unsettable via the API.
func TestPutConfig_PersistsOffload(t *testing.T) {
	s := cfgFileServer(t)
	cfg := s.config()
	cfg.RoutingMode = "fast"
	cfg.Offload = "sw"
	cfg.OffloadDevices = []string{"wan", "br-lan"}
	body, _ := json.Marshal(cfg)
	if w := putConfig(t, s, string(body)); w.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", w.Code, w.Body.String())
	}
	got := s.config()
	if got.Offload != "sw" || len(got.OffloadDevices) != 2 {
		t.Fatalf("offload not persisted: offload=%q devices=%v", got.Offload, got.OffloadDevices)
	}
}

// TestPutConfig_SubscriptionTokenImmutable: the bulk Settings PUT must never
// change the subscription token (it has its own rotation path).
func TestPutConfig_SubscriptionTokenImmutable(t *testing.T) {
	s := cfgFileServer(t)
	s.cfg.Subscription.Token = "orig"
	cfg := s.config()
	cfg.Subscription.Token = "attacker"
	body, _ := json.Marshal(cfg)
	if w := putConfig(t, s, string(body)); w.Code != http.StatusOK {
		t.Fatalf("PUT = %d: %s", w.Code, w.Body.String())
	}
	if got := s.config().Subscription.Token; got != "orig" {
		t.Fatalf("PUT changed the subscription token: got %q, want orig", got)
	}
}

// TestPutConfig_AccurateRestartNeeded: a hot-only change reports restart_needed
// false; a restart-affecting change reports true.
func TestPutConfig_AccurateRestartNeeded(t *testing.T) {
	s := cfgFileServer(t)

	hot := s.config()
	hot.FailSafe.Target = "9.9.9.9" // hot field only
	body, _ := json.Marshal(hot)
	w := putConfig(t, s, string(body))
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if w.Code != http.StatusOK || resp["restart_needed"] != false {
		t.Fatalf("hot-only change should not need restart: code=%d resp=%v", w.Code, resp)
	}

	warm := s.config()
	warm.Ports.DNS = 5354 // restart-affecting
	body, _ = json.Marshal(warm)
	w = putConfig(t, s, string(body))
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if w.Code != http.StatusOK || resp["restart_needed"] != true {
		t.Fatalf("port change should need restart: code=%d resp=%v", w.Code, resp)
	}
}

func TestConfigExport_RedactsByDefault(t *testing.T) {
	s := cfgFileServer(t)
	s.cfg.Clash.Secret = "supersecret"
	s.cfg.Subscription.Token = "tok123"
	s.cfg.Watchdog.NotifyURL = "https://hook.test/abc"

	w := getRec(t, s.handleConfigExport, "/api/config/export")
	if w.Code != http.StatusOK {
		t.Fatalf("export = %d", w.Code)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("missing attachment disposition: %q", cd)
	}
	var red config.Config
	if err := json.Unmarshal(w.Body.Bytes(), &red); err != nil {
		t.Fatal(err)
	}
	if red.Clash.Secret != config.RedactedMark || red.Subscription.Token != config.RedactedMark || red.Watchdog.NotifyURL != config.RedactedMark {
		t.Fatalf("export leaked a secret: %+v", red)
	}

	w = getRec(t, s.handleConfigExport, "/api/config/export?secrets=1")
	var full config.Config
	if err := json.Unmarshal(w.Body.Bytes(), &full); err != nil {
		t.Fatal(err)
	}
	if full.Clash.Secret != "supersecret" || full.Subscription.Token != "tok123" {
		t.Fatalf("secrets=1 should include real secrets: %+v", full)
	}
}

func TestConfigImport_UnredactsAndValidates(t *testing.T) {
	s := cfgFileServer(t)
	s.cfg.Clash.Secret = "keepme"

	// A redacted backup that changes routing_mode but leaves the secret masked.
	imp := s.config()
	imp.RoutingMode = "fast"
	imp.Clash.Secret = config.RedactedMark
	body, _ := json.Marshal(imp)
	if w := opshandlers_post(s.handleConfigImport, "/api/config/import", string(body)); w.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", w.Code, w.Body.String())
	}
	got := s.config()
	if got.RoutingMode != "fast" {
		t.Errorf("import did not apply routing_mode: %q", got.RoutingMode)
	}
	if got.Clash.Secret != "keepme" {
		t.Errorf("redacted import wiped the secret: %q", got.Clash.Secret)
	}

	// An invalid backup is rejected (fail-closed).
	bad := `{"listen":":8088","ports":{"ui":0,"clash":9090,"dns":5353,"mixed":7890}}`
	if w := opshandlers_post(s.handleConfigImport, "/api/config/import", bad); w.Code != http.StatusBadRequest {
		t.Fatalf("invalid import should be 400, got %d", w.Code)
	}
}

func TestConfigReset_PreservesReachability(t *testing.T) {
	s := cfgFileServer(t)
	s.cfg.Listen = "192.168.1.1:8090"
	s.cfg.Ports = config.Ports{UI: 8090, Clash: 9099, DNS: 5399, Mixed: 7899}
	s.cfg.AllowedHosts = []string{"router.lan"}
	s.cfg.Subscription.Token = "tok"
	s.cfg.RoutingMode = "fast"

	if w := opshandlers_post(s.handleConfigReset, "/api/config/reset", ""); w.Code != http.StatusOK {
		t.Fatalf("reset = %d: %s", w.Code, w.Body.String())
	}
	got := s.config()
	// Preserved (reachability + identity).
	if got.Listen != "192.168.1.1:8090" || got.Ports.UI != 8090 {
		t.Errorf("reset moved the bind: listen=%q ui=%d", got.Listen, got.Ports.UI)
	}
	if len(got.AllowedHosts) != 1 || got.AllowedHosts[0] != "router.lan" {
		t.Errorf("reset dropped allowed_hosts: %v", got.AllowedHosts)
	}
	if got.Subscription.Token != "tok" {
		t.Errorf("reset changed the subscription token: %q", got.Subscription.Token)
	}
	// Reset to defaults (the point of reset).
	if got.Ports.Clash != 9090 || got.Ports.DNS != 5353 {
		t.Errorf("non-UI ports not reset: %+v", got.Ports)
	}
	if got.RoutingMode != "" {
		t.Errorf("routing_mode not reset: %q", got.RoutingMode)
	}
}

// TestConfigReset_DropsInvalidPreservedAllowList: reset is a recovery action, so a
// pre-existing invalid AllowedHosts (e.g. a blank entry hand-edited into config.json)
// must not block it — reset drops the bad list and still yields a valid config.
func TestConfigReset_DropsInvalidPreservedAllowList(t *testing.T) {
	s := cfgFileServer(t)
	s.cfg.AllowedHosts = []string{"  "} // blank → fails config.Validate
	if w := opshandlers_post(s.handleConfigReset, "/api/config/reset", ""); w.Code != http.StatusOK {
		t.Fatalf("reset must succeed despite a pre-existing invalid allow-list, got %d: %s", w.Code, w.Body.String())
	}
	got := s.config()
	if len(got.AllowedHosts) != 0 {
		t.Fatalf("reset should have dropped the invalid allow-list, got %v", got.AllowedHosts)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("reset produced an invalid config: %v", err)
	}
}

// unwritableCfgServer builds a *Server whose config is seeded with defaults but
// whose backing file CANNOT be written: after Load creates the config dir, we
// replace that dir with a regular file of the same name, so the next Save() ->
// atomicfile.Write -> os.MkdirAll fails (ENOTDIR / "not a directory") on every
// platform. Used to exercise the failed-Save rollback path.
func unwritableCfgServer(t *testing.T) *Server {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cfgdir")
	cfg, err := config.Load(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Sanity: a Save must now fail, otherwise the test would be vacuous.
	if err := cfg.Save(); err == nil {
		t.Fatal("setup: Save unexpectedly succeeded; rollback test would be vacuous")
	}
	return &Server{cfg: cfg}
}

// TestPersistConfig_RollbackOnSaveFailure: when Save() fails, persistConfig must
// leave the live config byte-identical to before (no memory/disk divergence) and
// return the error. Covers the bug where applyConfigFields mutated s.cfg in place
// before a failed Save, so the daemon used new values while disk kept the old.
func TestPersistConfig_RollbackOnSaveFailure(t *testing.T) {
	s := unwritableCfgServer(t)
	before := s.config()
	beforeJSON, _ := json.Marshal(before)

	in := before // start from the live config so only the edits below differ
	in.RoutingMode = "fast"
	in.Offload = "sw"
	in.OffloadDevices = []string{"wan", "br-lan"}
	in.AllowedHosts = []string{"router.lan"}
	in.Updater.Mirrors = []string{"https://example.test/"}

	if err := s.persistConfig(&in); err == nil {
		t.Fatal("persistConfig should have returned the Save error")
	}

	after := s.config()
	afterJSON, _ := json.Marshal(after)
	if string(afterJSON) != string(beforeJSON) {
		t.Fatalf("live config diverged after a failed Save:\n before=%s\n  after=%s", beforeJSON, afterJSON)
	}
	// The restored snapshot must not alias the rejected request's backing arrays:
	// mutating in's slices afterward must not change the live config.
	if len(in.OffloadDevices) > 0 {
		in.OffloadDevices[0] = "MUTATED"
	}
	if len(in.AllowedHosts) > 0 {
		in.AllowedHosts[0] = "MUTATED"
	}
	if reAfter := s.config(); reflect.DeepEqual(reAfter, after) == false {
		t.Fatalf("restored config aliased the rejected request's slices: %+v", reAfter)
	}
}

// TestConfigImport_RollbackOnSaveFailure: the import handler shares persistConfig,
// so a failed Save must leave the live config unchanged and reply 500.
func TestConfigImport_RollbackOnSaveFailure(t *testing.T) {
	s := unwritableCfgServer(t)
	before := s.config()
	beforeJSON, _ := json.Marshal(before)

	imp := before
	imp.RoutingMode = "fast"
	imp.AllowedHosts = []string{"router.lan"}
	body, _ := json.Marshal(imp)

	w := opshandlers_post(s.handleConfigImport, "/api/config/import", string(body))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("failed Save should be 500, got %d: %s", w.Code, w.Body.String())
	}
	afterJSON, _ := json.Marshal(s.config())
	if string(afterJSON) != string(beforeJSON) {
		t.Fatalf("import diverged the live config after a failed Save:\n before=%s\n  after=%s", beforeJSON, afterJSON)
	}
}

// TestHostAllowGuard_Hot proves the guard reads the list per request: tightening
// it takes effect immediately and a self-excluding list is recoverable by
// clearing it — no restart, no lock-out.
func TestHostAllowGuard_Hot(t *testing.T) {
	var allowed []string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := hostAllowGuard(func() []string { return allowed }, next)

	do := func(host string) int {
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/api/config", nil)
		req.Host = host
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}

	if do("router.lan") != http.StatusOK {
		t.Fatal("empty allow-list must allow any host")
	}
	allowed = []string{"192.168.2.1"} // tighten — applies on the NEXT request, no restart
	if do("router.lan") != http.StatusForbidden {
		t.Fatal("tightened list must block a non-listed host immediately")
	}
	if do("192.168.2.1") != http.StatusOK {
		t.Fatal("listed host must pass")
	}
	allowed = nil // clear — recover from a lock-out straight away
	if do("router.lan") != http.StatusOK {
		t.Fatal("clearing the list must restore access immediately")
	}
}
