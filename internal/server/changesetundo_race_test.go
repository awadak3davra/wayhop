package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// waitForUndoOnStoreLock returns once the undo handler is parked on the store's write lock, by which
// point it has read everything it reads before writing. Goroutine stacks are the only observable
// point (the handler has no hook), and a sleep instead would let this test pass on base code on a
// slow box without ever exercising the race.
func waitForUndoOnStoreLock(t *testing.T) {
	t.Helper()
	buf := make([]byte, 1<<20)
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		n := runtime.Stack(buf, true)
		for _, g := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.Contains(g, "handleChangeSetUndo") && strings.Contains(g, "store.(*Store)") &&
				(strings.Contains(g, "Mutex.Lock") || strings.Contains(g, "Mutex).Lock") || strings.Contains(g, "lockSlow")) {
				return
			}
		}
	}
	t.Fatal("the undo never reached the store's write lock")
}

// QA-090: an undo must not write back what it read before it waited. It read the config and the
// profile, then waited for the store's write lock (held by a background CIDR refresh, standing in
// for any store writer) and published its stale copy of the profile over the refresh's caches; then
// it saved its stale copy of the WHOLE config, silently reverting a Settings save (allowed hosts)
// that had answered 200 meanwhile. Both writes now start from what is current when they happen.
func TestHandleChangeSetUndo_KeepsWritesThatLandWhileItWaits(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		check func(t *testing.T, p model.Profile, c config.Config)
	}{
		{
			name: "settings row",
			body: `{"scope":"field","id":"settings","object_type":"setting","field":"Routing mode"}`,
			check: func(t *testing.T, p model.Profile, c config.Config) {
				if c.RoutingMode != "tun" {
					t.Errorf("the undone routing mode should be back to tun, got %q", c.RoutingMode)
				}
				if p.Endpoints[0].Port != 8443 {
					t.Errorf("the endpoint edit was not undone and must stay pending, got port %d", p.Endpoints[0].Port)
				}
			},
		},
		{
			name: "profile row",
			body: `{"scope":"field","id":"a","object_type":"endpoint","field":"Port"}`,
			check: func(t *testing.T, p model.Profile, c config.Config) {
				if p.Endpoints[0].Port != 443 {
					t.Errorf("the undone port should be back to 443, got %d", p.Endpoints[0].Port)
				}
				if c.RoutingMode != "hybrid" {
					t.Errorf("the routing mode was not undone and must stay pending, got %q", c.RoutingMode)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := applyhealth_server(t)
			cfgPath := filepath.Join(t.TempDir(), "config.json")
			cfg, err := config.Load(cfgPath) // a config with a file, so the undo's settings write can Save
			if err != nil {
				t.Fatal(err)
			}
			cfg.SingBox, cfg.DataDir, cfg.Demo, cfg.RoutingMode = s.cfg.SingBox, s.cfg.DataDir, true, "tun"
			s.cfg = cfg

			base := model.Profile{
				Endpoints: []model.Endpoint{{
					ID: "a", Name: "Alpha", Engine: model.EngineSingBox, Protocol: model.ProtoTrojan,
					Server: "203.0.113.9", Port: 443, Enabled: true, Params: map[string]any{"password": "p"},
				}},
				RoutingLists: []model.RoutingList{{
					ID: "rl", Name: "RL", Outbound: "direct", Enabled: true, Manual: []string{"example.net"},
					CIDRSource: "https://example.net/v4.txt",
				}},
			}
			if err := s.store.Replace(base); err != nil {
				t.Fatal(err)
			}
			changesetapi_recordBaseline(t, s, base)

			// Two pending edits: one setting, one endpoint field.
			edited := base
			edited.Endpoints = []model.Endpoint{base.Endpoints[0]}
			edited.Endpoints[0].Port = 8443
			if err := s.store.Replace(edited); err != nil {
				t.Fatal(err)
			}
			pending := s.config()
			pending.RoutingMode = "hybrid"
			if err := s.persistConfig(&pending); err != nil {
				t.Fatal(err)
			}

			// A background refresh holds the store's write lock while it stages a fetched feed.
			entered, release, refreshed := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			go func() {
				refreshed <- s.store.Reconcile(func(p *model.Profile) bool {
					close(entered)
					<-release
					lists := append([]model.RoutingList(nil), p.RoutingLists...)
					lists[0].CIDRCache = []string{"10.0.0.0/8"}
					p.RoutingLists = lists
					return true
				})
			}()
			<-entered

			undo, undone := httptest.NewRecorder(), make(chan struct{})
			go func() {
				defer close(undone)
				s.handleChangeSetUndo(undo, httptest.NewRequest(http.MethodPost, "/api/changeset/undo", strings.NewReader(tc.body)))
			}()
			waitForUndoOnStoreLock(t)

			// Meanwhile the operator saves Settings in another tab.
			settings := s.config()
			settings.AllowedHosts = []string{"router.example.net"}
			raw, err := json.Marshal(settings)
			if err != nil {
				t.Fatal(err)
			}
			put := httptest.NewRecorder()
			s.handlePutConfig(put, httptest.NewRequest(http.MethodPut, "/api/config", bytes.NewReader(raw)))
			if put.Code != http.StatusOK {
				t.Fatalf("PUT /api/config = %d (%s)", put.Code, put.Body.String())
			}

			close(release)
			if err := <-refreshed; err != nil {
				t.Fatalf("refresh: %v", err)
			}
			<-undone
			if undo.Code != http.StatusOK {
				t.Fatalf("undo = %d (%s)", undo.Code, undo.Body.String())
			}

			p, c := s.store.Profile(), s.config()
			if got := p.RoutingLists[0].CIDRCache; len(got) != 1 || got[0] != "10.0.0.0/8" {
				t.Errorf("the refresh that landed while the undo waited was overwritten: cidr_cache=%v", got)
			}
			if len(c.AllowedHosts) != 1 || c.AllowedHosts[0] != "router.example.net" {
				t.Errorf("the Settings save that landed while the undo waited was reverted: allowed_hosts=%v", c.AllowedHosts)
			}
			onDisk, err := config.Load(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			if len(onDisk.AllowedHosts) != 1 || onDisk.RoutingMode != c.RoutingMode {
				t.Errorf("config.json disagrees with the live config: allowed_hosts=%v routing_mode=%q (live %q)",
					onDisk.AllowedHosts, onDisk.RoutingMode, c.RoutingMode)
			}
			tc.check(t, p, c)
		})
	}
}
