package plugin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wayhop/internal/model"
)

// pluginsup_awgEndpoint builds an AmneziaWG endpoint mirroring the shape used in
// plugin_test.go's TestAwgConfig, with a unique name to avoid symbol clashes.
func pluginsup_awgEndpoint(id string) model.Endpoint {
	return model.Endpoint{
		ID: id, Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
		Server: "198.51.100.20", Port: 51820,
		Params: map[string]any{
			"private_key": "PRIV", "peer_public_key": "PUB", "pre_shared_key": "PSK",
			"local_address": []string{"10.8.0.2/32"},
			"jc":            4, "jmin": 40, "jmax": 70, "s1": 0, "s2": 0,
			"h1": 1, "h2": 2, "h3": 3, "h4": float64(4),
		},
	}
}

// pluginsup_dsyEndpoint builds an nfqws2 desync endpoint, the long-running supervised engine.
func pluginsup_dsyEndpoint(id string) model.Endpoint {
	return model.Endpoint{
		ID: id, Engine: model.EngineNfqws,
		Params: map[string]any{"dpi_desync": "disorder2"},
	}
}

// pluginsup_statusByID indexes a Status slice by plugin id for easy assertions.
func pluginsup_statusByID(ss []Status) map[string]Status {
	m := make(map[string]Status, len(ss))
	for _, s := range ss {
		m[s.ID] = s
	}
	return m
}

// pluginsup_newManager builds a Manager with two distinct temp dirs (configs +
// an empty binDir) so resolve() finds no engine binaries.
func pluginsup_newManager(t *testing.T) (*Manager, string) {
	t.Helper()
	cfgDir := t.TempDir()
	binDir := t.TempDir() // intentionally empty: no engine binaries present
	return New(cfgDir, binDir), cfgDir
}

// TestPluginsup_SyncNoBinariesWritesConfigsAndNeedsBinary verifies that syncing
// an amneziawg + an nfqws2 Spec on a host without engine binaries writes each
// per-id native config to disk and reports needs_binary=true, running=false.
func TestPluginsup_SyncNoBinariesWritesConfigsAndNeedsBinary(t *testing.T) {
	// Hermetic: resolve() falls back to PATH to find an engine binary, so a host
	// with a real nfqws2/awg on PATH (e.g. the self-hosted CI runner = a live VPN
	// box) would make "no binary present" false. An empty PATH keeps it deterministic.
	t.Setenv("PATH", t.TempDir())
	m, cfgDir := pluginsup_newManager(t)

	specs := []Spec{
		{ID: "awg1", Endpoint: pluginsup_awgEndpoint("awg1"), SOCKSPort: 0},
		{ID: "dsy1", Endpoint: pluginsup_dsyEndpoint("dsy1"), SOCKSPort: 17901},
	}
	m.Sync(specs)

	// Both config files must be written with the engine-native names/extensions.
	awgPath := filepath.Join(cfgDir, "awg1.conf")
	dsyPath := filepath.Join(cfgDir, "dsy1.nfqws")

	awgBytes, err := os.ReadFile(awgPath)
	if err != nil {
		t.Fatalf("amneziawg config not written: %v", err)
	}
	if got := string(awgBytes); !strings.Contains(got, "[Interface]") || !strings.Contains(got, "PrivateKey = PRIV") {
		t.Errorf("awg config content unexpected:\n%s", got)
	}

	dsyBytes, err := os.ReadFile(dsyPath)
	if err != nil {
		t.Fatalf("nfqws2 config not written: %v", err)
	}
	if got := string(dsyBytes); !strings.Contains(got, "--qnum=200") || !strings.Contains(got, "--dpi-desync=disorder2") {
		t.Errorf("nfqws2 config content unexpected:\n%s", got)
	}

	st := pluginsup_statusByID(m.Status())
	if len(st) != 2 {
		t.Fatalf("Status() len = %d, want 2: %+v", len(st), st)
	}
	for _, id := range []string{"awg1", "dsy1"} {
		s, ok := st[id]
		if !ok {
			t.Fatalf("Status() missing id %q", id)
		}
		if !s.NeedsBinary {
			t.Errorf("%s: NeedsBinary = false, want true (no engine binary present)", id)
		}
		if s.Running {
			t.Errorf("%s: Running = true, want false (no engine binary present)", id)
		}
	}
	// Engine + SOCKSPort are surfaced verbatim.
	if st["awg1"].Engine != string(model.EngineAmneziaWG) {
		t.Errorf("awg1 Engine = %q, want %q", st["awg1"].Engine, model.EngineAmneziaWG)
	}
	if st["dsy1"].Engine != string(model.EngineNfqws) {
		t.Errorf("dsy1 Engine = %q, want %q", st["dsy1"].Engine, model.EngineNfqws)
	}
	if st["dsy1"].SOCKSPort != 17901 {
		t.Errorf("dsy1 SOCKSPort = %d, want 17901", st["dsy1"].SOCKSPort)
	}
}

// TestPluginsup_SyncReportsTheSameStateAndConfig verifies a second identical Sync ends in the same
// reported state and the same rendered config. That is worth having — a Sync whose second pass
// produced different output would be caught here — but it is NOT the restart guarantee.
//
// The name used to be SyncIdempotent, with a comment claiming the second Sync "neither restarts nor
// mutates the tracked set". It cannot see either: Status is a value struct and the config is
// deterministic, so a tear-down-and-rebuild ends at identical values and identical bytes. Measured on
// this very fixture — no engine binaries, so both procs are needs_binary and NOT running — the second
// Sync replaces both *proc objects and rewrites the config file, and this test stays green. The
// branch the old name described, "a running proc is untouched", was never reached, because nothing in
// the fixture is running. TestPluginsup_SyncKeepsARunningPluginAlive below exercises it.
func TestPluginsup_SyncReportsTheSameStateAndConfig(t *testing.T) {
	m, cfgDir := pluginsup_newManager(t)

	specs := []Spec{
		{ID: "awg1", Endpoint: pluginsup_awgEndpoint("awg1"), SOCKSPort: 0},
		{ID: "dsy1", Endpoint: pluginsup_dsyEndpoint("dsy1"), SOCKSPort: 17901},
	}
	m.Sync(specs)
	first := pluginsup_statusByID(m.Status())

	dsyPath := filepath.Join(cfgDir, "dsy1.nfqws")
	before, err := os.ReadFile(dsyPath)
	if err != nil {
		t.Fatalf("read nfqws2 config: %v", err)
	}

	// Second identical sync must be a no-op.
	m.Sync(specs)
	second := pluginsup_statusByID(m.Status())

	if len(second) != len(first) {
		t.Fatalf("Status() len changed after idempotent Sync: %d -> %d", len(first), len(second))
	}
	for id, s := range first {
		got, ok := second[id]
		if !ok {
			t.Errorf("id %q disappeared after idempotent Sync", id)
			continue
		}
		if got != s {
			t.Errorf("id %q status changed after idempotent Sync: %+v -> %+v", id, s, got)
		}
	}

	after, err := os.ReadFile(dsyPath)
	if err != nil {
		t.Fatalf("read nfqws2 config after second Sync: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("nfqws2 config content changed after idempotent Sync")
	}
}

// TestPluginsup_SyncEmptyStopsAndRemoves verifies Sync(nil)/Sync([]) tears down
// all tracked plugins, leaving an empty Status.
func TestPluginsup_SyncEmptyStopsAndRemoves(t *testing.T) {
	m, _ := pluginsup_newManager(t)

	m.Sync([]Spec{
		{ID: "awg1", Endpoint: pluginsup_awgEndpoint("awg1"), SOCKSPort: 0},
		{ID: "dsy1", Endpoint: pluginsup_dsyEndpoint("dsy1"), SOCKSPort: 17901},
	})
	if got := len(m.Status()); got != 2 {
		t.Fatalf("precondition: Status() len = %d, want 2", got)
	}

	m.Sync([]Spec{})
	if got := m.Status(); len(got) != 0 {
		t.Fatalf("Status() after Sync([]) = %+v, want empty", got)
	}

	// nil is equivalent to empty.
	m.Sync([]Spec{{ID: "awg1", Endpoint: pluginsup_awgEndpoint("awg1")}})
	if got := len(m.Status()); got != 1 {
		t.Fatalf("precondition: Status() len = %d, want 1", got)
	}
	m.Sync(nil)
	if got := m.Status(); len(got) != 0 {
		t.Fatalf("Status() after Sync(nil) = %+v, want empty", got)
	}
}

// TestPluginsup_SuperviseNoopWhenNothingRunning verifies Supervise is a safe
// no-op when no process is actually running (all degraded to needs_binary).
func TestPluginsup_SuperviseNoopWhenNothingRunning(t *testing.T) {
	// Hermetic: empty PATH so resolve()'s PATH fallback can't find a host engine
	// binary (the self-hosted runner has real nfqws2/awg on PATH).
	t.Setenv("PATH", t.TempDir())
	m, _ := pluginsup_newManager(t)

	// On an empty manager.
	m.Supervise()
	if got := len(m.Status()); got != 0 {
		t.Fatalf("Supervise on empty manager produced status: %+v", got)
	}

	// With needs_binary plugins (running=false), Supervise must not flip state.
	m.Sync([]Spec{
		{ID: "awg1", Endpoint: pluginsup_awgEndpoint("awg1")},
		{ID: "dsy1", Endpoint: pluginsup_dsyEndpoint("dsy1"), SOCKSPort: 17901},
	})
	before := pluginsup_statusByID(m.Status())

	m.Supervise()
	after := pluginsup_statusByID(m.Status())

	if len(after) != len(before) {
		t.Fatalf("Supervise changed plugin count: %d -> %d", len(before), len(after))
	}
	for id, s := range before {
		if after[id] != s {
			t.Errorf("Supervise mutated %q: %+v -> %+v", id, s, after[id])
		}
		if after[id].Running {
			t.Errorf("Supervise marked %q running with no binary present", id)
		}
	}
}

// TestPluginsup_StopAllClearsStatus verifies StopAll empties the tracked set.
func TestPluginsup_StopAllClearsStatus(t *testing.T) {
	m, _ := pluginsup_newManager(t)
	m.Sync([]Spec{
		{ID: "awg1", Endpoint: pluginsup_awgEndpoint("awg1")},
		{ID: "dsy1", Endpoint: pluginsup_dsyEndpoint("dsy1"), SOCKSPort: 17901},
	})
	if got := len(m.Status()); got != 2 {
		t.Fatalf("precondition: Status() len = %d, want 2", got)
	}

	m.StopAll()
	if got := m.Status(); len(got) != 0 {
		t.Errorf("Status() after StopAll = %+v, want empty", got)
	}

	// StopAll on an already-empty manager is safe and stays empty.
	m.StopAll()
	if got := m.Status(); len(got) != 0 {
		t.Errorf("Status() after second StopAll = %+v, want empty", got)
	}
}

// TestPluginsup_SuperviseThrottleSkipsDuringCooldown verifies that a managed
// long-running proc still inside its crash-loop cooldown window is NOT relaunched on this
// tick — Supervise only decrements the cooldown. This is the log-spam fix: a tick
// that throttles writes nothing and spawns no process.
func TestPluginsup_SuperviseThrottleSkipsDuringCooldown(t *testing.T) {
	m, _ := pluginsup_newManager(t) // empty binDir: no nfqws2 binary resolvable

	p := &proc{
		engine:   model.EngineNfqws,
		managed:  true,
		running:  false, // crashed; awaiting its next backed-off relaunch
		cfgPath:  filepath.Join(t.TempDir(), "dsy1.nfqws"),
		restarts: 6,
		cooldown: 3,
	}
	m.mu.Lock()
	m.procs["dsy1"] = p
	m.mu.Unlock()

	m.Supervise()

	m.mu.Lock()
	defer m.mu.Unlock()
	if p.cooldown != 2 {
		t.Errorf("cooldown not decremented: got %d, want 2", p.cooldown)
	}
	if p.running {
		t.Errorf("proc relaunched during cooldown (running=true); want throttled")
	}
	if p.restarts != 6 {
		t.Errorf("restarts changed during a cooldown tick: got %d, want 6", p.restarts)
	}
	if p.needsBin {
		t.Errorf("cooldown tick must not touch the binary (needs_binary flipped)")
	}
	// The throttled state must be visible in Status (not read as idle).
	if !strings.Contains(p.reason, "crash-looping") {
		t.Errorf("throttled proc Reason = %q, want it to mention crash-looping", p.reason)
	}
}

// TestPluginsup_SuperviseResetsThrottleWhenAlive verifies a managed long-running proc
// that has stayed up for the stable window (alive, open done) has its crash-loop counters
// reset — so a plugin that recovers keeps being restarted normally on a future crash — and
// that one alive tick soon after a relaunch is not yet that (QA-110).
func TestPluginsup_SuperviseResetsThrottleWhenAlive(t *testing.T) {
	for _, tc := range []struct {
		name  string
		up    time.Duration
		reset bool
	}{
		{"stable", pluginStableWindow + time.Second, true},
		{"just relaunched", time.Second, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _ := pluginsup_newManager(t)

			p := &proc{
				engine:     model.EngineNfqws,
				managed:    true,
				running:    true,
				done:       make(chan struct{}), // open => procDied=false => observed alive
				restarts:   5,
				cooldown:   7,
				launchedAt: time.Now().Add(-tc.up),
			}
			m.mu.Lock()
			m.procs["dsy1"] = p
			m.mu.Unlock()

			m.Supervise()

			m.mu.Lock()
			defer m.mu.Unlock()
			if reset := p.restarts == 0 && p.cooldown == 0; reset != tc.reset {
				t.Errorf("up %v: restarts=%d cooldown=%d, want reset=%v", tc.up, p.restarts, p.cooldown, tc.reset)
			}
			if !tc.reset && (p.restarts != 5 || p.cooldown != 7) {
				t.Errorf("an alive tick changed the throttle: restarts=%d cooldown=%d, want 5/7", p.restarts, p.cooldown)
			}
			if !p.running {
				t.Errorf("Supervise flipped a healthy proc to not-running")
			}
		})
	}
}

// TestPluginsup_SyncReCreatesDownProc verifies a re-Apply (Sync with the same
// spec) RE-CREATES a not-running proc, so its binary is re-resolved — the path
// that lets a plugin start after its binary is installed without a daemon restart.
// White-box: the tracked *proc identity must change across the two Syncs.
func TestPluginsup_SyncReCreatesDownProc(t *testing.T) {
	// Hermetic: empty PATH so resolve()'s PATH fallback can't find a host nfqws2
	// (the self-hosted runner has one), which would make the proc "running".
	t.Setenv("PATH", t.TempDir())
	m, _ := pluginsup_newManager(t) // empty binDir -> the proc is needs_binary (not running)
	spec := Spec{ID: "dsy1", Endpoint: pluginsup_dsyEndpoint("dsy1"), SOCKSPort: 17901}

	m.Sync([]Spec{spec})
	m.mu.Lock()
	first := m.procs["dsy1"]
	m.mu.Unlock()
	if first == nil || first.running {
		t.Fatalf("precondition: dsy1 should be a tracked, not-running proc, got %+v", first)
	}

	m.Sync([]Spec{spec}) // re-Apply, unchanged spec
	m.mu.Lock()
	second := m.procs["dsy1"]
	m.mu.Unlock()
	if second == nil {
		t.Fatal("dsy1 dropped after re-Apply")
	}
	if second == first {
		t.Error("re-Apply did not re-create the down proc (same *proc) — its binary would never be re-resolved without a daemon restart")
	}
}

// TestPluginsup_ProcDiedNilDone verifies procDied reports false for a proc with
// a nil done channel (one-shot awg-quick or a not-yet-launched process).
func TestPluginsup_ProcDiedNilDone(t *testing.T) {
	p := &proc{done: nil}
	if procDied(p) {
		t.Errorf("procDied(nil-done) = true, want false")
	}

	// An open (unclosed) done channel must also report not-dead.
	p2 := &proc{done: make(chan struct{})}
	if procDied(p2) {
		t.Errorf("procDied(open-done) = true, want false")
	}

	// A closed done channel reports dead.
	done := make(chan struct{})
	close(done)
	p3 := &proc{done: done}
	if !procDied(p3) {
		t.Errorf("procDied(closed-done) = false, want true")
	}
}
