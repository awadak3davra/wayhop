package plugin

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPluginsup_SyncKeepsARunningPluginAlive pins the guarantee Sync's own comment makes and no test
// reached: "A running proc is untouched (don't kill a healthy plugin)".
//
// Why it needs its own fixture. Every other test in this package runs against an empty binDir, so no
// plugin ever comes up — needs_binary, running=false — and Sync's kept-unchanged branch takes the
// re-create path every time. The sibling test that used to be called SyncIdempotent therefore passed
// while the second Sync replaced both *proc objects and rewrote the config file: Status is a value
// struct and the render is deterministic, so a tear-down-and-rebuild lands on identical values and
// identical bytes. What was missing was not a stricter assertion, it was a RUNNING plugin.
//
// Starting a real engine is not available here (that is what the empty binDir is for), so the proc is
// marked running directly — this is an in-package test and the field is the same one Supervise and
// Status read. Deleting the `if !p.running` guard makes every Apply kill and relaunch every healthy
// tunnel; that is a datapath outage on each Apply, and until now the whole package stayed green.
func TestPluginsup_SyncKeepsARunningPluginAlive(t *testing.T) {
	m, cfgDir := pluginsup_newManager(t)

	specs := []Spec{
		{ID: "awg1", Endpoint: pluginsup_awgEndpoint("awg1"), SOCKSPort: 0},
		{ID: "olc1", Endpoint: pluginsup_olcEndpoint("olc1"), SOCKSPort: 17901},
	}
	m.Sync(specs)

	// Mark them up, as a host with the engines installed would leave them, and give each a crash-loop
	// throttle so the branch's other half — clearing it — is observable too.
	firstPtr := map[string]*proc{}
	m.mu.Lock()
	for id, p := range m.procs {
		p.running = true
		p.restarts, p.cooldown = 3, 42
		firstPtr[id] = p
	}
	m.mu.Unlock()

	// The precondition, asserted rather than assumed: with nothing running this test would exercise
	// the re-create path and prove exactly what the old one did.
	if len(firstPtr) != len(specs) {
		t.Fatalf("tracked %d proc(s), want %d — there is no running plugin to keep alive", len(firstPtr), len(specs))
	}

	// A sentinel in the rendered config. Content equality cannot tell a kept file from an identically
	// rewritten one; a byte the renderer would never produce can.
	olcPath := filepath.Join(cfgDir, "olc1.yaml")
	orig, err := os.ReadFile(olcPath)
	if err != nil {
		t.Fatalf("read olc config: %v", err)
	}
	const sentinel = "\n# sentinel: a rewrite would drop this line\n"
	if err := os.WriteFile(olcPath, append(append([]byte(nil), orig...), []byte(sentinel)...), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	m.Sync(specs)

	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.procs) != len(firstPtr) {
		t.Fatalf("tracked set changed across an identical Sync: %d -> %d", len(firstPtr), len(m.procs))
	}
	for id, want := range firstPtr {
		got, ok := m.procs[id]
		if !ok {
			t.Errorf("running plugin %q was dropped by an identical Sync", id)
			continue
		}
		if got != want {
			t.Errorf("running plugin %q was stopped and re-created by an identical Sync (%p -> %p) — "+
				"every Apply would drop a healthy tunnel", id, want, got)
			continue
		}
		if !got.running {
			t.Errorf("running plugin %q is no longer marked running after an identical Sync", id)
		}
		if got.restarts != 0 || got.cooldown != 0 {
			t.Errorf("plugin %q kept its crash-loop throttle (restarts=%d cooldown=%d); a re-Apply must "+
				"retry a backed-off plugin promptly", id, got.restarts, got.cooldown)
		}
	}

	after, err := os.ReadFile(olcPath)
	if err != nil {
		t.Fatalf("read olc config after: %v", err)
	}
	if string(after) != string(orig)+sentinel {
		t.Errorf("the config of a RUNNING plugin was rewritten by an identical Sync — the secrets file " +
			"is unlinked and re-rendered under a live engine")
	}
}
