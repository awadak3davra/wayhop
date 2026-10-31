package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"wayhop/internal/model"
)

// TestProfileMigrationCompat locks the deploy/rollback compat for the user's endpoint DATA —
// the most painful thing to lose on a device upgrade. BACKWARD (deploy: old profile -> new
// binary): an older profile loads with new endpoint fields defaulted. FORWARD (rollback: new
// profile -> old binary): a profile carrying fields this binary doesn't know still loads with
// endpoints intact — so a post-deploy rollback fed the new profile.json isn't bricked. Holds
// while Open stays lenient (plain json.Unmarshal); a model.Endpoint field rename/retype, or
// DisallowUnknownFields, fails here before it can lose a router's saved connections.
func TestProfileMigrationCompat(t *testing.T) {
	prof := model.Profile{Endpoints: []model.Endpoint{{
		ID: "e1", Name: "NL", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
		Server: "1.2.3.4", Port: 443, Enabled: true,
		Params: map[string]any{"uuid": "u-1"},
	}}}
	base, err := json.Marshal(prof)
	if err != nil {
		t.Fatal(err)
	}
	open := func(b []byte) (*Store, error) {
		p := filepath.Join(t.TempDir(), "profile.json")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return Open(p)
	}

	// BACKWARD: the marshaled profile omits omitempty new endpoint fields (mtu/kill_switch/…),
	// standing in for an older profile — it must load with the endpoint intact + new fields default.
	s, err := open(base)
	if err != nil {
		t.Fatalf("backward: Open(old-style profile) errored: %v", err)
	}
	if eps := s.Profile().Endpoints; len(eps) != 1 || eps[0].ID != "e1" || eps[0].MTU != 0 {
		t.Fatalf("backward: endpoint not migrated cleanly: %+v", eps)
	}

	// FORWARD/ROLLBACK: inject a field this binary doesn't know; Open must ignore it (not error)
	// and keep the endpoint — else a rollback after deploy would brick on the new profile.json.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(base, &m); err != nil {
		t.Fatal(err)
	}
	m["future_profile_field"] = json.RawMessage(`{"x":1}`)
	fwd, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := open(fwd)
	if err != nil {
		t.Fatalf("forward: Open(profile with unknown field) errored — rollback would brick: %v", err)
	}
	if eps := s2.Profile().Endpoints; len(eps) != 1 || eps[0].ID != "e1" {
		t.Errorf("forward: endpoint lost when an unknown field was present: %+v", eps)
	}
}

// An empty or whitespace-only profile.json must load as an empty profile and
// rewrite a valid file — NOT brick boot with "unexpected end of JSON input". A
// non-empty garbage file still errors.
func TestOpenEmptyOrGarbage(t *testing.T) {
	for _, content := range []string{"", "   ", "\n\t \n"} {
		path := filepath.Join(t.TempDir(), "profile.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := Open(path)
		if err != nil {
			t.Fatalf("Open(empty %q) returned error: %v", content, err)
		}
		if p := s.Profile(); len(p.Endpoints) != 0 || len(p.Groups) != 0 || len(p.Rules) != 0 {
			t.Fatalf("Open(empty) did not yield an empty profile: %+v", p)
		}
		// The file must have been rewritten so a reopen succeeds (valid JSON).
		if _, err := Open(path); err != nil {
			t.Fatalf("reopen after empty-file recreate errored: %v", err)
		}
	}

	// A genuinely-corrupt NON-empty file must still surface its parse error.
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open(garbage) should error, not swallow real corruption")
	}
}

func TestStoreCRUDAndPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	ep := model.Endpoint{ID: "e1", Name: "E1", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "1.1.1.1", Port: 443, Enabled: true}
	if err := s.UpsertEndpoint(ep); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertGroup(model.Group{ID: "g1", Name: "G1", Type: model.GroupURLTest, Members: []string{"e1"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertRule(model.Rule{ID: "r1", Default: true, Outbound: "g1"}); err != nil {
		t.Fatal(err)
	}

	// Upsert replaces by ID rather than duplicating.
	ep.Name = "E1b"
	if err := s.UpsertEndpoint(ep); err != nil {
		t.Fatal(err)
	}
	if n := len(s.Profile().Endpoints); n != 1 {
		t.Fatalf("want 1 endpoint, got %d", n)
	}
	if s.Profile().Endpoints[0].Name != "E1b" {
		t.Fatal("upsert did not replace in place")
	}

	// Give g1 a second member so deleting e1 prunes rather than empties it
	// (deleting the sole member of a group is refused).
	if err := s.UpsertEndpoint(model.Endpoint{ID: "e2", Name: "E2", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "2.2.2.2", Port: 443, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertGroup(model.Group{ID: "g1", Name: "G1", Type: model.GroupURLTest, Members: []string{"e1", "e2"}}); err != nil {
		t.Fatal(err)
	}

	// A rule targeting the endpoint blocks its deletion.
	if err := s.UpsertRule(model.Rule{ID: "r2", Domain: []string{"x.com"}, Outbound: "e1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteEndpoint("e1"); err == nil {
		t.Fatal("expected deletion to be blocked by rule r2")
	}

	// Remove the rule, then deletion succeeds and prunes the group member.
	if err := s.DeleteRule("r2"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteEndpoint("e1"); err != nil {
		t.Fatal(err)
	}
	if got := s.Profile().Groups[0].Members; len(got) != 1 || got[0] != "e2" {
		t.Fatalf("group member e1 not pruned (e2 should remain): %v", got)
	}

	// Reopen from disk: state persisted.
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.Profile().Endpoints) != 1 || len(s2.Profile().Groups) != 1 {
		t.Fatalf("persistence mismatch: %d endpoints, %d groups", len(s2.Profile().Endpoints), len(s2.Profile().Groups))
	}
}

// TestMutatorSaveFailureLeavesMemoryMatchingDisk: when the durable write fails (a full
// router overlay / EROFS), a mutator must roll back its in-memory change — otherwise the
// panel and the next Apply would use a phantom edit that silently vanishes on reboot
// (memory diverges from disk). Covers an Upsert (whole-element replace) AND a Delete
// (in-place slice + Group.Members compaction), the two mutation shapes.
func TestMutatorSaveFailureLeavesMemoryMatchingDisk(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	mk := func(id, name string) model.Endpoint {
		return model.Endpoint{ID: id, Name: name, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "1.1.1.1", Port: 443, Enabled: true}
	}
	if err := s.UpsertEndpoint(mk("a", "A")); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertEndpoint(mk("b", "B")); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertGroup(model.Group{ID: "g", Name: "G", Members: []string{"a", "b"}}); err != nil {
		t.Fatal(err)
	}
	before := s.Profile()

	// Redirect persistence to an unwritable location so the next saves fail.
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.path = filepath.Join(blocker, "sub", "profile.json") // MkdirAll over a file → error

	if err := s.UpsertEndpoint(mk("a", "MUTATED")); err == nil {
		t.Fatal("UpsertEndpoint should have failed on the unwritable path")
	}
	if err := s.DeleteEndpoint("b"); err == nil {
		t.Fatal("DeleteEndpoint should have failed on the unwritable path")
	}

	after := s.Profile()
	if len(after.Endpoints) != len(before.Endpoints) {
		t.Fatalf("endpoint count diverged after failed writes: %d vs %d", len(after.Endpoints), len(before.Endpoints))
	}
	names := map[string]string{}
	for _, e := range after.Endpoints {
		names[e.ID] = e.Name
	}
	if names["a"] != "A" {
		t.Fatalf("failed Upsert leaked into memory: a=%q, want A", names["a"])
	}
	if _, ok := names["b"]; !ok {
		t.Fatal("failed Delete leaked into memory: endpoint b is gone")
	}
	// The group's members must also be intact (DeleteEndpoint prunes Members in place).
	if len(after.Groups) != 1 || len(after.Groups[0].Members) != 2 {
		t.Fatalf("failed Delete leaked into group members: %+v", after.Groups)
	}
}

// A kill between atomicfile.Write's temp creation and its rename leaves a full copy of the profile,
// endpoint keys included, beside profile.json, and nothing ever removed it: keys the operator rotated
// stayed on disk and repeated crashes filled the overlay. Open sweeps them before any writer starts.
func TestOpen_SweepsTempsACrashLeftBehind(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, []byte(`{"endpoints":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	orphan := path + ".123456.tmp"
	other := filepath.Join(dir, "servers.json.123456.tmp") // another store's temp is not ours to judge
	for _, p := range []string{orphan, other} {
		if err := os.WriteFile(p, []byte(`{"endpoints":[{"id":"e1"`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := Open(path); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("an orphaned profile temp survived Open: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("Open removed a temp that is not its own: %v", err)
	}
}

// The working copy owns its DNS plane. It shared the published one, so a delete or disable that
// repointed a DNS server's detour wrote into the profile readers were using - before validation,
// and even when the write was then refused.
func TestCloneProfileDoesNotShareTheDNSPlane(t *testing.T) {
	src := &model.Profile{DNS: &model.DNSSettings{
		Servers: []model.DNSServer{{Tag: "d", Type: "https", Server: "198.51.100.53", Detour: "a"}},
		Rules:   []model.DNSRule{{ID: "r", Server: "d"}},
	}}
	p := cloneProfile(src)
	p.DNS.Servers[0].Detour = "b"
	p.DNS.Rules[0].Server = "x"
	p.DNS.Final = "x"
	if src.DNS.Servers[0].Detour != "a" || src.DNS.Rules[0].Server != "d" || src.DNS.Final != "" {
		t.Fatalf("the published DNS plane changed through the working copy: %+v", *src.DNS)
	}
}
