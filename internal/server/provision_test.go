package server

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"velinx/internal/config"
	"velinx/internal/initserver"
	"velinx/internal/serverstore"
	"velinx/internal/store"
	"velinx/internal/util"
)

// redactSecrets must blank credential-bearing marker lines (client configs, the
// SSH private key) before raw installer output is echoed to the job console,
// while keeping non-secret lines (and the public key) intact.
func TestRedactSecrets(t *testing.T) {
	in := strings.Join([]string{
		"[install] apt-get ok",
		"WR_PROTO=vless-reality",
		"WR_CLIENT_CONFIG=vless://SECRETUUID@1.2.3.4:443?security=reality#x",
		"WR_CLIENT_CONFIG_B64=c2VjcmV0LXdnLWNvbmYtd2l0aC1rZXk=",
		"WR_SSH_KEY_B64=c2VjcmV0LXNzaC1wcml2YXRlLWtleQ==",
		"WR_SSH_PUB=ssh-ed25519 AAAApublic velinx",
		"[velinx-harden] done",
	}, "\n")
	out := redactSecrets(in)
	for _, secret := range []string{"SECRETUUID", "c2VjcmV0LXdnLWNvbmY", "c2VjcmV0LXNzaC1wcml2"} {
		if strings.Contains(out, secret) {
			t.Errorf("redactSecrets leaked %q:\n%s", secret, out)
		}
	}
	for _, keep := range []string{"WR_PROTO=vless-reality", "apt-get ok", "ssh-ed25519 AAAApublic"} {
		if !strings.Contains(out, keep) {
			t.Errorf("redactSecrets dropped non-secret content %q:\n%s", keep, out)
		}
	}
}

// provision_newServer builds a minimal demo *Server with just the fields the
// provisioning/hardening flows touch: a Demo config, a profile store, a server
// registry, and a job manager. Everything is backed by t.TempDir() so nothing
// leaks between tests. Prefixed to avoid clashing with other test files in this
// package.
func provision_newServer(t *testing.T) *Server {
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
	}
}

// provision_waitDone polls job.Snapshot() until the job reports Done, returning
// the final view. It fails the test if the job never finishes — a job that never
// Finishes would make the UI poll forever, so the test must not hang either.
func provision_waitDone(t *testing.T, job *initserver.Job) initserver.JobView {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		v := job.Snapshot()
		if v.Done {
			return v
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("job %s never finished (Done stayed false)", job.ID())
	return initserver.JobView{}
}

func provision_indexOf(haystack, needle string) int {
	// tiny strings.Index without importing strings just for one call site
	n, h := len(needle), len(haystack)
	if n == 0 {
		return 0
	}
	for i := 0; i+n <= h; i++ {
		if haystack[i:i+n] == needle {
			return i
		}
	}
	return -1
}

// TestProvisionDemoAddsEndpoints drives a full demo provision job for BOTH
// protocols and asserts: the job finishes ok, both client configs are parsed and
// added to Connections with the right protocol-labelled names, the saved-server
// record gets a non-empty created_at and a merged installed list, and the job
// result echoes the requested protocols.
func TestProvisionDemoAddsEndpoints(t *testing.T) {
	s := provision_newServer(t)
	job := s.jobs.New("provision", "")
	b := provisionReq{
		Name:      "edge",
		Host:      "203.0.113.7",
		Port:      22,
		User:      "root",
		Protocols: []string{initserver.ProtoAmneziaWG, initserver.ProtoReality},
	}
	s.runProvision(job, b)

	v := provision_waitDone(t, job)
	if !v.OK {
		t.Fatalf("provision job not ok: %+v", v)
	}

	// Two endpoints landed in the profile store, one per protocol.
	eps := s.store.Profile().Endpoints
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints, got %d: %+v", len(eps), eps)
	}

	// Names must carry the human protocol label appended after the server name.
	byProto := map[string]bool{}
	for _, ep := range eps {
		byProto[string(ep.Protocol)] = true
		if ep.Server != "203.0.113.7" {
			t.Errorf("endpoint %q has server %q, want 203.0.113.7", ep.Name, ep.Server)
		}
		switch ep.Protocol {
		case "amneziawg":
			if want := "edge · AmneziaWG"; ep.Name != want {
				t.Errorf("awg endpoint name = %q, want %q", ep.Name, want)
			}
			if ep.Port != 51820 {
				t.Errorf("awg endpoint port = %d, want 51820", ep.Port)
			}
		case "vless":
			if want := "edge · VLESS-Reality"; ep.Name != want {
				t.Errorf("vless endpoint name = %q, want %q", ep.Name, want)
			}
			if ep.Port != 443 {
				t.Errorf("vless endpoint port = %d, want 443", ep.Port)
			}
		default:
			t.Errorf("unexpected protocol %q", ep.Protocol)
		}
	}
	if !byProto["amneziawg"] || !byProto["vless"] {
		t.Fatalf("missing a protocol: %v", byProto)
	}

	// Job result echoes the request.
	if v.Result == nil {
		t.Fatal("finished provision job has no result map")
	}
	if got, _ := v.Result["server_id"].(string); got != serverIDFor(b) {
		t.Errorf("result server_id = %q, want %q", got, serverIDFor(b))
	}
	added, _ := v.Result["added_endpoints"].([]string)
	if len(added) != 2 {
		t.Fatalf("result added_endpoints = %v, want 2 ids", v.Result["added_endpoints"])
	}

	// Saved server record: created_at set, both protocols recorded.
	sv, ok := s.servers.Get(serverIDFor(b))
	if !ok {
		t.Fatalf("provisioned server %q not saved", serverIDFor(b))
	}
	if sv.CreatedAt == "" {
		t.Error("saved server has empty created_at")
	}
	if sv.Host != "203.0.113.7" || sv.User != "root" || sv.Port != 22 {
		t.Errorf("saved server addressing wrong: %+v", sv)
	}
	if sv.Name != "edge" {
		t.Errorf("saved server name = %q, want edge", sv.Name)
	}
	if len(sv.Installed) != 2 {
		t.Errorf("installed list = %v, want both protocols", sv.Installed)
	}
	if sv.LastJob != job.ID() {
		t.Errorf("last_job = %q, want %q", sv.LastJob, job.ID())
	}
}

// TestProvisionDemoReversedProtocolsTagging is the WR_PROTO guard: with the
// protocol list REVERSED relative to the catalog (vless-reality BEFORE
// amneziawg), each client config must still be labelled with the protocol that
// actually produced it — never paired by position. A regression that paired by
// index would mislabel the vless link as AmneziaWG and vice-versa.
func TestProvisionDemoReversedProtocolsTagging(t *testing.T) {
	s := provision_newServer(t)
	job := s.jobs.New("provision", "")
	b := provisionReq{
		Name:      "rev",
		Host:      "198.51.100.9",
		Port:      22,
		User:      "root",
		Protocols: []string{initserver.ProtoReality, initserver.ProtoAmneziaWG}, // reversed
	}
	s.runProvision(job, b)
	v := provision_waitDone(t, job)
	if !v.OK {
		t.Fatalf("reversed provision not ok: %+v", v)
	}

	eps := s.store.Profile().Endpoints
	if len(eps) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(eps))
	}

	// The decisive assertions: the vless:// payload is labelled VLESS-Reality and
	// the [Interface] payload is labelled AmneziaWG, regardless of input order.
	for _, ep := range eps {
		switch ep.Protocol {
		case "vless":
			if ep.Name != "rev · VLESS-Reality" {
				t.Errorf("vless mis-tagged: name=%q (proto pairing by index would mislabel it)", ep.Name)
			}
			if ep.Port != 443 {
				t.Errorf("vless port = %d, want 443", ep.Port)
			}
		case "amneziawg":
			if ep.Name != "rev · AmneziaWG" {
				t.Errorf("awg mis-tagged: name=%q", ep.Name)
			}
			if ep.Port != 51820 {
				t.Errorf("awg port = %d, want 51820", ep.Port)
			}
		default:
			t.Errorf("unexpected protocol %q", ep.Protocol)
		}
	}

	// The console steps name the protocols by their display label too.
	var sawAWGStep, sawVlessStep bool
	for _, st := range v.Steps {
		if provision_indexOf(st.Name, "AmneziaWG") >= 0 && provision_indexOf(st.Name, "Create client") >= 0 {
			sawAWGStep = true
		}
		if provision_indexOf(st.Name, "VLESS-Reality") >= 0 && provision_indexOf(st.Name, "Create client") >= 0 {
			sawVlessStep = true
		}
	}
	if !sawAWGStep || !sawVlessStep {
		t.Errorf("expected create-client steps for both labels; awg=%v vless=%v", sawAWGStep, sawVlessStep)
	}
}

// TestProvisionDemoMergesExistingServer verifies saveProvisionedServer MERGES
// into an existing record: it preserves the original created_at and name, and
// unions the installed protocol list (dedup) rather than overwriting it.
func TestProvisionDemoMergesExistingServer(t *testing.T) {
	s := provision_newServer(t)
	b := provisionReq{
		Name:      "", // empty so the existing name is kept
		Host:      "203.0.113.50",
		Port:      22,
		User:      "root",
		Protocols: []string{initserver.ProtoReality},
	}
	id := serverIDFor(b)

	// Seed a pre-existing record with amneziawg already installed and a known
	// created_at + custom name.
	const created = "2020-01-02T03:04:05Z"
	if err := s.servers.Upsert(serverstore.Server{
		ID: id, Name: "my-box", Host: "203.0.113.50", Port: 22, User: "root",
		Installed: []string{initserver.ProtoAmneziaWG}, CreatedAt: created,
	}); err != nil {
		t.Fatal(err)
	}

	job := s.jobs.New("provision", "")
	s.runProvision(job, b)
	v := provision_waitDone(t, job)
	if !v.OK {
		t.Fatalf("provision not ok: %+v", v)
	}

	sv, ok := s.servers.Get(id)
	if !ok {
		t.Fatalf("server %q vanished", id)
	}
	if sv.CreatedAt != created {
		t.Errorf("created_at = %q, want preserved %q", sv.CreatedAt, created)
	}
	if sv.Name != "my-box" {
		t.Errorf("name = %q, want preserved my-box", sv.Name)
	}
	// Union of {amneziawg} and {vless-reality}, in order, no dupes.
	if len(sv.Installed) != 2 ||
		sv.Installed[0] != initserver.ProtoAmneziaWG ||
		sv.Installed[1] != initserver.ProtoReality {
		t.Errorf("installed = %v, want [amneziawg vless-reality]", sv.Installed)
	}
}

// saveProvisionedServer must record only the protocols that ACTUALLY provisioned
// (its installedProtos arg), never every REQUESTED one (b.Protocols) — a protocol
// whose install failed must not appear in the saved server's Installed list.
func TestSaveProvisionedServer_OnlyMarksSucceeded(t *testing.T) {
	s := provision_newServer(t)
	job := s.jobs.New("provision", "")
	b := provisionReq{
		Host: "198.51.100.7", Port: 22, User: "root",
		Protocols: []string{initserver.ProtoAmneziaWG, initserver.ProtoReality}, // BOTH requested
	}
	// Only amneziawg actually provisioned; Reality's install failed (no client config).
	s.saveProvisionedServer(job, b, []string{initserver.ProtoAmneziaWG})

	sv, ok := s.servers.Get(serverIDFor(b))
	if !ok {
		t.Fatal("server not saved")
	}
	if len(sv.Installed) != 1 || sv.Installed[0] != initserver.ProtoAmneziaWG {
		t.Errorf("Installed = %v, want [amneziawg] (Reality failed; must not be marked installed)", sv.Installed)
	}
}

// TestRunHardenKeysDemo: the demo harden-keys job finishes ok and its result
// carries a private key and a download filename derived from the host.
func TestRunHardenKeysDemo(t *testing.T) {
	s := provision_newServer(t)
	job := s.jobs.New("harden-keys", "")
	b := hardenReq{Host: "192.0.2.40", Port: 22, User: "root"}
	s.runHardenKeys(job, b)
	v := provision_waitDone(t, job)

	if !v.OK {
		t.Fatalf("harden-keys job not ok: %+v", v)
	}
	if v.Result == nil {
		t.Fatal("harden-keys result is nil")
	}
	priv, _ := v.Result["private_key"].(string)
	if provision_indexOf(priv, "PRIVATE KEY") < 0 {
		t.Errorf("private_key looks wrong: %q", priv)
	}
	fn, _ := v.Result["filename"].(string)
	if want := "velinx-192-0-2-40-ed25519"; fn != want {
		t.Errorf("filename = %q, want %q", fn, want)
	}
	if _, ok := v.Result["public_key"].(string); !ok {
		t.Error("harden-keys result missing public_key")
	}
}

// TestRunLockdownDemo: the demo lockdown job finishes ok and flips the saved
// server's hardened flag (the server must pre-exist in the registry, since
// lockdown patches it by ServerID).
func TestRunLockdownDemo(t *testing.T) {
	s := provision_newServer(t)
	const id = "srv-lock"
	if err := s.servers.Upsert(serverstore.Server{
		ID: id, Name: "lockbox", Host: "192.0.2.77", Port: 22, User: "root",
	}); err != nil {
		t.Fatal(err)
	}

	job := s.jobs.New("lockdown", id)
	b := hardenReq{ServerID: id, Host: "192.0.2.77", Port: 22, User: "root"}
	s.runLockdown(job, b)
	v := provision_waitDone(t, job)

	if !v.OK {
		t.Fatalf("lockdown job not ok: %+v", v)
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
	if sv.LastJob != job.ID() {
		t.Errorf("last_job = %q, want %q", sv.LastJob, job.ID())
	}
}

// ---- direct unit tests of the small pure helpers ----

func TestMergeStrings(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		want []string
	}{
		{"dedup across both", []string{"x", "y"}, []string{"y", "z"}, []string{"x", "y", "z"}},
		{"drops empties", []string{"", "a", ""}, []string{"b", ""}, []string{"a", "b"}},
		{"dedup within a", []string{"a", "a"}, nil, []string{"a"}},
		{"both nil", nil, nil, nil},
		{"order preserved (a then b)", []string{"b"}, []string{"a"}, []string{"b", "a"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := mergeStrings(c.a, c.b)
			if len(got) != len(c.want) {
				t.Fatalf("mergeStrings = %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("mergeStrings = %v, want %v", got, c.want)
				}
			}
		})
	}
}

func TestSlug(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7":    "203-0-113-7",
		"Example.COM":    "example-com",
		"a_b c":          "a-b-c",
		"--lead.trail--": "lead-trail",
		"":               "",
		"!!!":            "",
		"host123":        "host123",
	}
	for in, want := range cases {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestServerIDFor(t *testing.T) {
	// Explicit ServerID wins verbatim.
	if got := serverIDFor(provisionReq{ServerID: "srv-custom", Host: "1.2.3.4"}); got != "srv-custom" {
		t.Errorf("serverIDFor(explicit) = %q, want srv-custom", got)
	}
	// Otherwise it is derived from the host slug.
	if got := serverIDFor(provisionReq{Host: "203.0.113.7"}); got != "srv-203-0-113-7" {
		t.Errorf("serverIDFor(host) = %q, want srv-203-0-113-7", got)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := util.FirstNonEmpty("", "", "third", "fourth"); got != "third" {
		t.Errorf("firstNonEmpty = %q, want third", got)
	}
	if got := util.FirstNonEmpty("first", "second"); got != "first" {
		t.Errorf("firstNonEmpty = %q, want first", got)
	}
	if got := util.FirstNonEmpty("", ""); got != "" {
		t.Errorf("util.FirstNonEmpty(all empty) = %q, want empty", got)
	}
	if got := util.FirstNonEmpty(); got != "" {
		t.Errorf("util.FirstNonEmpty() = %q, want empty", got)
	}
}
