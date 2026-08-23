package server

import (
	"strings"
	"testing"
	"time"

	"wayhop/internal/initserver"
	"wayhop/internal/platform"
)

// Provisioning is the one endpoint writer where the two ends are different machines: the remote
// server really did install the protocol, while the client side has to run HERE. An exit created
// enabled on a router that cannot carry it fails at Apply, after a configuration has been built
// around it — so the gate belongs on this path too, with the reason narrated to the operator who is
// watching the console rather than swallowed.
//
// Demo mode is the whole test environment: it produces the same tagged client configs the installer
// prints, with no SSH and no remote host involved.

func gateProvisionServer(t *testing.T, state platform.CapState) *Server {
	t.Helper()
	s := dnsSeed(t)
	s.jobs = initserver.NewJobManager() // the shared fixture builds no job manager
	s.cfgMu.Lock()
	s.cfg.Demo = true
	s.cfgMu.Unlock()
	s.caps.mu.Lock()
	s.caps.set = platform.CapabilitySet{
		Items: map[string]platform.Capability{
			platform.CapEngineSingbox: {
				ID: platform.CapEngineSingbox, State: platform.CapSupported,
			},
			platform.CapProtocolPrefix + "vless": {
				ID: platform.CapProtocolPrefix + "vless", State: state,
				Detail: "no path on this platform",
			},
		},
		ProbedAt: time.Now(),
	}
	s.caps.mu.Unlock()
	return s
}

func gateProvisionRun(t *testing.T, s *Server) (added []string, console []string) {
	t.Helper()
	job := s.jobs.New("provision", "srv-test")
	s.runProvision(job, provisionReq{
		ServerID: "srv-test", Name: "bench", Host: "198.51.100.60", Port: 22,
		User: "root", Protocols: []string{"vless-reality"},
	})
	view := job.Snapshot()
	if !view.Done {
		t.Fatal("the job never finished; nothing below would be measuring the outcome")
	}
	for _, e := range s.store.Profile().Endpoints {
		if strings.Contains(strings.ToLower(string(e.Protocol)), "vless") {
			added = append(added, e.ID)
		}
	}
	return added, view.Console
}

func TestGateProvision_UnsupportedIsCreatedDisabledAndSaidSo(t *testing.T) {
	s := gateProvisionServer(t, platform.CapUnsupportedPlatform)
	added, console := gateProvisionRun(t, s)
	if len(added) == 0 {
		t.Fatal("provisioning stored no vless endpoint at all; a refusal is not what this path should do")
	}
	for _, e := range s.store.Profile().Endpoints {
		if strings.Contains(strings.ToLower(string(e.Protocol)), "vless") && e.Enabled {
			t.Errorf("endpoint %s was created ENABLED on a router that cannot carry vless", e.ID)
		}
	}
	var said bool
	for _, line := range console {
		if strings.Contains(line, "kept disabled") {
			said = true
		}
	}
	if !said {
		t.Errorf("the console never says the exit was kept disabled; a silent flip leaves the operator hunting for why it will not start:\n%s",
			strings.Join(console, "\n"))
	}
}

// A router that can run it gets what it always got.
func TestGateProvision_SupportedStaysEnabled(t *testing.T) {
	s := gateProvisionServer(t, platform.CapSupported)
	added, console := gateProvisionRun(t, s)
	if len(added) == 0 {
		t.Fatal("provisioning stored no vless endpoint")
	}
	for _, e := range s.store.Profile().Endpoints {
		if strings.Contains(strings.ToLower(string(e.Protocol)), "vless") && !e.Enabled {
			t.Errorf("endpoint %s came back disabled on a router that supports vless", e.ID)
		}
	}
	for _, line := range console {
		if strings.Contains(line, "kept disabled") {
			t.Errorf("the console reported a gate that should not have fired: %q", line)
		}
	}
}
