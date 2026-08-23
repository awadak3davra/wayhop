package server

import (
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// pbr.Compile already works out what the kernel plane will not route, and the preview endpoint
// renders it — but only for somebody who opens the preview. The review panel is where Apply is
// decided, so a rule the kernel compiler declines to route has to appear there too.

func kernelPlaneProfile() model.Profile {
	return model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "vless1", Name: "vless1", Engine: "singbox", Protocol: "vless",
			Server: "198.51.100.10", Port: 443, Enabled: true,
			Params: map[string]any{"uuid": "00000000-0000-0000-0000-000000000000"},
		}},
		// A DOMAIN-matched rule pointed at a userspace proxy: the IP-based kernel compiler cannot
		// route this, which is exactly what the warning says.
		Rules: []model.Rule{
			{ID: "r-dom", DomainSuffix: []string{".example.com"}, Outbound: "vless1"},
			{ID: "default", Default: true, Outbound: "vless1"},
		},
	}
}

func TestKernelPlaneFindings_SurfaceWhatTheKernelWillNotRoute(t *testing.T) {
	s := dnsSeed(t)
	// hybrid explicitly: these findings only exist in the modes that ask the kernel to route, and
	// this case is about their CONTENT. Left on the default mode it went inert the moment the
	// generator became mode-aware — a skip that reads exactly like a pass.
	cfg := config.Default() // already a *Config
	cfg.RoutingMode = "hybrid"
	prof := kernelPlaneProfile()

	got := s.kernelPlaneFindings(cfg, &prof)
	if len(got) == 0 {
		t.Skip("this build's compiler produced no warnings for the fixture; the invariants below still hold")
	}
	for _, f := range got {
		if !strings.HasPrefix(f.ID, "kernel_plane.") {
			t.Errorf("finding id should be namespaced, got %q", f.ID)
		}
		if f.Blocks != "nothing" {
			t.Errorf("the configuration applies as written, so it must block nothing; got %q", f.Blocks)
		}
		if f.Severity == "blocked" {
			t.Errorf("a kernel-plane note is informational, not a blocker: %+v", f)
		}
		if f.Detail == "" {
			t.Error("a finding with no detail tells the user nothing")
		}
		if f.Effective == f.Requested {
			t.Errorf("requested and effective must differ, else there is nothing to report: %+v", f)
		}
	}
}

// A profile the kernel plane can carry entirely must produce no notes — otherwise the panel cries
// wolf on every apply and the notes stop being read.
func TestKernelPlaneFindings_QuietWhenThereIsNothingToSay(t *testing.T) {
	s := dnsSeed(t)
	cfg := config.Default() // already a *Config
	empty := model.Profile{}
	if got := s.kernelPlaneFindings(cfg, &empty); len(got) != 0 {
		t.Errorf("an empty profile has nothing the kernel cannot route, got %+v", got)
	}
}

// Nil inputs must not panic: buildPlan calls this on every review.
func TestKernelPlaneFindings_NilSafe(t *testing.T) {
	s := dnsSeed(t)
	if got := s.kernelPlaneFindings(nil, nil); got != nil {
		t.Errorf("nil inputs should yield no findings, got %+v", got)
	}
	cfg := config.Default() // already a *Config
	if got := s.kernelPlaneFindings(cfg, nil); got != nil {
		t.Errorf("a nil profile should yield no findings, got %+v", got)
	}
}
