package server

import (
	"context"
	"strings"
	"testing"

	"wayhop/internal/awg"
	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// The generation the router carries without amneziawg-go: its own tunnels up to what their writer
// expresses, or the kernel module where WayHop's engine may use it - whichever is newer.
func TestAWGBuiltin(t *testing.T) {
	for _, c := range []struct {
		name      string
		probe     awg.Probe
		firmware  bool
		native    bool
		nativeGen awg.Generation
		want      string
	}{
		{"OpenWrt: UCI writer and module both generation 2", awg.Probe{Kernel: awg.Gen2}, false, true, awg.Gen2, "2"},
		{"OpenWrt: a 3.1 module beats the UCI writer", awg.Probe{Kernel: awg.Gen31}, false, true, awg.Gen2, "3.1"},
		{"KeeneticOS: NDM's writer; the firmware's module is not WayHop's", awg.Probe{Kernel: awg.Gen31}, true, true, awg.Gen2, "2"},
		{"KeeneticOS without AmneziaWG in the firmware", awg.Probe{}, true, false, awg.Gen2, "none"},
		{"a generic router with a 3.0 module", awg.Probe{Kernel: awg.Gen30}, false, false, awg.GenNone, "3.0"},
		{"no module, no native tunnels", awg.Probe{}, false, false, awg.GenNone, "none"},
		{"an unanswered probe and nothing else", awg.Probe{Err: "no netlink"}, false, false, awg.GenNone, "unknown"},
		{"an unanswered probe beside a native writer", awg.Probe{Err: "no netlink"}, false, true, awg.Gen2, "2"},
	} {
		if got := awgBuiltin(c.probe, c.firmware, c.native, c.nativeGen); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// A generation-2 router is not "carrying AmneziaWG itself, nothing to install": the component is
// offered, as optional, and a connection set to run on it makes it needed instead.
func TestAWGComponentOffersTheNewestGeneration(t *testing.T) {
	gen2 := awg.Probe{Kernel: awg.Gen2, TUN: true, GenlVersion: 2, GenlMaxAttr: 25}
	chosen := executionAWGEndpoint("chosen")
	chosen.AWGUserspace = true

	s := awgComponentServer(platform.OpenWrt, openWrtAWGCapabilities(), gen2, false)
	st := s.awgComponent(context.Background(), model.Profile{Endpoints: []model.Endpoint{executionAWGEndpoint("g1")}})
	if st.Builtin != "2" || st.Newest != "3.1" || !st.Optional || st.Needed || awgRuns(st)["g1"] != "native" {
		t.Errorf("OpenWrt, generation 2, a native connection: %+v", st)
	}
	if awgCarriedByKernel(true, st) {
		t.Error("a generation-2 router was reported as carrying AmneziaWG with nothing to install")
	}

	st = s.awgComponent(context.Background(), model.Profile{Endpoints: []model.Endpoint{chosen}})
	run := st.Connections[0]
	if !st.Needed || st.Optional || run.Path != "userspace" || !strings.Contains(run.Reason, "set to run on amneziawg-go") {
		t.Errorf("OpenWrt, a connection set to amneziawg-go: %+v", st)
	}

	st = awgComponentServer(platform.Keenetic, keeneticAWGCapabilities(), gen2, false).
		awgComponent(context.Background(), model.Profile{})
	if st.Builtin != "2" || !st.Optional {
		t.Errorf("KeeneticOS: %+v", st)
	}

	// Already the newest generation: nothing to offer, and "carries it itself" is true.
	st = awgComponentServer(platform.Unknown, platform.CapabilitySet{}, awg.Probe{Kernel: awg.Gen31, TUN: true}, false).
		awgComponent(context.Background(), model.Profile{})
	if st.Builtin != "3.1" || st.Optional || !awgCarriedByKernel(true, st) {
		t.Errorf("a 3.1 module: %+v", st)
	}

	// No /dev/net/tun: amneziawg-go could not run, so it is not offered.
	st = awgComponentServer(platform.Unknown, platform.CapabilitySet{}, awg.Probe{Kernel: awg.Gen2}, false).
		awgComponent(context.Background(), model.Profile{})
	if st.Optional {
		t.Errorf("offered without /dev/net/tun: %+v", st)
	}
}

// The review states the choice where it acts: in the userspace lane on KeeneticOS and OpenWrt, and on
// the generic path, where the only thing worth saying is that amneziawg-go is missing.
func TestReviewAWGEngineChoice(t *testing.T) {
	chosen := executionAWGEndpoint("chosen")
	chosen.AWGUserspace = true
	findings := func(p platform.Platform, capset platform.CapabilitySet, installed bool) map[string]PlanFinding {
		cfg := *config.Default()
		s := &Server{cfg: &cfg, platformOf: func() platform.Platform { return p },
			binaryPresentOf: func(name string) bool { return installed && name == "amneziawg-go" }}
		s.applyState.loaded = true
		out := map[string]PlanFinding{}
		for _, f := range s.endpointFindings(model.Profile{Endpoints: []model.Endpoint{chosen}}, capset) {
			out[f.ID] = f
		}
		return out
	}
	for name, c := range map[string]struct {
		p      platform.Platform
		capset platform.CapabilitySet
	}{
		"KeeneticOS": {platform.Keenetic, keeneticAWGCapabilities()},
		"OpenWrt":    {platform.OpenWrt, openWrtAWGCapabilities()},
	} {
		if f := findings(c.p, c.capset, false)["endpoint.engine.amneziawg_go"]; f.Blocks != platform.BlocksFeature ||
			!strings.Contains(f.Detail, "set to run on amneziawg-go") {
			t.Errorf("%s, not installed: %+v", name, f)
		}
		f := findings(c.p, c.capset, true)["endpoint.amneziawg.userspace"]
		if f.Reason != platform.ReasonOperatorChoice || f.Blocks != platform.BlocksNothing || !strings.Contains(f.Remedy, "Automatic") {
			t.Errorf("%s, installed: %+v", name, f)
		}
	}

	missing := findings(platform.Unknown, platform.CapabilitySet{}, false)["endpoint.engine.amneziawg_go"]
	if missing.Blocks != platform.BlocksFeature || missing.Reason != platform.ReasonMissingBinary ||
		!strings.Contains(missing.Detail, "set to run on amneziawg-go") {
		t.Errorf("generic path, not installed: %+v", missing)
	}
	if got := findings(platform.Unknown, platform.CapabilitySet{}, true); len(got) != 0 {
		t.Errorf("generic path, installed: %+v; the plugin runs it and there is nothing to report", got)
	}
}

// Only WayHop's own AmneziaWG connection can be moved onto amneziawg-go; on anything else the flag
// would be a setting nothing reads.
func TestValidateAWGUserspace(t *testing.T) {
	adopted := executionAWGEndpoint("adopted")
	adopted.Engine, adopted.Owner = model.EngineExternal, model.OwnerExternal
	adopted.Params = map[string]any{"interface": "awg0"}
	proxy := model.Endpoint{ID: "proxy", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "192.0.2.30",
		Port: 443, Enabled: true, Params: map[string]any{"uuid": "00000000-0000-0000-0000-000000000000"}}
	for name, e := range map[string]model.Endpoint{"an adopted tunnel": adopted, "a sing-box proxy": proxy} {
		e.AWGUserspace = true
		if err := (&model.Profile{Endpoints: []model.Endpoint{e}}).Validate(); err == nil || !strings.Contains(err.Error(), "awg_userspace") {
			t.Errorf("%s: %v, want awg_userspace refused", name, err)
		}
	}
	chosen := executionAWGEndpoint("chosen")
	chosen.AWGUserspace = true
	if err := (&model.Profile{Endpoints: []model.Endpoint{chosen}}).Validate(); err != nil {
		t.Errorf("a WayHop AmneziaWG connection: %v", err)
	}
}
