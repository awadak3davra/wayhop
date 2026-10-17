package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"wayhop/internal/awg"
	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
)

// awgSwitchProfile: a and b run on amneziawg-go and the module now carries them, c is not running, d is
// set to run on amneziawg-go whatever the module can do.
func awgSwitchProfile() model.Profile {
	d := executionAWGEndpoint("d")
	d.AWGUserspace = true
	return model.Profile{Endpoints: []model.Endpoint{awg3Endpoint("a"), executionAWGEndpoint("b"), executionAWGEndpoint("c"), d}}
}

func awgRunning(ids ...string) func() []string { return func() []string { return ids } }

// After a kernel module install the connections still on amneziawg-go are named, with when they switch;
// nothing is said to switch on a probe that did not answer, or for a connection the operator put on
// amneziawg-go.
func TestAWGComponentSaysWhichConnectionsSwitch(t *testing.T) {
	module := awg.Probe{Kernel: awg.Gen31, GenlVersion: 3, GenlMaxAttr: 34, TUN: true}
	s := awgComponentServer(platform.Unknown, platform.CapabilitySet{}, module, false)
	s.awgUserspaceRunningOf = awgRunning("a", "b", "d")
	st := s.awgComponent(context.Background(), awgSwitchProfile())
	got := map[string]string{}
	for _, c := range st.Connections {
		got[c.ID] = c.Switch
	}
	if got["a"] != "kernel" || got["b"] != "kernel" || got["c"] != "" || got["d"] != "" {
		t.Errorf("switches %v", got)
	}
	if !strings.HasPrefix(st.Switching, "2 connections (a, b) still run on amneziawg-go") ||
		!strings.Contains(st.Switching, "the next time it starts") || !strings.HasSuffix(st.Switching, "Running tunnels are not moved.") {
		t.Errorf("note %q", st.Switching)
	}

	s.awgProbeOf = func() awg.Probe { return awg.Probe{Err: "netlink: timed out", TUN: true} }
	if st := s.awgComponent(context.Background(), awgSwitchProfile()); st.Switching != "" {
		t.Errorf("a failed probe reads as the kernel path; that is no switch: %q", st.Switching)
	}
	s.awgUserspaceRunningOf = awgRunning()
	s.awgProbeOf = func() awg.Probe { return module }
	if st := s.awgComponent(context.Background(), awgSwitchProfile()); st.Switching != "" {
		t.Errorf("nothing runs on amneziawg-go: %q", st.Switching)
	}
}

// On OpenWrt a connection the engine ran that OpenWrt's own AmneziaWG carries now is a move of two
// Applies, and the row says so instead of promising it at the next start.
func TestAWGComponentSaysAMoveTakesTwoApplies(t *testing.T) {
	e := awg3Endpoint("m")
	last := &executionMaterializationV1{SchemaVersion: ExecutionSnapshotSchemaV1,
		Native: &executionNativeMaterializationV1{Delta: executionNativeDeltaV1{Reconcile: nativeplan.Reconciliation{
			Platform: platform.OpenWrt,
			Target: &nativeplan.Plan{Platform: platform.OpenWrt, Decisions: []nativeplan.EndpointDecision{{
				EndpointID: e.ID, Protocol: model.ProtoAmneziaWG, Path: nativeplan.PathEnginePlugin, Interface: "wr-m"}}},
		}}}}
	s := awgKernelServer(awg.Probe{Kernel: awg.Gen31, GenlVersion: 3, GenlMaxAttr: 34, TUN: true}, awgHandler31, "version=1", last)
	s.caps.set = openWrtAWGCapabilities()
	s.caps.set.ProbedAt = time.Now()
	s.awgUserspaceRunningOf = awgRunning("m")
	st := s.awgComponent(context.Background(), model.Profile{Endpoints: []model.Endpoint{e}})
	if len(st.Connections) != 1 || st.Connections[0].Path != "native" || st.Connections[0].Switch != "native" ||
		!strings.Contains(st.Switching, "moving it takes two Applies") {
		t.Errorf("connections %+v, note %q", st.Connections, st.Switching)
	}
}

// The review says the same in its own idiom: an informational finding per connection, folded into one.
func TestReviewSaysWhichConnectionsSwitchToTheKernel(t *testing.T) {
	findings := func(p platform.Platform, probe awg.Probe) []PlanFinding {
		s := awgComponentServer(p, platform.CapabilitySet{}, probe, false)
		s.applyState.loaded = true
		s.binaryPresentOf = func(string) bool { return true }
		s.awgUserspaceRunningOf = awgRunning("a", "b", "d")
		var out []PlanFinding
		for _, f := range s.endpointFindings(awgSwitchProfile(), platform.CapabilitySet{}) {
			if f.ID == "endpoint.amneziawg.kernel_switch" {
				out = append(out, f)
			}
		}
		return out
	}
	module := awg.Probe{Kernel: awg.Gen31, GenlVersion: 3, GenlMaxAttr: 34, TUN: true}
	got := findings(platform.Unknown, module)
	if len(got) != 2 || got[0].Item != "a" || got[1].Item != "b" || got[0].Blocks != platform.BlocksNothing ||
		!strings.Contains(got[0].Detail, "An Apply that leaves it unchanged does not restart it") {
		t.Fatalf("findings %+v", got)
	}
	folded := foldFindings(got, nil)
	if len(folded) != 1 || folded[0].Count != 2 || folded[0].AckRequired || folded[0].Code != "AWG_KERNEL_SWITCH_PENDING" {
		t.Errorf("folded %+v", folded)
	}
	if got := findings(platform.Unknown, awg.Probe{Err: "netlink: timed out", TUN: true}); len(got) != 0 {
		t.Errorf("failed probe: %+v", got)
	}
	// KeeneticOS's module is the firmware's: WayHop's engine never switches onto it.
	if got := findings(platform.Keenetic, module); len(got) != 0 {
		t.Errorf("KeeneticOS: %+v", got)
	}
}

// While netifd has not read the AmneziaWG handler, an Apply that writes OpenWrt's own AmneziaWG
// interfaces needs an acknowledgement; one that writes none does not hear about it.
func TestReviewWarnsWhileNetifdRunsAnOldHandler(t *testing.T) {
	review := func(e model.Endpoint, stale bool) *PlanFinding {
		s := awgKernelServer(awg.Probe{Kernel: awg.GenNone, TUN: true}, awgHandler31, "", nil)
		s.binaryPresentOf = func(string) bool { return true }
		s.netifdStaleOf = func() (bool, bool) { return stale, true }
		for _, f := range s.endpointFindings(model.Profile{Endpoints: []model.Endpoint{e}}, openWrtAWGCapabilities()) {
			if f.ID == "endpoint.amneziawg.netifd_restart" {
				return &f
			}
		}
		return nil
	}
	f := review(executionAWGEndpoint("n"), true)
	if f == nil || f.Blocks != platform.BlocksFeature || !strings.Contains(f.Remedy, "Restart the network service") {
		t.Fatalf("finding %+v", f)
	}
	if folded := foldFindings([]PlanFinding{*f}, nil); !folded[0].AckRequired {
		t.Errorf("not acknowledged: %+v", folded[0])
	}
	if f := review(executionAWGEndpoint("n"), false); f != nil {
		t.Errorf("netifd read the handler: %+v", f)
	}
	// With no module the 3.x connection stays on the engine: nothing native is written.
	if f := review(awg3Endpoint("u"), true); f != nil {
		t.Errorf("an engine-only Apply: %+v", f)
	}
}
