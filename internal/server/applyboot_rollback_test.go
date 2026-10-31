package server

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
)

// A Test window that a power loss or a daemon restart cut short leaves its configuration on the
// router: on OpenWrt every UCI write is committed as it is made, and a restart leaves everything
// running. Boot used to drop the record of it and converge the committed plan additively, which
// cannot undo it — on OpenWrt the committed plan's preflight found the Test's values and refused
// before sing-box was started at all.

// applyboot_openWrtRouter is an OpenWrt router whose committed state created one AmneziaWG tunnel and
// whose Test then moved that tunnel's endpoint: the UCI on "flash" holds the Test's values.
func applyboot_openWrtRouter(t *testing.T) (s *Server, fake *applytest_ops, runner *exactOpenWrtRunner, iface string) {
	t.Helper()
	desired, host, capture := executionNativeTestTuple(t)
	committedArt, err := buildExecutionNativeArtifactV1(desired, host, capture, nil)
	if err != nil {
		t.Fatal(err)
	}
	runner = &exactOpenWrtRunner{network: capture.NetworkUCI}
	adapter, err := newExactOpenWrtNativeAdapter(runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.prepare(context.Background(), committedArt.Plan); err != nil {
		t.Fatal(err)
	}
	iface = committedArt.Plan.OpenWrt[0].Iface
	// The fake runner does not model the firewall commit; the zone holds the tunnel from here on.
	runner.firewall = capture.FirewallUCI + "firewall.@zone[0].network='" + iface + "'\n"

	profile := desired.Profile
	profile.Endpoints = append(profile.Endpoints[:0:0], profile.Endpoints...)
	profile.Endpoints[0].Server = "198.51.100.77"
	tested, err := newDesiredSnapshot(desired.Config, profile, desired.ProfileGen+1)
	if err != nil {
		t.Fatal(err)
	}
	probe := hostTestProbe(tested)
	probe.RawCapabilities.Native["amneziawg"] = true
	delete(probe.RawCapabilities.Installable, "amneziawg")
	probe.RawCapabilities.NetifdProtos["amneziawg"] = true
	testedHost, err := newHostSnapshot(tested, probe, nil)
	if err != nil {
		t.Fatal(err)
	}
	testedCapture := capture
	testedCapture.NetworkUCI, testedCapture.FirewallUCI = runner.network, runner.firewall
	testedArt, err := buildExecutionNativeArtifactV1(tested, testedHost, testedCapture, &committedArt.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.prepare(context.Background(), testedArt.Plan); err != nil {
		t.Fatal(err)
	}
	if got := applyboot_endpointHost(runner, iface); got != "198.51.100.77" {
		t.Fatalf("setup: the Test's endpoint is not on flash: %q", got)
	}

	s, fake = applytest_server(t)
	native, err := newExactNativePlatformAdapter(adapter, nil)
	if err != nil {
		t.Fatal(err)
	}
	ops := fake.ops()
	ops.prepareNative, ops.commitNative, ops.abortNative = native.prepare, native.commit, native.abort
	ops.persistNative, ops.postcheckNative = native.persist, native.postcheck
	s.execOps = &ops
	s.uciReader = func() (string, string, error) { return runner.network, runner.firewall, nil }

	materialization := func(plan nativeplan.Plan) executionMaterializationV1 {
		m := applytest_materialization(ExecutionEnsurePresent, ExecutionEnsureAbsent, ExecutionEnsureAbsent, true)
		m.Native.Delta.Reconcile = nativeplan.Reconciliation{Platform: platform.OpenWrt, Target: &plan}
		return *m
	}
	s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1, Materialization: materialization(committedArt.Plan)})
	s.recordApplied(false, &appliedRevision{Rev: "tested", At: 2, Materialization: materialization(testedArt.Plan)})
	return s, fake, runner, iface
}

func applyboot_endpointHost(runner *exactOpenWrtRunner, iface string) string {
	section := iface + "_peer1"
	host := ""
	for _, line := range strings.Split(runner.network, "\n") {
		if v, ok := strings.CutPrefix(line, "network."+section+".endpoint_host="); ok {
			host = strings.Trim(v, "'") // the last write wins, as in uci
		}
	}
	return host
}

func TestBoot_RollsBackAnOpenWrtTestLeftOnFlash(t *testing.T) {
	s, fake, runner, iface := applyboot_openWrtRouter(t)

	cancelled, cancel := context.WithCancel(context.Background())
	cancel() // only the synchronous part of StartApply; the boot pass is driven below
	s.StartApply(cancelled, filepath.Join(s.applyStateDir, "config.json"))
	if s.liveRevision() == nil {
		t.Fatal("the Test is still on flash: boot must keep the record of it until it is rolled back")
	}
	fake.reset()
	s.convergeOnBoot(context.Background())

	if got := applyboot_endpointHost(runner, iface); got != "198.51.100.9" {
		t.Fatalf("the committed endpoint was not restored; UCI holds %q", got)
	}
	if calls := strings.Join(fake.snapshot(), ","); !strings.Contains(calls, "core:ensure_present") {
		t.Fatalf("boot never reached the core step: %v", calls)
	}
	if s.liveRevision() != nil {
		t.Error("a rollback that worked must end the live state")
	}
	if c := s.committedRevision(); c == nil || c.Rev != "committed" {
		t.Errorf("the committed state must survive: %+v", c)
	}
}

// The same rollback during the window: a Test that edited an endpoint could not be rolled back at all,
// because the committed plan's preflight compared the UCI to the interface as it was BEFORE the
// committed apply.
func TestRollbackTo_RevertsAnOpenWrtInterfaceTheTestModified(t *testing.T) {
	s, _, runner, iface := applyboot_openWrtRouter(t)
	live := s.liveRevision()
	if _, err := s.rollbackTo(context.Background(), s.productionExecOps(), s.committedRevision(), &live.Materialization); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got := applyboot_endpointHost(runner, iface); got != "198.51.100.9" {
		t.Fatalf("UCI holds %q after the rollback", got)
	}
}

// Someone else's edit after the Test is not the Test's to undo: the recorded plan's refusal stands.
func TestRollbackTo_KeepsAnOpenWrtEditNobodyRecorded(t *testing.T) {
	s, _, runner, iface := applyboot_openWrtRouter(t)
	runner.network += "network." + iface + "_peer1.endpoint_host='203.0.113.5'\n"
	live := s.liveRevision()
	if _, err := s.rollbackTo(context.Background(), s.productionExecOps(), s.committedRevision(), &live.Materialization); err == nil {
		t.Fatal("a rollback over an unrecorded edit must refuse")
	}
	if got := applyboot_endpointHost(runner, iface); got != "203.0.113.5" {
		t.Fatalf("the operator's edit was overwritten: %q", got)
	}
}

// A daemon restart leaves a Test running on any platform. With no committed revision (the first Apply
// was a Test) boot used to find "nothing to converge" and leave it running, unwatched and unrecorded.
func TestBoot_TearsDownATestLeftRunningByARestart(t *testing.T) {
	s, fake := applytest_server(t)
	s.recordApplied(false, &appliedRevision{Rev: "tested", At: 2, Materialization: applyboot_kernelMaterialization()})

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	s.StartApply(cancelled, filepath.Join(s.applyStateDir, "config.json"))
	s.convergeOnBoot(context.Background())

	calls := strings.Join(fake.snapshot(), ",")
	for _, want := range []string{"core:ensure_absent", "kernelTeardown"} {
		if !strings.Contains(calls, want) {
			t.Fatalf("boot did not tear the Test down (%s missing): %v", want, calls)
		}
	}
	if s.liveRevision() != nil {
		t.Error("a teardown that worked must end the live state")
	}
}

// A Keenetic daemon restart (same kernel boot) keeps NDM's running config, Test interfaces included:
// the next `system configuration save` would make them permanent. Only a reboot loses them.
func TestStartApply_KeeneticRestartKeepsTheTestForRollback(t *testing.T) {
	for _, tc := range []struct {
		name       string
		then, now  string
		wantRecord bool
	}{
		{name: "daemon restart", then: "boot-1", now: "boot-1", wantRecord: true},
		{name: "reboot", then: "boot-1", now: "boot-2", wantRecord: false},
		{name: "boot unknown", then: "", now: "boot-2", wantRecord: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := applytest_server(t)
			s.platformOf = func() platform.Platform { return platform.Keenetic }
			boot := tc.then
			s.bootIDOf = func() string { return boot }
			s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1, Materialization: applyboot_kernelMaterialization()})
			s.recordApplied(false, &appliedRevision{Rev: "tested", At: 2, Materialization: applyboot_kernelMaterialization()})
			boot = tc.now

			cancelled, cancel := context.WithCancel(context.Background())
			cancel()
			s.StartApply(cancelled, filepath.Join(s.applyStateDir, "config.json"))
			if got := s.liveRevision() != nil; got != tc.wantRecord {
				t.Fatalf("live kept = %v, want %v", got, tc.wantRecord)
			}
		})
	}
}

// Keep can reach the daemon before boot's rollback of the Test does (the panel and the bot answer as
// soon as it starts). The rollback then found the record replaced and returned, and nothing converged
// the revision Keep had just committed: after an OpenWrt reboot its UCI was on flash, but sing-box and
// the kernel plane were never started.
func TestBoot_ConvergesATestKeptBeforeItsRollback(t *testing.T) {
	s, fake := applytest_server(t)
	s.recordApplied(true, &appliedRevision{Rev: "committed", At: 1,
		Materialization: *applytest_materialization(ExecutionEnsureAbsent, ExecutionEnsureAbsent, ExecutionEnsureAbsent, false)})
	s.recordApplied(false, &appliedRevision{Rev: "tested", At: 2, Materialization: applyboot_kernelMaterialization()})

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	s.StartApply(cancelled, filepath.Join(s.applyStateDir, "config.json"))
	if s.bootLive == nil {
		t.Fatal("setup: boot should be about to roll the Test back")
	}
	if code, resp := s.applyConfirm(context.Background(), ""); code != http.StatusOK {
		t.Fatalf("Keep = %d %v", code, resp)
	}
	fake.reset()
	s.convergeOnBoot(context.Background())

	calls := strings.Join(fake.snapshot(), ",")
	for _, want := range []string{"core:ensure_present", "kernel:ensure_present"} {
		if !strings.Contains(calls, want) {
			t.Fatalf("boot did not converge the kept revision (%s missing): %v", want, calls)
		}
	}
	if c := s.committedRevision(); c == nil || c.Rev != "tested" {
		t.Errorf("the kept revision must stay committed: %+v", c)
	}
}
