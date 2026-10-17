package server

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/awg"
	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/platform"
)

// Handler scripts that name the 3.x options as the community amneziawg.sh does: before 3.0, with the
// 3.0 settings, and with the 3.1 switches too.
const (
	awgHandler2  = "proto_amneziawg_init_config() { proto_config_add_string awg_jc; }\n"
	awgHandler30 = awgHandler2 + "awg_header_protection_key awg_content_padding_addition awg_rekey_after_time " +
		"awg_rekey_timeout awg_reject_after_time awg_keepalive_timeout awg_max_handshake_attempts\n"
	awgHandler31 = awgHandler30 + "awg_random_trailers awg_disable_cookies\n"
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestResolveAWGKernel(t *testing.T) {
	const mod = "version=3.1.20260906;srcversion=ABC;coresize=98304"
	ok := func(g awg.Generation) awg.Probe { return awg.Probe{Kernel: g, GenlVersion: 3, TUN: true} }
	failed := awg.Probe{Err: "netlink recv: resource temporarily unavailable", TUN: true}
	kept31 := &awgKernelCaptureV1{Generation: awg.Gen31, HandlerSHA256: sha256Hex(awgHandler31), Module: mod}
	cases := []struct {
		name           string
		probe          awg.Probe
		handler        string
		handlerPresent bool
		module         string
		modulePresent  bool
		previous       *awgKernelCaptureV1
		want           awg.Generation
		wantKept       bool
	}{
		{"3.1 module, 3.1 handler", ok(awg.Gen31), awgHandler31, true, mod, true, nil, awg.Gen31, false},
		{"3.1 module, 3.0 handler", ok(awg.Gen31), awgHandler30, true, mod, true, nil, awg.Gen30, false},
		{"3.1 module, pre-3.0 handler", ok(awg.Gen31), awgHandler2, true, mod, true, nil, awg.Gen2, false},
		{"3.0 module, 3.1 handler", ok(awg.Gen30), awgHandler31, true, mod, true, nil, awg.Gen30, false},
		{"no module, 3.1 handler", ok(awg.GenNone), awgHandler31, true, "", false, nil, awg.GenNone, false},
		{"3.1 module, no handler", ok(awg.Gen31), "", false, mod, true, nil, awg.GenNone, false},
		{"an answering probe overrules the last Apply", ok(awg.Gen2), awgHandler31, true, mod, true, kept31, awg.Gen2, false},
		{"probe failed, nothing applied before", failed, awgHandler31, true, mod, true, nil, awg.GenNone, false},
		{"probe failed, module and handler unchanged", failed, awgHandler31, true, mod, true, kept31, awg.Gen31, true},
		{"probe failed, module unloaded", failed, awgHandler31, true, "", false, kept31, awg.GenNone, false},
		{"probe failed, module replaced", failed, awgHandler31, true, "version=3.0.20260805;srcversion=DEF", true, kept31, awg.GenNone, false},
		{"probe failed, handler changed", failed, awgHandler30, true, mod, true, kept31, awg.GenNone, false},
		{"probe failed, handler removed", failed, "", false, mod, true, kept31, awg.GenNone, false},
		{"probe failed, the last Apply had no module", failed, awgHandler31, true, mod, true,
			&awgKernelCaptureV1{Generation: awg.GenNone, HandlerSHA256: sha256Hex(awgHandler31), Module: mod}, awg.GenNone, false},
		{"probe failed, the last Apply could not identify the module", failed, awgHandler31, true, "", true,
			&awgKernelCaptureV1{Generation: awg.Gen31, HandlerSHA256: sha256Hex(awgHandler31)}, awg.GenNone, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := resolveAWGKernel(c.probe, []byte(c.handler), c.handlerPresent, c.module, c.modulePresent, c.previous)
			if got.Generation != c.want || got.Kept != c.wantKept {
				t.Fatalf("got %+v, want generation %s kept=%v", got, c.want, c.wantKept)
			}
			// The evidence recorded is always what was read now, so a kept value is compared afresh
			// next time rather than carried forward blind.
			if c.handlerPresent != (got.HandlerSHA256 != "") || (c.handlerPresent && got.HandlerSHA256 != sha256Hex(c.handler)) {
				t.Errorf("handler digest %q for present=%v", got.HandlerSHA256, c.handlerPresent)
			}
			if c.modulePresent && got.Module != c.module || !c.modulePresent && got.Module != "" {
				t.Errorf("module identity %q, read %q present=%v", got.Module, c.module, c.modulePresent)
			}
			if (c.probe.Err != "") != (got.ProbeError != "") {
				t.Errorf("probe error %q for probe %+v", got.ProbeError, c.probe)
			}
		})
	}
}

func TestAWGModuleIdentity(t *testing.T) {
	if id, present := awgModuleIdentity(filepath.Join(t.TempDir(), "absent")); present || id != "" {
		t.Errorf("absent module: %q present=%v", id, present)
	}
	dir := t.TempDir()
	if id, present := awgModuleIdentity(dir); !present || id != "" {
		t.Errorf("module with nothing to say: %q present=%v", id, present)
	}
	for name, v := range map[string]string{"version": "3.1.20260906\n", "srcversion": "ABC\n", "coresize": "98304\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if id, _ := awgModuleIdentity(dir); id != "version=3.1.20260906;srcversion=ABC;coresize=98304" {
		t.Errorf("identity %q", id)
	}
}

// awgKernelServer is an OpenWrt router whose probe, netifd handler and module answer as given, with the
// last Apply's materialization committed.
func awgKernelServer(probe awg.Probe, handler string, module string, last *executionMaterializationV1) *Server {
	cfg := *config.Default()
	s := &Server{cfg: &cfg, platformOf: func() platform.Platform { return platform.OpenWrt },
		awgProbeOf: func() awg.Probe { return probe },
		awgKernelReadsOf: &awgKernelReads{
			handler: func() ([]byte, bool) { return []byte(handler), handler != "" },
			module:  func() (string, bool) { return module, module != "" },
		}}
	s.applyState.loaded = true
	if last != nil {
		s.applyState.rec = applyStateRecord{Committed: &appliedRevision{Rev: "r1", Materialization: *last}}
	}
	return s
}

func TestAWGKernelCaptureForAsksOnlyOpenWrt(t *testing.T) {
	s := awgKernelServer(awg.Probe{Kernel: awg.Gen31, GenlVersion: 3}, awgHandler31, "version=1", nil)
	if got := s.awgKernelCaptureFor(platform.OpenWrt, s.awgHostProbe()); got.Generation != awg.Gen31 {
		t.Errorf("OpenWrt: %+v", got)
	}
	if got := s.awgKernelCaptureFor(platform.Keenetic, s.awgHostProbe()); got != (awgKernelCaptureV1{}) {
		t.Errorf("KeeneticOS ignores the module, so nothing is captured: %+v", got)
	}
	s.cfg.Demo = true
	if got := s.awgKernelGeneration(); got != awg.GenNone {
		t.Errorf("the demo's router is synthetic: %s", got)
	}
}

// The Apply path end to end: a 3.1 connection compiled native with a 3.1 module stays native when the
// next Apply's probe fails while the module and the handler are what they were, and is refused as a move
// (not silently rewritten) once the module is gone.
func TestApplyKeepsANativeAWG31ConnectionThroughAFailedProbe(t *testing.T) {
	desired, host, capture := executionNativeTestTuple(t)
	endpoint := awg3Endpoint("ep-native")
	endpoint.Params["disable_cookies"] = true
	desired.Profile.Endpoints = []model.Endpoint{endpoint}
	const mod = "version=3.1.20260906;srcversion=ABC"

	first := capture
	ok := awgKernelServer(awg.Probe{Kernel: awg.Gen31, GenlVersion: 3, GenlMaxAttr: 34, TUN: true}, awgHandler31, mod, nil)
	k := ok.awgKernelCaptureFor(platform.OpenWrt, ok.awgHostProbe())
	first.AWGKernel = &k
	m, warnings, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host}, native: &first})
	if err != nil || m.Native == nil {
		t.Fatalf("materialize with a 3.1 module: native=%v err=%v warnings=%q", m.Native != nil, err, warnings)
	}
	target := m.Native.Delta.Reconcile.Target
	if len(target.OpenWrt) != 1 || target.Decisions[0].Path != nativeplan.PathNativeCreate {
		t.Fatalf("a 3.1 module and handler must carry the connection natively: %+v", target.Decisions)
	}
	if m.Native.AWGKernel == nil || m.Native.AWGKernel.Generation != awg.Gen31 || m.Native.AWGKernel.Module != mod {
		t.Fatalf("the capture is persisted with the materialization: %+v", m.Native.AWGKernel)
	}

	failed := awg.Probe{Err: "netlink recv: timed out", TUN: true}
	for name, tc := range map[string]struct {
		module, handler string
		wantErr         bool
	}{
		"module and handler unchanged": {mod, awgHandler31, false},
		"module gone":                  {"", awgHandler31, true},
		"handler replaced":             {mod, awgHandler30 + "# rebuilt\n", true},
	} {
		t.Run(name, func(t *testing.T) {
			s := awgKernelServer(failed, tc.handler, tc.module, &m)
			again := capture
			k := s.awgKernelCaptureFor(platform.OpenWrt, s.awgHostProbe())
			again.AWGKernel = &k
			next, _, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host},
				native: &again, previous: &m})
			if !tc.wantErr {
				if err != nil || next.Native == nil || len(next.Native.Delta.Reconcile.Target.OpenWrt) != 1 {
					t.Fatalf("a failed probe must not move a working native connection: err=%v", err)
				}
				if !next.Native.AWGKernel.Kept || next.Native.AWGKernel.Generation != awg.Gen31 {
					t.Errorf("kept capture %+v", next.Native.AWGKernel)
				}
				return
			}
			stage, detail, _ := materializeFailure(err)
			if err == nil || stage != "native" || !strings.Contains(detail, "would move") {
				t.Fatalf("with nothing proving the generation, the connection is a refused move: err=%v detail=%q", err, detail)
			}
		})
	}
}

// The review asks with the same generation, so a module upgrade under a connection the engine ran is the
// move finding, which now says what moved it.
func TestReviewNamesTheModuleUpgradeAsTheMove(t *testing.T) {
	e := awg3Endpoint("m")
	last := &executionMaterializationV1{SchemaVersion: ExecutionSnapshotSchemaV1,
		Native: &executionNativeMaterializationV1{Delta: executionNativeDeltaV1{Reconcile: nativeplan.Reconciliation{
			Platform: platform.OpenWrt,
			Target: &nativeplan.Plan{Platform: platform.OpenWrt, Decisions: []nativeplan.EndpointDecision{{
				EndpointID: e.ID, Protocol: model.ProtoAmneziaWG, Path: nativeplan.PathEnginePlugin, Interface: "wr-m"}}},
		}}}}
	findings := func(probe awg.Probe, handler string) map[string]PlanFinding {
		s := awgKernelServer(probe, handler, "version=1", last)
		s.binaryPresentOf = func(string) bool { return true }
		out := map[string]PlanFinding{}
		for _, f := range s.endpointFindings(model.Profile{Endpoints: []model.Endpoint{e}}, openWrtAWGCapabilities()) {
			out[f.ID] = f
		}
		return out
	}
	move, ok := findings(awg.Probe{Kernel: awg.Gen31, GenlVersion: 3, GenlMaxAttr: 34}, awgHandler31)["endpoint.amneziawg.move"]
	if !ok || move.Requested != "OpenWrt's own AmneziaWG" ||
		!strings.Contains(move.Detail, "It moves because the router's AmneziaWG kernel module is generation 3.1") {
		t.Errorf("move after the module upgrade: %+v", move)
	}
	// A 3.1 module behind a handler written before 3.0 carries nothing more: no move, the lane keeps it.
	got := findings(awg.Probe{Kernel: awg.Gen31, GenlVersion: 3, GenlMaxAttr: 34}, awgHandler2)
	if _, moved := got["endpoint.amneziawg.move"]; moved {
		t.Errorf("an old handler caps the generation, so the connection stays on the engine: %+v", got)
	}
	if _, lane := got["endpoint.amneziawg.userspace"]; !lane {
		t.Errorf("the lane note is missing: %+v", got)
	}
}

// The handler WayHop's own amneziawg-tools package installs passes every 3.1 option on, so with a 3.1
// module the capture lets OpenWrt's own interfaces carry 3.1.
func TestAWGKernelWithTheShippedHandler(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "packaging", "awg", "openwrt", "amneziawg-tools", "files", "amneziawg.sh"))
	if err != nil {
		t.Fatal(err)
	}
	got := resolveAWGKernel(awg.Probe{Kernel: awg.Gen31, GenlVersion: 3, GenlMaxAttr: 34}, script, true, "version=1", true, nil)
	if got.Generation != awg.Gen31 {
		t.Errorf("the shipped handler caps the generation at %s", got.Generation)
	}
}
