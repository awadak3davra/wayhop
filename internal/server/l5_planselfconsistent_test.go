package server

import "testing"

// TestPlanPlatformAgreesWithItsOwnVerdict (L5): one response must not answer the same question twice
// with different answers.
//
// The demo poses as a router that has the proxy core — platform.DemoCapabilities sets
// SingboxPresent, and the plan's verdict is computed from that pose. The platform block beside the
// verdict read the real machine instead, so a single /api/apply/plan carried:
//
//	"verdict": "ready"          (the pose: the core is there, nothing blocks Apply)
//	"core_available": false     (the machine: no sing-box here)
//
// Measured on the demo after pointing the default route at a group whose members the core carries:
// zero findings, and the Failover card for that same group reading "Not running: … the proxy core
// (sing-box) is not installed". A reader has no way to settle that, and neither does a gate.
func TestPlanPlatformAgreesWithItsOwnVerdict(t *testing.T) {
	s := dnsSeed(t)
	cfg := s.config()
	if !cfg.Demo {
		cfg.Demo = true
		s.cfg = &cfg
	}
	got := s.planPlatform()
	if !got.CoreAvailable || !got.CoreRunning {
		t.Errorf("in demo the platform block must report the core the way the verdict assumes it: %+v", got)
	}
	if got.Name != "demo" {
		t.Errorf("and must still name itself demo: %q", got.Name)
	}

	// Outside demo the block keeps reading the machine — that is its whole job there, and a pose that
	// leaked onto a real router would tell an operator their core is fine when it is missing.
	//
	// The manager is cleared so the expected answer is fixed rather than whatever the harness happened
	// to wire: an earlier version of this check was guarded on `s.singbox == nil`, which the harness
	// does not satisfy, so the mutation that made the pose unconditional passed it.
	real := s.config()
	real.Demo = false
	s.cfg = &real
	s.singbox = nil
	if off := s.planPlatform(); off.CoreAvailable || off.CoreRunning {
		t.Errorf("outside demo, with no core manager, the block must not invent one: %+v", off)
	}
}
