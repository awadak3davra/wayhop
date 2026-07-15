package server

import (
	"errors"
	"strings"
	"testing"

	"wayhop/internal/pbr"
)

func countRRCalls(rr *pbr.RecordRunner, substr string) int {
	n := 0
	for _, c := range rr.Calls {
		if strings.Contains(c, substr) {
			n++
		}
	}
	return n
}

// probeFail makes the kernel-table probe (`nft list table inet wayhop_pbr`) report the table
// gone, while leaving teardown/apply/ip calls untouched (they don't contain "list table").
func probeFail() map[string]error {
	return map[string]error{"list table inet " + pbrKernelTable: errors.New("No such file or directory")}
}

// TestReconcilePBR_SelfHealsFlushedTable: after the kernel `wayhop_pbr` table is flushed
// out-of-band (the probe reports it gone) while the daemon still believes the plane is
// installed, reconcilePBR forces a real re-install (a fresh `nft -f -`) and keeps the plan —
// the recovery a bare applyPBR would skip via DeepEqual idempotency. And when the table is
// present it must NOT re-apply (no churn).
func TestReconcilePBR_SelfHealsFlushedTable(t *testing.T) {
	s, rr := pbrApplyServer(t) // RoutingMode=hybrid, RecordRunner, Demo=false
	seedVoWiFi(t, s)
	p := s.store.Profile()
	plan, _, err := pbr.Compile(&p, pbr.Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if err := s.applyPBR(plan); err != nil {
		t.Fatalf("applyPBR: %v", err)
	}
	if s.pbrPlan == nil {
		t.Fatal("precondition: a plane must be installed")
	}

	// Out-of-band flush: the probe now errors (table absent).
	rr.Fail = probeFail()
	before := countRRCalls(rr, "nft -f -")
	s.reconcilePBR()
	if got := countRRCalls(rr, "nft -f -"); got <= before {
		t.Errorf("reconcile did not re-install the flushed table: nft -f - count %d (was %d)", got, before)
	}
	if s.pbrPlan == nil {
		t.Error("reconcile must keep the plane installed after healing")
	}

	// Healthy path: probe succeeds → reconcile must NOT re-apply.
	rr.Fail = nil
	before2 := countRRCalls(rr, "nft -f -")
	s.reconcilePBR()
	if got := countRRCalls(rr, "nft -f -"); got != before2 {
		t.Errorf("reconcile re-applied on a present table (churn): %d != %d", got, before2)
	}
}

// TestReconcilePBR_HealsFromUninstalled: the incident state — the daemon believes nothing is
// installed (s.pbrPlan == nil, installed:false) in fast/hybrid with routing lists configured
// and no kernel table. Reconcile must compile the store and install the plane fresh.
func TestReconcilePBR_HealsFromUninstalled(t *testing.T) {
	s, rr := pbrApplyServer(t)
	seedVoWiFi(t, s)
	s.pbrPlan = nil // installed:false
	rr.Fail = probeFail()

	before := countRRCalls(rr, "nft -f -")
	s.reconcilePBR()
	if got := countRRCalls(rr, "nft -f -"); got <= before {
		t.Errorf("reconcile did not install the plane from the uninstalled state: %d (was %d)", got, before)
	}
	if s.pbrPlan == nil {
		t.Error("reconcile must install + record the plane")
	}
}

// TestReconcilePBR_SkipsDemoAndTunMixed: reconcile must never touch nft in demo, and must be a
// no-op in tun/mixed mode (no kernel plane exists there).
func TestReconcilePBR_SkipsDemoAndTunMixed(t *testing.T) {
	// Demo: even with a flushed-probe and a plan, reconcile must not run any nft.
	s, rr := pbrApplyServer(t)
	seedVoWiFi(t, s)
	s.cfg.Demo = true
	rr.Fail = probeFail()
	s.reconcilePBR()
	if len(rr.Calls) != 0 {
		t.Errorf("demo reconcile must issue no runner calls, got %v", rr.Calls)
	}

	// tun mode: no kernel plane → no-op regardless of the probe.
	s2, rr2 := pbrApplyServer(t)
	seedVoWiFi(t, s2)
	s2.cfg.RoutingMode = "tun"
	rr2.Fail = probeFail()
	s2.reconcilePBR()
	if len(rr2.Calls) != 0 {
		t.Errorf("tun-mode reconcile must issue no runner calls, got %v", rr2.Calls)
	}
}
