package server

import (
	"context"
	"log"
	"time"

	"wayhop/internal/pbr"
)

// pbrKernelTable is the nft table the kernel PBR plane installs into (the pbr.Options.Table
// default; its own table so it coexists with `inet fw4`). Its presence is the sentinel the
// self-heal reconcile probes for.
const pbrKernelTable = "wayhop_pbr"

// reconcilePBR self-heals the kernel policy-based-routing plane. In fast/hybrid mode the
// daemon installs the `inet wayhop_pbr` nft table + ip-rules that steer routing-list traffic
// into its tunnel. But an out-of-band nft flush — an `fw4 reload`, an https-dns-proxy notrack
// regen, an adblock reload — can drop that table WITHOUT the daemon noticing: s.pbrPlan still
// holds the plan, so applyPBR's DeepEqual idempotency would skip a re-apply and the list
// traffic silently stops entering its tunnel (the "RU exit stopped working" incident).
//
// This probes the kernel for the table and, when it is gone while a plane is wanted, forcibly
// re-installs it. It keys off the KERNEL probe (not s.pbrPlan), so it heals both the drift case
// (daemon believes installed) and the never-came-up case (installed:false after a failed boot
// apply). No-op when the table is present, in tun/mixed mode, or in demo. Runs under pbrMu, so
// it serializes with applyPBR / the fail-safe restore and can never race a plane operation.
func (s *Server) reconcilePBR() {
	c := s.config()
	if c.Demo {
		return // demo daemons never touch nft/ip
	}
	s.pbrMu.Lock()
	defer s.pbrMu.Unlock()
	if s.pbrRunner == nil {
		return
	}
	if m := s.routingMode(c); m != "fast" && m != "hybrid" {
		return // tun/mixed route via the sing-box TUN — there is no kernel plane to heal
	}
	// The plane that SHOULD be installed: the one we last installed (repairs a drift where the
	// daemon still believes it is up), or — if we believe nothing is installed (installed:false,
	// e.g. a failed boot apply) — a fresh compile of the store, so that state also heals.
	desired := s.pbrPlan
	if desired == nil {
		p := s.store.Profile()
		fresh, _, err := pbr.Compile(&p, s.pbrCompileOptions(c))
		if err != nil || fresh == nil || len(fresh.Zones) == 0 {
			return // no lists to route, or a compile error — nothing to (re)install
		}
		desired = fresh
	}
	if len(desired.Zones) == 0 {
		return
	}
	// Kernel probe: the plane is physically present iff its nft table exists. `nft list table`
	// exits non-zero (→ error) when the table is absent — the exact out-of-band-flush signature.
	if _, err := s.pbrRunner.Run("", "nft", "list", "table", "inet", pbrKernelTable); err == nil {
		return // table present — nothing to heal
	}
	// Table gone while a plane is wanted → force a real re-install. Teardown first clears any
	// surviving ip-rules/routes (only the nft table was flushed); apply rebuilds table + rules.
	// This deliberately bypasses applyPBR's DeepEqual skip, which an out-of-band flush defeats.
	_ = desired.Teardown(s.pbrRunner, pbr.Options{})
	if err := desired.Apply(s.pbrRunner, pbr.Options{}); err != nil {
		_ = desired.Teardown(s.pbrRunner, pbr.Options{})
		s.pbrPlan = nil // indeterminate — let the next apply/reconcile cleanly reinstall
		log.Printf("pbr reconcile: kernel PBR re-install failed: %v", err)
		return
	}
	s.pbrPlan = desired
	log.Printf("pbr reconcile: kernel PBR table was missing — re-installed %d zone(s)", len(desired.Zones))
}

// PBRReconcileLoop periodically runs reconcilePBR to self-heal the kernel PBR plane after an
// out-of-band nft flush. 30s cadence: the healthy-path probe is a cheap `nft list table`, and a
// flushed plane means routing-list traffic silently leaves via the wrong path until rebuilt, so
// fast detection matters. Stops on ctx cancellation (daemon shutdown).
func (s *Server) PBRReconcileLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.reconcilePBR()
		}
	}
}
