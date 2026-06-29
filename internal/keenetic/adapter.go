package keenetic

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"velinx/internal/atomicfile"
	"velinx/internal/model"
	"velinx/internal/platform"
)

// Backend is the KeeneticOS implementation of platform.RoutingBackend. It compiles a profile
// to a native Plan (WireguardN interfaces + ip routes + a sing-box fallback for non-native
// protocols) and Deploys/Teardowns it over RCI + the Entware sing-box service. Stateful: it
// remembers the last applied Plan so Apply is idempotent — it tears the prior plan down
// before deploying the new one (NDM config is additive, so a plain re-apply would leak stale
// interfaces/routes).
//
// ⚠️ Apply/Teardown are DEVICE-WRITING (the research loop never calls them). Apply is the
// blunt path (replace + save); SafeApply (failsafe_apply.go) is the SAFE path — it deploys
// UNSAVED and arms a failsafe.Manager so a connectivity loss rolls back to the last-good plan
// (or reboots to the saved config). Cross-restart idempotency is handled by WithStatePath. On
// the device the RCIClient base is http://localhost.
type Backend struct {
	rci   *RCIClient
	run   Runner
	cOpt  CompileOptions
	aOpt  ApplyOptions
	sbOpt SingboxApplyOptions

	mu        sync.Mutex
	last      *Plan  // last CONFIRMED plan (the rollback target)
	candidate *Plan  // plan deployed-but-unconfirmed during a SafeApply window
	statePath string // persist last Plan here for cross-restart idempotency ("" = in-memory only)
}

// NewBackend builds the Keenetic routing backend from its device handles (an RCI client + a
// command Runner for the Entware sing-box service) and the compile/apply knobs.
func NewBackend(rci *RCIClient, run Runner, cOpt CompileOptions, aOpt ApplyOptions, sbOpt SingboxApplyOptions) *Backend {
	return &Backend{rci: rci, run: run, cOpt: cOpt, aOpt: aOpt, sbOpt: sbOpt}
}

// WithStatePath enables cross-restart idempotency: the last applied Plan is persisted to path
// after each Apply and reloaded here, so the FIRST Apply after a daemon restart still tears
// down the previously-applied config (the adapter otherwise only remembers in-memory). A
// corrupt/absent file is ignored (treated as "nothing applied yet"). Returns b for chaining.
func (b *Backend) WithStatePath(path string) *Backend {
	b.statePath = path
	if data, err := os.ReadFile(path); err == nil {
		var p Plan
		if json.Unmarshal(data, &p) == nil {
			b.last = &p
		}
	}
	return b
}

// persist writes the last applied Plan (best-effort) when state persistence is enabled.
func (b *Backend) persist() {
	if b.statePath == "" {
		return
	}
	if b.last == nil {
		_ = os.Remove(b.statePath)
		return
	}
	if data, err := json.Marshal(b.last); err == nil {
		_ = atomicfile.Write(b.statePath, data, 0o600)
	}
}

// Platform reports the platform this backend drives.
func (b *Backend) Platform() platform.Platform { return platform.Keenetic }

// Apply compiles the profile and deploys it, first tearing down the previously-applied plan
// so the result is idempotent. Save (if set in ApplyOptions) happens once, on the deploy.
func (b *Backend) Apply(ctx context.Context, p *model.Profile) error {
	plan, err := Compile(p, b.cOpt)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last != nil {
		// Remove the prior NDM config without saving (the deploy below saves once at the end).
		if err := b.last.Teardown(ctx, b.rci, ApplyOptions{}); err != nil {
			return fmt.Errorf("teardown prior plan: %w", err)
		}
	}
	if err := plan.Deploy(ctx, b.rci, b.run, b.aOpt, b.sbOpt); err != nil {
		return err
	}
	b.last = plan
	b.persist()
	return nil
}

// Teardown removes the last-applied plan's routing (NDM `no` commands over RCI). The sing-box
// fallback config is left in place — a subsequent Apply rewrites it wholesale.
func (b *Backend) Teardown(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last == nil {
		return nil
	}
	if err := b.last.Teardown(ctx, b.rci, b.aOpt); err != nil {
		return err
	}
	b.last = nil
	b.persist()
	return nil
}

// Compile-time check that the adapter satisfies the platform contract.
var _ platform.RoutingBackend = (*Backend)(nil)
