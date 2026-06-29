package keenetic

import (
	"context"
	"fmt"

	"velinx/internal/failsafe"
	"velinx/internal/model"
)

// Reboot reboots the router via RCI (`system reboot`). KeeneticOS boots the SAVED config, so
// a reboot is a valid rollback ONLY for changes applied WITHOUT `system configuration save`
// (exactly how SafeApply deploys). ⚠️ DEVICE-WRITING + DISRUPTIVE; the failsafe last resort.
func (b *Backend) Reboot(ctx context.Context) error {
	if _, err := b.rci.ParseBatch(ctx, []string{"system reboot"}); err != nil {
		return fmt.Errorf("reboot: %w", err)
	}
	return nil
}

// Save persists the running config to flash (`system configuration save`) — the commit step
// once a SafeApply has survived its verification window. ⚠️ DEVICE-WRITING.
func (b *Backend) Save(ctx context.Context) error {
	if _, err := b.rci.ParseBatch(ctx, []string{"system configuration save"}); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	return nil
}

// SafeApply deploys a profile UNSAVED and arms a failsafe window (the native-first safety
// net): KeeneticOS keeps the previously-SAVED config on flash, so if the new routing breaks
// connectivity the failsafe rolls back — re-deploying the last-good plan, or as a last resort
// rebooting (which loads the saved good config). The change is committed only by ConfirmSafe.
//
// check reports whether connectivity is healthy (injected — e.g. an exit-IP/ping probe, which
// is reachability-generic, not Keenetic-specific); allowReboot gates the reboot last resort.
// ⚠️ DEVICE-WRITING; user-gated; the research loop never calls it.
func (b *Backend) SafeApply(ctx context.Context, p *model.Profile, mgr *failsafe.Manager, check func() bool, allowReboot bool) error {
	plan, err := Compile(p, b.cOpt)
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	b.mu.Lock()
	prev := b.last
	b.mu.Unlock()

	// Replace the prior config with the candidate, UNSAVED (so a reboot reverts to saved).
	if prev != nil {
		if err := prev.Teardown(ctx, b.rci, ApplyOptions{}); err != nil {
			return fmt.Errorf("teardown prior: %w", err)
		}
	}
	if err := plan.Deploy(ctx, b.rci, b.run, ApplyOptions{Save: false}, b.sbOpt); err != nil {
		// Deploy failed mid-flight — restore the prior config so routing isn't left down.
		if prev != nil {
			_ = prev.Deploy(ctx, b.rci, b.run, ApplyOptions{}, b.sbOpt)
		}
		return fmt.Errorf("deploy candidate: %w", err)
	}

	b.mu.Lock()
	b.candidate = plan
	b.mu.Unlock()

	rollback := func() error {
		// Detached context: the failsafe fires this rollback minutes after SafeApply returns, by
		// which time the request-scoped ctx is long cancelled. Using it would make Teardown/Deploy
		// return context.Canceled, the rollback would FAIL (phase → rollback_failed), and the bad
		// config would stay live — defeating the failsafe. The reboot closure below detaches for the
		// same reason. (The mid-flight recovery above runs synchronously, so ctx is still valid there.)
		rbCtx := context.Background()
		if err := plan.Teardown(rbCtx, b.rci, ApplyOptions{}); err != nil {
			return err
		}
		if prev != nil {
			if err := prev.Deploy(rbCtx, b.rci, b.run, ApplyOptions{}, b.sbOpt); err != nil {
				return err
			}
		}
		b.mu.Lock()
		b.candidate = nil
		b.mu.Unlock()
		return nil
	}
	reboot := func() { _ = b.Reboot(context.Background()) }
	mgr.Arm(check, rollback, reboot, allowReboot)
	return nil
}

// ConfirmSafe commits the candidate from a SafeApply: it persists the config to flash and
// confirms the failsafe window, promoting the candidate to the last-good plan.
func (b *Backend) ConfirmSafe(ctx context.Context, mgr *failsafe.Manager) error {
	b.mu.Lock()
	cand := b.candidate
	b.mu.Unlock()
	if cand == nil {
		return fmt.Errorf("no candidate to confirm")
	}
	if err := b.Save(ctx); err != nil {
		return err
	}
	mgr.Confirm()
	b.mu.Lock()
	b.last = cand
	b.candidate = nil
	b.persist()
	b.mu.Unlock()
	return nil
}
