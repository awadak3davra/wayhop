package plugin

import "testing"

// TestPluginBackoffTicks locks the crash-loop throttle curve a long-running plugin (olcRTC/nfqws2)
// is restarted on: no backoff within the grace window, then exponential, monotonic non-decreasing,
// capped at pluginMaxCooldown (so a plugin that dies every tick is throttled, never hammered), and
// safe against a pathological restart counter. Asserts PROPERTIES, not the constants' values.
func TestPluginBackoffTicks(t *testing.T) {
	// Within the grace window: no throttle (a one-off crash recovers promptly).
	for r := 0; r <= pluginRestartGrace; r++ {
		if got := pluginBackoffTicks(r); got != 0 {
			t.Errorf("pluginBackoffTicks(%d) = %d, want 0 within grace", r, got)
		}
	}
	// Past grace: positive, monotonic non-decreasing, never above the cap.
	prev := 0
	for r := pluginRestartGrace + 1; r <= pluginRestartGrace+40; r++ {
		got := pluginBackoffTicks(r)
		if got <= 0 {
			t.Errorf("pluginBackoffTicks(%d) = %d, want > 0 past grace", r, got)
		}
		if got < prev {
			t.Errorf("backoff regressed at %d: %d < previous %d", r, got, prev)
		}
		if got > pluginMaxCooldown {
			t.Errorf("pluginBackoffTicks(%d) = %d exceeds cap %d", r, got, pluginMaxCooldown)
		}
		prev = got
	}
	// It must eventually reach the cap, and a pathological counter stays capped (shift guard).
	if prev != pluginMaxCooldown {
		t.Errorf("backoff never reached the cap %d (got %d) — ramp too slow or cap unreached", pluginMaxCooldown, prev)
	}
	if got := pluginBackoffTicks(1 << 20); got != pluginMaxCooldown {
		t.Errorf("pluginBackoffTicks(huge) = %d, want cap %d", got, pluginMaxCooldown)
	}
}
