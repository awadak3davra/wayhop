package generator

import (
	"testing"
	"time"

	"wayhop/internal/model"
)

// TestGroupOutboundIntervalFloor pins the urltest interval floor: the 60s default and any
// deliberate >=5s choice pass through unchanged, but a pathological sub-5s value (which would
// TLS-probe every member that often and storm a weak router's CPU/sockets/log) is bounded to
// 5s. Mirrors the WG-MTU clamp; protects against API / hand-edit / subscription inputs.
func TestGroupOutboundIntervalFloor(t *testing.T) {
	cases := []struct {
		name     string
		interval int
		want     string
	}{
		{"unset-default", 0, "1m"},
		{"pathological-1s", 1, "5s"},
		{"4s-floored", 4, "5s"},
		{"5s-kept", 5, "5s"},
		{"10s-kept", 10, "10s"},
		{"60s-kept", 60, "60s"},
	}
	for _, c := range cases {
		g := &model.Group{ID: "g", Type: model.GroupURLTest, Members: []string{"a"}}
		if c.interval > 0 {
			g.Test = &model.Health{Interval: c.interval}
		}
		ob := groupOutbound(g)
		if got, _ := ob["interval"].(string); got != c.want {
			t.Errorf("%s: Test.Interval=%d → interval %q, want %q", c.name, c.interval, got, c.want)
		}
	}
}

// secOf parses a sing-box duration string (e.g. "1m", "1800s") into whole seconds (test helper).
func secOf(t *testing.T, s string) int {
	t.Helper()
	d, err := time.ParseDuration(s)
	if err != nil {
		t.Fatalf("not a duration: %q (%v)", s, err)
	}
	return int(d.Seconds())
}

// TestGroupOutboundIdleTimeoutInvariant pins F2: every urltest/fallback group emits an explicit
// idle_timeout that is ALWAYS >= interval, so sing-box 1.12.x (which rejects the whole config when
// interval > idle_timeout) can never be tripped — even by a pathological interval far above the 30m
// default, which is only floored, never capped.
func TestGroupOutboundIdleTimeoutInvariant(t *testing.T) {
	cases := []struct {
		name        string
		interval    int
		wantIdleSec int
	}{
		{"default 60s → 30m idle", 0, 1800},
		{"30s → 30m idle", 30, 1800},
		{"exactly 30m → 30m idle", 1800, 1800},
		{"above 30m is lifted (2h)", 7200, 7200},
		{"far above 30m (24h)", 86400, 86400},
	}
	for _, c := range cases {
		g := &model.Group{ID: "g", Type: model.GroupURLTest, Members: []string{"a"}}
		if c.interval > 0 {
			g.Test = &model.Health{Interval: c.interval}
		}
		ob := groupOutbound(g)
		idle, ok := ob["idle_timeout"].(string)
		if !ok {
			t.Fatalf("%s: no idle_timeout emitted", c.name)
		}
		if got := secOf(t, idle); got != c.wantIdleSec {
			t.Errorf("%s: idle_timeout=%q (%ds), want %ds", c.name, idle, got, c.wantIdleSec)
		}
		// The load-time invariant: interval must never exceed idle_timeout.
		if iv := secOf(t, ob["interval"].(string)); iv > secOf(t, idle) {
			t.Errorf("%s: interval %ds > idle_timeout %ds — sing-box would reject the config", c.name, iv, secOf(t, idle))
		}
	}

	// A selector group never gets a urltest idle_timeout (not a urltest outbound).
	sel := groupOutbound(&model.Group{ID: "s", Type: model.GroupSelector, Members: []string{"a"}})
	if _, ok := sel["idle_timeout"]; ok {
		t.Errorf("selector group unexpectedly carries idle_timeout: %v", sel["idle_timeout"])
	}
}
