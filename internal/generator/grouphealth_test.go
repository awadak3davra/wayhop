package generator

import (
	"testing"

	"velinx/internal/model"
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
