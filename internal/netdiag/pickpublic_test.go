package netdiag

import (
	"net"
	"testing"
)

// pickPublic must prefer a public IPv4 even when a resolver lists v6 first — the router
// and its tunnels are v4-only, so pinning a v6 literal makes curl fail (the bug that
// briefly made every "Test all exits" exit read unreachable). It falls back to v6 only
// when there is no public v4, and refuses an all-internal answer.
func TestPickPublic(t *testing.T) {
	v4 := net.ParseIP("149.154.167.99")
	v6 := net.ParseIP("2001:67c:4e8:f004::9")
	priv := net.ParseIP("10.0.0.1")
	lo := net.ParseIP("127.0.0.1")

	// v6 listed FIRST (telegram's real ordering) — must still pick the v4.
	if got, err := pickPublic([]net.IP{v6, v4}); err != nil || got != "149.154.167.99" {
		t.Errorf("v6-first: got %q err=%v, want the v4", got, err)
	}
	// internal v4 ahead of the public v4 — skip the internal, pick the public v4.
	if got, err := pickPublic([]net.IP{priv, v4}); err != nil || got != "149.154.167.99" {
		t.Errorf("internal-first: got %q err=%v, want the public v4", got, err)
	}
	// v6-only public answer — fall back to the v6.
	if got, err := pickPublic([]net.IP{lo, v6}); err != nil || got != v6.String() {
		t.Errorf("v6-only: got %q err=%v, want the v6", got, err)
	}
	// all internal — refuse.
	if _, err := pickPublic([]net.IP{priv, lo}); err == nil {
		t.Error("all-internal: want an error")
	}
}
