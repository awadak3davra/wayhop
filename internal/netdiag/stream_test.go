package netdiag

import "testing"

// TestParsePingMs covers the latency extraction used by ReachableViaIface (the native-iface
// health probe): prefer the summary AVG over all echoes, fall back to the first per-packet
// time=, round (not truncate), and return 0 when nothing is parseable.
func TestParsePingMs(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want int
	}{
		{"coreutils summary avg", "rtt min/avg/max/mdev = 11.2/12.8/14.0/0.9 ms", 13},
		{"busybox summary avg", "round-trip min/avg/max = 10.0/20.6/31.0 ms", 21},
		{"per-packet fallback (no summary)", "64 bytes from 1.2.3.4: seq=0 ttl=55 time=42.3 ms", 42},
		{"no latency parseable", "3 packets transmitted, 3 received, 0% loss", 0},
		{"prefers avg over first packet", "64 bytes from h: time=99.0 ms\nrtt min/avg/max = 5.0/7.4/9.0 ms", 7},
	}
	for _, c := range cases {
		if got := parsePingMs(c.out); got != c.want {
			t.Errorf("%s: parsePingMs = %d, want %d", c.name, got, c.want)
		}
	}
}
