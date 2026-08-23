package core

import (
	"strings"
	"testing"
)

func TestIsStraySingbox(t *testing.T) {
	cfg := "/etc/wayhop/singbox.json"
	nul := func(parts ...string) []byte { return []byte(strings.Join(parts, "\x00") + "\x00") }
	cases := []struct {
		name string
		cmd  []byte
		want bool
	}{
		{"our sing-box running our config", nul("/usr/bin/sing-box", "run", "-c", cfg), true},
		{"basename match from a different dir", nul("/opt/sbin/sing-box", "run", "-c", cfg), true},
		{"sing-box but a different config", nul("/usr/bin/sing-box", "run", "-c", "/other/singbox.json"), false},
		{"not sing-box (dnsmasq referencing the path)", nul("/usr/sbin/dnsmasq", "-C", cfg), false},
		{"empty cmdline", nil, false},
	}
	for _, c := range cases {
		if got := isStraySingbox(c.cmd, "sing-box", cfg); got != c.want {
			t.Errorf("%s: isStraySingbox(%q) = %v, want %v", c.name, c.cmd, got, c.want)
		}
	}
}

func TestIsStraySingbox_EmptyConfigNeverMatches(t *testing.T) {
	// An empty config must never match, or ReapStrays would SIGKILL every sing-box on the box.
	if isStraySingbox([]byte("/usr/bin/sing-box\x00run\x00"), "sing-box", "") {
		t.Error("empty config must never match")
	}
}

func TestReapStrays_SafeNoop(t *testing.T) {
	// config="" -> immediate no-op; a real config -> scans /proc on Linux (or no-ops without
	// procfs) and must never SIGKILL the test process itself (self is skipped) or panic.
	(&SingBox{}).ReapStrays()
	New("/usr/bin/sing-box", "/nonexistent/wayhop/singbox.json").ReapStrays()
}
