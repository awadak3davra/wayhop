package pbr

import (
	"strings"
	"testing"
)

// listRunner serves canned `ip rule` / `ip -6 rule` output and records every other command.
type listRunner struct {
	v4, v6 string
	calls  []string
}

func (l *listRunner) Run(stdin, name string, args ...string) (string, error) {
	line := strings.TrimSpace(name + " " + strings.Join(args, " "))
	switch line {
	case "ip rule":
		return l.v4, nil
	case "ip -6 rule":
		return l.v6, nil
	}
	l.calls = append(l.calls, line)
	return "", nil
}

// Real busybox/iproute2 output shapes (tab after the pref colon), mixing wayhop strands with
// decoys that MUST survive: system rules, a bare numeric-table rule without fwmark, an
// mwan3-style fwmark with a foreign mask, a foreign fwmark table outside the window, and a
// to-main rule outside the exclude priority band.
const sweepV4 = `0:	from all lookup local
50:	from all to 203.0.113.0/24 lookup main
100:	from all lookup 200
120:	from all fwmark 0x100/0x3f00 lookup 1001
145:	from all fwmark 0x20000/0xff0000 lookup 250
147:	from all to 10.0.0.0/8 lookup main
148:	from all to 172.16.0.0/12 lookup main
149:	from all to 192.168.0.0/16 lookup main
150:	from all fwmark 0x20000/0xff0000 lookup 151
151:	from all fwmark 0x30000/0xff0000 lookup 152
32766:	from all lookup main
32767:	from all lookup default`

const sweepV6 = `0:	from all lookup local
149:	from all to fd00::/8 lookup main
150:	from all fwmark 0x20000/0xff0000 lookup 151
32766:	from all lookup main`

func TestSweepStrandedRules(t *testing.T) {
	r := &listRunner{v4: sweepV4, v6: sweepV6}
	n, err := SweepStrandedRules(r, Options{})
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	// v4: 2 fwmark rules + 3 excludes; v6: 1 fwmark + 1 exclude = 7 swept.
	if n != 7 {
		t.Errorf("swept = %d, want 7\ncalls:\n  %s", n, strings.Join(r.calls, "\n  "))
	}
	want := []string{
		"ip rule del to 10.0.0.0/8 lookup main priority 147",
		"ip rule del to 172.16.0.0/12 lookup main priority 148",
		"ip rule del to 192.168.0.0/16 lookup main priority 149",
		// hexMark zero-pads — the del must match the exact form wayhop's own teardown emits.
		"ip rule del fwmark 0x00020000/0x00ff0000 table 151 priority 150",
		"ip rule del fwmark 0x00030000/0x00ff0000 table 152 priority 151",
		"ip route flush table 151",
		"ip route flush table 152",
		"ip -6 rule del to fd00::/8 lookup main priority 149",
		"ip -6 rule del fwmark 0x00020000/0x00ff0000 table 151 priority 150",
		"ip -6 route flush table 151",
	}
	for _, w := range want {
		found := false
		for _, c := range r.calls {
			if c == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing expected command: %s", w)
		}
	}
	// Decoys must be untouched: table 200 (no fwmark), mwan3 mask 0x3f00, wayhop-mask table 250
	// (outside the [151,215) window), to-main at pref 50 (outside the exclude band), system rules.
	for _, c := range r.calls {
		for _, poison := range []string{"table 200", "table 1001", "table 250", "203.0.113.0/24", "lookup local", "lookup default", "priority 50", "priority 32766"} {
			if strings.Contains(c, poison) {
				t.Errorf("swept an UNRELATED rule: %s", c)
			}
		}
	}
}

// TestSweepStrandedRules_CleanSystem: a box with only stock rules sweeps nothing and runs no
// mutating command at all.
func TestSweepStrandedRules_CleanSystem(t *testing.T) {
	r := &listRunner{
		v4: "0:\tfrom all lookup local\n32766:\tfrom all lookup main\n32767:\tfrom all lookup default",
		v6: "0:\tfrom all lookup local\n32766:\tfrom all lookup main",
	}
	n, err := SweepStrandedRules(r, Options{})
	if err != nil || n != 0 {
		t.Fatalf("clean system: swept=%d err=%v, want 0,nil", n, err)
	}
	if len(r.calls) != 0 {
		t.Errorf("clean system must run no mutating commands, got: %v", r.calls)
	}
}

// TestParseRuleLine covers the format edge cases: no-mask fwmark, named lookup, garbage lines.
func TestParseRuleLine(t *testing.T) {
	rl, ok := parseRuleLine("150:\tfrom all fwmark 0x20000/0xff0000 lookup 151")
	if !ok || rl.pref != 150 || rl.fwmark != 0x20000 || rl.fwmask != 0xff0000 || rl.lookup != "151" {
		t.Errorf("parse full: %+v ok=%v", rl, ok)
	}
	rl, ok = parseRuleLine("120:\tfrom all fwmark 0x1 lookup main") // mask-less fwmark
	if !ok || rl.fwmark != 1 || rl.fwmask != 0 || rl.lookup != "main" {
		t.Errorf("parse maskless: %+v ok=%v", rl, ok)
	}
	if _, ok := parseRuleLine("garbage without a pref"); ok {
		t.Error("garbage must not parse")
	}
}
