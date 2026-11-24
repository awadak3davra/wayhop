package awg

import "testing"

func TestIPacketProblem(t *testing.T) {
	refused := []string{
		"<r -5><b 0x01>", // kmod PR #237: a negative length
		"<b 0x01><rc -1>",
		"<r 70000>",                // kmod PR #247: past 65535
		"<r 65000><r 600>",         // the sum, not one tag
		"<r 99999999999999999999>", // too many digits to parse
	}
	for _, s := range refused {
		if IPacketProblem(s) == "" {
			t.Errorf("IPacketProblem(%q) = \"\", want a problem", s)
		}
	}
	kept := []string{
		"", "0xa1b2c3", "<b 0xc0ffee><r 16><t><c>", "<r 65535>", "<r 65531><t>",
		"<x -5>", "<r abc>", "<r", "<>",
	}
	for _, s := range kept {
		if p := IPacketProblem(s); p != "" {
			t.Errorf("IPacketProblem(%q) = %q, want none: the module decides what it cannot parse", s, p)
		}
	}
}
