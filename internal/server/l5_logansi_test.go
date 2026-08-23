package server

import (
	"strings"
	"testing"
)

// TestLogAnalyzerStripsTerminalColour (L5): the log the panel shows is the log a person can read.
//
// sing-box colours its output whether or not a terminal is attached, so the lines the daemon reads
// carry raw CSI escapes and the analyzer passed them through. Measured on a live Keenetic:
// "Load sing-box log" rendered its single line as "ESC[33mWARN ESC[0m inbound/tun[tun-in]: enable
// offload: …" — escape bytes printed as text in a monospace block.
//
// The severity is not lost with the colour: the line still carries the word, and the row's colour
// comes from IsErrorLine/Entries, not from the escape.
func TestLogAnalyzerStripsTerminalColour(t *testing.T) {
	esc := "\x1b"
	coloured := "+0000 2026-08-20 06:24:54 " + esc + "[33mWARN" + esc + "[0m inbound/tun[tun-in]: " +
		"enable offload: set udp offload: TUNSETOFFLOAD: invalid argument"

	got := analyze([]string{coloured})
	if len(got) != 1 {
		t.Fatalf("one line in, one line out: %+v", got)
	}
	if strings.Contains(got[0].Line, esc) {
		t.Errorf("the line handed to the panel still carries escape bytes: %q", got[0].Line)
	}
	if !strings.Contains(got[0].Line, "WARN") {
		t.Errorf("the severity word must survive the colour: %q", got[0].Line)
	}
	if !strings.Contains(got[0].Line, "TUNSETOFFLOAD: invalid argument") {
		t.Errorf("and so must the message: %q", got[0].Line)
	}
	// This line says "invalid argument", which is what makes it an error line — the verdict must not
	// change because the colour left.
	if !got[0].Error {
		t.Errorf("stripping colour must not change the error verdict: %+v", got[0])
	}

	// A knowledge-base hit found on the coloured line is still found on the stripped one.
	fatal := "2026-08-20 " + esc + "[31mFATAL" + esc + "[0m start service: configure tun interface: invalid argument"
	hits := analyze([]string{fatal})
	if len(hits[0].Entries) == 0 {
		t.Errorf("a known cause must still match after stripping: %q", hits[0].Line)
	}

	// A plain line is returned byte-for-byte: stripping must not rewrite ordinary text.
	plain := "2026-08-20 06:24:54 INFO router: sniffed domain example.com"
	if out := analyze([]string{plain}); out[0].Line != plain {
		t.Errorf("an uncoloured line must pass through unchanged:\n got %q\nwant %q", out[0].Line, plain)
	}
}
