package core

import (
	"bytes"
	"strings"
	"testing"
)

// esc is written as a rune constant so the fixtures below stay readable as source:
// a literal ESC byte in a Go string is invisible in every diff and editor.
const esc = "\x1b"

// A live AX3000T `logread` line. sing-box colours the level and the connection id, and
// procd copies the daemon's stdout into logd verbatim; the panel renders the same bytes.
var colouredEngineLine = esc + "[31mERROR" + esc + "[0m[" + esc + "[38;5;144m2070870144" + esc +
	"[0m 5.0s] connection: open connection to 203.0.113.8:585 using outbound/direct[direct]: dial tcp: i/o timeout\n"

func TestANSIStripWriter_RemovesColourFromEngineOutput(t *testing.T) {
	var buf bytes.Buffer
	w := &ansiStripWriter{w: &buf}

	n, err := w.Write([]byte(colouredEngineLine))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	// The caller wrote every byte it handed us; the escapes were consumed, not short-written.
	if n != len(colouredEngineLine) {
		t.Errorf("n = %d, want %d (a short count would make io.Copy report ErrShortWrite)", n, len(colouredEngineLine))
	}
	want := "ERROR[2070870144 5.0s] connection: open connection to 203.0.113.8:585 " +
		"using outbound/direct[direct]: dial tcp: i/o timeout\n"
	if got := buf.String(); got != want {
		t.Errorf("stripped = %q\nwant       %q", got, want)
	}
	if strings.ContainsRune(buf.String(), 0x1b) {
		t.Error("an ESC byte survived: logread and the Diagnostics buffer would still show escape codes")
	}
}

// os/exec copies the pipe in fixed-size chunks, so an escape sequence is routinely
// split across two Write calls. The parser state has to survive that boundary.
func TestANSIStripWriter_SequenceSplitAcrossWrites(t *testing.T) {
	in := []byte(esc + "[38;5;144mid" + esc + "]0;engine title\a" + esc + "(B" + esc + "[0m done")
	for cut := 1; cut < len(in); cut++ {
		var buf bytes.Buffer
		w := &ansiStripWriter{w: &buf}
		if _, err := w.Write(in[:cut]); err != nil {
			t.Fatalf("first Write: %v", err)
		}
		if _, err := w.Write(in[cut:]); err != nil {
			t.Fatalf("second Write: %v", err)
		}
		if got, want := buf.String(), "id done"; got != want {
			t.Errorf("cut after %d bytes: got %q, want %q", cut, got, want)
		}
	}
}

// Plain engine output must pass through untouched — including the square brackets
// sing-box uses for tags, which must not be mistaken for the start of a sequence.
func TestANSIStripWriter_LeavesPlainTextAlone(t *testing.T) {
	var buf bytes.Buffer
	w := &ansiStripWriter{w: &buf}
	const plain = "+0000 2026-08-27 14:08:14 WARN inbound/tun[tun-in]: enable offload: TUNSETOFFLOAD: invalid argument\n"
	if _, err := w.Write([]byte(plain)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := buf.String(); got != plain {
		t.Errorf("plain text was altered:\n got %q\nwant %q", got, plain)
	}
}

// The classifier reads the ring buffer, and the failure it builds carries RawLine
// straight into the panel. A coloured FATAL must classify AND come back clean.
func TestANSIStripWriter_ClassifierSeesACleanFatal(t *testing.T) {
	var buf bytes.Buffer
	w := &ansiStripWriter{w: &buf}
	coloured := esc + "[31mFATAL" + esc + "[0m[0002] start service: (initialize rule-set[3]: " +
		"initial rule-set: rs-ai_openai: invalid sing-box rule-set file)\n"
	if _, err := w.Write([]byte(coloured)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	line := strings.TrimSuffix(buf.String(), "\n") // the ring log splits on the newline
	f := ClassifyStartFailure([]string{line})
	if f.Kind != "rule-set" {
		t.Fatalf("Kind = %q, want rule-set", f.Kind)
	}
	if len(f.Items) != 1 || f.Items[0] != "rs-ai_openai" {
		t.Errorf("Items = %v, want [rs-ai_openai]", f.Items)
	}
	if strings.ContainsRune(f.RawLine, 0x1b) {
		t.Error("RawLine still carries an ESC byte; the panel would render the escape codes")
	}
}

// The engine binary is replaceable, so the stripper cannot rely on sing-box's SGR-only habit.
// These are the other 7-bit ECMA-48 forms a logger can emit: an OSC (a terminal title, a
// hyperlink) ended by BEL or by ST, a charset designation (an nF sequence), the two-byte
// escapes, and a CSI carrying a private-mode marker and an intermediate byte.
func TestANSIStripWriter_OtherEscapeForms(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"OSC ended by BEL", esc + "]0;engine title\a" + "line", "line"},
		{"OSC ended by ST", esc + "]2;log" + esc + "\\" + "link" + esc + "]8;;" + esc + "\\", "link"},
		{"nF charset designation", esc + "(B" + "ok", "ok"},
		{"two-byte RIS", esc + "c" + "reset", "reset"},
		{"two-byte save cursor", "a" + esc + "7" + "b", "ab"},
		{"ESC ESC then CSI", "x" + esc + esc + "[31m" + "y", "xy"},
		{"private-mode CSI with an intermediate", esc + "[?25l" + "cursor" + esc + "[0 q", "cursor"},
	} {
		var buf bytes.Buffer
		w := &ansiStripWriter{w: &buf}
		if _, err := w.Write([]byte(tc.in)); err != nil {
			t.Fatalf("%s: Write: %v", tc.name, err)
		}
		if got := buf.String(); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A sequence the engine never finished — killed mid-write, or a logger bug — must not swallow
// the lines after it. The ring buffer splits on newlines and the classifier reads whole lines,
// so a control byte ends whatever sequence was in progress and passes through.
func TestANSIStripWriter_TruncatedSequenceStopsAtTheLine(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"CSI cut by a newline", "a" + esc + "[31" + "\nb\n", "a\nb\n"},
		{"OSC never terminated", esc + "]0;junk" + "\nnext\n", "\nnext\n"},
		{"lone ESC before a newline", "a" + esc + "\nb", "a\nb"},
		{"ESC followed by UTF-8", "a" + esc + "\xd0\xb0b", "a\xd0\xb0b"},
	} {
		var buf bytes.Buffer
		w := &ansiStripWriter{w: &buf}
		if _, err := w.Write([]byte(tc.in)); err != nil {
			t.Fatalf("%s: Write: %v", tc.name, err)
		}
		if got := buf.String(); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}
