package awg

import (
	"math"
	"strings"
	"testing"
)

func TestParseRange(t *testing.T) {
	ok := []struct {
		in     string
		max    uint32
		lo, hi uint32
	}{
		{"5", math.MaxUint32, 5, 5},
		{"1-9", math.MaxUint32, 1, 9},
		{"007", math.MaxUint32, 7, 7},
		{"4294967295", math.MaxUint32, math.MaxUint32, math.MaxUint32},
		{"25", math.MaxUint16, 25, 25},
	}
	for _, c := range ok {
		lo, hi, err := ParseRange(c.in, c.max)
		if err != nil || lo != c.lo || hi != c.hi {
			t.Errorf("ParseRange(%q) = %d-%d, %v; want %d-%d", c.in, lo, hi, err, c.lo, c.hi)
		}
	}
	for _, in := range []string{"", "a", "9-1", "1-", "-1", "1-2-3", " 5", "+5", "4294967296", "0x10"} {
		if _, _, err := ParseRange(in, math.MaxUint32); err == nil {
			t.Errorf("ParseRange(%q) was accepted", in)
		}
	}
	if _, _, err := ParseRange("70000", math.MaxUint16); err == nil {
		t.Error("a value above the field's bound was accepted")
	}
}

func TestParseBool(t *testing.T) {
	for in, want := range map[string]bool{"on": true, "ON": true, "Off": false, "true": true, "FALSE": false, "0": false, "1": true, "2": true} {
		if got, err := ParseBool(in); err != nil || got != want {
			t.Errorf("ParseBool(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "yes", "-1", "1.5", "o n"} {
		if _, err := ParseBool(in); err == nil {
			t.Errorf("ParseBool(%q) was accepted", in)
		}
	}
}

// Every shape here was read off amneziawg-go's newObfChain or the kernel module's jp_parse_tags.
func TestGoIPacket(t *testing.T) {
	cases := []struct {
		in, out string
		noteHas string // "" = no note
		why     string
	}{
		{"", "", "", "unset"},
		{"<b 0xc0ff00><r 16><t>", "<b 0xc0ff00><r 16><t>", "", "already canonical"},
		{"<b c0ff00>", "<b 0xc0ff00>", "", "0x added, so the kernel module reads it too"},
		{"<r\t16>  <rc 8><rd 4><dz 2><d><ds>", "<r 16><rc 8><rd 4><dz 2><d><ds>", "", "whitespace normalised, every amneziawg-go tag"},
		{"0xc0ffee00c0ffee00", "", "not sent", "bare hex: nothing is built from it anywhere"},
		{"<b 0x01><c><r 2>", "<b 0x01><r 4><r 2>", "<c>", "the kernel's counter becomes 4 random bytes"},
		{"junk<b 0x01>tail", "<b 0x01>", "skipped", "text between tags is dropped"},
		{"<r 65507>", "<r 65507>", "", "exactly one full datagram"},
		{"<r 65503><t>", "<r 65503><t>", "", "the timestamp's 4 bytes count"},
	}
	for _, c := range cases {
		out, note, err := GoIPacket(c.in)
		if err != nil || out != c.out {
			t.Errorf("%s: GoIPacket(%q) = %q, %v; want %q", c.why, c.in, out, err, c.out)
		}
		if (c.noteHas == "") != (note == "") || !strings.Contains(note, c.noteHas) {
			t.Errorf("%s: note %q, want one mentioning %q", c.why, note, c.noteHas)
		}
	}
	for in, why := range map[string]string{
		"<b 0x01":                "no closing >",
		"<>":                     "empty tag",
		"<x 1>":                  "unknown tag",
		"<b 0x0>":                "odd hex",
		"<b 0x>":                 "empty hex",
		"<b zz>":                 "not hex",
		"<r -1>":                 "negative length: amneziawg-go panics allocating it",
		"<r>":                    "length missing",
		"<r 65508>":              "over one datagram",
		"<r 65504><t>":           "over one datagram once the timestamp is added",
		"<r 40000><r 30000>":     "over one datagram in total",
		"<t 5>":                  "value on a tag that takes none",
		"<c 1>":                  "value on <c>",
		"<b 0x01 0x02>":          "second value, which amneziawg-go would silently ignore",
		"<t 1 2>":                "values on a tag that takes none, which amneziawg-go would silently ignore",
		"<b 0x01><r 2147483647>": "a length that wraps a 32-bit int once added to the byte before it",
	} {
		if out, _, err := GoIPacket(in); err == nil {
			t.Errorf("%s: GoIPacket(%q) accepted as %q", why, in, out)
		}
	}
}

// What GoIPacket emits is its own fixed point: sending it again changes nothing and notes nothing.
// Anything else would mean the canonical form is not canonical.
func FuzzGoIPacket(f *testing.F) {
	for _, s := range []string{"<b 0xc0ff00><r 16><t>", "0xdead", "<c><b 01>", "a<rd 3>b", "<ds><d><dz 1>"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out, _, err := GoIPacket(s)
		if err != nil || out == "" {
			return
		}
		again, note, err := GoIPacket(out)
		if err != nil || again != out || note != "" {
			t.Fatalf("GoIPacket(%q) = %q is not a fixed point: %q, %q, %v", s, out, again, note, err)
		}
	})
}
