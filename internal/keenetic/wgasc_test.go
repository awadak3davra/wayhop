package keenetic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Both forms are taken from a live KeeneticOS 5.01.C `show running-config`, structurally verbatim.
// The numbers are altered: they are the operator's own tunnel parameters and nothing here needs the
// real values — only the shape, the arity, and the range-versus-bare-number distinction.
const (
	ascShort = "3 40 70 35 89 129283013 143710984 194788937 189347894"
	ascLong  = "3 40 70 35 89 168781656-175897653 218638374-232742829 310726521-327400208 425164664-434856083 97 20 \"\" \"\" \"\" \"\" \"\""
)

func TestParseWGAsc_ReadsBothFormsTheDeviceActuallyCarries(t *testing.T) {
	short, err := ParseWGAsc(ascShort)
	if err != nil {
		t.Fatalf("the nine-argument form was refused: %v", err)
	}
	if short.Jc != "3" || short.Jmin != "40" || short.Jmax != "70" || short.S1 != "35" || short.S2 != "89" {
		t.Errorf("the fixed head was misread: %+v", short)
	}
	if short.H1 != "129283013" || short.H4 != "189347894" {
		t.Errorf("H values misread: H1=%q H4=%q", short.H1, short.H4)
	}
	if len(short.Tail) != 0 {
		t.Errorf("the short form has no tail, got %v", short.Tail)
	}

	long, err := ParseWGAsc(ascLong)
	if err != nil {
		t.Fatalf("the sixteen-argument form was refused: %v", err)
	}
	if long.H1 != "168781656-175897653" {
		t.Errorf("an H RANGE was not kept whole: %q", long.H1)
	}
	// The tail is kept verbatim and unnamed. If a later version learns what these mean it can name
	// them; until then, losing them on a rewrite is the failure to avoid.
	if len(long.Tail) != 7 {
		t.Fatalf("the tail should hold the 7 unidentified arguments, got %v", long.Tail)
	}
	if long.Tail[0] != "97" || long.Tail[6] != `""` {
		t.Errorf("the tail was altered rather than preserved: %v", long.Tail)
	}
}

// A short line must be refused, not padded. Nine arguments have a fixed meaning; fewer means the
// line was truncated or came from something else, and inventing the rest produces a tunnel that
// negotiates and fails in a way that reads like a network fault.
func TestParseWGAsc_RefusesAnIncompleteLine(t *testing.T) {
	for _, bad := range []string{"", "3", "3 40 70", "3 40 70 35 89 1 2 3"} {
		if _, err := ParseWGAsc(bad); err == nil {
			t.Errorf("accepted %q, which cannot describe an obfuscation set", bad)
		}
	}
}

// The line only means anything under an interface, and an interface with no asc line must be absent
// rather than present-and-empty: "no obfuscation configured" and "we could not read it" are
// different answers and must not look alike.
func TestParseWGAscLines_KeysByInterfaceAndOmitsTheOnesWithout(t *testing.T) {
	rc := "" +
		"interface Wireguard0\n" +
		"    description NL\n" +
		"    wireguard asc " + ascShort + "\n" +
		"    !\n" +
		"!\n" +
		"interface Wireguard1\n" +
		"    description plain wireguard, no obfuscation\n" +
		"    !\n" +
		"!\n" +
		"interface Wireguard2\n" +
		"    wireguard asc " + ascLong + "\n" +
		"!\n"

	got := ParseWGAscLines(rc)
	if len(got) != 2 {
		t.Fatalf("expected the two interfaces that carry an asc line, got %d: %v", len(got), keysOf(got))
	}
	if _, ok := got["Wireguard1"]; ok {
		t.Error("an interface with no asc line was reported as having one")
	}
	if got["Wireguard0"].Jc != "3" || len(got["Wireguard2"].Tail) != 7 {
		t.Errorf("the lines were attributed to the wrong interfaces: %+v", got)
	}
}

// The case above only covers an interface with NO asc line, which is absent whatever the parser
// does. This covers the one that has an UNREADABLE one — a truncated line, from a firmware that
// writes a shape we do not know. Storing the zero value there would report an interface whose
// obfuscation is "Jc=, Jmin=, …" as though those were its settings.
func TestParseWGAscLines_AnUnreadableLineIsNotStoredAsAnEmptyOne(t *testing.T) {
	rc := "interface Wireguard0\n    wireguard asc 3 40 70\n!\n"

	got := ParseWGAscLines(rc)
	if len(got) != 0 {
		t.Fatalf("a line too short to parse was stored anyway: %+v", got)
	}
	if a, ok := got["Wireguard0"]; ok {
		t.Errorf("Wireguard0 is present with Jc=%q, which is not something the device said", a.Jc)
	}
}

// The check a writer needs before rewriting a line it did not author. NDM accepts a different arity
// without complaint, so nothing on the device will catch this; the tunnel just obfuscates
// differently from what the other end expects.
func TestWGAsc_SameShapeCatchesAnArityOrRangeChange(t *testing.T) {
	short, _ := ParseWGAsc(ascShort)
	long, _ := ParseWGAsc(ascLong)

	if !short.SameShape(short) || !long.SameShape(long) {
		t.Fatal("a line is not the same shape as itself")
	}
	if short.SameShape(long) {
		t.Error("a 9-argument line was called the same shape as a 16-argument one")
	}

	// That pair differs in BOTH arity and range-ness, so on its own it cannot say which check did
	// the work — disabling the arity comparison entirely still left it passing. These two differ
	// only in the number of arguments.
	nine, _ := ParseWGAsc("3 40 70 35 89 1 2 3 4")
	eleven, _ := ParseWGAsc("3 40 70 35 89 1 2 3 4 5 6")
	if nine.SameShape(eleven) {
		t.Error("two lines differing only in argument count were called the same shape; a rewrite " +
			"would drop the trailing arguments without anything on the device objecting")
	}

	// Same arity, but H given as bare numbers where the original had ranges — the change that does
	// not alter the argument COUNT and so slips past a length check.
	ranged, _ := ParseWGAsc("3 40 70 35 89 1-2 3-4 5-6 7-8")
	bare, _ := ParseWGAsc("3 40 70 35 89 1 2 3 4")
	if ranged.SameShape(bare) {
		t.Error("a range was called the same shape as a bare number; the count matched and the meaning did not")
	}
}

func keysOf(m map[string]WGAsc) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// The synthetic cases above are shaped by the same hand that wrote the parser. This one is not: the
// fixture is the interface headers and `wireguard asc` lines extracted from a live KeeneticOS
// 5.01.C `show running-config`, in device order and with device indentation. Only those two line
// kinds were extracted, so the 43 KB of keys and credentials around them could not travel; the
// digits are substituted, keeping arity and the range-versus-bare distinction the parser depends on.
func TestParseWGAscLines_AgainstTheLiveDeviceCapture(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "running-config-wg.txt"))
	if err != nil {
		t.Fatalf("the device capture is missing, so nothing here is measured against a real router: %v", err)
	}
	got := ParseWGAscLines(string(b))

	// Six of the device's interfaces carry an asc line; the rest — ethernet, bridges, and the
	// Wireguard interfaces without obfuscation — must not appear.
	if len(got) != 6 {
		t.Fatalf("read %d asc lines from the capture, want 6: %v", len(got), keysOf(got))
	}
	for name, a := range got {
		if !strings.HasPrefix(name, "Wireguard") {
			t.Errorf("an asc line was attributed to %q, which is not a Wireguard interface", name)
		}
		if a.Jc == "" || a.H4 == "" {
			t.Errorf("%s: the fixed head did not parse: %+v", name, a)
		}
	}

	// Both arities are present on the same device, which is the fact that makes SameShape necessary.
	short, long := 0, 0
	for _, a := range got {
		switch len(a.Args) {
		case 9:
			short++
		case 16:
			long++
		default:
			t.Errorf("an asc line has %d arguments, a form neither the parser nor this test has seen", len(a.Args))
		}
	}
	if short == 0 || long == 0 {
		t.Errorf("the capture should carry both forms; got %d short and %d long — a fixture with only "+
			"one of them would let an arity bug through", short, long)
	}
	// And the long form is the one with H ranges, on the device as in the synthetic cases.
	for _, a := range got {
		if len(a.Args) == 16 && !strings.Contains(a.H1, "-") {
			t.Errorf("a 16-argument line has a bare H1 %q; the two variations were assumed to travel together", a.H1)
		}
	}
}

// NamedHead exposes exactly what is established and nothing beyond it. Handing callers a map with a
// plausible "s3" would be believed everywhere it was used, and the only evidence for that position
// is that the argument count happens to match a 16-parameter set.
func TestNamedHead_StopsWhereTheEvidenceDoes(t *testing.T) {
	long, err := ParseWGAsc(ascLong)
	if err != nil {
		t.Fatal(err)
	}
	head := long.NamedHead()
	if len(head) != 9 {
		t.Fatalf("NamedHead returned %d keys, want the 9 established ones: %v", len(head), head)
	}
	for _, guessed := range []string{"s3", "s4", "i1", "i2", "i3", "i4", "i5"} {
		if _, ok := head[guessed]; ok {
			t.Errorf("%q is named although its position was never established", guessed)
		}
	}
	if head["jc"] != "3" || head["h1"] != "168781656-175897653" {
		t.Errorf("the established keys carry the wrong values: %v", head)
	}
}

// HeadMatches is the cross-device comparison that identified the head in the first place: the
// Keenetic's positional line against the AX3000T's named uci options for a tunnel to the same host.
func TestHeadMatches_ComparesOnlyWhatItCan(t *testing.T) {
	a, err := ParseWGAsc("5 49 998 17 110 1 2 3 4")
	if err != nil {
		t.Fatal(err)
	}
	// The shape of the real measurement: five named options, all agreeing.
	if !a.HeadMatches(map[string]string{"jc": "5", "jmin": "49", "jmax": "998", "s1": "17", "s2": "110"}) {
		t.Error("a line agreeing on every compared parameter was reported as different")
	}
	if a.HeadMatches(map[string]string{"jc": "5", "s1": "18"}) {
		t.Error("a disagreement on s1 was not reported")
	}
	// The failure this guard exists for: asking about positions whose meaning is NOT established
	// compares nothing, and "nothing disagreed" must not be reported as agreement.
	if a.HeadMatches(map[string]string{"s3": "25", "i1": "0xdeadbeef"}) {
		t.Error("a comparison that examined no established parameter reported a match")
	}
	if a.HeadMatches(map[string]string{}) {
		t.Error("an empty comparison reported a match")
	}
}
