package core

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// coresingbox_missingBin returns a path inside t.TempDir() that does not exist,
// so New(...) points at a binary that can never be found or run.
func coresingbox_missingBin(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "definitely-not-a-real-sing-box-binary")
}

// ---- SingBox lifecycle against a non-existent binary --------------------------

func TestCoresingbox_AvailableFalseForMissingBinary(t *testing.T) {
	s := New(coresingbox_missingBin(t), filepath.Join(t.TempDir(), "config.json"))
	if s.Available() {
		t.Fatal("Available() = true for a non-existent binary path; want false")
	}
}

func TestCoresingbox_AvailableFalseForEmptyBinary(t *testing.T) {
	s := New("", filepath.Join(t.TempDir(), "config.json"))
	if s.Available() {
		t.Fatal("Available() = true for empty binary path; want false")
	}
}

// Start on a missing binary must error AND leave Desired() == false. This is the
// critical invariant: if Start marked desired=true on failure, the watchdog would
// loop forever trying to launch a binary that can never start.
func TestCoresingbox_StartMissingBinaryErrorsAndLeavesDesiredFalse(t *testing.T) {
	bin := coresingbox_missingBin(t)
	s := New(bin, filepath.Join(t.TempDir(), "config.json"))

	if s.Desired() {
		t.Fatal("Desired() = true before any Start; want false")
	}

	err := s.Start()
	if err == nil {
		t.Fatal("Start() returned nil error for a non-existent binary; want an error")
	}
	if !strings.Contains(err.Error(), "sing-box binary not found") {
		t.Fatalf("Start() error = %q; want it to mention the binary was not found", err.Error())
	}

	if s.Desired() {
		t.Fatal("Desired() = true after a failed Start; want false (watchdog must not loop on a missing binary)")
	}
	if s.Alive() {
		t.Fatal("Alive() = true after a failed Start; want false")
	}
	if s.Running() {
		t.Fatal("Running() = true after a failed Start; want false")
	}
	if !s.StartedAt().IsZero() {
		t.Fatalf("StartedAt() = %v after a failed Start; want zero time", s.StartedAt())
	}
}

// Stop with nothing running must be a safe no-op (no panic, nil error) and must
// keep Desired() false.
func TestCoresingbox_StopIsSafeNoOpWhenNothingRunning(t *testing.T) {
	s := New(coresingbox_missingBin(t), filepath.Join(t.TempDir(), "config.json"))

	if err := s.Stop(); err != nil {
		t.Fatalf("Stop() on a never-started supervisor returned error %v; want nil", err)
	}
	// A second Stop must also be safe.
	if err := s.Stop(); err != nil {
		t.Fatalf("second Stop() returned error %v; want nil", err)
	}
	if s.Desired() {
		t.Fatal("Desired() = true after Stop; want false")
	}
	if s.Alive() || s.Running() {
		t.Fatal("Alive()/Running() = true after Stop with nothing running; want false")
	}
}

func TestCoresingbox_StateAccessorsZeroValueBeforeStart(t *testing.T) {
	s := New(coresingbox_missingBin(t), filepath.Join(t.TempDir(), "config.json"))

	if s.Alive() {
		t.Error("Alive() = true on a fresh supervisor; want false")
	}
	if s.Running() {
		t.Error("Running() = true on a fresh supervisor; want false")
	}
	if s.Desired() {
		t.Error("Desired() = true on a fresh supervisor; want false")
	}
	if !s.StartedAt().IsZero() {
		t.Errorf("StartedAt() = %v on a fresh supervisor; want zero time", s.StartedAt())
	}
	if got := s.LogLines(); len(got) != 0 {
		t.Errorf("LogLines() = %v on a fresh supervisor; want empty", got)
	}
}

// ---- ringLog ------------------------------------------------------------------

func TestCoresingbox_RingLogSplitsTrimsAndSkipsEmpty(t *testing.T) {
	r := newRingLog(10)

	// Write data in multiple chunks, including a partial final line and \r\n
	// terminators. The trailing "partial" has no newline yet so it should not
	// surface until completed.
	coresingbox_writeAll(t, r, "alpha\r\n")
	coresingbox_writeAll(t, r, "beta\n")
	coresingbox_writeAll(t, r, "\n")       // blank line, must be skipped
	coresingbox_writeAll(t, r, "  \n")     // whitespace-only line: NOT empty after \r-trim, kept
	coresingbox_writeAll(t, r, "gam")      // partial line, not yet terminated
	coresingbox_writeAll(t, r, "ma\r\n")   // completes "gamma"
	coresingbox_writeAll(t, r, "trailing") // partial with no newline; must not appear

	got := r.Lines()
	want := []string{"alpha", "beta", "  ", "gamma"}
	if !coresingbox_eq(got, want) {
		t.Fatalf("Lines() = %#v; want %#v", got, want)
	}

	// Completing the trailing partial surfaces it.
	coresingbox_writeAll(t, r, "-done\n")
	got = r.Lines()
	want = []string{"alpha", "beta", "  ", "gamma", "trailing-done"}
	if !coresingbox_eq(got, want) {
		t.Fatalf("after completing partial, Lines() = %#v; want %#v", got, want)
	}
}

func TestCoresingbox_RingLogTrimsOnlyTrailingCR(t *testing.T) {
	r := newRingLog(10)
	// A \r in the middle of a line must be preserved; only trailing \r is trimmed.
	coresingbox_writeAll(t, r, "mid\rline\r\n")
	got := r.Lines()
	want := []string{"mid\rline"}
	if !coresingbox_eq(got, want) {
		t.Fatalf("Lines() = %#v; want %#v", got, want)
	}
}

func TestCoresingbox_RingLogWriteReturnsFullLength(t *testing.T) {
	r := newRingLog(10)
	p := []byte("line1\npartial-without-newline")
	n, err := r.Write(p)
	if err != nil {
		t.Fatalf("Write returned error %v; want nil", err)
	}
	if n != len(p) {
		t.Fatalf("Write returned n=%d; want %d (must report the full input length)", n, len(p))
	}
}

func TestCoresingbox_RingLogLinesReturnsCopy(t *testing.T) {
	r := newRingLog(10)
	coresingbox_writeAll(t, r, "one\ntwo\n")

	first := r.Lines()
	if len(first) != 2 {
		t.Fatalf("Lines() returned %d lines; want 2", len(first))
	}
	// Mutate the returned slice; the internal state must be unaffected.
	first[0] = "MUTATED"

	second := r.Lines()
	if second[0] != "one" {
		t.Fatalf("internal state was mutated via returned slice: second Lines()[0] = %q; want %q", second[0], "one")
	}
}

// Writing far more than `size` lines must keep the most-recent ones and never let
// the backing slice exceed 2*size.
func TestCoresingbox_RingLogKeepsRecentAndBoundsLength(t *testing.T) {
	const size = 5
	r := newRingLog(size)

	const total = 1000
	var sb strings.Builder
	for i := 0; i < total; i++ {
		fmt.Fprintf(&sb, "L%d\n", i)
	}
	coresingbox_writeAll(t, r, sb.String())

	got := r.Lines()
	if len(got) == 0 {
		t.Fatal("Lines() is empty after writing many lines; want recent lines")
	}
	if len(got) > 2*size {
		t.Fatalf("Lines() returned %d lines; must never exceed 2*size = %d", len(got), 2*size)
	}

	// Whatever survives must be a contiguous tail of the most-recent lines: the
	// very last line written must be present and last.
	lastWant := fmt.Sprintf("L%d", total-1)
	if got[len(got)-1] != lastWant {
		t.Fatalf("last retained line = %q; want %q (most-recent line)", got[len(got)-1], lastWant)
	}
	// The retained lines must be the contiguous most-recent block ending at total-1.
	startIdx := total - len(got)
	for i, line := range got {
		want := fmt.Sprintf("L%d", startIdx+i)
		if line != want {
			t.Fatalf("retained line[%d] = %q; want %q (must be a contiguous recent tail)", i, line, want)
		}
	}
}

// Compaction happens at the 2*size boundary: at exactly 2*size lines no compaction
// has occurred yet, and crossing it compacts back down to size.
func TestCoresingbox_RingLogCompactsAtTwiceSizeBoundary(t *testing.T) {
	const size = 4
	r := newRingLog(size)

	// Exactly 2*size lines: condition is len > 2*size, so no compaction yet.
	for i := 0; i < 2*size; i++ {
		coresingbox_writeAll(t, r, fmt.Sprintf("A%d\n", i))
	}
	if got := len(r.Lines()); got != 2*size {
		t.Fatalf("after writing exactly 2*size lines, len(Lines())=%d; want %d", got, 2*size)
	}

	// One more line crosses the boundary and triggers compaction to `size`.
	coresingbox_writeAll(t, r, "A8\n")
	got := r.Lines()
	if len(got) != size {
		t.Fatalf("after crossing 2*size, len(Lines())=%d; want %d (compacted to size)", len(got), size)
	}
	// The kept lines must be the most recent `size`.
	wantLast := []string{"A5", "A6", "A7", "A8"}
	if !coresingbox_eq(got, wantLast) {
		t.Fatalf("after compaction Lines() = %#v; want %#v", got, wantLast)
	}
}

// ---- helpers ------------------------------------------------------------------

func coresingbox_writeAll(t *testing.T, r *ringLog, s string) {
	t.Helper()
	n, err := r.Write([]byte(s))
	if err != nil {
		t.Fatalf("Write(%q) error = %v; want nil", s, err)
	}
	if n != len(s) {
		t.Fatalf("Write(%q) returned n=%d; want %d", s, n, len(s))
	}
}

func coresingbox_eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
