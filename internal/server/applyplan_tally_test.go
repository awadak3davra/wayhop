package server

import (
	"strings"
	"testing"
)

// The shape here is the refusal the operator actually got from their own router: one capability ID
// repeated about ninety times because a finding is produced per affected routing list, with the two
// IDs that mattered at either end of the wall. Acknowledgement is keyed by ID — one tickbox covers
// every occurrence — so every repeat after the first carried no information and hid the ones that
// did.
func TestTally_CollapsesTheRepeatsTheOperatorSaw(t *testing.T) {
	ids := []string{"offload_devices=(empty)", "kernel_plane.list-adult", "kernel_plane.mig-example-b"}
	for i := 0; i < 4; i++ {
		ids = append(ids, "kernel_plane.list-blocked")
	}
	for i := 0; i < 90; i++ {
		ids = append(ids, "kernel_plane.list-cascade")
	}
	ids = append(ids, "kernel_plane.mig-example-c", "svc-twitter")

	got := tally(ids)
	msg := strings.Join(got, ", ")

	if len(got) != 7 {
		t.Fatalf("tally produced %d entries, want 7 distinct: %v", len(got), got)
	}
	// First-seen order, because the list is read top to bottom and reordering it would move the
	// entries the operator is hunting for.
	if got[0] != "offload_devices=(empty)" || got[len(got)-1] != "svc-twitter" {
		t.Fatalf("order changed: %v", got)
	}
	// The count is information, not noise: ninety affected lists and one are different situations.
	if !strings.Contains(msg, "kernel_plane.list-cascade (×90)") {
		t.Fatalf("the repeat count was dropped: %s", msg)
	}
	if !strings.Contains(msg, "kernel_plane.list-blocked (×4)") {
		t.Fatalf("a smaller repeat lost its count: %s", msg)
	}
	// A one-off must NOT be decorated — "(×1)" on every line would be the same wall in a new form.
	if strings.Contains(msg, "svc-twitter (×") {
		t.Fatalf("a single occurrence was given a count: %s", msg)
	}
	// The whole point: the message is now readable.
	if strings.Count(msg, "list-cascade") != 1 {
		t.Fatalf("the repeated ID still appears %d times", strings.Count(msg, "list-cascade"))
	}
}

func TestTally_EmptyAndSingle(t *testing.T) {
	if got := tally(nil); len(got) != 0 {
		t.Fatalf("tally(nil) = %v", got)
	}
	if got := tally([]string{"a"}); len(got) != 1 || got[0] != "a" {
		t.Fatalf("tally([a]) = %v", got)
	}
}
