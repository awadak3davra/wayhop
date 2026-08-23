package server

import "testing"

func hasID(list []string, id string) bool {
	for _, v := range list {
		if v == id {
			return true
		}
	}
	return false
}

// Dismissing is per-object: adding one ID must leave the others intact, so a user who dismisses a
// stale tunnel is still told about the next one that disappears.
func TestApplyIgnore_AddsWithoutDisturbingOthers(t *testing.T) {
	got := applyIgnore([]string{"a", "b"}, "c", true)
	for _, want := range []string{"a", "b", "c"} {
		if !hasID(got, want) {
			t.Errorf("%q missing from %v", want, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("unexpected list %v", got)
	}
}

// Dismissal must be reversible, or a user who changes their mind is editing config by hand.
func TestApplyIgnore_RemovesOnUnignore(t *testing.T) {
	got := applyIgnore([]string{"a", "b", "c"}, "b", false)
	if hasID(got, "b") {
		t.Errorf("b should have been removed: %v", got)
	}
	if len(got) != 2 {
		t.Errorf("unexpected list %v", got)
	}
}

// Re-adding an existing ID must not duplicate it — the field is a set.
func TestApplyIgnore_IsIdempotent(t *testing.T) {
	got := applyIgnore([]string{"a"}, "a", true)
	if len(got) != 1 {
		t.Errorf("re-ignoring must not duplicate: %v", got)
	}
	// And an already-absent removal is a no-op rather than an error.
	if g := applyIgnore([]string{"a"}, "zzz", false); len(g) != 1 || !hasID(g, "a") {
		t.Errorf("removing an absent id must be a no-op: %v", g)
	}
}

// A hand-edited config may already contain duplicates; they must be cleaned rather than multiplied.
func TestApplyIgnore_DropsPreexistingDuplicates(t *testing.T) {
	got := applyIgnore([]string{"a", "a", "b"}, "c", true)
	n := 0
	for _, v := range got {
		if v == "a" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("duplicate 'a' not collapsed: %v", got)
	}
}

// Emptying the list must yield nil so the omitempty field disappears from the persisted config
// rather than being written as an empty array — the same back-compat property every other new field
// in this release holds to.
func TestApplyIgnore_EmptyBecomesNil(t *testing.T) {
	if got := applyIgnore([]string{"a"}, "a", false); got != nil {
		t.Errorf("want nil so the key is omitted, got %v", got)
	}
}
