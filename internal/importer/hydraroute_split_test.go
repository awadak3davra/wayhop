package importer

import "testing"

// The target is what follows the LAST "/", and it is one name. A prefix pasted among the names made
// "24/nwg0" the target; a trailing comment made "HydraRoute # video" one. Both read as valid groups.
func TestParseHydraRoute_TargetIsTheLastSlashAndOneName(t *testing.T) {
	r := ParseHydraRoute("example.com,192.0.2.0/24/nwg0\nyoutube.com/HydraRoute # video\n")
	if len(r.Targets) != 1 || r.Targets[0].Target != "nwg0" {
		t.Fatalf("targets = %+v, want only nwg0", r.Targets)
	}
	if got := r.Targets[0].Domains; len(got) != 1 || got[0] != "example.com" {
		t.Errorf("nwg0 domains = %v", got)
	}
	// The prefix is not a name; the commented line names no target. Both are reported.
	var prefixSkipped, commentSkipped bool
	for _, s := range r.Targets[0].Skipped {
		prefixSkipped = prefixSkipped || (s.Entry == "192.0.2.0/24" && s.Reason == HydraSkipInvalid)
	}
	for _, s := range r.Skipped {
		commentSkipped = commentSkipped || (s.Line == 2 && s.Reason == HydraSkipInvalid)
	}
	if !prefixSkipped || !commentSkipped {
		t.Errorf("prefix reported %v, commented line reported %v; skips %+v / %+v", prefixSkipped, commentSkipped, r.Targets[0].Skipped, r.Skipped)
	}
}
