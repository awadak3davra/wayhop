package model

import (
	"regexp"
	"testing"
)

// bareHost: a valid SNI hostname — lowercase letters/digits/dot/hyphen, at least one dot, no
// scheme/port/slash/space. Matches what a Reality server_name needs AND what netdiag.ValidTarget
// accepts, so every catalog Host can be fed straight into POST /api/probe/tls.
var bareHost = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

func TestRealityDests_Invariants(t *testing.T) {
	dests := RealityDests()
	if len(dests) == 0 {
		t.Fatal("RealityDests() is empty — the picker needs candidates")
	}
	seen := map[string]bool{}
	for _, d := range dests {
		if d.Host == "" || d.Name == "" || d.Category == "" {
			t.Errorf("entry missing a required field: %+v", d)
		}
		if seen[d.Host] {
			t.Errorf("duplicate host %q", d.Host)
		}
		seen[d.Host] = true
		// A Reality dest is a bare SNI hostname on :443 — no scheme, port, path, or spaces — so it
		// is both a valid server_name and directly probe-safe.
		if !bareHost.MatchString(d.Host) {
			t.Errorf("host %q is not a bare hostname (must be probe-safe SNI, no scheme/port/slash)", d.Host)
		}
	}
}
