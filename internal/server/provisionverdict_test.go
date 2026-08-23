package server

import "testing"

// A provisioning run that delivered part of what was asked for must be reportable as partial.
//
// The job was OK as soon as one protocol came up, and the panel rendered any OK as a plain
// "Done — client added to Connections". Asking for three and getting one therefore read as full
// success, with the failures visible only to somebody who scrolled the console.
func TestProvisionVerdict(t *testing.T) {
	cases := []struct {
		name                 string
		requested, delivered int
		wantOK, wantPartial  bool
	}{
		{"everything asked for came up", 3, 3, true, false},
		{"one of three came up", 3, 1, true, true},
		{"two of three came up", 3, 2, true, true},
		{"nothing came up is a failure, not a partial result", 3, 0, false, false},
		{"single protocol, delivered", 1, 1, true, false},
		{"single protocol, failed", 1, 0, false, false},
		// Defensive: more delivered than requested should never happen, but it must not be
		// reported as partial if it ever does.
		{"more delivered than requested is not partial", 1, 2, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ok, partial := provisionVerdict(c.requested, c.delivered)
			if ok != c.wantOK {
				t.Errorf("ok: got %v, want %v (%d requested, %d delivered)", ok, c.wantOK, c.requested, c.delivered)
			}
			if partial != c.wantPartial {
				t.Errorf("partial: got %v, want %v (%d requested, %d delivered)", partial, c.wantPartial, c.requested, c.delivered)
			}
		})
	}
}

// The two states the panel must be able to tell apart: a partial run is NOT a plain success.
func TestProvisionVerdict_PartialIsDistinguishableFromFullSuccess(t *testing.T) {
	fullOK, fullPartial := provisionVerdict(3, 3)
	partOK, partPartial := provisionVerdict(3, 1)
	if fullOK != partOK {
		t.Fatal("test premise changed: both are expected to be ok, and the flag is what separates them")
	}
	if fullPartial == partPartial {
		t.Fatal("a full run and a one-of-three run are indistinguishable — this is the whole defect")
	}
}
