package updater

import "testing"

// "Could not decide" must not be reported as "already up to date". Newer folds both into false,
// which is right for auto-update (do nothing on an undecidable tag) and wrong for anything that
// DISPLAYS the result.
func TestCompare_SeparatesUndecidableFromNotNewer(t *testing.T) {
	cases := []struct {
		current, latest        string
		wantNewer, wantDecided bool
	}{
		{"0.5.5", "0.5.6", true, true},
		{"0.5.5", "0.5.5", false, true},
		{"0.5.5", "v0.5.5-r2", true, true},
		{"0.5.5-r2", "v0.5.5-r2", false, true},
		{"0.5.5-r2", "v0.5.5-r3", true, true},
		{"0.5.6", "0.5.5", false, true},
		// Tags carrying no version at all: undecidable, NOT "up to date".
		{"0.5.5", "nightly", false, false},
		{"0.5.5", "latest", false, false},
		{"0.5.5", "dev", false, false},
		{"0.5.5", "", false, false},
		// An unparseable CURRENT is decidable against a real tag: Newer offers the update, which is
		// the safe direction, and the panel may say so.
		{"", "0.5.6", true, true},
	}
	for _, c := range cases {
		newer, decided := Compare(c.current, c.latest)
		if newer != c.wantNewer || decided != c.wantDecided {
			t.Errorf("Compare(%q, %q) = (%v, %v), want (%v, %v)",
				c.current, c.latest, newer, decided, c.wantNewer, c.wantDecided)
		}
	}
}

// Compare must agree with Newer wherever Newer is meaningful, so auto-update behaviour is unchanged.
func TestCompare_AgreesWithNewerWhenDecided(t *testing.T) {
	for _, p := range [][2]string{{"0.5.5", "0.5.6"}, {"0.5.6", "0.5.5"}, {"1.0.0", "1.0.0"}, {"", "2.0.0"}} {
		newer, decided := Compare(p[0], p[1])
		if decided && newer != Newer(p[0], p[1]) {
			t.Errorf("Compare and Newer disagree for (%q, %q)", p[0], p[1])
		}
	}
}
