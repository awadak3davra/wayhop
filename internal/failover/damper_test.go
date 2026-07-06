package failover

import "testing"

func TestDamperSuppressReuseHysteresis(t *testing.T) {
	// Small, explicit config: penalty 1000/flap, suppress >2000, reuse <750, half-life 1000ms.
	d := NewDamper(DampConfig{FlapPenalty: 1000, HalfLifeMS: 1000, SuppressAt: 2000, ReuseAt: 750, MaxSuppressMS: 1_000_000})

	// One flap: penalty 1000, below suppress.
	d.Penalize("m", 0)
	if d.Suppressed("m", 0) {
		t.Fatal("one flap should not suppress")
	}
	// Three flaps in quick succession → penalty ~3000 > 2000 → suppressed.
	d.Penalize("m", 0)
	d.Penalize("m", 0)
	if !d.Suppressed("m", 0) {
		t.Fatal("three quick flaps should suppress")
	}
	// Hysteresis: penalty must decay below ReuseAt (750), not just below SuppressAt, to release.
	// After 1 half-life (t=1000): 3000→1500 (>750) still suppressed.
	if !d.Suppressed("m", 1000) {
		t.Fatal("still suppressed at 1 half-life (penalty ~1500 > reuse 750)")
	}
	// After 2 half-lives (t=2000): 3000→750 → at/below reuse → released.
	if d.Suppressed("m", 2000) {
		t.Fatal("should be released once penalty decays below reuse threshold")
	}
}

func TestDamperMaxSuppressCap(t *testing.T) {
	// Keep re-penalizing so the penalty never decays below reuse — only the max-suppress cap releases it.
	d := NewDamper(DampConfig{FlapPenalty: 1000, HalfLifeMS: 100000, SuppressAt: 2000, ReuseAt: 750, MaxSuppressMS: 5000})
	d.Penalize("m", 0)
	d.Penalize("m", 0)
	d.Penalize("m", 0) // ~3000 → suppressed at first check
	if !d.Suppressed("m", 0) {
		t.Fatal("should suppress")
	}
	// Even with the penalty still high (slow decay), the max-suppress cap releases it after 5s.
	if d.Suppressed("m", 6000) {
		t.Fatalf("max-suppress cap should release after 5s regardless of penalty")
	}
}

func TestDamperUnknownMemberNotSuppressed(t *testing.T) {
	d := NewDamper(DampConfig{})
	if d.Suppressed("never-seen", 1000) {
		t.Error("a member that never flapped must not be suppressed")
	}
}

func TestDamperDecayReducesPenalty(t *testing.T) {
	d := NewDamper(DampConfig{FlapPenalty: 1000, HalfLifeMS: 1000, SuppressAt: 100000, ReuseAt: 1})
	d.Penalize("m", 0) // 1000
	// After one half-life the penalty should roughly halve; a second flap then lands on ~500.
	d.Penalize("m", 1000) // decay 1000→~500, +1000 → ~1500
	s := d.state["m"]
	if s.penalty < 1400 || s.penalty > 1600 {
		t.Errorf("penalty after decay+flap = %.0f, want ~1500", s.penalty)
	}
}

func TestDampConfigDefaults(t *testing.T) {
	c := DampConfig{}
	if c.flapPenalty() != defaultFlapPenalty || c.halfLife() != defaultHalfLifeMS ||
		c.suppressAt() != defaultSuppressAt || c.reuseAt() != defaultReuseAt || c.maxSuppress() != defaultMaxSuppressMS {
		t.Errorf("zero DampConfig did not fall back to defaults: %+v", c)
	}
}
