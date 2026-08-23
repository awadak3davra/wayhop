package util

import "testing"

func TestAWGIface(t *testing.T) {
	// A documentation address (RFC 5737), written the way an endpoint id writes one: dots become
	// dashes. The previous fixture used a real host, and the dashed spelling walked straight past a
	// deny pattern written with dots — one value in two textual forms, compared literally.
	id := "amneziawg-203-0-113-10-8443"
	a := AWGIface(id)
	if a != AWGIface(id) {
		t.Fatal("AWGIface not deterministic")
	}
	if len(a) > 15 {
		t.Fatalf("iface %q too long (%d > 15 kernel limit)", a, len(a))
	}
	if a[:3] != "wr_" {
		t.Fatalf("iface %q missing wr_ prefix", a)
	}
	// The property behind the spelling, so a future tidy-up cannot restore the hyphen: this name is
	// also used verbatim as a uci SECTION name, and uci accepts only letters, digits and underscore
	// (measured on OpenWrt 24.10 — a hyphen answers "Invalid argument"). It was a hyphen until the
	// native writer had to name the same device and could not.
	for _, r := range a {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
		default:
			t.Fatalf("iface %q contains %q, which uci refuses in a section name", a, string(r))
		}
	}
	if AWGIface("x") == AWGIface("y") {
		t.Fatal("AWGIface collided for different ids")
	}
}
