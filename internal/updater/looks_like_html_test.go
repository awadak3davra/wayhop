package updater

import "testing"

// TestLooksLikeHTML guards the mirror-interstitial fix: a 200 HTML/captcha/error page must
// be rejected (so it is never installed as a "binary"), while real release assets (raw ELF,
// gzip, zip) must pass even when served with an odd content-type.
func TestLooksLikeHTML(t *testing.T) {
	reject := []struct {
		ct   string
		body string
	}{
		{"text/html; charset=utf-8", "<!doctype html><html>blocked</html>"},
		{"application/xhtml+xml", "<html/>"},
		{"", "  \n<!DOCTYPE html>"},          // leading whitespace, body sniff
		{"", "<html><body>captcha</body>"},   // no content-type, html body
		{"", "<?xml version=\"1.0\"?><err>"}, // xml error doc
		{"", "<Html>"},                       // case-insensitive
	}
	for _, c := range reject {
		if !looksLikeHTML(c.ct, []byte(c.body)) {
			t.Errorf("looksLikeHTML(%q, %q) = false, want true (should reject)", c.ct, c.body)
		}
	}

	pass := []struct {
		ct   string
		body []byte
	}{
		{"application/octet-stream", []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}}, // ELF
		{"application/gzip", []byte{0x1f, 0x8b, 0x08, 0x00}},                  // gzip
		{"application/zip", []byte{'P', 'K', 0x03, 0x04}},                     // zip
		{"binary/octet-stream", []byte{0x00, 0x01, 0x02}},                     // arbitrary binary
		{"", []byte{}}, // empty: don't reject (other paths handle it)
	}
	for _, c := range pass {
		if looksLikeHTML(c.ct, c.body) {
			t.Errorf("looksLikeHTML(%q, %v) = true, want false (must not false-reject a real asset)", c.ct, c.body)
		}
	}
}
