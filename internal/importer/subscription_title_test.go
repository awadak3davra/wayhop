package importer

import "testing"

// TestDecodeProfileTitle covers the base64-or-raw discrimination + sanitization
// of a subscription's Profile-Title value. All inputs are synthetic.
func TestDecodeProfileTitle(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"whitespace only", "   \t ", ""},
		// Base64 of "Main Servers" (the documented clash/subconverter convention).
		{"base64 ascii", "TWFpbiBTZXJ2ZXJz", "Main Servers"},
		// Base64 of "🇳🇱 NL" — proves non-ASCII titles survive (the whole reason
		// providers base64-encode the header value).
		{"base64 utf8 flag", "8J+Hs/Cfh7EgTkw=", "🇳🇱 NL"},
		// A raw title that is NOT valid base64 (contains a space) must pass through
		// verbatim, not be dropped.
		{"raw with space", "My VPN", "My VPN"},
		// A raw ASCII title that *happens* to be valid base64 must NOT be mangled:
		// "Main" decodes to non-printable bytes, so we keep the raw value.
		{"raw that is valid base64", "Main", "Main"},
		// A short raw title like "NL" is valid base64 (decodes to "4") yet must be
		// preserved — the looksDecoded guard rejects the spurious base64 reading.
		{"short raw valid base64", "NL", "NL"},
		// Trailing/leading whitespace is trimmed; inner runs collapse to one space.
		{"collapse + trim", "  Tokyo    Node  ", "Tokyo Node"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DecodeProfileTitle(c.in); got != c.want {
				t.Errorf("DecodeProfileTitle(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestDecodeProfileTitle_StripsControlChars ensures embedded control bytes (e.g. a
// CR/LF a hostile server might splice in) are removed from the display name. NUL
// and BEL are dropped outright; the trailing newline is whitespace so it trims.
func TestDecodeProfileTitle_StripsControlChars(t *testing.T) {
	if got := DecodeProfileTitle("Good\x00\x07Name\n"); got != "GoodName" {
		t.Errorf("control-char strip = %q, want %q", got, "GoodName")
	}
}

// TestDecodeProfileTitle_LengthCap caps absurdly long titles on a rune boundary.
func TestDecodeProfileTitle_LengthCap(t *testing.T) {
	long := ""
	for i := 0; i < 200; i++ {
		long += "x"
	}
	got := DecodeProfileTitle(long)
	if len([]rune(got)) != maxTitleLen {
		t.Errorf("length cap = %d runes, want %d", len([]rune(got)), maxTitleLen)
	}
}
