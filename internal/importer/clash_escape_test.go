package importer

import "testing"

// TestUnquote_DecodesYAMLEscapes: unquote must DECODE YAML escape sequences, not just strip the
// quotes — the exporter's yamlScalar emits \\ \" \n \t inside double quotes, so failing to decode
// them corrupts any password/name containing those characters on re-import.
func TestUnquote_DecodesYAMLEscapes(t *testing.T) {
	cases := map[string]string{
		`"a\\b"`:  `a\b`,   // escaped backslash -> one backslash
		`"a\"b"`:  `a"b`,   // escaped quote
		`"a\tb"`:  "a\tb",  // tab
		`"a\nb"`:  "a\nb",  // newline
		`"plain"`: "plain", // no escapes
		`'it''s'`: "it's",  // single-quoted doubled-quote escape
		`'a\\b'`:  `a\\b`,  // single-quoted: backslash is LITERAL, not an escape
		`bare`:    "bare",  // unquoted unchanged
		`"a\zb"`:  `a\zb`,  // unknown escape kept verbatim (no data loss)
	}
	for in, want := range cases {
		if got := unquote(in); got != want {
			t.Errorf("unquote(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestParseClash_RoundTripsEscapedPassword: a trojan password containing a backslash must survive
// the export-form YAML -> ParseClash path unchanged (the round-trip contract the exporter documents).
func TestParseClash_RoundTripsEscapedPassword(t *testing.T) {
	// yamlScalar would emit `password: "p\\w"` for the 3-char password `p\w`.
	cfg := "proxies:\n  - {name: n, type: trojan, server: s.example, port: 443, password: \"p\\\\w\"}\n"
	eps, errs := ParseClash(cfg)
	if len(errs) != 0 || len(eps) != 1 {
		t.Fatalf("parse: errs=%v eps=%d", errs, len(eps))
	}
	if got := eps[0].Params["password"]; got != `p\w` {
		t.Errorf("password round-tripped as %q, want %q (backslash must not double)", got, `p\w`)
	}
}
