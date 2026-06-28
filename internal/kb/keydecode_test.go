package kb

import "testing"

func keydecode_has(line, id string) bool {
	for _, e := range Match(line) {
		if e.ID == id {
			return true
		}
	}
	return false
}

func keydecode_ids(line string) []string {
	var ids []string
	for _, e := range Match(line) {
		ids = append(ids, e.ID)
	}
	return ids
}

// TestMatchKeyDecodeErrors pins that the specific malformed-key/short-id decode errors
// (WireGuard private/peer key, Reality public key, Reality short-id) match the dedicated
// sb-decode-key entry — these were previously only caught by the generic sb-fatal-start,
// which gives no actionable "fix your key" guidance.
func TestMatchKeyDecodeErrors(t *testing.T) {
	hits := []string{
		`FATAL[0000] start service: initialize endpoint[0]: decode private key: illegal base64 data at input byte 7`,
		`FATAL[0000] start service: initialize outbound[1]: decode public_key: illegal base64 data at input byte 43`,
		`start service: decode short_id: encoding/hex: invalid byte`,
		`reality: invalid public_key`,
	}
	for _, ln := range hits {
		if !keydecode_has(ln, "sb-decode-key") {
			t.Errorf("line %q did not match sb-decode-key (got %v)", ln, keydecode_ids(ln))
		}
	}

	// The matched entry must carry actionable text + a source (the kb's reason to exist).
	var fix, expl string
	var srcN int
	for _, e := range Match(hits[0]) {
		if e.ID == "sb-decode-key" {
			fix, expl, srcN = e.Fix, e.Explanation, len(e.Sources)
		}
	}
	if fix == "" || expl == "" || srcN == 0 {
		t.Errorf("sb-decode-key missing text/sources (fix=%q expl=%q sources=%d)", fix, expl, srcN)
	}

	// Benign lines (and the neighbouring config-parse error) must NOT match sb-decode-key.
	for _, ln := range []string{
		"INFO public key loaded for peer",
		"router started, 5 outbounds loaded",
		"decode config at /etc/sing-box/config.json: ok",
	} {
		if keydecode_has(ln, "sb-decode-key") {
			t.Errorf("benign line %q wrongly matched sb-decode-key", ln)
		}
	}
}
