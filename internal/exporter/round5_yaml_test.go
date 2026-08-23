package exporter

import "testing"

// TestYamlScalar_EscapesControlChars: every C0 control char in a string field must be quoted and
// escaped, not emitted raw — a raw CR is a YAML line break for yaml.v3/mihomo (structural corruption)
// and a NUL is rejected outright, which would break the whole served clash config.
func TestYamlScalar_EscapesControlChars(t *testing.T) {
	cases := map[string]string{
		"plain":       "plain",
		"US\rEast":    `"US\rEast"`, // CR -> \r
		"a\x00b":      `"a\x00b"`,   // NUL -> \x00
		"a\x0bb":      `"a\x0bb"`,   // vertical tab -> \x0b
		"a\x0cb":      `"a\x0cb"`,   // form feed -> \x0c
		"a\tb":        `"a\tb"`,     // tab
		"a\nb":        `"a\nb"`,     // newline
		"back\\slash": `"back\\slash"`,
	}
	for in, want := range cases {
		if got := yamlScalar(in); got != want {
			t.Errorf("yamlScalar(%q) = %q, want %q", in, got, want)
		}
	}
	// A value with a CR must NOT contain a raw CR after escaping.
	if out := yamlScalar("x\ry"); containsByte(out, '\r') {
		t.Errorf("yamlScalar left a raw CR in the output: %q", out)
	}
}

func containsByte(s string, b byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return true
		}
	}
	return false
}
