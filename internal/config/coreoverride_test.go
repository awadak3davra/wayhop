package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// A malformed override is refused at save (the Settings PUT and import fail closed on Validate), so
// it can never reach Apply. The format's own cases are in generator/override_test.go; these pin that
// Validate is where they bite, on every shape a hand-written override goes wrong in.
func TestValidate_CoreOverride(t *testing.T) {
	for _, ok := range []string{
		"",
		`{"log":{"level":"info"}}`,
		`{"route":{"final":"direct"},"prepend":{"route.rules":[{"action":"sniff"}],"outbounds":[{"type":"direct","tag":"x"}],"dns.rules":[],"dns.servers":[]}}`,
	} {
		c := Default()
		c.CoreOverride = ok
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, tc := range []struct{ text, want string }{
		{`[{"log":{}}]`, "must be a JSON object"},
		{`"log"`, "must be a JSON object"},
		{`{"log":`, "not valid JSON"},
		{`{"x":"` + strings.Repeat("a", 64<<10) + `"}`, "the limit is 65536"},
		{`{"prepend":{"inbounds":[{"type":"mixed"}]}}`, `prepend "inbounds" is not supported`},
		{`{"prepend":{"experimental":{}}}`, `prepend "experimental" is not supported`},
		{`{"prepend":{"route.rules":"sniff"}}`, "must be an array"},
	} {
		c := Default()
		c.CoreOverride = tc.text
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%.50s: Validate = %v, want an error containing %q", tc.text, err, tc.want)
		}
	}
}

// The override can carry a server's credentials in a prepended outbound, so a shared export masks it
// whole, and a config without one stays byte-identical on disk (omitempty) for a downgrade.
func TestCoreOverride_RedactedAndOmitted(t *testing.T) {
	c := Default()
	c.CoreOverride = `{"prepend":{"outbounds":[{"type":"trojan","tag":"t","password":"secret"}]}}`
	if r := c.Redacted(); r.CoreOverride != RedactedMark {
		t.Errorf("Redacted().CoreOverride = %q", r.CoreOverride)
	}
	b, err := json.Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "core_override") {
		t.Error("an unset override must not appear in config.json")
	}
}
