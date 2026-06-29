package plugin

import (
	"strings"
	"testing"

	"velinx/internal/model"
)

// TestAwgConfig_KeyNewlineNoInjection guards confLine: a key param carrying an embedded
// newline must NOT inject extra directives into the awg .conf that `awg setconf` parses.
// The value is truncated at the control char (drop-don't-brick) instead.
func TestAwgConfig_KeyNewlineNoInjection(t *testing.T) {
	e := model.Endpoint{
		Engine: model.EngineAmneziaWG, Server: "1.2.3.4", Port: 51820,
		Params: map[string]any{
			"private_key":     "GOODPRIV\nPublicKey = ATTACKER",
			"peer_public_key": "GOODPUB\nEndpoint = evil.example:1",
			"pre_shared_key":  "PSK\nAllowedIPs = 10.0.0.0/8",
		},
	}
	c := awgConfig(e)
	for _, bad := range []string{"PublicKey = ATTACKER", "Endpoint = evil.example:1", "AllowedIPs = 10.0.0.0/8"} {
		if strings.Contains(c, bad) {
			t.Errorf("awgConfig leaked injected directive %q:\n%s", bad, c)
		}
	}
	// The pre-newline prefix survives (a malformed single-line key — the tunnel just won't
	// come up, rather than smuggling in attacker config).
	if !strings.Contains(c, "PrivateKey = GOODPRIV\n") {
		t.Errorf("awgConfig dropped the legit key prefix:\n%s", c)
	}
	// The real Endpoint line (from e.Server) must still be the only Endpoint directive.
	if strings.Count(c, "Endpoint = ") != 1 || !strings.Contains(c, "Endpoint = 1.2.3.4:51820") {
		t.Errorf("awgConfig Endpoint line corrupted:\n%s", c)
	}
}
