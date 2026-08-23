package exporter

import "testing"

// hasAWGParams decides whether a WireGuard endpoint is secretly an AmneziaWG one and must therefore
// NOT be emitted as a clash wireguard proxy. Getting that wrong in the false direction is the bad
// direction: the endpoint ships as plain WireGuard and the obfuscation is gone without a word.
//
// The detector's key list was the AmneziaWG 1.x set (jc/jmin/jmax, s1/s2, h1..h4) while the importer
// had already grown the 2.x/3.x additions — s3, s4 and the hex magic-header params i1..i5
// (internal/importer/conf.go: awgKeys + awgKeysHex). An endpoint carrying only the newer knobs read
// as "no obfuscation" and slipped through.
//
// This is not hypothetical: /etc/config/network on the AX3000T carries awg_s3, awg_s4 and
// awg_i1..awg_i5 today.
func TestHasAWGParams_DetectsAmneziaWG3ParamSet(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]any
		want   bool
	}{
		// The regression: none of the 1.x knobs, only the newer ones.
		{"only i-params (hex magic headers)", map[string]any{
			"i1": "0x11111111111111111111111111111111",
			"i5": "0x55555555555555555555555555555555",
		}, true},
		{"only s3/s4", map[string]any{"s3": 25, "s4": 40}, true},
		{"a full 3.x set as the router writes it", map[string]any{
			"jc": 5, "jmin": 49, "jmax": 998,
			"s1": 17, "s2": 110, "s3": 25, "s4": 40,
			"h1": "500000000-900000000", "h2": "1000000000-1400000000",
			"h3": "1500000000-1900000000", "h4": "2000000000-2400000000",
			"i1": "0x11111111111111111111111111111111",
		}, true},
		// Still true for the 1.x set — the old behaviour must not regress.
		{"classic 1.x set", map[string]any{"jc": 4, "s1": 15, "h1": "1"}, true},
		// And still false for a genuinely plain WireGuard endpoint, or the detector would refuse to
		// export anything and the fix would be worse than the defect.
		{"plain wireguard", map[string]any{"mtu": 1420, "keepalive": 25}, false},
		{"present but zero", map[string]any{"jc": 0, "s1": "0", "i1": ""}, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasAWGParams(c.params); got != c.want {
				t.Fatalf("hasAWGParams(%v) = %v, want %v — an undetected AmneziaWG endpoint is "+
					"exported as plain WireGuard and loses its obfuscation silently", c.params, got, c.want)
			}
		})
	}
}
