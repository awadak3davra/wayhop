package model

import "testing"

func TestMissingProtoParam_Snell(t *testing.T) {
	for _, tc := range []struct {
		params map[string]any
		want   string
	}{
		{map[string]any{"version": 4}, "psk"},
		{map[string]any{"version": 4, "psk": "short"}, ""},
		{map[string]any{"version": float64(6), "psk": "short"}, "psk (Snell v6 needs 12 to 255 bytes)"},
		{map[string]any{"version": "6", "psk": "abcdefghijkl"}, ""},
	} {
		e := Endpoint{Protocol: ProtoSnell, Params: tc.params}
		if got := missingProtoParam(&e); got != tc.want {
			t.Errorf("params %v: missing = %q, want %q", tc.params, got, tc.want)
		}
	}
}
