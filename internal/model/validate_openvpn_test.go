package model

import "testing"

// An OpenVPN endpoint without its trust material would pass the store and fail only when sing-box
// loads it; the model refuses it first, by the field that is missing.
func TestMissingProtoParam_OpenVPN(t *testing.T) {
	for _, tc := range []struct {
		params map[string]any
		want   string
	}{
		{map[string]any{"mode": "tls"}, "ca"},
		{map[string]any{"mode": "tls", "ca": "PEM"}, ""},
		{map[string]any{"ca": "PEM"}, ""},
		{map[string]any{"mode": "static_key", "static_key": "K"}, "address"},
		{map[string]any{"mode": "static_key", "static_key": "K", "address": "10.8.0.2", "peer_address": "10.8.0.1"}, ""},
	} {
		e := Endpoint{Protocol: ProtoOpenVPN, Params: tc.params}
		if got := missingProtoParam(&e); got != tc.want {
			t.Errorf("params %v: missing = %q, want %q", tc.params, got, tc.want)
		}
	}
}
