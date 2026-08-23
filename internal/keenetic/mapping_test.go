package keenetic

import (
	"testing"

	"wayhop/internal/model"
)

func TestResolveNDMName(t *testing.T) {
	tests := []struct {
		name      string
		ep        model.Endpoint
		wantName  string
		wantKnown bool
	}{
		{
			name:      "explicit ndm_name is used",
			ep:        model.Endpoint{Params: map[string]any{"ndm_name": "Wireguard5", "interface": "nwg5"}},
			wantName:  "Wireguard5",
			wantKnown: true,
		},
		{
			name:      "hand-named tunnel: kernel iface present but NO ndm_name ⇒ refuse (never guess)",
			ep:        model.Endpoint{Params: map[string]any{"interface": "nwg5", "discovered": true}},
			wantName:  "",
			wantKnown: false,
		},
		{
			name:      "no params at all ⇒ refuse",
			ep:        model.Endpoint{},
			wantName:  "",
			wantKnown: false,
		},
		{
			name:      "blank ndm_name ⇒ refuse",
			ep:        model.Endpoint{Params: map[string]any{"ndm_name": "   "}},
			wantName:  "",
			wantKnown: false,
		},
		{
			name:      "non-string ndm_name ⇒ refuse",
			ep:        model.Endpoint{Params: map[string]any{"ndm_name": 5}},
			wantName:  "",
			wantKnown: false,
		},
		{
			name:      "ndm_name trimmed",
			ep:        model.Endpoint{Params: map[string]any{"ndm_name": "  Wireguard0 "}},
			wantName:  "Wireguard0",
			wantKnown: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, known := ResolveNDMName(tt.ep)
			if name != tt.wantName || known != tt.wantKnown {
				t.Errorf("ResolveNDMName() = (%q,%v), want (%q,%v)", name, known, tt.wantName, tt.wantKnown)
			}
		})
	}
}
