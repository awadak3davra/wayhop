package generator

import (
	"encoding/json"
	"reflect"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// QA-019: the sing-box 1.14 protocols, and Hysteria2's 1.14 options, survive Generate -> ParseSingbox -> Generate. The importer
// rejected snell outbounds and openvpn-client / openconnect endpoints, so a config WayHop wrote could
// not be read back, nor a sing-box config carrying them imported.
func TestRoundTrip114Protocols(t *testing.T) {
	var eps []model.Endpoint
	eps = append(eps, openvpnTestProfile(t).Endpoints...)
	eps = append(eps, snellTestProfile().Endpoints...)
	eps = append(eps, openconnectTestProfile().Endpoints...)
	eps = append(eps, hy2ExtrasProfile().Endpoints...)
	profile := func(eps []model.Endpoint) *model.Profile {
		return &model.Profile{Endpoints: eps, Rules: []model.Rule{{ID: "def", Default: true, Outbound: eps[0].ID}}}
	}
	first, err := Generate(profile(eps), Options{MixedPort: 7890, CoreVersion: "1.14.4"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	raw, _ := json.Marshal(first.Config)
	back, errs := importer.ParseSingbox(string(raw))
	if len(errs) > 0 {
		t.Fatalf("ParseSingbox: %v", errs)
	}
	// Parsed endpoints are named and identified by their tags, which are the original ids.
	for i := range back {
		back[i].ID, back[i].Enabled = back[i].Name, true
	}
	second, err := Generate(profile(back), Options{MixedPort: 7890, CoreVersion: "1.14.4"})
	if err != nil {
		t.Fatalf("generate from the read-back config: %v", err)
	}
	collect := func(cfg map[string]any) map[string]any {
		out := map[string]any{}
		for _, key := range []string{"endpoints", "outbounds"} {
			list, _ := cfg[key].([]map[string]any)
			for _, m := range list {
				switch m["type"] {
				case "openvpn-client", "openconnect", "snell", "hysteria2":
					b, _ := json.Marshal(m)
					var norm map[string]any
					_ = json.Unmarshal(b, &norm)
					out[m["tag"].(string)] = norm
				}
			}
		}
		return out
	}
	a, b := collect(first.Config), collect(second.Config)
	if len(a) != 9 {
		t.Fatalf("first render has %d of the 9 test connections: %v", len(a), a)
	}
	for tag, want := range a {
		if got := b[tag]; !reflect.DeepEqual(got, want) {
			t.Errorf("%s changed across the round-trip:\nfirst  %v\nsecond %v", tag, want, got)
		}
	}
}
