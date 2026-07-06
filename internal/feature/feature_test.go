package feature

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"wayhop/internal/config"
)

type fakeModule struct{ id string }

func (m *fakeModule) Descriptor() Descriptor       { return Descriptor{ID: m.id, Name: m.id, Icon: "x"} }
func (m *fakeModule) Routes(*http.ServeMux, *Deps) {}
func (m *fakeModule) Start(context.Context, *Deps) {}
func (m *fakeModule) Stop()                        {}

func resetRegistry() { registry = nil }

func ids(ms []Module) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.Descriptor().ID
	}
	return out
}

func TestRegisterAndAllOrder(t *testing.T) {
	resetRegistry()
	Register(&fakeModule{id: "a"})
	Register(&fakeModule{id: "b"})
	if got := ids(All()); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("All() = %v, want [a b] in registration order", got)
	}
}

func TestEnabledFiltersByConfig(t *testing.T) {
	resetRegistry()
	Register(&fakeModule{id: "iptv"})
	Register(&fakeModule{id: "other"})
	cfg := config.Config{Features: map[string]config.FeatureConfig{
		"iptv":  {Enabled: true},
		"other": {Enabled: false},
	}}
	if got := ids(Enabled(cfg)); len(got) != 1 || got[0] != "iptv" {
		t.Fatalf("Enabled = %v, want [iptv]", got)
	}
	// A module absent from Features is NOT enabled; an empty config enables nothing.
	if got := Enabled(config.Config{}); len(got) != 0 {
		t.Errorf("Enabled(empty cfg) = %v, want none", ids(got))
	}
}

func TestFeatureConfigRoundTrip(t *testing.T) {
	c := config.Config{Features: map[string]config.FeatureConfig{
		"iptv": {Enabled: true, Settings: json.RawMessage(`{"country":"it"}`)},
	}}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var back config.Config
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	fc := back.Features["iptv"]
	if !fc.Enabled || string(fc.Settings) != `{"country":"it"}` {
		t.Fatalf("round-trip lost data: %+v", fc)
	}
	// omitempty: an empty Features map is omitted from the JSON.
	b2, _ := json.Marshal(config.Config{})
	if strings.Contains(string(b2), `"features"`) {
		t.Errorf("empty Features should be omitted, got %s", b2)
	}
}
