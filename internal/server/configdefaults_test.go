package server

import (
	"encoding/json"
	"testing"

	"wayhop/internal/config"
)

func defaultsMap(t *testing.T) map[string]any {
	t.Helper()
	d := config.Default()
	d.Clash.Secret = ""
	d.Watchdog.NotifyURL = ""
	raw, err := json.Marshal(completeJSONFields(d))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func dug(m map[string]any, path ...string) (any, bool) {
	var cur any = m
	for _, key := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = obj[key]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// The Settings index answers "is this still the default" by looking the field up in this payload, so
// a field missing from it is a setting the page cannot judge. `omitempty` was dropping exactly the
// fields whose default is empty — measured on a live router: routing_mode, flow_offload and
// flow_offload_devices were all absent, which left the filter blind to the routing mode.
func TestConfigDefaultsCarryFieldsWhoseDefaultIsEmpty(t *testing.T) {
	defaults := defaultsMap(t)
	for _, key := range []string{"routing_mode", "offload", "offload_devices"} {
		value, ok := dug(defaults, key)
		if !ok {
			t.Fatalf("%q is absent from the defaults payload, so the page cannot compare it", key)
		}
		// offload_devices is a slice; its empty default marshals as null, and the page renders that
		// as "(blank)" like the empty strings. What matters is that the key is THERE.
		if value != nil && value != "" {
			t.Fatalf("%q default = %v, want empty", key, value)
		}
	}
}

// Nested paths are what most of the page's metadata uses, and an embedded/typed struct must not
// change shape just because it is walked field by field.
func TestConfigDefaultsKeepNestedShape(t *testing.T) {
	defaults := defaultsMap(t)
	for _, path := range [][]string{
		{"ports", "ui"}, {"ports", "dns"}, {"clash", "controller"},
		{"singbox", "bin"}, {"failsafe", "target"}, {"failsafe", "auto_reboot"}, {"watchdog", "notify_url"},
		{"updater", "mirrors"}, {"auth", "username"}, {"backup", "auto_hours"},
	} {
		if _, ok := dug(defaults, path...); !ok {
			t.Fatalf("%v is absent from the defaults payload", path)
		}
	}
	// The values still have to be the real defaults, not zeroes invented by the walk.
	if got, _ := dug(defaults, "ports", "ui"); got != float64(config.Default().Ports.UI) {
		t.Fatalf("ports.ui = %v, want %d", got, config.Default().Ports.UI)
	}
	// And a path that does NOT exist must stay absent, or a typo in the page's metadata would be
	// silently compared against an invented empty default instead of reporting that it cannot judge.
	if _, ok := dug(defaults, "flow_offload_typo"); ok {
		t.Fatal("an unknown key resolved in the defaults payload")
	}
}

// A defaults endpoint has no reason to be credential-bearing, and the walk must not resurrect what
// the handler blanked.
func TestConfigDefaultsCarryNoSecrets(t *testing.T) {
	defaults := defaultsMap(t)
	if got, _ := dug(defaults, "clash", "secret"); got != "" {
		t.Fatalf("clash.secret = %v, want blank", got)
	}
	if got, _ := dug(defaults, "watchdog", "notify_url"); got != "" {
		t.Fatalf("watchdog.notify_url = %v, want blank", got)
	}
	if got, _ := dug(defaults, "auth", "password_hash"); got != "" {
		t.Fatalf("auth.password_hash = %v, want blank", got)
	}
}
