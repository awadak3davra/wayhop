package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Deliverable 9: migration behaviour for existing users.
//
// Every field the deep-integration work added is optional, and "absent" must mean "behave exactly as
// this user's router behaved before the upgrade". That is a promise about somebody's live router, so
// it is pinned here rather than left to the reader of a struct tag: an upgrade that silently changed
// routing mode, switched on offload, or re-pointed rule-set downloads would be a serious regression
// discovered only in production.
//
// legacyConfigJSON is a config as written by a pre-deep-integration build: no routing_mode, no
// offload, no offload_devices, no rule_set_detour.
const legacyConfigJSON = `{
  "listen": ":8088",
  "data_dir": "/opt/var/wayhop",
  "demo": false,
  "gateway": false,
  "ports": {"ui": 8088, "clash": 9091, "dns": 5353, "mixed": 7890},
  "clash": {"controller": "127.0.0.1:9091", "secret": ""},
  "singbox": {"bin": "/opt/bin/sing-box", "config": "/opt/etc/wayhop/singbox.json"},
  "updater": {"auto_update": true},
  "failsafe": {"target": "1.1.1.1", "auto_reboot": false}
}`

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// A config from the previous release must load, validate, and leave every new field at the value
// that reproduces the old behaviour.
func TestMigration_LegacyConfigLoadsUnchanged(t *testing.T) {
	c, err := Load(writeTemp(t, "config.json", legacyConfigJSON))
	if err != nil {
		t.Fatalf("a config written by the previous release must still load: %v", err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("a legacy config must validate: %v", err)
	}

	// Each of these defaults is a behavioural promise, not a formality.
	if c.RoutingMode != "" {
		t.Errorf("routing_mode = %q, want empty: an upgrade must not change how traffic is routed", c.RoutingMode)
	}
	if c.Offload != "" && c.Offload != "off" {
		t.Errorf("offload = %q, want off/empty: an upgrade must not enable flow offload by itself", c.Offload)
	}
	if len(c.OffloadDevices) != 0 {
		t.Errorf("offload_devices = %v, want none", c.OffloadDevices)
	}
	if c.RuleSetDetour != "" {
		t.Errorf("rule_set_detour = %q, want empty: downloads must keep going out direct as before", c.RuleSetDetour)
	}
}

// The new fields are omitempty, so re-saving a legacy config must not inject them. This is what
// keeps a DOWNGRADE safe: a user who rolls back to the previous binary gets a file it still
// understands, rather than one carrying keys it will reject.
func TestMigration_ResaveDoesNotInjectNewKeys(t *testing.T) {
	c, err := Load(writeTemp(t, "config.json", legacyConfigJSON))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	out, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"routing_mode", "offload", "offload_devices", "rule_set_detour"} {
		if _, present := got[k]; present {
			t.Errorf("re-saving a legacy config added %q; an untouched setting must not appear on disk", k)
		}
	}
}

// An operator who DID set the new fields must keep them across a round-trip — the omitempty above
// must not be so eager that it drops real settings.
func TestMigration_ExplicitNewFieldsSurviveRoundTrip(t *testing.T) {
	src := `{
	  "listen": ":8088",
	  "ports": {"ui": 8088, "clash": 9091, "dns": 5353, "mixed": 7890},
	  "routing_mode": "fast",
	  "offload": "sw",
	  "offload_devices": ["wan", "br-lan"],
	  "rule_set_detour": "regiona"
	}`
	c, err := Load(writeTemp(t, "config.json", src))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	out, _ := json.Marshal(c)
	var round Config
	if err := json.Unmarshal(out, &round); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if round.RoutingMode != "fast" || round.Offload != "sw" || round.RuleSetDetour != "regiona" {
		t.Errorf("explicit settings lost in round-trip: %+v", round)
	}
	if len(round.OffloadDevices) != 2 {
		t.Errorf("offload_devices lost in round-trip: %v", round.OffloadDevices)
	}
}

// A config carrying keys this build does not know (i.e. written by a NEWER build, after a downgrade)
// must not brick start-up. Load tolerates and warns rather than refusing to boot.
func TestMigration_UnknownKeysDoNotBlockStartup(t *testing.T) {
	src := `{
	  "listen": ":8088",
	  "ports": {"ui": 8088, "clash": 9091, "dns": 5353, "mixed": 7890},
	  "some_future_field": {"nested": true},
	  "another_future_flag": 42
	}`
	c, err := Load(writeTemp(t, "config.json", src))
	if err != nil {
		t.Fatalf("unknown keys must not prevent start-up: %v", err)
	}
	if c.Listen != ":8088" {
		t.Errorf("known fields must still be read: listen = %q", c.Listen)
	}
}

// IgnoredDrift is new in this release and must obey the same back-compat rules as every other added
// field: absent means empty, and re-saving must not write the key.
func TestMigration_IgnoredDriftIsBackCompatible(t *testing.T) {
	c, err := Load(writeTemp(t, "config.json", legacyConfigJSON))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.IgnoredDrift) != 0 {
		t.Errorf("ignored_drift = %v, want empty on a legacy config", c.IgnoredDrift)
	}
	out, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := got["ignored_drift"]; present {
		t.Error("re-saving a legacy config must not add an ignored_drift key")
	}
}
