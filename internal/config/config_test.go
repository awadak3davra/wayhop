package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestConfigMigrationCompat locks in the deploy/rollback config-compat invariant that
// makes a device upgrade safe in BOTH directions:
//
//   - BACKWARD (deploy: old config -> new binary): a config missing the newer fields
//     loads with them at their zero/default.
//   - FORWARD (rollback: new config -> older binary): a config carrying fields this
//     binary does NOT know still loads — it must ignore them, not error, or a post-deploy
//     rollback fed the new binary's config would brick boot.
//
// Both hold only while Load stays lenient (plain json.Unmarshal, no DisallowUnknownFields).
// Renaming/retyping a persisted field, or tightening the decoder, fails this test before it
// can reach a router. (Verified 20281db..HEAD that every config json tag change is additive.)
func TestConfigMigrationCompat(t *testing.T) {
	base, err := json.Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	load := func(b []byte) (*Config, error) {
		dir := t.TempDir()
		p := filepath.Join(dir, "config.json")
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return Load(p)
	}

	// BACKWARD: Default()'s JSON omits the omitempty new fields (url/refresh_hours/offload…),
	// so it stands in for an older config — it must load with those fields defaulted.
	c, err := load(base)
	if err != nil {
		t.Fatalf("backward: Load(old-style config) errored: %v", err)
	}
	if c.Subscription.URL != "" || c.Subscription.RefreshHours != 0 {
		t.Errorf("backward: new fields not defaulted: url=%q hours=%d", c.Subscription.URL, c.Subscription.RefreshHours)
	}

	// FORWARD/ROLLBACK: inject fields this binary doesn't know; Load must ignore them (not
	// error) and preserve the known fields — else a rollback after a deploy would brick.
	var m map[string]json.RawMessage
	if err := json.Unmarshal(base, &m); err != nil {
		t.Fatal(err)
	}
	m["future_top_field"] = json.RawMessage(`{"nested":[1,2,3],"flag":true}`)
	fwd, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := load(fwd)
	if err != nil {
		t.Fatalf("forward: Load(newer config with an unknown field) errored — a rollback would brick: %v", err)
	}
	if c2.Listen != Default().Listen {
		t.Errorf("forward: a known field was lost when an unknown field was present: Listen=%q", c2.Listen)
	}
}

// An empty or whitespace-only config.json (the canonical power-loss / overlayfs
// artifact on a router) must load as defaults and rewrite a valid file — NOT brick
// boot with "unexpected end of JSON input". A non-empty garbage file still errors.
func TestLoadEmptyOrGarbage(t *testing.T) {
	for _, content := range []string{"", "   ", "\n\t  \n"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := Load(path)
		if err != nil {
			t.Fatalf("Load(empty %q) returned error: %v", content, err)
		}
		if c.Listen != Default().Listen {
			t.Fatalf("Load(empty) did not apply defaults: Listen=%q", c.Listen)
		}
		// The file must have been rewritten to a valid (re-loadable) config.
		c2, err := Load(path)
		if err != nil {
			t.Fatalf("reload after empty-file recreate errored: %v", err)
		}
		if c2.Listen != Default().Listen {
			t.Fatalf("rewritten config not valid defaults: %q", c2.Listen)
		}
	}

	// A genuinely-corrupt NON-empty file must still surface its parse error.
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load(garbage) should error, not swallow real corruption")
	}
}

func TestConfigValidate(t *testing.T) {
	// Default() must always validate — it is the reset/import baseline.
	if err := Default().Validate(); err != nil {
		t.Fatalf("Default() config rejected by Validate: %v", err)
	}

	base := func() *Config { return Default() }
	cases := []struct {
		name string
		mut  func(*Config)
		ok   bool
	}{
		{"default", func(*Config) {}, true},
		{"empty listen", func(c *Config) { c.Listen = "" }, false},
		{"listen no port", func(c *Config) { c.Listen = "192.168.1.1" }, false},
		{"listen bind-any ok", func(c *Config) { c.Listen = ":8080" }, true},
		{"port out of range", func(c *Config) { c.Ports.UI = 0 }, false},
		{"port too high", func(c *Config) { c.Ports.DNS = 70000 }, false},
		{"duplicate ports", func(c *Config) { c.Ports.Clash = c.Ports.UI }, false},
		{"clash controller bad", func(c *Config) { c.Clash.Controller = "nope" }, false},
		{"clash controller empty ok", func(c *Config) { c.Clash.Controller = "" }, true},
		{"routing mode valid", func(c *Config) { c.RoutingMode = "fast" }, true},
		{"routing mode invalid", func(c *Config) { c.RoutingMode = "turbo" }, false},
		{"offload valid", func(c *Config) { c.Offload = "hw" }, true},
		{"offload invalid", func(c *Config) { c.Offload = "max" }, false},
		{"gateway mtu valid", func(c *Config) { c.GatewayMTU = 1280 }, true},
		{"gateway mtu too low", func(c *Config) { c.GatewayMTU = 100 }, false},
		{"gateway addr valid", func(c *Config) { c.GatewayAddr = "172.19.0.1/30" }, true},
		{"gateway addr invalid", func(c *Config) { c.GatewayAddr = "172.19.0.1" }, false},
		{"webhook http ok", func(c *Config) { c.Watchdog.NotifyURL = "https://hook.test/x" }, true},
		{"webhook not a url", func(c *Config) { c.Watchdog.NotifyURL = "hook.test" }, false},
		{"allowed host ok", func(c *Config) { c.AllowedHosts = []string{"router.lan"} }, true},
		{"allowed host blank", func(c *Config) { c.AllowedHosts = []string{"  "} }, false},
	}
	for _, tc := range cases {
		c := base()
		tc.mut(c)
		err := c.Validate()
		if (err == nil) != tc.ok {
			t.Errorf("%s: Validate() err=%v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestPortsValidate(t *testing.T) {
	if err := (Ports{UI: 8088, Clash: 9090, DNS: 5353, Mixed: 7890}).Validate(); err != nil {
		t.Fatalf("valid ports rejected: %v", err)
	}
	bad := []Ports{
		{UI: 0, Clash: 9090, DNS: 5353, Mixed: 7890},
		{UI: 70000, Clash: 9090, DNS: 5353, Mixed: 7890},
		{UI: 8088, Clash: 8088, DNS: 5353, Mixed: 7890},
		{UI: 8088, Clash: 9090, DNS: 5353, Mixed: 5353},
	}
	for i, p := range bad {
		if err := p.Validate(); err == nil {
			t.Errorf("case %d: invalid ports %+v accepted", i, p)
		}
	}
}

func TestRedacted(t *testing.T) {
	c := Default()
	c.Clash.Secret = "supersecret"
	c.Subscription.Token = "tok123"
	c.Subscription.URL = "https://provider.example/sub/secrettoken"
	c.Watchdog.NotifyURL = "https://hook.test/abc"
	r := c.Redacted()
	if r.Clash.Secret != RedactedMark || r.Subscription.Token != RedactedMark || r.Watchdog.NotifyURL != RedactedMark {
		t.Fatalf("Redacted left a secret exposed: %+v", r)
	}
	// The subscription URL embeds a per-account token, so the share-safe export must mask it.
	if r.Subscription.URL != RedactedMark {
		t.Fatalf("Redacted leaked the token-bearing subscription URL: %q", r.Subscription.URL)
	}
	// Original must be untouched (value receiver — operates on a copy).
	if c.Clash.Secret != "supersecret" || c.Subscription.URL != "https://provider.example/sub/secrettoken" {
		t.Fatalf("Redacted mutated the original config")
	}
	// Empty secrets stay empty (not masked into a sentinel).
	empty := Default().Redacted()
	if empty.Clash.Secret != "" || empty.Subscription.Token != "" || empty.Subscription.URL != "" || empty.Watchdog.NotifyURL != "" {
		t.Fatalf("Redacted masked an empty secret: %+v", empty)
	}
}
