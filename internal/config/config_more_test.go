package config

import (
	"os"
	"path/filepath"
	"testing"
)

// storemodelconfig_cfgPath returns a unique, not-yet-existing config path.
func storemodelconfig_cfgPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "storemodelconfig_config.json")
}

func TestStoremodelconfigDefaultSaneValues(t *testing.T) {
	c := Default()
	if c == nil {
		t.Fatal("Default() returned nil")
	}
	if c.Listen != ":8088" {
		t.Errorf("Listen: want :8088, got %q", c.Listen)
	}
	if c.DataDir != "/opt/var/wayhop" {
		t.Errorf("DataDir: want /opt/var/wayhop, got %q", c.DataDir)
	}
	if c.Demo {
		t.Error("Demo should default to false")
	}
	if c.Ports.UI != 8088 || c.Ports.Clash != 9090 || c.Ports.DNS != 5353 || c.Ports.Mixed != 7890 {
		t.Errorf("unexpected default Ports: %+v", c.Ports)
	}
	if c.Clash.Controller != "127.0.0.1:9090" {
		t.Errorf("Clash.Controller: want 127.0.0.1:9090, got %q", c.Clash.Controller)
	}
	if c.SingBox.Bin == "" || c.SingBox.Config == "" {
		t.Errorf("SingBox paths should be set: %+v", c.SingBox)
	}
	if c.FailSafe.Target != "1.1.1.1" {
		t.Errorf("FailSafe.Target: want 1.1.1.1, got %q", c.FailSafe.Target)
	}
	if c.FailSafe.AutoReboot {
		t.Error("FailSafe.AutoReboot should default to false (opt-in)")
	}
	if len(c.Updater.Mirrors) == 0 {
		t.Error("Updater.Mirrors should have defaults")
	}
	if c.Updater.Mirrors[0] != "" {
		t.Errorf("first mirror should be the direct (empty) prefix, got %q", c.Updater.Mirrors[0])
	}
}

// TestStoremodelconfigLoadCreatesDefaultWhenAbsent verifies Load writes a
// default config file when the path does not exist, and the loaded config
// matches Default()'s key values.
func TestStoremodelconfigLoadCreatesDefaultWhenAbsent(t *testing.T) {
	path := storemodelconfig_cfgPath(t)

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("precondition: path should not exist yet (err=%v)", err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Listen != ":8088" {
		t.Errorf("loaded Listen: want :8088, got %q", c.Listen)
	}

	// The file must now exist on disk.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Load should have created the file: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("created config file is empty")
	}
}

// TestStoremodelconfigSaveLoadRoundTrip verifies a modified config survives
// Save and a fresh Load with all fields intact.
func TestStoremodelconfigSaveLoadRoundTrip(t *testing.T) {
	path := storemodelconfig_cfgPath(t)

	c, err := Load(path) // creates default
	if err != nil {
		t.Fatalf("initial Load: %v", err)
	}

	c.Listen = ":9999"
	c.DataDir = "/tmp/storemodelconfig"
	c.Demo = true
	c.Ports.UI = 1234
	c.Clash.Secret = "s3cr3t"
	c.Watchdog.NotifyURL = "http://example/hook"
	c.Subscription.Token = "tok-abc"
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	c2, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if c2.Listen != ":9999" {
		t.Errorf("Listen not round-tripped: %q", c2.Listen)
	}
	if c2.DataDir != "/tmp/storemodelconfig" {
		t.Errorf("DataDir not round-tripped: %q", c2.DataDir)
	}
	if !c2.Demo {
		t.Error("Demo not round-tripped")
	}
	if c2.Ports.UI != 1234 {
		t.Errorf("Ports.UI not round-tripped: %d", c2.Ports.UI)
	}
	if c2.Clash.Secret != "s3cr3t" {
		t.Errorf("Clash.Secret not round-tripped: %q", c2.Clash.Secret)
	}
	if c2.Watchdog.NotifyURL != "http://example/hook" {
		t.Errorf("Watchdog.NotifyURL not round-tripped: %q", c2.Watchdog.NotifyURL)
	}
	if c2.Subscription.Token != "tok-abc" {
		t.Errorf("Subscription.Token not round-tripped: %q", c2.Subscription.Token)
	}
}

// TestStoremodelconfigLoadMalformedJSONErrors verifies malformed JSON yields an
// error rather than a panic.
func TestStoremodelconfigLoadMalformedJSONErrors(t *testing.T) {
	path := storemodelconfig_cfgPath(t)
	if err := os.WriteFile(path, []byte("{ this is not valid json "), 0o600); err != nil {
		t.Fatalf("seed malformed file: %v", err)
	}

	c, err := Load(path)
	if err == nil {
		t.Fatalf("expected an error loading malformed JSON, got config %+v", c)
	}
	if c != nil {
		t.Fatalf("expected nil config on parse error, got %+v", c)
	}
}

// TestStoremodelconfigSaveNoPathErrors verifies Save refuses when no path is set
// (e.g. a bare Default() that was never associated with a file).
func TestStoremodelconfigSaveNoPathErrors(t *testing.T) {
	c := Default()
	if err := c.Save(); err == nil {
		t.Fatal("expected Save to error when path is unset")
	}
}

// TestStoremodelconfigPathPreservedAcrossSave verifies the unexported path,
// captured by Load, is reused by Save so the same file is rewritten in place
// (no path argument is needed for Save). We assert this by Saving and observing
// the original file is the one updated.
func TestStoremodelconfigPathPreservedAcrossSave(t *testing.T) {
	path := storemodelconfig_cfgPath(t)

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read created file: %v", err)
	}

	// Mutate and Save with no explicit path; Save must reuse the stored path.
	c.Listen = ":7777"
	if err := c.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the original path should still be the target of Save: %v", err)
	}
	if string(before) == string(after) {
		t.Fatal("Save did not rewrite the original file (path not preserved)")
	}

	// And the change is readable back from that same path.
	c2, err := Load(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if c2.Listen != ":7777" {
		t.Errorf("change not persisted to the preserved path: %q", c2.Listen)
	}

	// No stray temp file left behind.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file should not linger after Save (err=%v)", err)
	}
}
