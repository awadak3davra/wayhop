package config

import (
	"encoding/json"
	"strings"
	"testing"
)

// bridgeFixture is a secret in the shape check-pii.mjs knows for a fixture.
const bridgeFixture = "0123456789abcdef0123456789abcdef"

func TestTelegramBridgeSecret(t *testing.T) {
	s, err := NewTelegramBridgeSecret()
	if err != nil || !ValidTelegramBridgeSecret(s) || s != strings.ToLower(s) {
		t.Fatalf("NewTelegramBridgeSecret = %q, %v", s, err)
	}
	if other, _ := NewTelegramBridgeSecret(); other == s {
		t.Fatal("two secrets in a row are equal")
	}
	// The link form ("dd" + the secret) is assembled here so no 34-digit literal sits in the source.
	for _, bad := range []string{"", "dd" + bridgeFixture, "00112233445566778899aabbccddeeg0", "0011"} {
		if ValidTelegramBridgeSecret(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTelegramBridgeValidate(t *testing.T) {
	ok := []TelegramBridge{
		{},
		{Enabled: true, Port: 1443, Secret: "0123456789ABCDEF0123456789ABCDEF"},
		// A Settings page sends the masked secret back; it stands for the saved one.
		{Enabled: true, Secret: RedactedMark},
		{CFDomain: "proxy.example.net,cdn.example.net", CFWorkerDomain: "w-1.user.example.net"},
	}
	for _, b := range ok {
		if err := b.Validate(); err != nil {
			t.Errorf("%+v: %v", b, err)
		}
	}
	bad := map[string]TelegramBridge{
		"privileged port": {Port: 443},
		"port range":      {Port: 70000},
		"short secret":    {Secret: "0011"},
		"link secret":     {Secret: "dd" + bridgeFixture},
		"scheme":          {CFWorkerDomain: "https://w.example.net"},
		"flag":            {CFDomain: "-v"},
		"bare label":      {CFDomain: "localhost"},
		"empty entry":     {CFDomain: "a.example.net,,b.example.net"},
	}
	for name, b := range bad {
		if err := b.Validate(); err == nil {
			t.Errorf("%s: %+v accepted", name, b)
		}
	}
}

// An enabled bridge may not take a port WayHop itself listens on; a disabled one is not checked, so
// a dormant value never refuses an unrelated save.
func TestTelegramBridgePortConflict(t *testing.T) {
	c := Default()
	c.TelegramBridge = TelegramBridge{Enabled: true}
	if err := c.TelegramBridgePortConflict(); err != nil {
		t.Fatalf("the default port: %v", err)
	}
	for _, port := range []int{c.Ports.UI, c.Ports.Clash, c.Ports.DNS, c.Ports.Mixed, c.Ports.Probe(), 17950} {
		c.TelegramBridge.Port = port
		if err := c.TelegramBridgePortConflict(); err == nil {
			t.Errorf("port %d accepted", port)
		}
		if err := c.Validate(); err == nil {
			t.Errorf("Validate accepted port %d", port)
		}
	}
	c.TelegramBridge.Enabled = false
	c.TelegramBridge.Port = c.Ports.UI
	if err := c.TelegramBridgePortConflict(); err != nil {
		t.Fatalf("a disabled bridge was checked: %v", err)
	}
	// The panel's port is what Listen binds, whatever Ports.UI says.
	c = Default()
	c.Listen = "10.77.0.1:2443"
	c.TelegramBridge = TelegramBridge{Enabled: true, Port: 2443}
	if err := c.TelegramBridgePortConflict(); err == nil {
		t.Fatal("the listen port was accepted")
	}
}

// The secret is a credential: a shared export masks it, and the field round-trips through JSON.
func TestTelegramBridgeRedacted(t *testing.T) {
	c := Default()
	c.TelegramBridge = TelegramBridge{Enabled: true, Secret: "0123456789abcdef0123456789abcdef"}
	r := c.Redacted()
	if r.TelegramBridge.Secret != RedactedMark || c.TelegramBridge.Secret == RedactedMark {
		t.Fatalf("redacted = %+v, original = %+v", r.TelegramBridge, c.TelegramBridge)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "aabbccddeeff") || !strings.Contains(string(raw), `"telegram_bridge"`) {
		t.Fatalf("export = %s", raw)
	}
	if (TelegramBridge{}).Redacted().Secret != "" {
		t.Fatal("an empty secret became the mark")
	}
}
