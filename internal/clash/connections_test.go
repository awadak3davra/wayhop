package clash

import (
	"encoding/json"
	"testing"
)

// TestConnectionsDecode verifies the enriched Conn fields (host/rule/start/metadata)
// decode from a real-shaped Clash /connections payload — the data the Dashboard's
// live-connections table relies on.
func TestConnectionsDecode(t *testing.T) {
	payload := `{
	  "downloadTotal": 1000, "uploadTotal": 500,
	  "connections": [
	    {"upload": 12, "download": 34, "chains": ["Reality","Main failover"],
	     "rule": "RuleSet", "rulePayload": "youtube",
	     "start": "2026-06-14T05:00:00.000Z",
	     "metadata": {"host": "youtube.com", "destinationIP": "203.0.113.7", "destinationPort": "443", "network": "tcp"}}
	  ]
	}`
	var c Connections
	if err := json.Unmarshal([]byte(payload), &c); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(c.Connections) != 1 {
		t.Fatalf("want 1 connection, got %d", len(c.Connections))
	}
	cn := c.Connections[0]
	if cn.Metadata.Host != "youtube.com" {
		t.Errorf("Metadata.Host = %q, want youtube.com", cn.Metadata.Host)
	}
	if cn.Metadata.DestinationPort != "443" {
		t.Errorf("Metadata.DestinationPort = %q, want 443", cn.Metadata.DestinationPort)
	}
	if cn.Rule != "RuleSet" || cn.RulePayload != "youtube" {
		t.Errorf("rule=%q payload=%q, want RuleSet/youtube", cn.Rule, cn.RulePayload)
	}
	if cn.Start == "" {
		t.Error("Start should decode (used for connection age)")
	}
	if len(cn.Chains) != 2 {
		t.Errorf("Chains = %v, want 2 entries", cn.Chains)
	}
	if cn.Upload != 12 || cn.Download != 34 {
		t.Errorf("bytes up=%d down=%d, want 12/34", cn.Upload, cn.Download)
	}
}
