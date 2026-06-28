package plugin

import (
	"strings"
	"testing"

	"wakeroute/internal/model"
)

// TestAWGKeepalive (L4): an AmneziaWG peer gets a 20s PersistentKeepalive default when the config
// omits one (an idle tunnel otherwise lets its NAT mapping expire and silently drops); an explicit
// typed field or Params value still wins. Mirrors awgMTU's consumer-side default.
func TestAWGKeepalive(t *testing.T) {
	if got := awgKeepalive(model.Endpoint{PersistentKeepalive: 25}); got != "25" {
		t.Errorf("explicit typed keepalive: got %q, want 25", got)
	}
	if got := awgKeepalive(model.Endpoint{Params: map[string]any{"persistent_keepalive": 30}}); got != "30" {
		t.Errorf("explicit Params keepalive: got %q, want 30", got)
	}
	if got := awgKeepalive(model.Endpoint{}); got != "20" {
		t.Errorf("omitted keepalive should default to the 20s floor (L4): got %q", got)
	}
}

// TestAWGConfigKeepaliveDefault (L4): the rendered .conf [Peer] (fed to awg setconf, keepalive's
// live consumer) carries the 20s default when the config omits a keepalive.
func TestAWGConfigKeepaliveDefault(t *testing.T) {
	c := awgConfig(model.Endpoint{
		Engine: model.EngineAmneziaWG, Server: "1.2.3.4", Port: 8443,
		Params: map[string]any{"private_key": "P", "peer_public_key": "Q"},
	})
	if !strings.Contains(c, "PersistentKeepalive = 20") {
		t.Errorf("awgConfig must default keepalive to 20 when unset:\n%s", c)
	}
	// An explicit keepalive still wins over the default.
	c2 := awgConfig(model.Endpoint{
		Engine: model.EngineAmneziaWG, Server: "1.2.3.4", Port: 8443, PersistentKeepalive: 25,
		Params: map[string]any{"private_key": "P", "peer_public_key": "Q"},
	})
	if !strings.Contains(c2, "PersistentKeepalive = 25") || strings.Contains(c2, "PersistentKeepalive = 20") {
		t.Errorf("explicit keepalive must win over the default:\n%s", c2)
	}
}
