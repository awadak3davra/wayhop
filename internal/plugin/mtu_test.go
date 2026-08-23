package plugin

import (
	"testing"

	"wayhop/internal/model"
)

// TestAWGMTU (QW2): an AmneziaWG iface gets a safe 1280 MTU floor at bring-up when the config
// omits one (the kernel default 1500 fragments / PMTU-blackholes over the AWG encap+junk
// overhead); an explicit MTU — typed field or Params — still wins.
func TestAWGMTU(t *testing.T) {
	if got := awgMTU(model.Endpoint{MTU: 1420}); got != "1420" {
		t.Errorf("explicit typed MTU: got %q, want 1420", got)
	}
	if got := awgMTU(model.Endpoint{Params: map[string]any{"mtu": 1380}}); got != "1380" {
		t.Errorf("explicit Params MTU: got %q, want 1380", got)
	}
	if got := awgMTU(model.Endpoint{}); got != "1280" {
		t.Errorf("omitted MTU should default to the 1280 floor (QW2): got %q", got)
	}
}
