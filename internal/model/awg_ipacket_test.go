package model

import (
	"strings"
	"testing"
)

// An I1-I5 the kernel module would turn into memory corruption (kmod before v3.1.20261113) is
// refused at save and Apply, on every engine.
func TestAmneziaWGIPacketRefused(t *testing.T) {
	e := &Endpoint{Protocol: ProtoAmneziaWG, Params: map[string]any{"i1": "<b 0x01>", "i3": "<r -5><b 0x01>"}}
	if p := invalidProtoParam(e); !strings.HasPrefix(p, "I3: ") {
		t.Fatalf("invalidProtoParam = %q, want an I3 problem", p)
	}
	e.Params["i3"] = "<b 0x01><r 16>"
	if p := invalidProtoParam(e); p != "" {
		t.Fatalf("a valid I3 was refused: %q", p)
	}
}
