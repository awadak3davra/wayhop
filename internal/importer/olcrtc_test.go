package importer

import (
	"errors"
	"testing"
)

// A pasted olcRTC config is refused with the reason, client and server alike, and never becomes a
// connection: WayHop no longer ships an engine that could run it.
func TestParse_OlcRTCConfigIsRefusedAsRetired(t *testing.T) {
	for _, cfg := range []string{
		"auth:\n  provider: jitsi\ncrypto:\n  key: 0123456789abcdef\nroom:\n  id: https://meet.example.org/r1",
		"mode: srv\nauth:\n  provider: telemost\nnet:\n  transport: datachannel\n",
	} {
		e, err := Parse(cfg)
		if !errors.Is(err, errOlcRTCRetired) || e != nil {
			t.Errorf("Parse(%q) = %+v, %v; want the retired-olcRTC refusal", cfg, e, err)
		}
	}
}
