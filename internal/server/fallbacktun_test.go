package server

import (
	"strings"
	"testing"
)

// The KeeneticOS fallback core reaches the router encoded. A core that accepts the TUN `stack` gets
// those bytes untouched; one that would refuse it (1.16+) gets them without it, and nothing else changes.
func TestFitFallbackTUN(t *testing.T) {
	in := []byte(`{"inbounds":[{"type":"tun","tag":"tun-a","stack":"gvisor"},{"type":"socks","tag":"s"}],"outbounds":[{"type":"direct","tag":"direct"}]}`)
	for _, v := range []string{"", "1.13.19", "1.15.0-alpha.13"} {
		out, err := fitFallbackCore(in, v, "", nil)
		if err != nil || string(out) != string(in) {
			t.Errorf("core %q: changed the config (%v):\n%s", v, err, out)
		}
	}
	out, err := fitFallbackCore(in, "1.16.0", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "stack") || !strings.Contains(string(out), `"tun-a"`) || !strings.Contains(string(out), `"socks"`) {
		t.Errorf("core 1.16.0:\n%s", out)
	}
	if _, err := fitFallbackCore([]byte(`{`), "1.16.0", "", nil); err == nil {
		t.Error("a config that does not decode must be refused, not passed on")
	}
}
