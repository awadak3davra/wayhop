package server

import (
	"context"
	"testing"

	"wayhop/internal/pbr"
)

// The server and pbr validated interface names differently. A name the server took
// (an "@" or a leading "-") and pbr dropped gave coverNewIfaces an empty program, after which it
// logged "now also covers" and recorded the interface without a rule. One validator now.
func TestInterfaceNameValidatorIsShared(t *testing.T) {
	for _, name := range []string{"br0", "eth2.5", "nwg0", "ppp0", "a_b-c", "@x", "eth2.5@eth2", "-br0", ".x", "", "abcdefghijklmnop", "br 0"} {
		if got, want := validWANInterfaceName(name), pbr.ValidIfaceName(name); got != want {
			t.Errorf("%q: server %v, pbr %v", name, got, want)
		}
	}
}

// coverNewIfaces never records an interface it rendered no rule for.
func TestCoverNewIfacesRecordsOnlyCoveredIfaces(t *testing.T) {
	s, _, _ := mirrorServer(t)
	s.ksb.probeIfaces = func() []string { return []string{"-bad"} }
	k := s.kernelBaseline()
	if k == nil {
		t.Fatal("no baseline")
	}
	s.coverNewIfaces(context.Background(), k.Plan, *k.Ipset)
	if len(s.ksb.extra) != 0 {
		t.Fatalf("recorded without a rule: %v", s.ksb.extra)
	}
}
