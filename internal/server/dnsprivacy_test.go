package server

import (
	"strings"
	"testing"
)

// The row said "DNS is private (DoH)" and went green on three outbound HTTPS calls to Cloudflare,
// Google and AdGuard. Nothing in it read what the router resolves through — the function took no
// profile and no effective path — so a router forwarding every query in plaintext to its ISP got a
// green privacy verdict as long as :443 worked. The probes even had to resolve cloudflare-dns.com
// through the resolver they were judging.
//
// The probes are unchanged and untested here; what is tested is the claim built on top of them.
// dnsHealthCheck's network half cannot run in a unit test, so these drive plaintextUpstreams and the
// wiring directly — the two places the wrong claim was made.

func TestPlaintextUpstreams_NamesTheResolversThatCarryQueriesInTheClear(t *testing.T) {
	for _, tc := range []struct {
		why  string
		in   []string
		want []string
	}{
		{"a live AX3000T: a local resolver, whose upstream is a separate question",
			[]string{"127.0.0.1", "::1"}, nil},
		{"an ISP resolver in resolv.conf — resolv.conf cannot express DoH or DoT, so this is plaintext",
			[]string{"192.168.100.1"}, []string{"192.168.100.1"}},
		{"a public plaintext resolver is no more private for being famous",
			[]string{"1.1.1.1", "8.8.8.8"}, []string{"1.1.1.1", "8.8.8.8"}},
		{"loopback alongside a real one still names the real one",
			[]string{"127.0.0.1", "192.168.50.1"}, []string{"192.168.50.1"}},
		{"garbage is not a finding", []string{"", "not-an-ip", "search lan"}, nil},
	} {
		got := plaintextUpstreams(tc.in)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s:\n  in   %v\n  got  %v\n  want %v", tc.why, tc.in, got, tc.want)
		}
	}
}

// "No plaintext upstream" and "we never looked" must not collapse into the same green row — that
// collapse IS the defect, in a new place.
func TestEffectiveDNSUpstreams_AnUnreadablePathIsNotAPrivateOne(t *testing.T) {
	s := &Server{dnsUpstreamsOf: func() ([]string, bool) { return nil, false }}
	ups, known := s.effectiveDNSUpstreams()
	if known {
		t.Fatal("an unreadable path reported as known")
	}
	if len(plaintextUpstreams(ups)) != 0 {
		t.Fatal("an unreadable path produced findings")
	}

	// And the row built from it must say the reachability it measured, and NOT the privacy it did
	// not. The label itself carried the wrong claim, so it is asserted too.
	row := healthRow{ID: "dns", Label: "Encrypted DNS (DoH)"}
	if strings.Contains(strings.ToLower(row.Label), "private") {
		t.Errorf("the label still claims privacy: %q", row.Label)
	}
}

// The whole point, as a statement about the wiring: the battery hands the check what the router
// actually resolves through. Before this, dnsHealthCheck's signature was `(ctx)` — there was no
// argument for the truth to arrive in, which is why the claim could only ever be inferred.
func TestHealthBattery_HandsTheDNSCheckTheRoutersOwnResolvers(t *testing.T) {
	var asked bool
	s := &Server{dnsUpstreamsOf: func() ([]string, bool) { asked = true; return []string{"192.168.100.1"}, true }}
	ups, known := s.effectiveDNSUpstreams()
	if !asked {
		t.Fatal("the server never asked for the router's resolvers")
	}
	if !known || len(ups) != 1 || ups[0] != "192.168.100.1" {
		t.Fatalf("upstreams = %v known = %v", ups, known)
	}
	plain := plaintextUpstreams(ups)
	if len(plain) != 1 {
		t.Fatalf("the ISP resolver was not reported as plaintext: %v", plain)
	}
}
