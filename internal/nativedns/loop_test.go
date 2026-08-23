package nativedns

import "testing"

var dnsListeners = []DNSListener{{Proto: "udp", Addr: "0.0.0.0:53", Process: "dnsmasq"}}

func loopFor(list []DNSLoop, upstream string) *DNSLoop {
	for i := range list {
		if list[i].Upstream == upstream {
			return &list[i]
		}
	}
	return nil
}

// The classic self-loop: the router's resolver is told to forward to the router. Queries go out and
// come straight back, and nothing in the config reads as wrong.
func TestDetectDNSLoops_LoopbackWithLocalResolver(t *testing.T) {
	got := DetectDNSLoops(dnsListeners, []string{"127.0.0.1"}, []string{"192.168.50.1"})

	l := loopFor(got, "127.0.0.1")
	if l == nil {
		t.Fatal("a loopback upstream while serving DNS locally is a loop and must be reported")
	}
	if !l.Confirmed || l.Kind != "self" {
		t.Errorf("want a confirmed self-loop, got kind=%q confirmed=%v", l.Kind, l.Confirmed)
	}
}

// Same shape, different cause: loopback upstream with nothing listening is broken, but it is not the
// same fault and must not be described as one.
func TestDetectDNSLoops_LoopbackWithNoResolverIsDescribedDifferently(t *testing.T) {
	got := DetectDNSLoops(nil, []string{"127.0.0.1"}, []string{"192.168.50.1"})
	l := loopFor(got, "127.0.0.1")
	if l == nil {
		t.Fatal("a loopback upstream with no listener must still be reported")
	}
	if !contains(l.Detail, "nothing is listening") {
		t.Errorf("the detail must say resolution cannot succeed, not that it loops: %q", l.Detail)
	}
}

// An upstream equal to one of the router's own addresses is the same loop wearing a LAN IP.
func TestDetectDNSLoops_RouterOwnAddress(t *testing.T) {
	got := DetectDNSLoops(dnsListeners, []string{"192.168.50.1"}, []string{"192.168.50.1/24"})

	l := loopFor(got, "192.168.50.1")
	if l == nil {
		t.Fatal("an upstream pointing at the router's own address is a loop")
	}
	if !l.Confirmed {
		t.Error("this is provable from local state and must be reported as confirmed")
	}
}

// A listener bound to a CONCRETE address proves the router owns it, even when that address was not
// in the supplied list.
func TestDetectDNSLoops_ListenerAddressCountsAsOwn(t *testing.T) {
	got := DetectDNSLoops(
		[]DNSListener{{Proto: "udp", Addr: "10.0.0.1:53", Process: "dnsmasq"}},
		[]string{"10.0.0.1"}, nil)
	if loopFor(got, "10.0.0.1") == nil {
		t.Error("an address the router is listening on is an address it owns")
	}
}

// A wildcard bind says nothing about WHICH address the router has, so it must not be treated as
// proof of ownership of an arbitrary upstream.
func TestDetectDNSLoops_WildcardBindIsNotOwnership(t *testing.T) {
	got := DetectDNSLoops(dnsListeners, []string{"8.8.8.8"}, nil)
	if len(got) != 0 {
		t.Errorf("a public upstream must never be flagged from a 0.0.0.0 listener: %+v", got)
	}
}

// A LAN resolver on another box (Pi-hole, AdGuard Home) is a completely normal setup. It MIGHT loop,
// but only depending on how that host resolves — which cannot be seen from here. Reporting it as
// certain would make the whole check untrustworthy.
func TestDetectDNSLoops_LANUpstreamIsSuspectedNotConfirmed(t *testing.T) {
	got := DetectDNSLoops(dnsListeners, []string{"192.168.1.50"}, []string{"192.168.50.1"})

	l := loopFor(got, "192.168.1.50")
	if l == nil {
		t.Fatal("a LAN upstream is worth surfacing")
	}
	if l.Confirmed {
		t.Error("whether a LAN host loops depends on ITS config, which this router cannot see; " +
			"reporting it as confirmed would cry wolf on a legitimate LAN resolver")
	}
	if l.Kind != "lan" {
		t.Errorf("kind = %q, want lan", l.Kind)
	}
}

// Public resolvers are the normal case and must stay silent.
func TestDetectDNSLoops_PublicUpstreamsAreSilent(t *testing.T) {
	got := DetectDNSLoops(dnsListeners, []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}, []string{"192.168.50.1"})
	if len(got) != 0 {
		t.Errorf("public upstreams are not loops: %+v", got)
	}
}

// A hostname cannot be judged without resolving it, and resolving during a diagnostic would be both
// slow and a side effect. It must be skipped, not guessed at.
func TestDetectDNSLoops_HostnameUpstreamIsSkipped(t *testing.T) {
	got := DetectDNSLoops(dnsListeners, []string{"dns.example.com"}, []string{"192.168.50.1"})
	if len(got) != 0 {
		t.Errorf("a hostname upstream must be skipped, not guessed: %+v", got)
	}
}

// Duplicates collapse, and an empty input set yields nothing rather than a spurious finding.
func TestDetectDNSLoops_DuplicatesAndEmpty(t *testing.T) {
	got := DetectDNSLoops(dnsListeners, []string{"127.0.0.1", "127.0.0.1"}, nil)
	if len(got) != 1 {
		t.Errorf("duplicate upstreams must collapse to one finding, got %d", len(got))
	}
	if n := DetectDNSLoops(dnsListeners, nil, nil); len(n) != 0 {
		t.Errorf("no upstreams means nothing to report, got %+v", n)
	}
}

// IPv6 must work the same way, including bracketed host:port forms.
func TestDetectDNSLoops_IPv6(t *testing.T) {
	if got := DetectDNSLoops(dnsListeners, []string{"[::1]:53"}, nil); loopFor(got, "[::1]:53") == nil {
		t.Error("IPv6 loopback must be detected")
	}
	if got := DetectDNSLoops(dnsListeners, []string{"2606:4700:4700::1111"}, nil); len(got) != 0 {
		t.Errorf("a public IPv6 resolver is not a loop: %+v", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
