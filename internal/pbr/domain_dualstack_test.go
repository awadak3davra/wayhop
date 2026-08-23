package pbr

import (
	"strings"
	"testing"
)

// TestDomainZoneDualStack: a DOMAIN-based routing zone must be dual-stack on the Keenetic
// ipset plane. Previously only the inet (A-record) set + v4 MARK rule were emitted, so the
// AAAA-resolved addresses of a tunnel-routed domain landed in no set, were never marked, and
// IPv6 leaked direct to the WAN. The fix makes all coordinated spots emit v6 for a domain zone.
func TestDomainZoneDualStack(t *testing.T) {
	io := IpsetOptions{WanIface: "eth0"}
	pl := &Plan{
		Mask: 0x00ff0000,
		Egresses: []Egress{
			{Tag: "wan", Kind: EgressWAN, Table: 254},
			{Tag: "nl", Kind: EgressInterface, Iface: "nwg1", Mark: 0x00010000, Table: 151},
		},
		Zones: []Zone{
			{Name: "yt", EgressTag: "nl", Mark: 0x00010000, Domains: []string{"youtube.com"}},
		},
	}

	if !pl.HasV6() {
		t.Error("a domain zone must make HasV6() true so the v6 datapath (ip6tables chain + v6 rules) is emitted")
	}

	// dnsmasq targets BOTH the inet and inet6 sets so A → inet, AAAA → inet6.
	if dnsmasq := pl.DnsmasqIpsetConfig(io, 1024); !strings.Contains(dnsmasq, "/wr_yt_4,wr_yt_6") {
		t.Errorf("dnsmasq must target both v4 and v6 sets (wr_yt_4,wr_yt_6):\n%s", dnsmasq)
	}

	// ipset restore creates the inet6 domain set as a timeout set (dnsmasq fills it at query time).
	restore := pl.RenderIpsetRestore(io)
	if !strings.Contains(restore, "create wr_yt_6 hash:net family inet6") {
		t.Errorf("ipset restore must create the inet6 domain set wr_yt_6:\n%s", restore)
	}
	if !strings.Contains(restore, "create wr_yt_6 hash:net family inet6 hashsize 1024 maxelem 131072 timeout 86400") {
		t.Errorf("wr_yt_6 must be a timeout set mirroring the v4 domain set:\n%s", restore)
	}

	// the ip6tables mangle chain MARKs the v6 domain set (else AAAA traffic is unmarked → WAN leak).
	ipt := pl.RenderIptablesScript(io)
	if !strings.Contains(ipt, "ip6tables") || !strings.Contains(ipt, "--match-set wr_yt_6 dst") {
		t.Errorf("ip6tables must MARK the v6 domain set wr_yt_6 dst:\n%s", ipt)
	}

	// teardown destroys the v6 domain set too.
	if names := pl.IpsetNames(io); !containsStr(names, "wr_yt_6") {
		t.Errorf("IpsetNames must include the v6 domain set for teardown: %v", names)
	}
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestSourceScopedDomainZoneBindsDest: a SOURCE-scoped zone whose destination is DOMAIN-populated
// (dnsmasq fills wr_<zone>_4/_6 at query time) must treat those sets as a real destination, exactly
// like the non-source path. Previously hasDest/noDest ignored Domains, so (A) a device-scoped
// domain-only list emitted a dest-less MARK — ALL of the device's traffic tunneled instead of just
// the listed domains — and (B) a MAC-scoped mixed v4-CIDR+domain list skipped the fam=6 rule
// entirely, leaking the device's IPv6 traffic to the dnsmasq-resolved AAAA addresses out the WAN.
func TestSourceScopedDomainZoneBindsDest(t *testing.T) {
	io := IpsetOptions{WanIface: "eth0"}

	// (A) domain-only zone scoped to a source IP: the v4 MARK must bind BOTH the source set and
	// the domain dest set (no dest-less over-capture).
	plA := &Plan{
		Mask: 0x00ff0000,
		Egresses: []Egress{
			{Tag: "wan", Kind: EgressWAN, Table: 254},
			{Tag: "nl", Kind: EgressInterface, Iface: "nwg1", Mark: 0x00010000, Table: 151},
		},
		Zones: []Zone{
			{Name: "dom", EgressTag: "nl", Mark: 0x00010000, Domains: []string{"youtube.com"},
				SrcScoped: true, SrcV4: []string{"192.168.1.50/32"}},
		},
	}
	ipt := plA.RenderIptablesScript(io)
	if !strings.Contains(ipt, "--match-set wr_dom_s4 src -m set --match-set wr_dom_4 dst -j MARK") {
		t.Errorf("source-scoped domain zone must bind the dnsmasq-fed dest set (no dest-less over-capture):\n%s", ipt)
	}
	if strings.Contains(ipt, "wr_dom_s4 src -j MARK") {
		t.Errorf("source-scoped domain zone emitted a dest-less MARK (captures ALL of the device's traffic):\n%s", ipt)
	}

	// (B) MAC-scoped mixed v4-CIDR + domain zone: fam=6 must emit a rule binding wr_mix_6 dst
	// (the AAAA set dnsmasq populates) — previously skipped, an IPv6 leak.
	plB := &Plan{
		Mask: 0x00ff0000,
		Egresses: []Egress{
			{Tag: "wan", Kind: EgressWAN, Table: 254},
			{Tag: "nl", Kind: EgressInterface, Iface: "nwg1", Mark: 0x00010000, Table: 151},
		},
		Zones: []Zone{
			{Name: "mix", EgressTag: "nl", Mark: 0x00010000, Domains: []string{"youtube.com"},
				V4:        []string{"198.51.100.0/24"},
				SrcScoped: true, SrcMAC: []string{"aa:bb:cc:dd:ee:ff"}},
		},
	}
	iptB := plB.RenderIptablesScript(io)
	if !strings.Contains(iptB, "ip6tables") {
		t.Fatalf("mixed source-scoped domain zone must emit the v6 datapath:\n%s", iptB)
	}
	v6part := iptB[strings.Index(iptB, "ip6tables"):]
	if !strings.Contains(v6part, "--mac-source aa:bb:cc:dd:ee:ff -m set --match-set wr_mix_6 dst -j MARK") {
		t.Errorf("fam=6 rule for the MAC-scoped mixed domain zone must bind wr_mix_6 dst (AAAA leak otherwise):\n%s", iptB)
	}
}
