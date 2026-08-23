package pbr

import (
	"strings"
	"testing"
)

// privateExcludes must cover the RFC1918 ranges at priorities just below RulePref, so a
// LAN-bound reply (re-marked by CONNMARK-restore) routes to the bridge instead of looping
// back out the tunnel — the live SYN_RECV-stall fix on the Keenetic.
func TestPrivateExcludes(t *testing.T) {
	var opt Options
	opt.withDefaults()
	want := map[string]int{"10.0.0.0/8": 147, "172.16.0.0/12": 148, "192.168.0.0/16": 149}
	xs := privateExcludes(opt)
	if len(xs) != len(want) {
		t.Fatalf("got %d excludes, want %d", len(xs), len(want))
	}
	for _, x := range xs {
		p, ok := want[x.CIDR]
		if !ok {
			t.Errorf("unexpected CIDR %q", x.CIDR)
		} else if x.Priority != p {
			t.Errorf("%s priority = %d, want %d", x.CIDR, x.Priority, p)
		}
		if x.Priority >= opt.RulePref {
			t.Errorf("%s priority %d must be below the fwmark base %d", x.CIDR, x.Priority, opt.RulePref)
		}
	}
}

// Both renderers emit the exclusion (above the fwmark rule) and tear it down symmetrically.
func TestRenderIPScript_LANExclude(t *testing.T) {
	pl := &Plan{Mask: 0x00ff0000, Egresses: []Egress{
		{Kind: EgressInterface, Iface: "nwg1", Mark: 0x20000, Table: 151},
	}}
	apply := pl.RenderIPScript(Options{})
	for _, w := range []string{
		"ip rule add to 10.0.0.0/8 lookup main priority 147",
		"ip rule add to 192.168.0.0/16 lookup main priority 149",
		"ip rule add fwmark 0x00020000/0x00ff0000 table 151 priority 150",
	} {
		if !strings.Contains(apply, w) {
			t.Errorf("RenderIPScript missing %q in:\n%s", w, apply)
		}
	}
	down := pl.RenderTeardownScript(Options{}, IpsetOptions{})
	if !strings.Contains(down, "ip rule del to 192.168.0.0/16 lookup main priority 149") {
		t.Errorf("RenderTeardownScript missing the LAN-exclusion removal:\n%s", down)
	}
	// nft renderer (OpenWrt) carries it too.
	ip := strings.Join(pl.RenderIP(Options{}), "\n")
	if !strings.Contains(ip, "ip rule add to 192.168.0.0/16 lookup main priority 149") {
		t.Errorf("RenderIP (nft path) missing the LAN exclusion:\n%s", ip)
	}
}
