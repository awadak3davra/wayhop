package server

import (
	"slices"
	"testing"
)

// Measured on a Keenetic (BusyBox ip): the unqualified listing printed the IPv6 defaults after the
// IPv4 ones, so the last line for table 152 named the v6 member and hid where IPv4 really went. The
// IPv4 read must ask for IPv4 alone.
func TestListFailoverReadsEachFamilyAlone(t *testing.T) {
	mixed := "default dev nwg0 table 152 scope link \n" + // IPv4, moved here by an outage
		"default dev nwg1 table 152  metric 1024 \n" // IPv6, still on the first member
	if got := parseTableDefaults(mixed)[152]; got != "nwg1" {
		t.Fatalf("test setup: the mixed listing should hide the v4 route, got %q", got)
	}
	if v4 := familyArgs(false, "route", "show", "table", "all"); !slices.Equal(v4, []string{"-4", "route", "show", "table", "all"}) {
		t.Errorf("IPv4 argv = %v, want it to name -4", v4)
	}
	if v6 := familyArgs(true, "route", "show", "table", "all"); v6[0] != "-6" {
		t.Errorf("IPv6 argv = %v", v6)
	}
}

// BusyBox ip ignores the `default` selector without -4 and prints the whole main table. With the WAN
// down there is no default line, and the first line with a `dev` is some host route: it must not be
// taken for the uplink.
func TestDefaultRouteDevNeedsADefaultLine(t *testing.T) {
	noDefault := "1.1.1.1 dev ppp0 scope link  metric 1000 \n10.66.0.1 dev awg1 scope link \n"
	if got := parseDefaultRouteDev(noDefault); got != "" {
		t.Errorf("no default route, but %q was taken for the uplink", got)
	}
	later := "198.51.100.1 dev ppp0 scope link \ndefault via 192.0.2.1 dev eth3  metric 1000 \n"
	if got := parseDefaultRouteDev(later); got != "eth3" {
		t.Errorf("default after other routes: got %q, want eth3", got)
	}
}

// The locked failover pass gives up well before an Apply waiting on the same lock would: two hung
// v6 group tables held applyMu past applyLockWait, so the panel and the bot reported another Apply.
func TestListFailoverLockedPassEndsBeforeAnApplyGivesUp(t *testing.T) {
	if listFailoverLockedPass >= applyLockWait {
		t.Fatalf("locked pass %v, applyLockWait %v: an Apply could time out behind the failover tick", listFailoverLockedPass, applyLockWait)
	}
}
