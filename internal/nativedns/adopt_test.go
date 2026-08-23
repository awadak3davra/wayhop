package nativedns

import (
	"errors"
	"strings"
	"testing"
)

func TestAdoptOpenWrt(t *testing.T) {
	fake := func(name string, args ...string) (string, error) {
		j := strings.Join(args, " ")
		switch {
		case strings.Contains(j, "https-dns-proxy"):
			return fixtureHTTPSDNSProxy, nil
		case strings.Contains(j, "dhcp"):
			return fixtureDHCP, nil
		}
		return "", nil
	}
	nd, err := AdoptOpenWrt(fake)
	if err != nil {
		t.Fatal(err)
	}
	if nd.Platform != "openwrt" || len(nd.Resolvers) != 6 || !nd.NoResolv {
		t.Fatalf("adopt openwrt = %+v", nd)
	}
}

// TestAdoptOpenWrt_MissingHTTPSDNSProxyStillAdopts: https-dns-proxy is an OPTIONAL OpenWrt package,
// so `uci show https-dns-proxy` exits non-zero on a stock box ("Entry not found"). That must NOT fail
// the whole adopt — the dnsmasq/dhcp half is present and adoptable. Regression guard for a bug found
// on a REAL OpenWrt 24.10.4, where this made native DNS report unavailable on most routers.
func TestAdoptOpenWrt_MissingHTTPSDNSProxyStillAdopts(t *testing.T) {
	fake := func(name string, args ...string) (string, error) {
		j := strings.Join(args, " ")
		if strings.Contains(j, "https-dns-proxy") {
			return "", errors.New("exit status 1") // package not installed
		}
		return fixtureDHCP, nil
	}
	nd, err := AdoptOpenWrt(fake)
	if err != nil {
		t.Fatalf("a missing https-dns-proxy package must not fail the adopt, got %v", err)
	}
	if nd.Platform != "openwrt" {
		t.Errorf("platform = %q, want openwrt", nd.Platform)
	}
	// The dnsmasq-derived resolvers must still be adopted.
	if len(nd.Resolvers) == 0 {
		t.Error("dhcp/dnsmasq resolvers should still be adopted without the DoH proxy")
	}
}

// A failing dhcp read IS fatal — without it there is no DNS plane to report.
func TestAdoptOpenWrt_MissingDHCPIsError(t *testing.T) {
	fake := func(name string, args ...string) (string, error) { return "", errors.New("exit status 1") }
	if _, err := AdoptOpenWrt(fake); err == nil {
		t.Error("a failing `uci show dhcp` must surface an error")
	}
}

func TestAdoptKeenetic(t *testing.T) {
	fake := func(name string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "dnsmasq.d") {
			return fixtureKeeneticUpstream, nil
		}
		return "", nil // no https-dns-proxy running
	}
	nd, err := AdoptKeenetic(fake)
	if err != nil {
		t.Fatal(err)
	}
	if nd.Platform != "keenetic" || len(nd.Resolvers) != 4 || !nd.StrictOrder {
		t.Fatalf("adopt keenetic = %+v", nd)
	}
}

// TestAdoptKeenetic_NoConfIsEmptyNotError: on a stock Keenetic with no Entware dnsmasq.d/*.conf,
// busybox leaves the glob unmatched and cat exits non-zero (surfacing as a runner error). Adopt
// must degrade to an empty-but-valid keenetic plane, NOT propagate that as an error — otherwise
// GET /api/dns/native 500s for every box without the opkg dnsmasq confs. Guards the old
// `if err != nil { return NativeDNS{}, err }` from creeping back.
func TestAdoptKeenetic_NoConfIsEmptyNotError(t *testing.T) {
	fake := func(name string, args ...string) (string, error) {
		return "", errors.New("cat: /opt/etc/dnsmasq.d/*.conf: No such file or directory")
	}
	nd, err := AdoptKeenetic(fake)
	if err != nil {
		t.Fatalf("no-conf adopt must not error, got %v", err)
	}
	if nd.Platform != "keenetic" || len(nd.Resolvers) != 0 {
		t.Fatalf("want an empty-but-valid keenetic plane, got %+v", nd)
	}
}

func TestAdopt_UnknownPlatformIsEmpty(t *testing.T) {
	nd, err := Adopt(func(string, ...string) (string, error) { return "", nil }, "")
	if err != nil || len(nd.Resolvers) != 0 {
		t.Fatalf("unknown platform should be empty, got %+v err=%v", nd, err)
	}
}
