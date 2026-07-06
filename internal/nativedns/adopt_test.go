package nativedns

import (
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

func TestAdopt_UnknownPlatformIsEmpty(t *testing.T) {
	nd, err := Adopt(func(string, ...string) (string, error) { return "", nil }, "")
	if err != nil || len(nd.Resolvers) != 0 {
		t.Fatalf("unknown platform should be empty, got %+v err=%v", nd, err)
	}
}
