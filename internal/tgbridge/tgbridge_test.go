package tgbridge

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"wayhop/internal/platform"
)

// The argv pins the listener to the LAN address, keeps the secret out (it travels in TG_SECRET),
// and passes the Cloudflare routes in upstream's comma-separated form.
func TestArgs(t *testing.T) {
	lan := netip.MustParseAddr("10.20.0.1")
	got, err := Args(Settings{Listen: lan, Port: 1443})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"--host", "10.20.0.1", "--port", "1443", "--quiet"}; !slices.Equal(got, want) {
		t.Fatalf("argv = %q, want %q", got, want)
	}
	got, _ = Args(Settings{Listen: lan, Port: 2443, CFDomain: "a.example.net, b.example.net", CFWorkerDomain: "w.example.net"})
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "--cf-domain a.example.net,b.example.net") || !strings.Contains(joined, "--cf-worker-domain w.example.net") {
		t.Fatalf("argv = %q", got)
	}
	for _, s := range []Settings{{Port: 1443}, {Listen: netip.IPv4Unspecified(), Port: 1443}, {Listen: lan}} {
		if _, err := Args(s); err == nil {
			t.Errorf("Args(%+v) accepted", s)
		}
	}
	if env := Env("0123456789abcdef0123456789abcdef"); !slices.Equal(env, []string{"TG_SECRET=0123456789abcdef0123456789abcdef"}) {
		t.Fatalf("env = %q", env)
	}
}

// The link is upstream's own shape, with the dd prefix its link_secret_for adds to a plain secret.
func TestLink(t *testing.T) {
	got := Link(netip.MustParseAddr("10.20.0.1"), 1443, "0123456789ABCDEF0123456789ABCDEF")
	if want := "tg://proxy?server=10.20.0.1&port=1443&secret=dd" + "0123456789abcdef0123456789abcdef"; got != want {
		t.Fatalf("link = %q, want %q", got, want)
	}
	if Link(netip.Addr{}, 1443, "00") != "" || Link(netip.MustParseAddr("10.20.0.1"), 1443, "") != "" {
		t.Fatal("a link without an address or a secret")
	}
}

func TestLANIface(t *testing.T) {
	if LANIface(platform.OpenWrt) != "br-lan" || LANIface(platform.Keenetic) != "br0" || LANIface(platform.Unknown) != "" {
		t.Fatal("LAN bridge names")
	}
}

func TestLANAddress(t *testing.T) {
	ipnet := func(s string) net.Addr {
		ip, n, _ := net.ParseCIDR(s)
		n.IP = ip
		return n
	}
	read := func(addrs ...net.Addr) IfaceAddrs {
		return func(string) ([]net.Addr, error) { return addrs, nil }
	}
	// IPv6 and link-local come first on a real bridge; the first routable IPv4 is the one.
	got, err := LANAddress("br-lan", read(ipnet("fd00::1/64"), ipnet("169.254.3.4/16"), ipnet("10.20.0.1/24"), ipnet("10.0.0.1/8")))
	if err != nil || got != netip.MustParseAddr("10.20.0.1") {
		t.Fatalf("LANAddress = %v, %v", got, err)
	}
	if _, err := LANAddress("br-lan", read(ipnet("fd00::1/64"))); err == nil || !strings.Contains(err.Error(), "no IPv4") {
		t.Fatalf("no IPv4: %v", err)
	}
	if _, err := LANAddress("", read()); err == nil {
		t.Fatal("an unknown LAN interface was accepted")
	}
	failing := func(string) ([]net.Addr, error) { return nil, errors.New("no such network interface") }
	if _, err := LANAddress("br0", failing); err == nil || !strings.Contains(err.Error(), "br0") {
		t.Fatalf("read failure: %v", err)
	}
}

func TestPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"10.20.0.1": false, "10.0.0.1": false, "172.16.0.1": false, "100.64.0.1": false,
		"127.0.0.1": false, "169.254.1.1": false, "198.51.100.7": true, "203.0.113.9": true,
	} {
		if got := Public(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Public(%s) = %v, want %v", addr, got, want)
		}
	}
}
