package nativedns

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReal_AdoptRoundTrip validates the readers + writers against REAL captured device output. Gated on
// WR_NATIVEDNS_FIXTURE (a dir with the captured files) so it skips in CI, exactly like the WR_SINGBOX
// gate — the committed synthetic fixtures are the always-on check; this proves the pure logic adopts an
// ACTUAL router's DNS and round-trips it. Files (any subset):
//
//	openwrt-hdp.txt      = `uci show https-dns-proxy`
//	openwrt-dhcp.txt     = `uci show dhcp`
//	keenetic-dnsmasqd.txt= concatenated /opt/etc/dnsmasq.d/*.conf
//	keenetic-hdp-args.txt= the running https-dns-proxy argv (optional)
func TestReal_AdoptRoundTrip(t *testing.T) {
	dir := os.Getenv("WR_NATIVEDNS_FIXTURE")
	if dir == "" {
		t.Skip("set WR_NATIVEDNS_FIXTURE to a dir with captured device output")
	}
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return ""
		}
		return string(b)
	}

	if hdp := read("openwrt-hdp.txt"); hdp != "" {
		nd := ReadUCI(hdp, read("openwrt-dhcp.txt"))
		if len(nd.Resolvers) == 0 {
			t.Error("openwrt: no resolvers adopted from the real config")
		}
		t.Logf("OpenWrt adopted %d resolvers (noresolv=%v):", len(nd.Resolvers), nd.NoResolv)
		for i, r := range nd.Resolvers {
			t.Logf("  [%d] %-5s %-30s tier=%d via_tunnel=%v", i, r.Kind, r.Address, r.Tier, r.ViaTunnel)
		}
		if plan := RenderUCI(nd); len(plan) == 0 {
			t.Error("openwrt: empty render plan")
		} else {
			t.Logf("OpenWrt render plan: %d uci commands (+ %d apply)", len(plan), len(UCICommitCmds()))
		}
	}

	if conf := read("keenetic-dnsmasqd.txt"); conf != "" {
		nd := ReadDnsmasqD(conf, read("keenetic-hdp-args.txt"))
		if len(nd.Resolvers) == 0 {
			t.Error("keenetic: no resolvers adopted from the real config")
		}
		t.Logf("Keenetic adopted %d resolvers (strict_order=%v noresolv=%v):", len(nd.Resolvers), nd.StrictOrder, nd.NoResolv)
		for i, r := range nd.Resolvers {
			t.Logf("  [%d] %-5s %-30s tier=%d via_tunnel=%v", i, r.Kind, r.Address, r.Tier, r.ViaTunnel)
		}
		back := ReadDnsmasqD(RenderDnsmasqD(nd), read("keenetic-hdp-args.txt"))
		if len(back.Resolvers) != len(nd.Resolvers) || back.StrictOrder != nd.StrictOrder || back.NoResolv != nd.NoResolv {
			t.Errorf("keenetic round-trip drift: %d resolvers/strict=%v -> %d resolvers/strict=%v",
				len(nd.Resolvers), nd.StrictOrder, len(back.Resolvers), back.StrictOrder)
		} else {
			t.Logf("Keenetic round-trip OK: render dnsmasq.d -> re-adopt reproduces the chain")
		}
	}
}
