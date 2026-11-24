package pbr

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// fastProfile has a kernel tunnel (awg2, an adopted IPv4-only device), a dual-stack AmneziaWG, a
// proxy endpoint only the core carries, and lists and rules of every kind the fast DNS plane takes.
func fastProfile() *model.Profile {
	return &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "awg2", Engine: model.EngineExternal, Enabled: true, Server: "198.51.100.2", Params: map[string]any{"interface": "awg2"}},
			{ID: "wgx", Engine: model.EngineAmneziaWG, Enabled: true, Server: "198.51.100.3"},
			{ID: "vl", Protocol: "vless", Enabled: true, Server: "203.0.113.9"},
		},
		RoutingLists: []model.RoutingList{
			{ID: "ai", Manual: []string{"openai.com", "*.chatgpt.com", "192.0.2.0/24"}, Outbound: "awg2", Enabled: true},
			{ID: "media", Manual: []string{"example.org"}, Outbound: "wgx", Enabled: true},
			{ID: "yt", Manual: []string{"video.example", "198.18.0.0/15"}, Outbound: "vl", Enabled: true},
		},
		Rules: []model.Rule{
			{ID: "r1", Domain: []string{"chat.example.net"}, Outbound: "awg2"},
		},
	}
}

func fastOptions() Options {
	return Options{FastDNS: true, DNSEnforce: true, LANIfaces: []string{"br-lan", "bad name;"}}
}

func TestFastDNSCompile(t *testing.T) {
	plan, warns, err := Compile(fastProfile(), fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warns {
		t.Errorf("unexpected warning %s: %s", w.Scope, w.Msg)
	}
	byName := map[string]Zone{}
	for _, z := range plan.Zones {
		byName[z.Name] = z
	}
	ai := byName["list_ai"]
	if strings.Join(ai.Domains, ",") != "chatgpt.com,openai.com" || strings.Join(ai.V4, ",") != "192.0.2.0/24" || !ai.DNSNoV6 {
		t.Errorf("list_ai = %+v", ai)
	}
	if z := byName["list_media"]; len(z.Domains) != 1 || z.DNSNoV6 {
		t.Errorf("a dual-stack tunnel's domain zone takes AAAA answers: %+v", z)
	}
	if z := byName["rule_r1"]; strings.Join(z.Domains, ",") != "chat.example.net" {
		t.Errorf("a rule's Domain literal is a name of its zone: %+v", z)
	}
	if len(plan.CoreZones) != 1 || plan.CoreZones[0].Name != "core_yt" ||
		strings.Join(plan.CoreZones[0].Domains, ",") != "video.example" || strings.Join(plan.CoreZones[0].V4, ",") != "198.18.0.0/15" {
		t.Fatalf("core zones = %+v", plan.CoreZones)
	}
	if _, ok := byName["list_yt"]; ok {
		t.Error("a core-only list must not mark")
	}
	if !plan.CorePin || !plan.DNSEnforce || strings.Join(plan.LANIfaces, ",") != "br-lan" {
		t.Errorf("CorePin=%v DNSEnforce=%v LANIfaces=%v", plan.CorePin, plan.DNSEnforce, plan.LANIfaces)
	}
}

// TestFastDNSV6Refused (polish 1b): the names of a list sent to an IPv4-only tunnel keep a _6 set the
// resolver fills, nothing marks it, and wd_v6only refuses forwarded IPv6 to it while the packet would
// leave by the provider; a dual-stack tunnel's names and a device-scoped IPv4-only zone get no refusal.
func TestFastDNSV6Refused(t *testing.T) {
	p := fastProfile()
	p.DeviceGroups = []model.DeviceGroup{{ID: "kid", Members: []model.DeviceMember{{IP: "192.168.1.50"}}}}
	p.RoutingLists = append(p.RoutingLists, model.RoutingList{ID: "kidv4", Manual: []string{"kid.example"}, Outbound: "awg2",
		Enabled: true, ScopeMode: "only", ScopeGroups: []string{"kid"}})
	plan, _, err := Compile(p, fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	nft := plan.RenderNft()
	dns := nft[strings.Index(nft, "table inet wayhop_dns {\n"):]
	for _, want := range []string{
		"\tset dlist_list_ai_6 { type ipv6_addr; flags dynamic,timeout;",
		"\tchain wd_v6only {\n\t\ttype filter hook forward priority filter - 2; policy accept;\n",
		"ip6 daddr @dlist_list_ai_6 meta mark & 0x00ff0000 == { 0x00000000, 0x00010000, 0x00ff0000 } meta l4proto tcp reject with tcp reset\n",
		"ip6 daddr @dlist_list_ai_6 meta mark & 0x00ff0000 == { 0x00000000, 0x00010000, 0x00ff0000 } reject with icmpv6 type admin-prohibited\n",
	} {
		if !strings.Contains(dns, want) {
			t.Errorf("missing %q in\n%s", want, dns)
		}
	}
	if strings.Contains(dns, "ip6 daddr @dlist_list_ai_6 update") {
		t.Errorf("an IPv4-only tunnel's IPv6 is marked into it:\n%s", dns)
	}
	if strings.Contains(dns, "@dlist_list_media_6 meta mark") || strings.Contains(dns, "dlist_list_kidv4_6") {
		t.Errorf("a dual-stack tunnel or a device-scoped zone is refused:\n%s", dns)
	}
	snippet := plan.RenderFastDnsmasq(nil)
	if !strings.Contains(snippet, "6#inet#wayhop_dns#dlist_list_ai_6") || strings.Contains(snippet, "dlist_list_kidv4_6") {
		t.Errorf("snippet:\n%s", snippet)
	}
	sets := strings.Join(plan.DlistSets(), ",")
	if !strings.Contains(sets, "dlist_list_ai_6") || strings.Contains(sets, "dlist_list_kidv4_6") {
		t.Errorf("DlistSets %s", sets)
	}
}

func TestFastDNSRender(t *testing.T) {
	plan, _, err := Compile(fastProfile(), fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	nft := plan.RenderNft()
	i := strings.Index(nft, "table inet wayhop_dns {}\n")
	if i < 0 {
		t.Fatalf("no DNS table:\n%s", nft)
	}
	pbrPart, dnsPart := nft[:i], nft[i:]
	for _, want := range []string{
		"\tset core_yt_4 { type ipv4_addr; flags interval; elements = { 198.18.0.0/15 } }\n",
		"\t\tip daddr @list_ai_4 meta mark set meta mark & 0xff00ffff | 0x00020000\n",
		"\tchain wr_corepin {\n\t\ttype nat hook prerouting priority dstnat - 1; policy accept;\n" +
			"\t\tiifname != @corepin_lan return\n\t\tfib daddr type local return\n" +
			"\t\tip daddr @core_yt_4 return\n\t\tmeta mark & 0x00ff0000 == 0x00ff0000 return\n" +
			"\t\tmeta nfproto ipv4 dnat ip to ip daddr\n\t\tmeta nfproto ipv6 dnat ip6 to ip6 daddr\n\t}\n",
		"\tchain wr_dns {\n\t\ttype nat hook prerouting priority dstnat - 2; policy accept;\n" +
			"\t\tiifname { \"br-lan\" } fib daddr type != local meta l4proto { tcp, udp } th dport 53 redirect to :53\n\t}\n",
		"\t\tiifname { \"br-lan\" } tcp dport 853 reject with tcp reset\n",
		"type filter hook prerouting priority dstnat + 4; policy accept;\n",
	} {
		if !strings.Contains(pbrPart, want) {
			t.Errorf("plan table lacks %q\n%s", want, pbrPart)
		}
	}
	for _, want := range []string{
		"table inet wayhop_dns {}\ndelete table inet wayhop_dns\ntable inet wayhop_dns {\n",
		"\tset dlist_list_ai_4 { type ipv4_addr; flags dynamic,timeout; timeout 6h; size 65536; }\n",
		"\tset dlist_list_media_6 { type ipv6_addr; flags dynamic,timeout; timeout 6h; size 65536; }\n",
		"\tset dlist_core_yt_4 { type ipv4_addr; flags dynamic,timeout; timeout 6h; size 65536; }\n",
		"\tchain wd_mark {\n\t\ttype filter hook prerouting priority mangle - 1; policy accept;\n",
		"\t\tip daddr @dlist_list_ai_4 update @dlist_list_ai_4 { ip daddr } meta mark set meta mark & 0xff00ffff | 0x00020000\n",
		"\t\tip6 daddr @dlist_list_media_6 update @dlist_list_media_6 { ip6 daddr } meta mark set",
		"\t\tip daddr @dlist_core_yt_4 update @dlist_core_yt_4 { ip daddr } meta mark set meta mark & 0xff00ffff | 0x00ff0000\n",
		"\tchain wd_mark_late {\n\t\ttype filter hook prerouting priority dstnat + 3; policy accept;\n\t\tmeta l4proto != { icmp, udp, ipv6-icmp } return\n",
	} {
		if !strings.Contains(dnsPart, want) {
			t.Errorf("DNS table lacks %q\n%s", want, dnsPart)
		}
	}
	for _, absent := range []string{"dlist_", "corepin"} {
		if absent == "dlist_" && strings.Contains(pbrPart, absent) {
			t.Errorf("the plan's table references %q", absent)
		}
	}
	// The v4-only tunnel's _6 set exists only to be refused (polish 1b), never marked.
	if strings.Contains(dnsPart, "@dlist_list_ai_6 update") || strings.Contains(pbrPart, "\tset core_yt_6 {") || strings.Contains(nft, "@list_yt") {
		t.Error("v4-only or core-only parts rendered where they must not")
	}
	// A v4-only tunnel's names do not open the IPv6 plane; a dual-stack one's do.
	if !plan.HasV6() {
		t.Error("the dual-stack domain zone needs the ip -6 rules")
	}
	if td := plan.RenderTeardown(Options{}); len(td) < 2 || td[1] != "nft delete table inet wayhop_dns" {
		t.Errorf("teardown %v", td[:2])
	}
}

// TestFastDNSTableStaysSmall (live 22.11): dnsmasq adds through libnftables, which reads the whole
// target table first. The DNS table holds the dynamic sets, small source copies and two chains:
// never a list's static prefixes, never a remote list's.
func TestFastDNSTableStaysSmall(t *testing.T) {
	p := fastProfile()
	var big []string
	for i := 0; i < 5000; i++ {
		big = append(big, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}
	p.RoutingLists[0].Manual = append(p.RoutingLists[0].Manual, big...)
	opt := fastOptions()
	plan, _, err := Compile(p, opt)
	if err != nil {
		t.Fatal(err)
	}
	dns := plan.RenderNftDNS()
	if strings.Contains(dns, "elements = { 10.") || strings.Contains(dns, "rlist_") || len(dns) > 4096 {
		t.Errorf("the DNS table carries list content (%d bytes):\n%.600s", len(dns), dns)
	}
	if strings.Count(plan.RenderNft(), "\n") < 10 {
		t.Error("sanity")
	}
}

// TestDNSGuardPrecedence: a static line of a weaker zone does not take an address from a stronger
// zone's resolver-fed set; a weaker or equal dlist mark is overridden, as before.
func TestDNSGuardPrecedence(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{ID: "awg2", Engine: model.EngineExternal, Enabled: true, Params: map[string]any{"interface": "awg2"}}},
		RoutingLists: []model.RoutingList{
			{ID: "tun", Manual: []string{"203.0.113.0/24", "tun.example"}, Outbound: "awg2", Enabled: true},
			{ID: "blk", Manual: []string{"ads.example"}, Outbound: model.OutboundBlock, Enabled: true},
			{ID: "dir", Manual: []string{"198.51.100.0/24", "direct.example"}, Outbound: model.OutboundDirect, Enabled: true},
		},
	}
	plan, _, err := Compile(p, fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	var blk, tun uint32
	for _, z := range plan.Zones {
		switch z.Name {
		case "list_blk":
			blk = z.Mark
		case "list_tun":
			tun = z.Mark
		}
	}
	nft := plan.RenderNft()
	wantTun := fmt.Sprintf("meta mark & 0x00ff0000 != { %s } ip daddr @list_tun_4", hexMark(blk))
	if !strings.Contains(nft, wantTun) {
		t.Errorf("the tunnel's static line does not keep the block list's names:\n%s", nft)
	}
	wantDir := fmt.Sprintf("meta mark & 0x00ff0000 != { %s, %s } ip daddr @list_dir_4", hexMark(tun), hexMark(blk))
	if !strings.Contains(nft, wantDir) {
		t.Errorf("the direct list's static line does not keep stronger names (%s):\n%s", wantDir, nft)
	}
}

// TestFastDNSNoCoreNoPin: without a core-only list there is no pin (Phase 1a: no TUN either).
func TestFastDNSNoCoreNoPin(t *testing.T) {
	p := fastProfile()
	p.RoutingLists = p.RoutingLists[:2]
	plan, _, err := Compile(p, fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	if plan.CorePin || strings.Contains(plan.RenderNft(), "wr_corepin") {
		t.Error("core pin without a core-only list")
	}
	if !plan.DNSEnforceActive() {
		t.Error("names in fast mode enforce the router's resolver")
	}
	opt := fastOptions()
	opt.DNSEnforce = false
	plan, _, _ = Compile(p, opt)
	if strings.Contains(plan.RenderNft(), "wr_dns") {
		t.Error("fast_dns_enforce off still renders the DNS redirect")
	}
	// Unknown LAN devices: nothing that acts on input devices renders.
	opt = fastOptions()
	opt.LANIfaces = nil
	plan, _, _ = Compile(fastProfile(), opt)
	if nft := plan.RenderNft(); strings.Contains(nft, "wr_corepin") || strings.Contains(nft, "wr_dns") || !plan.CorePin {
		t.Errorf("no LAN devices: CorePin=%v render:\n%s", plan.CorePin, nft)
	}
}

// TestFastDNSOffIsByteIdentical: an IP-only profile renders the same with the plane on or off, so the
// artifacts stored on routers stay valid.
func TestFastDNSOffIsByteIdentical(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{ID: "awg2", Engine: model.EngineExternal, Enabled: true, Params: map[string]any{"interface": "awg2"}}},
		RoutingLists: []model.RoutingList{
			{ID: "tg", Manual: []string{"91.108.4.0/22", "2001:67c:4e8::/48"}, Outbound: "awg2", Enabled: true},
			{ID: "blk", Manual: []string{"10.66.0.0/16"}, Outbound: model.OutboundBlock, Enabled: true},
		},
	}
	off, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	on, _, err := Compile(p, fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	if off.RenderNft() != on.RenderNft() || strings.Join(off.RenderIP(Options{}), "\n") != strings.Join(on.RenderIP(Options{}), "\n") {
		t.Errorf("render moved:\n--- off ---\n%s\n--- on ---\n%s", off.RenderNft(), on.RenderNft())
	}
	if on.HasFastDNS() {
		t.Error("an IP-only plan has nothing of the fast DNS plane")
	}
}

func TestFastDNSRemoteSets(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{ID: "awg2", Engine: model.EngineExternal, Enabled: true, Params: map[string]any{"interface": "awg2"}}},
		RoutingLists: []model.RoutingList{
			{ID: "srs", Source: "https://example.test/a.srs", Outbound: "awg2", Enabled: true},
		},
	}
	opt := fastOptions()
	plan, warns, _ := Compile(p, opt)
	if len(warns) == 0 || len(plan.Zones) != 0 {
		t.Fatalf("an unfetched remote list is warned about and routes nothing: %v %+v", warns, plan.Zones)
	}
	opt.RemoteSets = map[string]RemoteSet{"srs": {Source: "https://example.test/a.srs", Domains: []string{"a.example"}, CIDRs: []string{"203.0.113.0/24"}}}
	plan, warns, _ = Compile(p, opt)
	if len(warns) != 0 || len(plan.Zones) != 1 || plan.Zones[0].RemoteList != "srs" || len(plan.Zones[0].Domains)+len(plan.Zones[0].V4) != 0 {
		t.Fatalf("remote content: %v %+v", warns, plan.Zones)
	}
	// The content stays out of the plan (it is persisted on flash) and reaches the kernel and the
	// resolver from the daemon's RAM copy.
	nft := plan.RenderNft()
	for _, want := range []string{"\tset rlist_list_srs_4 { type ipv4_addr; flags interval; }\n", "ip daddr @rlist_list_srs_4 meta mark set"} {
		if !strings.Contains(nft, want) {
			t.Errorf("render lacks %q:\n%s", want, nft)
		}
	}
	if strings.Contains(nft, "203.0.113.0/24") || strings.Contains(nft, "a.example") {
		t.Error("remote content in the rendered table")
	}
	el := plan.RenderRemoteElements(opt.RemoteSets)
	if el != "flush set inet wayhop_pbr rlist_list_srs_4\nadd element inet wayhop_pbr rlist_list_srs_4 { 203.0.113.0/24 }\n" {
		t.Errorf("elements program:\n%s", el)
	}
	if sn := plan.RenderFastDnsmasq(map[string][]string{"srs": {"a.example"}}); !strings.Contains(sn, "nftset=/a.example/4#inet#wayhop_dns#dlist_list_srs_4,6#inet#wayhop_dns#dlist_list_srs_6\n") ||
		!strings.Contains(sn, "address=/"+FastCanaryName+"/"+FastCanaryAddr) {
		t.Errorf("snippet:\n%s", sn)
	}
	// Content fetched for another URL, or with matchers nothing can express, is not the list's.
	opt.RemoteSets["srs"] = RemoteSet{Source: "https://example.test/old.srs", Domains: []string{"a.example"}}
	if _, warns, _ = Compile(p, opt); len(warns) == 0 {
		t.Error("stale content accepted")
	}
	opt.RemoteSets["srs"] = RemoteSet{Source: "https://example.test/a.srs", Domains: []string{"a.example"}, Unrepresentable: []string{"domain_keyword"}}
	if _, warns, _ = Compile(p, opt); len(warns) == 0 {
		t.Error("content with a keyword matcher accepted")
	}
}

func TestRenderFastDnsmasqChunks(t *testing.T) {
	var doms []string
	for i := 0; i < 400; i++ {
		doms = append(doms, strings.Repeat("x", i%40+1)+strconv.Itoa(i)+".example.com")
	}
	long := strings.Repeat("y", 64) + ".example.com" // a label over 63: dnsmasq cannot take it
	plan := &Plan{Table: "wayhop_pbr", Zones: []Zone{{Name: "list_big", Domains: append(append([]string(nil), doms...), long)}, {Name: "list_v4", Domains: []string{"a.example"}, DNSNoV6: true}}}
	got := plan.RenderFastDnsmasq(nil)
	if !strings.HasPrefix(got, FastDnsmasqHeader+"\n") {
		t.Fatal("no header")
	}
	seen := map[string]bool{}
	lines := strings.Split(strings.TrimSpace(got), "\n")[1:]
	for _, ln := range lines {
		if ln == "address=/"+FastCanaryName+"/"+FastCanaryAddr {
			continue
		}
		if len(ln) > fastDnsmasqLineMax {
			t.Errorf("line of %d bytes", len(ln))
		}
		parts := strings.Split(ln, "/")
		target := parts[len(parts)-1]
		if n := len(parts) - 2; n > fastDnsmasqLineNames {
			t.Errorf("%d names on one line", n)
		}
		switch {
		case strings.Contains(ln, "list_big"):
			if target != "4#inet#wayhop_dns#dlist_list_big_4,6#inet#wayhop_dns#dlist_list_big_6" {
				t.Errorf("target %q", target)
			}
		case target != "4#inet#wayhop_dns#dlist_list_v4_4,6#inet#wayhop_dns#dlist_list_v4_6":
			// The IPv4-only zone's _6 set is filled to be refused (polish 1b).
			t.Errorf("v4-only target %q", target)
		}
		for _, d := range parts[1 : len(parts)-1] {
			seen[d] = true
		}
	}
	if seen[long] || len(plan.InvalidFastNames(nil)["list_big"]) != 1 {
		t.Error("an invalid name reached the snippet, or is not reported")
	}
	if len(lines) < 9 {
		t.Errorf("expected several chunks, got %d", len(lines))
	}
	for _, d := range normalizeDomains(doms) {
		if !seen[d] {
			t.Errorf("%s lost in chunking", d)
		}
	}
	if (&Plan{Table: "wayhop_pbr"}).RenderFastDnsmasq(nil) != "" {
		t.Error("a plan without names writes a snippet")
	}
}

func TestDnsmasqConfDirs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"openwrt 25.12 one instance", map[string]string{
			"/var/etc/dnsmasq.conf.cfg01411c": "# auto-generated config file from /etc/config/dhcp\nconf-file=/etc/dnsmasq.conf\ndhcp-authoritative\nconf-dir=/tmp/dnsmasq.cfg01411c.d\nuser=dnsmasq\n",
		}, "/tmp/dnsmasq.cfg01411c.d"},
		{"two instances, filter suffix", map[string]string{
			"/var/etc/dnsmasq.conf.lan":   "conf-dir=/tmp/dnsmasq.lan.d\n",
			"/var/etc/dnsmasq.conf.guest": "conf-dir=/tmp/dnsmasq.guest.d,*.conf\n",
		}, "/tmp/dnsmasq.guest.d,/tmp/dnsmasq.lan.d"},
		{"none", map[string]string{"/var/etc/dnsmasq.conf.x": "port=53\n#conf-dir=/etc/nope\nconf-dir=relative\n"}, ""},
	} {
		if got := strings.Join(DnsmasqConfDirs(tc.files), ","); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestDnsmasqHasNftset(t *testing.T) {
	full := "Dnsmasq version 2.91  Copyright (c) 2000-2025 Simon Kelley\nCompile time options: IPv6 GNU-getopt no-DBus UBus no-i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset nftset auth cryptohash DNSSEC no-ID loop-detect inotify dumpfile\n"
	plain := "Dnsmasq version 2.91\nCompile time options: IPv6 GNU-getopt no-DBus UBus no-i18n no-IDN DHCP no-DHCPv6 no-Lua TFTP no-conntrack no-ipset no-nftset no-auth no-cryptohash no-DNSSEC loop-detect inotify dumpfile\n"
	if !DnsmasqHasNftset(full) || DnsmasqHasNftset(plain) || DnsmasqHasNftset("") {
		t.Error("nftset detection")
	}
}

func TestDlistCarry(t *testing.T) {
	listing := "table inet wayhop_pbr {\n\tset dlist_list_ai_4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t\ttimeout 6h\n" +
		"\t\telements = { 203.0.113.47 timeout 6h expires 5h59m48s896ms, 198.51.100.209 timeout 6h expires 12m3s,\n\t\t\t     bogus }\n\t}\n}\n"
	got := ParseDlistElements(listing)
	if len(got) != 2 || got[0].Addr != "203.0.113.47" || got[0].Left != 6*3600-11 || got[1].Left != 723 {
		t.Fatalf("parsed %+v", got)
	}
	plan := &Plan{Table: "wayhop_pbr", Zones: []Zone{{Name: "list_ai", Domains: []string{"openai.com"}, DNSNoV6: true}}}
	prog := plan.RenderDlistCarry(map[string][]DlistElement{
		"dlist_list_ai_4":   append(got, DlistElement{Addr: "2001:db8::1", Left: 5}, got[0]),
		"dlist_list_gone_4": {{Addr: "192.0.2.1"}},
	})
	want := "add element inet wayhop_dns dlist_list_ai_4 { 203.0.113.47 timeout 21589s, 198.51.100.209 timeout 723s }\n"
	if prog != want {
		t.Fatalf("carry program:\n%q\nwant\n%q", prog, want)
	}
	back := ParseDlistCarry(prog)
	if len(back["dlist_list_ai_4"]) != 2 || back["dlist_list_ai_4"][1].Left != 723 {
		t.Errorf("round trip %+v", back)
	}
	if ParseDlistElements("table inet wayhop_pbr {\n\tset dlist_x_4 {\n\t\ttype ipv4_addr\n\t}\n}\n") != nil {
		t.Error("an empty set has elements")
	}
}

// TestFastDNSRender_NftCheck runs the fast DNS plane through a real `nft -c` where one is available.
func TestFastDNSRender_NftCheck(t *testing.T) {
	nftBin, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft not in PATH")
	}
	plan, _, err := Compile(fastProfile(), fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	prog := plan.RenderNft() + plan.RenderDlistCarry(map[string][]DlistElement{"dlist_list_ai_4": {{Addr: "192.0.2.7", Left: 60}}})
	f := filepath.Join(t.TempDir(), "fast.nft")
	if err := os.WriteFile(f, []byte(prog), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(nftBin, "-c", "-f", f).CombinedOutput(); err != nil {
		if s := string(out); strings.Contains(s, "Operation not permitted") || strings.Contains(s, "cache initialization failed") {
			t.Skipf("nft -c cannot run here: %s", strings.TrimSpace(s))
		}
		t.Fatalf("nft -c rejected the fast DNS plane: %v\n%s\n%s", err, out, prog)
	}
}

func TestCarrySets(t *testing.T) {
	prev := &Plan{Zones: []Zone{{Name: "list_a", Domains: []string{"a.example"}}, {Name: "list_b", Domains: []string{"b.example", "x.example"}}}}
	cur := &Plan{Zones: []Zone{{Name: "list_a", Domains: []string{"a.example"}}, {Name: "list_b", Domains: []string{"b.example"}},
		{Name: "list_new", Domains: []string{"n.example"}}}}
	got := cur.CarrySets(prev)
	if !got["dlist_list_a_4"] || got["dlist_list_b_4"] || got["dlist_list_new_4"] {
		t.Errorf("carry sets %v", got)
	}
	if all := cur.CarrySets(nil); !all["dlist_list_b_4"] || !all["dlist_list_new_6"] {
		t.Errorf("no previous plan: %v", all)
	}
}

func TestParseNftSetListings(t *testing.T) {
	out := "table inet wayhop_pbr {\n\tset dlist_a_4 {\n\t\ttype ipv4_addr\n\t\telements = { 192.0.2.1 timeout 6h expires 1h }\n\t}\n}\n" +
		"table inet wayhop_pbr {\n\tset dlist_a_6 {\n\t\ttype ipv6_addr\n\t\telements = { 2001:db8::1 timeout 6h expires 2m }\n\t}\n}\n" +
		"table inet wayhop_pbr {\n\tset dlist_b_4 {\n\t\ttype ipv4_addr\n\t}\n}\n"
	got := ParseNftSetListings(out)
	if len(got["dlist_a_4"]) != 1 || got["dlist_a_4"][0].Left != 3600 || len(got["dlist_a_6"]) != 1 || got["dlist_a_6"][0].Left != 120 || len(got["dlist_b_4"]) != 0 {
		t.Errorf("parsed %+v", got)
	}
}

// TestRenderFastDnsmasqSharedNames: dnsmasq takes one nftset entry per query
// (the longest matching name), so a name in two zones, or under a name of another zone, gets one line
// that fills every set it belongs to.
func TestRenderFastDnsmasqSharedNames(t *testing.T) {
	plan := &Plan{Table: "t", Zones: []Zone{
		{Name: "list_a_dm", Domains: []string{"video.example"}},
		{Name: "list_a_di", Domains: []string{"video.example"}},
		// Device-scoped and IPv4-only: no _6 set at all (an all-device one keeps it to refuse, polish 1b).
		{Name: "list_blk", Domains: []string{"ads.video.example", "only.example"}, DNSNoV6: true, SrcScoped: true, SrcV4: []string{"192.168.1.50/32"}},
	}}
	got := plan.RenderFastDnsmasq(nil)
	for _, want := range []string{
		"nftset=/video.example/4#inet#t_dns#dlist_list_a_di_4,4#inet#t_dns#dlist_list_a_dm_4,6#inet#t_dns#dlist_list_a_di_6,6#inet#t_dns#dlist_list_a_dm_6\n",
		"nftset=/ads.video.example/4#inet#t_dns#dlist_list_a_di_4,4#inet#t_dns#dlist_list_a_dm_4,4#inet#t_dns#dlist_list_blk_4,6#inet#t_dns#dlist_list_a_di_6,6#inet#t_dns#dlist_list_a_dm_6\n",
		"nftset=/only.example/4#inet#t_dns#dlist_list_blk_4\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("snippet lacks %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "nftset=") != 3 {
		t.Errorf("one line per target group expected:\n%s", got)
	}
}

// TestCorePinHeldForRemoteLists: a remote list keeps the TUN, and the pin's
// devices are a set the daemon fills only once the lists are loaded.
func TestCorePinHeldForRemoteLists(t *testing.T) {
	p := &model.Profile{
		Endpoints:    []model.Endpoint{{ID: "awg2", Engine: model.EngineExternal, Enabled: true, Params: map[string]any{"interface": "awg2"}}},
		RoutingLists: []model.RoutingList{{ID: "srs", Source: "https://example.test/a.srs", Outbound: "awg2", Enabled: true}},
	}
	opt := fastOptions()
	opt.RemoteSets = map[string]RemoteSet{"srs": {Source: "https://example.test/a.srs", Domains: []string{"a.example"}}}
	plan, _, err := Compile(p, opt)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.CorePin || !strings.Contains(plan.RenderNft(), "\tset corepin_lan { type ifname; }\n") {
		t.Fatalf("remote list without the held pin:\n%s", plan.RenderNft())
	}
	if got := plan.RenderPinElements(false); got != "flush set inet wayhop_pbr corepin_lan\n" {
		t.Errorf("not ready: %q", got)
	}
	if got := plan.RenderPinElements(true); got != "flush set inet wayhop_pbr corepin_lan\nadd element inet wayhop_pbr corepin_lan { \"br-lan\" }\n" {
		t.Errorf("ready: %q", got)
	}
}

// TestRenderFastDnsmasqManyZones (polish 1a): a name under more zones than one line holds is left out
// of the snippet (with every name under it), never kept with only some of its zones; other names stay.
func TestRenderFastDnsmasqManyZones(t *testing.T) {
	plan := &Plan{Table: "wayhop_pbr"}
	for i := 0; i < 40; i++ {
		plan.Zones = append(plan.Zones, Zone{Name: fmt.Sprintf("list_zone_number_%02d", i), Domains: []string{"shared.example"}})
	}
	plan.Zones[0].Domains = append(plan.Zones[0].Domains, "alone.example", "sub.shared.example")
	got := plan.RenderFastDnsmasq(nil)
	for _, ln := range strings.Split(strings.TrimSpace(got), "\n") {
		if len(ln) > fastDnsmasqLineMax {
			t.Errorf("line of %d bytes", len(ln))
		}
	}
	if strings.Contains(got, "shared.example") {
		t.Errorf("an overfull name (or a name under it) is still in the snippet:\n%s", got)
	}
	if !strings.Contains(got, "nftset=/alone.example/4#inet#wayhop_dns#dlist_list_zone_number_00_4") {
		t.Errorf("a name of one zone was dropped with the overfull one:\n%s", got)
	}
	if over := plan.OverfullFastNames(nil); strings.Join(over, ",") != "shared.example,sub.shared.example" {
		t.Errorf("overfull %v", over)
	}
}

// TestScopedDirectNamesKeepPrecedence: a device-scoped direct zone's names
// get their own mark, ranked above the tunnels, even beside an unscoped direct name list.
func TestScopedDirectNamesKeepPrecedence(t *testing.T) {
	p := &model.Profile{
		Endpoints:    []model.Endpoint{{ID: "awg2", Engine: model.EngineExternal, Enabled: true, Params: map[string]any{"interface": "awg2"}}},
		DeviceGroups: []model.DeviceGroup{{ID: "kid", Members: []model.DeviceMember{{IP: "192.168.1.50"}}}},
		RoutingLists: []model.RoutingList{
			{ID: "tun", Manual: []string{"203.0.113.0/24"}, Outbound: "awg2", Enabled: true},
			{ID: "dir", Manual: []string{"plain.example"}, Outbound: model.OutboundDirect, Enabled: true},
			{ID: "exempt", Manual: []string{"exempt.example"}, Outbound: model.OutboundDirect, Enabled: true, ScopeMode: "only", ScopeGroups: []string{"kid"}},
		},
	}
	plan, _, err := Compile(p, fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	nft := plan.RenderNft()
	if !strings.Contains(nft, "@dlist_list_exempt_di_4 update @dlist_list_exempt_di_4 { ip daddr } meta mark set meta mark & 0xff00ffff | 0x00fe0000") {
		t.Errorf("scoped direct names without their own mark:\n%s", nft)
	}
	if !strings.Contains(nft, "meta mark & 0x00ff0000 != { 0x00fe0000 } ip daddr @list_tun_4") {
		t.Errorf("the tunnel's static line does not keep the scoped direct names:\n%s", nft)
	}
	if !strings.Contains(nft, "meta mark & 0x00ff0000 == 0x00fe0000 ct mark set ct mark & 0xff00ffff | 0x00010000") {
		t.Errorf("the scoped direct mark is not saved as the WAN mark:\n%s", nft)
	}
}

// TestFastDNSRound4: the scoped direct names' mark has an ip rule of its own, and a
// name under more zones than a line holds is reported.
func TestFastDNSRound4(t *testing.T) {
	p := &model.Profile{
		Endpoints:    []model.Endpoint{{ID: "awg2", Engine: model.EngineExternal, Enabled: true, Params: map[string]any{"interface": "awg2"}}},
		DeviceGroups: []model.DeviceGroup{{ID: "kid", Members: []model.DeviceMember{{IP: "192.168.1.50"}}}},
		RoutingLists: []model.RoutingList{
			{ID: "tun", Manual: []string{"203.0.113.0/24"}, Outbound: "awg2", Enabled: true},
			{ID: "exempt", Manual: []string{"exempt.example"}, Outbound: model.OutboundDirect, Enabled: true, ScopeMode: "only", ScopeGroups: []string{"kid"}},
		},
	}
	plan, _, err := Compile(p, fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	ip := strings.Join(plan.RenderIP(Options{}), "\n")
	if !strings.Contains(ip, "ip rule add fwmark 0x00fe0000/0x00ff0000 table 254 priority 151") {
		t.Errorf("no rule for the scoped direct mark:\n%s", ip)
	}
	if td := strings.Join(plan.RenderTeardown(Options{}), "\n"); !strings.Contains(td, "ip rule del fwmark 0x00fe0000/0x00ff0000 table 254 priority 151") {
		t.Errorf("teardown keeps the rule:\n%s", td)
	}
	if len(MissingIPRules("ip rule add fwmark 0x00fe0000/0x00ff0000 table 254 priority 151", "151:\tfrom all fwmark 0xfe0000/0xff0000 lookup main\n", "", false)) != 0 {
		t.Error("the postcheck does not recognise the rule as the kernel prints it")
	}
	many := &Plan{Table: "wayhop_pbr"}
	for i := 0; i < 40; i++ {
		many.Zones = append(many.Zones, Zone{Name: fmt.Sprintf("list_zone_number_%02d", i), Domains: []string{"shared.example"}})
	}
	if got := many.OverfullFastNames(nil); len(got) != 1 || got[0] != "shared.example" {
		t.Errorf("overfull %v", got)
	}
}

// TestFastDNSHunt1122: a list whose names come only from a remote rule-set turns
// DNS enforcement on; and while the core's TUN carries no IPv6, IPv6 to a core-only list's names,
// prefixes and remote prefixes is refused instead of leaving by the provider.
func TestFastDNSHunt1122(t *testing.T) {
	p := &model.Profile{
		Endpoints:    []model.Endpoint{{ID: "awg2", Engine: model.EngineExternal, Enabled: true, Params: map[string]any{"interface": "awg2"}}},
		RoutingLists: []model.RoutingList{{ID: "srs", Source: "https://example.test/a.srs", Outbound: "awg2", Enabled: true}},
	}
	opt := fastOptions()
	opt.RemoteSets = map[string]RemoteSet{"srs": {Source: "https://example.test/a.srs", Domains: []string{"a.example"}}}
	plan, _, err := Compile(p, opt)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.DNSEnforce || !strings.Contains(plan.RenderNft(), "\tchain wr_dns {\n") || !strings.Contains(plan.RenderNft(), "\tchain wr_dot {\n") {
		t.Errorf("a remote-only name list without DNS enforcement:\n%s", plan.RenderNft())
	}

	fp := fastProfile()
	fp.RoutingLists[2].Manual = append(fp.RoutingLists[2].Manual, "2001:db8:18::/48")
	plan, _, err = Compile(fp, fastOptions())
	if err != nil {
		t.Fatal(err)
	}
	nft := plan.RenderNft()
	for _, want := range []string{
		"ip6 daddr @dlist_core_yt_6 meta mark & 0x00ff0000 == { 0x00000000, 0x00010000, 0x00ff0000 } meta l4proto tcp reject with tcp reset\n",
		"\tchain wr_core_v6 {\n\t\ttype filter hook forward priority filter - 2; policy accept;\n",
		"ip6 daddr @core_yt_6 meta mark & 0x00ff0000 == { 0x00000000, 0x00010000 } reject with icmpv6 type admin-prohibited\n",
	} {
		if !strings.Contains(nft, want) {
			t.Errorf("missing %q in\n%s", want, nft)
		}
	}
	// The sets whose addresses a WAN-saved flow no longer goes by.
	beyond := plan.DlistSetsBeyondWAN()
	if !beyond["dlist_list_ai_4"] || !beyond["dlist_core_yt_4"] || plan.WANMark() == 0 {
		t.Errorf("beyond WAN %v, WAN mark %#x", beyond, plan.WANMark())
	}
	dp := &model.Profile{RoutingLists: []model.RoutingList{{ID: "home", Manual: []string{"home.example"}, Outbound: model.OutboundDirect, Enabled: true}}}
	if dplan, _, err := Compile(dp, fastOptions()); err != nil || len(dplan.DlistSetsBeyondWAN()) != 0 || len(dplan.DlistSets()) == 0 {
		t.Errorf("a direct name list counted beyond the WAN: %v %v", err, dplan.DlistSetsBeyondWAN())
	}
	plan.GuardNames = true // the TUN carries IPv6: nothing refused
	if nft := plan.RenderNft(); strings.Contains(nft, "wr_core_v6") || strings.Contains(nft, "@dlist_core_yt_6 meta mark") {
		t.Errorf("refused with an IPv6 TUN:\n%s", nft)
	}
}

// TestFastDNSCIDROnlyRemoteNoEnforcement: a remote list known to hold only prefixes does not
// turn DNS enforcement on.
func TestFastDNSCIDROnlyRemoteNoEnforcement(t *testing.T) {
	p := &model.Profile{
		Endpoints:    []model.Endpoint{{ID: "awg2", Engine: model.EngineExternal, Enabled: true, Params: map[string]any{"interface": "awg2"}}},
		RoutingLists: []model.RoutingList{{ID: "srs", Source: "https://example.test/a.srs", Outbound: "awg2", Enabled: true}},
	}
	opt := fastOptions()
	opt.RemoteSets = map[string]RemoteSet{"srs": {Source: "https://example.test/a.srs", CIDRs: []string{"203.0.113.0/24"}}}
	plan, _, err := Compile(p, opt)
	if err != nil {
		t.Fatal(err)
	}
	if nft := plan.RenderNft(); plan.DNSEnforce || strings.Contains(nft, "wr_dns") || strings.Contains(nft, "wr_dot") {
		t.Errorf("a prefix-only remote list enforces DNS:\n%s", nft)
	}
}
