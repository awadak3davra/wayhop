package nativedns

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// uciShowFromCommands turns what RenderUCI emits into what ReadUCI parses, so the two halves of the
// OpenWrt write-back can be compared against each other.
//
// The mapping is fixed by RenderUCI itself, not guessed: it deletes every https-dns-proxy section
// first and then adds one per DoH resolver in order, so the `[-1]` ("the section just added") in the
// Nth add block is `[N]` in uci show output. A `uci -q delete` means the setting is absent, which in
// show output is simply a line that is not there.
func uciShowFromCommands(cmds []string) string {
	var out []string
	idx := -1
	for _, c := range cmds {
		switch {
		case strings.HasPrefix(c, "while "), c == "uci commit https-dns-proxy", c == "uci commit dhcp":
			continue
		case c == "uci add https-dns-proxy https-dns-proxy":
			idx++
			continue
		case strings.HasPrefix(c, "uci -q delete "):
			continue // absent is absent
		case strings.HasPrefix(c, "uci set "), strings.HasPrefix(c, "uci add_list "):
			line := strings.TrimPrefix(strings.TrimPrefix(c, "uci set "), "uci add_list ")
			line = strings.ReplaceAll(line, "@https-dns-proxy[-1]", "@https-dns-proxy["+strconv.Itoa(idx)+"]")
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n") + "\n"
}

// TestOpenWrtWriteBackRoundTrips (L5): what RenderUCI writes, ReadUCI must read back as the same
// model.
//
// The OpenWrt side had no such test. Its "round trip" only checked that the plan MENTIONS certain
// strings, never read anything back and never touched the two booleans — which is precisely how
// strictorder came to be written by neither end: adopted as false on a router that had it, then
// written back without it, turning "try the tunnel resolver first" into "ask every upstream at once
// and keep the first reply". The Keenetic side has compared the whole model for a while; this brings
// the other platform to the same standard.
func TestOpenWrtWriteBackRoundTrips(t *testing.T) {
	in := NativeDNS{Platform: "openwrt", StrictOrder: true, NoResolv: true,
		Resolvers: []NativeResolver{
			{Kind: KindDoH, Address: "https://1.1.1.1/dns-query"},
			{Kind: KindDoH, Address: "https://9.9.9.9/dns-query"},
			{Kind: KindPlain, Address: "8.8.8.8"},
		}}

	cmds := RenderUCI(in)
	show := uciShowFromCommands(cmds)
	// The transform itself must not silently produce nothing: an empty show would pass every
	// assertion below by accident.
	if !strings.Contains(show, "dhcp.@dnsmasq[0]") || !strings.Contains(show, "@https-dns-proxy[0]") {
		t.Fatalf("the command-to-show transform produced nothing usable:\n%s", show)
	}

	// ReadUCI takes the two uci trees separately, exactly as the adopt path gives them.
	var proxyLines, dhcpLines []string
	for _, ln := range strings.Split(show, "\n") {
		switch {
		case strings.HasPrefix(ln, "https-dns-proxy."):
			proxyLines = append(proxyLines, ln)
		case strings.HasPrefix(ln, "dhcp."):
			dhcpLines = append(dhcpLines, ln)
		}
	}
	back := ReadUCI(strings.Join(proxyLines, "\n"), strings.Join(dhcpLines, "\n"))

	if back.StrictOrder != in.StrictOrder {
		t.Errorf("strict order must survive the write-back: %v -> %v\n%s", in.StrictOrder, back.StrictOrder, show)
	}
	if back.NoResolv != in.NoResolv {
		t.Errorf("no-resolv must survive: %v -> %v", in.NoResolv, back.NoResolv)
	}
	got := map[string]string{}
	for _, r := range back.Resolvers {
		got[r.Address] = string(r.Kind)
	}
	for _, want := range in.Resolvers {
		if _, ok := got[want.Address]; !ok {
			t.Errorf("resolver %q did not come back: %s", want.Address, fmt.Sprint(back.Resolvers))
		}
	}

	// Both booleans off must come back off, not on: a round trip that invents a setting is the same
	// defect facing the other way.
	off := RenderUCI(NativeDNS{Platform: "openwrt",
		Resolvers: []NativeResolver{{Kind: KindPlain, Address: "9.9.9.9"}}})
	offShow := uciShowFromCommands(off)
	var offDhcp []string
	for _, ln := range strings.Split(offShow, "\n") {
		if strings.HasPrefix(ln, "dhcp.") {
			offDhcp = append(offDhcp, ln)
		}
	}
	if b := ReadUCI("", strings.Join(offDhcp, "\n")); b.StrictOrder || b.NoResolv {
		t.Errorf("absent settings must come back absent: %+v", b)
	}
}
