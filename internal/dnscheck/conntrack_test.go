package dnscheck

import (
	"reflect"
	"testing"
)

const conntrackFixture = `ipv4     2 udp      17 29 src=203.0.113.10 dst=1.1.1.1 sport=51742 dport=53 packets=1 bytes=68 src=1.1.1.1 dst=203.0.113.10 sport=53 dport=51742 packets=1 bytes=84 [FASTNAT] mark=0 use=2
ipv4     2 udp      17 25 src=198.51.100.4 dst=8.8.8.8 sport=4000 dport=53 packets=1 bytes=68 [UNREPLIED] src=8.8.8.8 dst=198.51.100.4 sport=53 dport=4000 packets=0 bytes=0 mark=0 use=2
udp      17 12 src=203.0.113.10 dst=9.9.9.9 sport=4100 dport=53 packets=1 bytes=68 src=9.9.9.9 dst=203.0.113.10 sport=53 dport=4100 packets=1 bytes=84 mark=0 use=1`

func TestParseConntrack(t *testing.T) {
	got := ParseConntrack(conntrackFixture + `
not a conntrack line
ipv4 2 tcp 6 10 src=not-an-ip dst=1.1.1.1 sport=1234 dport=53
udp 17 10 src=203.0.113.10 dst=1.1.1.1 sport=bad dport=53
udp 17 10 src=203.0.113.10 dst=1.1.1.1 sport=1234 dport=443`)
	want := []ConnFlow{
		{Proto: "udp", Src: "203.0.113.10", Dst: "1.1.1.1", Sport: 51742, Dport: 53, Replied: true},
		{Proto: "udp", Src: "198.51.100.4", Dst: "8.8.8.8", Sport: 4000, Dport: 53},
		{Proto: "udp", Src: "203.0.113.10", Dst: "9.9.9.9", Sport: 4100, Dport: 53, Replied: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseConntrack() = %#v, want %#v", got, want)
	}
}

func TestParseConntrackVariants(t *testing.T) {
	got := ParseConntrack(`ipv6 2 tcp 6 20 src=2001:db8::1 dst=2001:db8::2 sport=1234 dport=853 packets=1 [ASSURED] src=2001:db8::2 dst=2001:db8::1 sport=853 dport=1234 packets=0
udp 17 src=203.0.113.10 dst=8.8.8.8 sport=5000 dport=53 src=8.8.8.8 dst=203.0.113.10 sport=53 dport=5000`)
	if len(got) != 2 || got[0].Proto != "tcp" || got[0].Dport != 853 || !got[0].Replied || !got[1].Replied {
		t.Fatalf("variants parsed as %#v", got)
	}
}

func TestDiffFlowsFindsCanary(t *testing.T) {
	before := ParseConntrack(conntrackFixture)
	unchanged := before[0]
	canary := ConnFlow{Proto: "udp", Src: "203.0.113.10", Dst: "1.0.0.1", Sport: 52000, Dport: 53, Replied: true}
	after := append(append([]ConnFlow{}, before...), canary)
	after[0] = unchanged
	got := DiffFlows(before, after)
	if !reflect.DeepEqual(got, []ConnFlow{canary}) {
		t.Fatalf("DiffFlows() = %#v, want canary only", got)
	}
}

func TestSummarizeFlowsOnlyRouterSources(t *testing.T) {
	flows := append(ParseConntrack(conntrackFixture),
		ConnFlow{Proto: "udp", Src: "127.0.0.1", Dst: "127.0.0.1", Sport: 53000, Dport: 53, Replied: true})
	canary := []ConnFlow{flows[0]}
	got := SummarizeFlows(flows, `1: lo inet 127.0.0.1/8
2: eth3 inet 203.0.113.10/24
3: br-lan inet 198.51.100.4/24
4: nwg1 inet 192.0.2.2/32`, map[string]bool{"eth3": false, "nwg1": true}, canary)
	// 198.51.100.4 is treated as a router address here, so all three fixture flows are its own. A
	// source absent from this listing is the client case, covered by the final assertion below.
	if len(got) != 3 {
		t.Fatalf("got %d summarized flows, want 3: %#v", len(got), got)
	}
	if !got[1].FromCanary {
		t.Fatalf("canary was not retained in summary: %#v", got)
	}
	for _, f := range got {
		if f.Iface == "lo" {
			t.Errorf("the router asking its own listener counted as a way out: %#v", f)
		}
	}
	withoutClient := SummarizeFlows(flows, `2: eth3 inet 203.0.113.10/24
1: lo inet 127.0.0.1/8`, nil, nil)
	for _, f := range withoutClient {
		if f.Server == "8.8.8.8" {
			t.Errorf("client flow was counted as the router's: %#v", f)
		}
	}
}
