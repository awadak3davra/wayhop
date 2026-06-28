package server

import (
	"context"
	"strings"
	"testing"
)

// TestDoHResolverList: every curated resolver is returned with a correct host CIDR (/32 v4, /128
// v6), sorted by provider — the data the UI builds a one-click "block public DoH" list from.
func TestDoHResolverList(t *testing.T) {
	list := dohResolverList()
	if len(list) != len(dohResolvers) {
		t.Fatalf("list has %d, want %d (every curated resolver)", len(list), len(dohResolvers))
	}
	byIP := map[string]dohResolver{}
	for i, r := range list {
		byIP[r.IP] = r
		if i > 0 && list[i-1].Provider > r.Provider {
			t.Errorf("not sorted by provider: %q after %q", r.Provider, list[i-1].Provider)
		}
	}
	if r := byIP["1.1.1.1"]; r.CIDR != "1.1.1.1/32" || r.Provider != "Cloudflare" {
		t.Errorf("1.1.1.1 → %+v, want /32 Cloudflare", r)
	}
	if r := byIP["2606:4700:4700::1111"]; r.CIDR != "2606:4700:4700::1111/128" {
		t.Errorf("v6 resolver CIDR = %q, want /128", r.CIDR)
	}
}

// TestDetectDoHClients locks the detection: only :443/:853 connections to a known resolver IP
// count, deduped per (client, provider), with the DHCP hostname when known; other ports and
// non-resolver destinations are ignored.
func TestDetectDoHClients(t *testing.T) {
	conns := []Conn{
		{Src: "192.168.1.50", Dst: "1.1.1.1", Dport: 443},              // Cloudflare DoH
		{Src: "192.168.1.50", Dst: "1.1.1.1", Dport: 443},              // dup → one finding
		{Src: "192.168.1.51", Dst: "8.8.8.8", Dport: 853},              // Google DoT
		{Src: "192.168.1.52", Dst: "1.2.3.4", Dport: 443},              // not a resolver → ignored
		{Src: "192.168.1.53", Dst: "1.1.1.1", Dport: 80},               // resolver but not 443/853 → ignored
		{Src: "192.168.1.54", Dst: "2606:4700:4700::1111", Dport: 443}, // Cloudflare v6
	}
	leases := map[string]string{"192.168.1.50": "tablet"}
	got := detectDoHClients(conns, leases)
	if len(got) != 3 {
		t.Fatalf("want 3 findings (.50 deduped, .51, .54; .52/.53 ignored), got %d: %v", len(got), got)
	}
	joined := strings.Join(got, " | ")
	for _, want := range []string{"tablet (192.168.1.50) → Cloudflare", "192.168.1.51 → Google", "192.168.1.54 → Cloudflare"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing finding %q in %v", want, got)
		}
	}
	if strings.Contains(joined, "192.168.1.52") || strings.Contains(joined, "192.168.1.53") {
		t.Errorf("a non-DoH connection was flagged: %v", got)
	}
}

// TestDnsBypassCheck: the battery probe returns a row and degrades to warn when conntrack is
// unreadable (the dev/CI host has no /proc/net/nf_conntrack).
func TestDnsBypassCheck(t *testing.T) {
	s, _ := sharehandlers_server(t)
	got := s.dnsBypassCheck(context.Background())
	if got.ID != "dns-bypass" {
		t.Fatalf("id=%q, want dns-bypass", got.ID)
	}
	if got.Status != "pass" && got.Status != "warn" {
		t.Fatalf("status=%q, want pass or warn", got.Status)
	}
}
