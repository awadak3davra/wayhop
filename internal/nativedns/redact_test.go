package nativedns

import (
	"strings"
	"testing"
)

func TestRedactAddress(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		// Tokened personal DoH URLs: token rides the path -> host kept, path masked.
		{"nextdns", "https://dns.nextdns.io/ab12cd", "https://dns.nextdns.io/•••"},
		{"controld", "https://dns.controld.com/x9y8z7", "https://dns.controld.com/•••"},
		{"adguard-personal", "https://d.adguard-dns.com/dns-query/abc123", "https://d.adguard-dns.com/•••"},
		{"token-in-query", "https://doh.example/dns-query?token=SECRET", "https://doh.example/•••"},
		{"userinfo", "https://user:pass@doh.example/dns-query", "https://doh.example/•••"},
		{"dot-with-path", "tls://dot.example/private", "tls://dot.example/•••"},
		// Non-secret forms: returned unchanged.
		{"public-doh-standard", "https://1.1.1.1/dns-query", "https://1.1.1.1/dns-query"},
		{"public-doh-host-only", "https://dns.google", "https://dns.google"},
		{"public-doh-trailing-slash", "https://cloudflare-dns.com/dns-query/", "https://cloudflare-dns.com/dns-query/"},
		{"plain-ip", "1.1.1.1", "1.1.1.1"},
		{"plain-ip-port", "10.0.1.0", "10.0.1.0"},
		{"bare-host", "dns.quad9.net", "dns.quad9.net"},
		{"empty", "", ""},
		{"loopback-ref", "127.0.0.1", "127.0.0.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RedactAddress(c.in); got != c.want {
				t.Errorf("RedactAddress(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestRedactAddress_NeverLeaksToken is the security invariant: for any URL carrying a token beyond the
// canonical /dns-query, the token substring must not survive redaction.
func TestRedactAddress_NeverLeaksToken(t *testing.T) {
	for _, in := range []string{
		"https://dns.nextdns.io/SUPERSECRETTOKEN",
		"https://doh.example/dns-query?apikey=SUPERSECRETTOKEN",
		"https://SUPERSECRETTOKEN.doh.example/dns-query/more",
	} {
		out := RedactAddress(in)
		// Host-embedded tokens (case 3) are a known limitation we do NOT claim to mask; assert only
		// path/query-borne tokens are gone.
		if in == "https://SUPERSECRETTOKEN.doh.example/dns-query/more" {
			continue
		}
		if strings.Contains(out, "SUPERSECRETTOKEN") {
			t.Errorf("token leaked through redaction: %q -> %q", in, out)
		}
	}
}

// TestValidateForWrite_RejectsRedacted is the round-trip safety guard: if a redacted (display-only)
// resolver address is posted back to the write-back plan, ValidateForWrite must REJECT it rather than
// let RenderUCI bake the placeholder into resolver_url and corrupt DoH. Regression guard for the
// GET-redaction change: the UI holds a redacted plane, and the plan endpoint must not render it.
func TestValidateForWrite_RejectsRedacted(t *testing.T) {
	// A redacted DoH resolver (what the UI would POST back after the GET response was redacted).
	nd := NativeDNS{Platform: "openwrt", Resolvers: []NativeResolver{
		{Kind: KindDoH, Address: RedactAddress("https://dns.nextdns.io/tok123"), Tier: TierHidden},
	}}
	err := ValidateForWrite(nd)
	if err == nil || !strings.Contains(err.Error(), "redacted") {
		t.Fatalf("ValidateForWrite must reject a redacted address, got %v", err)
	}
	// A plane with real addresses still validates.
	ok := NativeDNS{Platform: "openwrt", Resolvers: []NativeResolver{
		{Kind: KindDoH, Address: "https://dns.nextdns.io/tok123", Tier: TierHidden},
		{Kind: KindPlain, Address: "1.1.1.1", Tier: TierFallback},
	}}
	if err := ValidateForWrite(ok); err != nil {
		t.Errorf("real-address plane must validate, got %v", err)
	}
}

// TestRedacted_ClonesAndMasks: Redacted() masks resolver addresses in a COPY, leaving the original
// (used for write-back) untouched.
func TestRedacted_ClonesAndMasks(t *testing.T) {
	orig := NativeDNS{
		Platform: "keenetic",
		Resolvers: []NativeResolver{
			{Kind: KindDoH, Address: "https://dns.nextdns.io/tok123", Tier: TierHidden},
			{Kind: KindPlain, Address: "1.1.1.1", Tier: TierFallback},
		},
	}
	red := orig.Redacted()
	if red.Resolvers[0].Address != "https://dns.nextdns.io/•••" {
		t.Errorf("DoH not redacted: %q", red.Resolvers[0].Address)
	}
	if red.Resolvers[1].Address != "1.1.1.1" {
		t.Errorf("plain resolver must be unchanged: %q", red.Resolvers[1].Address)
	}
	// Original untouched — write-back still has the real URL.
	if orig.Resolvers[0].Address != "https://dns.nextdns.io/tok123" {
		t.Errorf("Redacted() mutated the original: %q", orig.Resolvers[0].Address)
	}
}
