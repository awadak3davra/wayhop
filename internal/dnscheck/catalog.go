package dnscheck

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

const dnsClassCH = 3

type operatorCatalog struct {
	name          string
	identityName  string
	identityClass uint16
	sitePattern   *regexp.Regexp
	dotSNI        string
	dohURL        string
	ownRanges     []netip.Prefix
}

var resolverCatalog = map[string]*operatorCatalog{
	"1.1.1.1": {
		name:          "cloudflare",
		identityName:  "id.server",
		identityClass: dnsClassCH,
		sitePattern:   regexp.MustCompile(`^[a-z]{3}\d{1,3}$`),
		dotSNI:        "one.one.one.one",
		dohURL:        "https://1.1.1.1/dns-query",
		ownRanges:     cloudflareRanges(),
	},
	"1.0.0.1": {
		name:          "cloudflare",
		identityName:  "id.server",
		identityClass: dnsClassCH,
		sitePattern:   regexp.MustCompile(`^[a-z]{3}\d{1,3}$`),
		dotSNI:        "one.one.one.one",
		dohURL:        "https://1.0.0.1/dns-query",
		ownRanges:     cloudflareRanges(),
	},
	"8.8.8.8": {
		name:          "google",
		identityName:  "o-o.myaddr.l.google.com",
		identityClass: dnsClassIN,
		dotSNI:        "dns.google",
		dohURL:        "https://8.8.8.8/dns-query",
	},
	"8.8.4.4": {
		name:          "google",
		identityName:  "o-o.myaddr.l.google.com",
		identityClass: dnsClassIN,
		dotSNI:        "dns.google",
		dohURL:        "https://8.8.4.4/dns-query",
	},
	"9.9.9.9": {
		name:          "quad9",
		identityName:  "id.server",
		identityClass: dnsClassCH,
		sitePattern:   regexp.MustCompile(`^res\d+\.[a-z0-9.-]+$`),
		dotSNI:        "dns.quad9.net",
		dohURL:        "https://9.9.9.9/dns-query",
	},
	// Seen on a test router as "unknown operator": the second address OpenWrt's own lists carry for Quad9.
	"149.112.112.112": {
		name:          "quad9",
		identityName:  "id.server",
		identityClass: dnsClassCH,
		sitePattern:   regexp.MustCompile(`^res\d+\.[a-z0-9.-]+$`),
		dotSNI:        "dns.quad9.net",
		dohURL:        "https://149.112.112.112/dns-query",
	},
}

func catalogFor(address string) (*operatorCatalog, bool) {
	catalog, ok := resolverCatalog[addressHost(address)]
	return catalog, ok
}

func cloudflareRanges() []netip.Prefix {
	// These are the published ranges listed in the measurement contract, not a guessed operator list.
	cidrs := []string{
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
		"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
		"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
		"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
		"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
	}
	ranges := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		ranges = append(ranges, netip.MustParsePrefix(cidr))
	}
	return ranges
}

func parseGoogleLocations(reply DNSReply) ([]netip.Prefix, error) {
	var joined strings.Builder
	for _, answer := range reply.Answers {
		if answer.Type == dnsTypeTXT {
			for _, text := range answer.TXT {
				joined.WriteString(text)
			}
		}
	}
	fields := strings.Fields(joined.String())
	if len(fields) == 0 || len(fields)%2 != 0 {
		return nil, fmt.Errorf("the list of Google locations has %d fields", len(fields))
	}
	ranges := make([]netip.Prefix, 0, len(fields)/2)
	for i := 0; i < len(fields); i += 2 {
		prefix, err := netip.ParsePrefix(fields[i])
		if err != nil {
			return nil, fmt.Errorf("a Google location prefix %q: %w", fields[i], err)
		}
		ranges = append(ranges, prefix)
	}
	return ranges, nil
}

func addressInRanges(address string, ranges []netip.Prefix) bool {
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, prefix := range ranges {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
