package importer

import (
	"reflect"
	"testing"
)

// domainConf follows HydraRoute Neo's README examples: "##" descriptions, a policy and an interface
// target, geosite entries alone and mixed with names, plus the mistakes the README warns about.
const domainConf = `# managed by HRweb
## Video
youtube.com,googlevideo.com,YouTu.be./HydraRoute

## Chat
openai.com, chatgpt.com ,.example.net,geosite:openai/nwg0
## Mixed
geosite:google,example.com,youtube.com/HydraRoute

## detached by the blank line below

geosite:google,geosite:netflix/HydraRoute
#example.org/nwg0
## Bad names
bad name,*.example.com,192.0.2.1,example.org/nwg0
no-target-here
192.0.2.0/24
/HydraRoute
example.com/
`

func TestParseHydraRoute_DomainConf(t *testing.T) {
	got := ParseHydraRoute(domainConf)
	if got.Format != HydraFormatDomains {
		t.Fatalf("format = %q, want %q", got.Format, HydraFormatDomains)
	}
	if len(got.Targets) != 2 {
		t.Fatalf("want 2 targets (rules grouped by target), got %+v", got.Targets)
	}

	hr := got.Targets[0]
	if hr.Target != "HydraRoute" {
		t.Fatalf("first target = %q", hr.Target)
	}
	// Names are lowercased without a root dot, merged across the target's rules, carried once.
	if want := []string{"youtube.com", "googlevideo.com", "youtu.be", "example.com"}; !reflect.DeepEqual(hr.Domains, want) {
		t.Errorf("HydraRoute domains = %v, want %v", hr.Domains, want)
	}
	// Only "##" lines directly above a rule describe it; the one cut off by a blank line does not.
	if want := []string{"Video", "Mixed"}; !reflect.DeepEqual(hr.Descriptions, want) {
		t.Errorf("HydraRoute descriptions = %v, want %v", hr.Descriptions, want)
	}
	if want := []HydraSkip{
		{Line: 8, Entry: "geosite:google", Reason: HydraSkipGeosite},
		{Line: 12, Entry: "geosite:google", Reason: HydraSkipGeosite},
		{Line: 12, Entry: "geosite:netflix", Reason: HydraSkipGeosite},
	}; !reflect.DeepEqual(hr.Skipped, want) {
		t.Errorf("HydraRoute skipped = %+v, want %+v", hr.Skipped, want)
	}
	if len(hr.CIDRs) != 0 {
		t.Errorf("domain.conf carries no prefixes, got %v", hr.CIDRs)
	}

	nwg := got.Targets[1]
	if nwg.Target != "nwg0" {
		t.Fatalf("second target = %q", nwg.Target)
	}
	if want := []string{"openai.com", "chatgpt.com", "example.org"}; !reflect.DeepEqual(nwg.Domains, want) {
		t.Errorf("nwg0 domains = %v, want %v (a commented-out rule is not a rule)", nwg.Domains, want)
	}
	if want := []string{"Chat", "Bad names"}; !reflect.DeepEqual(nwg.Descriptions, want) {
		t.Errorf("nwg0 descriptions = %v, want %v", nwg.Descriptions, want)
	}
	if want := []HydraSkip{
		{Line: 6, Entry: ".example.net", Reason: HydraSkipLeadingDot},
		{Line: 6, Entry: "geosite:openai", Reason: HydraSkipGeosite},
		{Line: 15, Entry: "bad name", Reason: HydraSkipInvalid},
		{Line: 15, Entry: "*.example.com", Reason: HydraSkipInvalid},
		{Line: 15, Entry: "192.0.2.1", Reason: HydraSkipInvalid},
	}; !reflect.DeepEqual(nwg.Skipped, want) {
		t.Errorf("nwg0 skipped = %+v, want %+v", nwg.Skipped, want)
	}

	// Lines that are no rule at all belong to no target, and are still reported.
	if want := []HydraSkip{
		{Line: 16, Entry: "no-target-here", Reason: HydraSkipInvalid},
		{Line: 17, Entry: "192.0.2.0/24", Reason: HydraSkipInvalid},
		{Line: 18, Entry: "/HydraRoute", Reason: HydraSkipInvalid},
		{Line: 19, Entry: "example.com/", Reason: HydraSkipInvalid},
	}; !reflect.DeepEqual(got.Skipped, want) {
		t.Errorf("orphan lines = %+v, want %+v", got.Skipped, want)
	}
}

// ipList follows the README's ip.list examples: blocks per target, a "##" description, a disabled
// block, a geoip directive, and a blank line closing a block.
const ipList = "\uFEFF##Google CDN\r\n" + `/HydraRoute
192.0.2.0/24
198.51.100.7
2001:db8::/32
geoip:ru
not-a-prefix

##YouTube (off for now)
#/HydraRoute
203.0.113.0/26

192.0.2.128/25
/nwg1
198.51.100.0/24
# a note
198.51.100.0/24
`

func TestParseHydraRoute_IPList(t *testing.T) {
	got := ParseHydraRoute(ipList)
	if got.Format != HydraFormatIPs {
		t.Fatalf("format = %q, want %q", got.Format, HydraFormatIPs)
	}
	if len(got.Targets) != 2 {
		t.Fatalf("want 2 targets, got %+v", got.Targets)
	}
	hr := got.Targets[0]
	if want := []string{"192.0.2.0/24", "198.51.100.7/32", "2001:db8::/32"}; hr.Target != "HydraRoute" || !reflect.DeepEqual(hr.CIDRs, want) {
		t.Errorf("HydraRoute = %+v, want cidrs %v", hr, want)
	}
	// A disabled block's description does not rename the list it would have joined.
	if want := []string{"Google CDN"}; !reflect.DeepEqual(hr.Descriptions, want) {
		t.Errorf("descriptions = %v, want %v", hr.Descriptions, want)
	}
	if want := []HydraSkip{
		{Line: 6, Entry: "geoip:ru", Reason: HydraSkipGeoIP},
		{Line: 7, Entry: "not-a-prefix", Reason: HydraSkipInvalid},
		{Line: 11, Entry: "203.0.113.0/26", Reason: HydraSkipDisabled},
	}; !reflect.DeepEqual(hr.Skipped, want) {
		t.Errorf("HydraRoute skipped = %+v, want %+v", hr.Skipped, want)
	}
	nwg := got.Targets[1]
	if want := []string{"198.51.100.0/24"}; nwg.Target != "nwg1" || !reflect.DeepEqual(nwg.CIDRs, want) || len(nwg.Domains) != 0 {
		t.Errorf("nwg1 = %+v, want cidrs %v", nwg, want)
	}
	// After the blank line the block is closed: a prefix there belongs to nothing.
	if want := []HydraSkip{{Line: 13, Entry: "192.0.2.128/25", Reason: HydraSkipInvalid}}; !reflect.DeepEqual(got.Skipped, want) {
		t.Errorf("orphan lines = %+v, want %+v", got.Skipped, want)
	}
}

func TestParseHydraRoute_FormatDetection(t *testing.T) {
	for text, want := range map[string]string{
		"":                                      HydraFormatDomains,
		"## only a comment\n# another\n":        HydraFormatDomains,
		"example.com/HydraRoute\n":              HydraFormatDomains,
		"## d\n/HydraRoute\n192.0.2.0/24":       HydraFormatIPs,
		"#/HydraRoute\n192.0.2.0/24\n":          HydraFormatIPs,
		"192.0.2.0/24\n/HydraRoute\n":           HydraFormatIPs,
		"##/not-a-header\n" + "example.com/x\n": HydraFormatDomains,
		// Degenerate lines are reported, never a panic.
		"/":          HydraFormatIPs,
		"#/\n\n/":    HydraFormatIPs,
		"##":         HydraFormatDomains,
		"/\n,,,/x\n": HydraFormatIPs,
		",/":         HydraFormatDomains,
	} {
		if got := ParseHydraRoute(text).Format; got != want {
			t.Errorf("format of %q = %q, want %q", text, got, want)
		}
	}
}
