package pbr

import (
	"reflect"
	"strings"
	"testing"
)

// All test data is synthetic (example.com / RFC 2606 reserved domains).

func TestRenderDnsmasqSets_Nftset(t *testing.T) {
	sets := []DomainSet{
		{SetBase: "list_block", Domains: []string{"example.com", "sub.example.com"}},
	}
	got := RenderDnsmasqSets(sets, DnsmasqOptions{Table: "velinx_pbr"})
	want := dnsmasqHeader + "\n" +
		"nftset=/example.com/sub.example.com/inet#velinx_pbr#list_block_4,inet#velinx_pbr#list_block_6\n"
	if got != want {
		t.Fatalf("nftset render mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestRenderDnsmasqSets_Ipset_Legacy(t *testing.T) {
	sets := []DomainSet{
		{SetBase: "list_block", Domains: []string{"example.com"}},
	}
	got := RenderDnsmasqSets(sets, DnsmasqOptions{Legacy: true})
	want := dnsmasqHeader + "\n" +
		"ipset=/example.com/list_block_4,list_block_6\n"
	if got != want {
		t.Fatalf("ipset render mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestRenderDnsmasqSets_NoV6(t *testing.T) {
	sets := []DomainSet{
		{SetBase: "z", Domains: []string{"example.org"}},
	}
	// nftset, v4-only
	got := RenderDnsmasqSets(sets, DnsmasqOptions{Table: "tbl", NoV6: true})
	want := dnsmasqHeader + "\nnftset=/example.org/inet#tbl#z_4\n"
	if got != want {
		t.Fatalf("nftset NoV6 mismatch:\n got: %q\nwant: %q", got, want)
	}
	// ipset, v4-only
	gotI := RenderDnsmasqSets(sets, DnsmasqOptions{Legacy: true, NoV6: true})
	wantI := dnsmasqHeader + "\nipset=/example.org/z_4\n"
	if gotI != wantI {
		t.Fatalf("ipset NoV6 mismatch:\n got: %q\nwant: %q", gotI, wantI)
	}
}

func TestRenderDnsmasqSets_DefaultTable(t *testing.T) {
	// Empty Table → defaults to velinx_pbr for the nftset form.
	sets := []DomainSet{{SetBase: "z", Domains: []string{"example.net"}}}
	got := RenderDnsmasqSets(sets, DnsmasqOptions{})
	if !strings.Contains(got, "inet#velinx_pbr#z_4") {
		t.Fatalf("expected default table velinx_pbr, got: %q", got)
	}
}

func TestRenderDnsmasqSets_Empty(t *testing.T) {
	cases := [][]DomainSet{
		nil,
		{},
		{{SetBase: "z", Domains: nil}}, // no domains
		{{SetBase: "z", Domains: []string{"  ", "#comment"}}}, // all noise → normalized away
		{{SetBase: "", Domains: []string{"example.com"}}},     // no set name
	}
	for i, c := range cases {
		if got := RenderDnsmasqSets(c, DnsmasqOptions{Table: "t"}); got != "" {
			t.Fatalf("case %d: expected empty snippet, got %q", i, got)
		}
	}
}

func TestRenderDnsmasqSets_NormalizeAndDedupe(t *testing.T) {
	sets := []DomainSet{
		{SetBase: "z", Domains: []string{
			"Example.COM",         // uppercase → lowercased
			"*.example.com",       // wildcard prefix stripped → example.com (dup)
			".example.com",        // leading dot stripped → example.com (dup)
			"  sub.example.com  ", // trimmed
			"example.com",         // exact dup
			"notadomain",          // no dot → dropped
			"bad domain.com",      // space → dropped
		}},
	}
	got := RenderDnsmasqSets(sets, DnsmasqOptions{Table: "t"})
	// normalizeDomains sorts: example.com, sub.example.com
	want := dnsmasqHeader + "\nnftset=/example.com/sub.example.com/inet#t#z_4,inet#t#z_6\n"
	if got != want {
		t.Fatalf("normalize/dedupe mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestRenderDnsmasqSets_MultipleSetsSorted(t *testing.T) {
	// Provided out of order; output must be sorted by SetBase.
	sets := []DomainSet{
		{SetBase: "list_zzz", Domains: []string{"z.example"}},
		{SetBase: "list_aaa", Domains: []string{"a.example"}},
	}
	got := RenderDnsmasqSets(sets, DnsmasqOptions{Table: "t"})
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected header + 2 lines, got %d: %q", len(lines), got)
	}
	if !strings.Contains(lines[1], "#list_aaa_4") || !strings.Contains(lines[2], "#list_zzz_4") {
		t.Fatalf("sets not sorted by SetBase:\n%q", got)
	}
}

func TestRenderDnsmasqSets_SkipsEmptyAmongNonEmpty(t *testing.T) {
	sets := []DomainSet{
		{SetBase: "good", Domains: []string{"example.com"}},
		{SetBase: "empty", Domains: []string{"#comment-only"}},
	}
	got := RenderDnsmasqSets(sets, DnsmasqOptions{Table: "t"})
	if strings.Contains(got, "empty") {
		t.Fatalf("empty set should be skipped, got: %q", got)
	}
	if !strings.Contains(got, "#good_4") {
		t.Fatalf("good set missing, got: %q", got)
	}
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 2 { // header + 1
		t.Fatalf("expected header + 1 line, got %d: %q", len(lines), got)
	}
}

func TestPlanDomainSets(t *testing.T) {
	pl := &Plan{
		Zones: []Zone{
			{Name: "zb", Domains: []string{"b.example"}},
			{Name: "za", Domains: []string{"a.example"}},
			{Name: "noDomains", V4: []string{"203.0.113.0/24"}}, // CIDR-only → skipped
		},
	}
	got := pl.PlanDomainSets()
	want := []DomainSet{
		{SetBase: "za", Domains: []string{"a.example"}},
		{SetBase: "zb", Domains: []string{"b.example"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PlanDomainSets mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestPlanRenderDnsmasq(t *testing.T) {
	pl := &Plan{
		Table: "mytbl",
		Zones: []Zone{
			{Name: "list_x", Domains: []string{"example.com"}},
			{Name: "cidrzone", V4: []string{"198.51.100.0/24"}},
		},
	}
	got := pl.RenderDnsmasq(DnsmasqOptions{Table: pl.Table})
	want := dnsmasqHeader + "\nnftset=/example.com/inet#mytbl#list_x_4,inet#mytbl#list_x_6\n"
	if got != want {
		t.Fatalf("plan render mismatch:\n got: %q\nwant: %q", got, want)
	}
}

func TestPlanRenderDnsmasq_NoDomains(t *testing.T) {
	pl := &Plan{Zones: []Zone{{Name: "cidr", V4: []string{"203.0.113.0/24"}}}}
	if got := pl.RenderDnsmasq(DnsmasqOptions{}); got != "" {
		t.Fatalf("expected empty snippet for CIDR-only plan, got %q", got)
	}
}

func TestDnsmasqSetNames(t *testing.T) {
	pl := &Plan{
		Zones: []Zone{
			{Name: "zb", Domains: []string{"b.example"}},
			{Name: "za", Domains: []string{"a.example"}},
			{Name: "cidr", V4: []string{"203.0.113.0/24"}}, // no domains → no set names
		},
	}
	got := pl.DnsmasqSetNames(DnsmasqOptions{})
	want := []string{"za_4", "za_6", "zb_4", "zb_6"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("set names mismatch:\n got: %v\nwant: %v", got, want)
	}

	gotV4 := pl.DnsmasqSetNames(DnsmasqOptions{NoV6: true})
	wantV4 := []string{"za_4", "zb_4"}
	if !reflect.DeepEqual(gotV4, wantV4) {
		t.Fatalf("v4-only set names mismatch:\n got: %v\nwant: %v", gotV4, wantV4)
	}
}

func TestDnsmasqSetNames_SkipsNoiseDomains(t *testing.T) {
	pl := &Plan{Zones: []Zone{{Name: "z", Domains: []string{"#only-a-comment"}}}}
	if got := pl.DnsmasqSetNames(DnsmasqOptions{}); len(got) != 0 {
		t.Fatalf("expected no set names for noise-only zone, got %v", got)
	}
}

// Integration with Compile: CollectDomainZones surfaces a list's domain entries into
// Zone.Domains, which RenderDnsmasq then turns into a directive — proving the dnsmasq
// renderer aligns with the compiler's domain-zone output end to end.
func TestRenderDnsmasq_FromCompiledPlan(t *testing.T) {
	// Build via the public renderer path against a synthetic plan that mirrors what
	// Compile(..., Options{CollectDomainZones:true}) produces for a domain list.
	pl := &Plan{
		Table: "velinx_pbr",
		Zones: []Zone{
			{Name: "list_censored", EgressTag: "ep1", Domains: []string{"example.com", "test.example"}},
		},
	}
	snippet := pl.RenderDnsmasq(DnsmasqOptions{Table: pl.Table})
	if !strings.HasPrefix(snippet, dnsmasqHeader) {
		t.Fatalf("snippet missing header: %q", snippet)
	}
	if !strings.Contains(snippet, "nftset=/example.com/test.example/inet#velinx_pbr#list_censored_4") {
		t.Fatalf("snippet missing expected directive: %q", snippet)
	}
}
