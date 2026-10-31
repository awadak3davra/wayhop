package cidrfeed

import (
	"net/netip"
	"reflect"
	"testing"
)

// QA-111. An entry covering the whole address space, or a large share of it, is one no list may
// carry: the default route in any spelling, two /1 halves, anything shorter than an IPv4 /4 or an
// IPv6 /8. A /4 and a /8 themselves stay, as do a feed's ordinary networks, and both halves keep the
// feed's order.
func TestScreenRefusesPrefixesTooBroadForAList(t *testing.T) {
	feed := "0.0.0.0/0\n" +
		"203.0.113.4/0 label\n" + // a typo'd mask on an ordinary address
		"::/0\n" +
		"::ffff:0.0.0.0/96\n" + // the IPv4 default route, written as IPv6
		"::ffff:192.0.2.0/99\n" + // a v4-mapped /3
		"0.0.0.0/1\n203.0.113.4/1\n" + // the two halves, the upper one written from an ordinary address
		"192.0.2.1/3\n" +
		"2001:db8::/7\n" +
		"192.0.2.1/4\n" + // the shortest IPv4 prefix a list may carry
		"2001:db8::/8\n" + // and IPv6
		"::ffff:198.51.100.0/120\n" + // a v4-mapped /24 stays (pbr files it as IPv4)
		"203.0.113.0/24\n"
	cidrs, skipped := ParseList(feed)
	if skipped != 0 {
		t.Fatalf("ParseList skipped %d well-formed lines; breadth is the screen's question", skipped)
	}
	upper, _ := NormalizeCIDR("203.0.113.4/1")
	kept, refused := Screen(cidrs)
	wantKept := []string{"192.0.0.0/4", "2000::/8", "::ffff:198.51.100.0/120", "203.0.113.0/24"}
	wantRefused := []string{"0.0.0.0/0", "::/0", "::ffff:0.0.0.0/96", "::ffff:192.0.0.0/99", "0.0.0.0/1",
		upper, "192.0.0.0/3", "2000::/7"}
	if !reflect.DeepEqual(kept, wantKept) || !reflect.DeepEqual(refused, wantRefused) {
		t.Fatalf("Screen = kept %v, refused %v; want kept %v, refused %v", kept, refused, wantKept, wantRefused)
	}

	// A RIPEstat answer goes through the same screen.
	body := []byte(`{"data":{"prefixes":[{"prefix":"0.0.0.0/0"},{"prefix":"::/0"},{"prefix":"192.0.2.0/3"},` +
		`{"prefix":"203.0.113.0/24"},{"prefix":"2001:db8::/32"}]}}`)
	cidrs, _, err := ParseRIPEstat(body)
	if err != nil {
		t.Fatal(err)
	}
	kept, refused = Screen(cidrs)
	if want := []string{"203.0.113.0/24", "2001:db8::/32"}; !reflect.DeepEqual(kept, want) || len(refused) != 3 {
		t.Fatalf("Screen(RIPEstat) = kept %v, refused %v; want kept %v and 3 refused", kept, refused, want)
	}

	// Nothing to refuse: the entries come back as they were, and nothing is named.
	if kept, refused := Screen([]string{"198.51.100.0/24", "2001:db8::/48"}); len(kept) != 2 || refused != nil {
		t.Fatalf("Screen(ordinary) = kept %v, refused %v", kept, refused)
	}
}

// A country list is networks of one purpose however short its prefixes. ipdeny's
// us-aggregated.zone merges whole blocks into six aggregates of /6 and /7, some 268M addresses with a
// single company's /8 inside one of them, and an IPv6 list for a region carries registry blocks as
// short as /12. The screen first refused them all, and a "US networks" list lost them. They are
// spelled here from documentation addresses at the lengths those feeds carry; the default route, a
// /1 half and ::/0 beside them are still refused.
func TestScreenKeepsCountryAggregates(t *testing.T) {
	var aggregates []string
	for _, s := range []string{"192.0.2.0/7", "198.51.100.0/6", "203.0.113.0/7", "192.0.2.0/6",
		"198.51.100.0/7", "203.0.113.0/6", "2001:db8::/12", "2001:db8::/29"} {
		n, ok := NormalizeCIDR(s)
		if !ok {
			t.Fatalf("NormalizeCIDR(%s) failed", s)
		}
		aggregates = append(aggregates, n)
	}
	kept, refused := Screen(append([]string{"0.0.0.0/0", "0.0.0.0/1", "::/0"}, aggregates...))
	if want := []string{"0.0.0.0/0", "0.0.0.0/1", "::/0"}; !reflect.DeepEqual(kept, aggregates) || !reflect.DeepEqual(refused, want) {
		t.Fatalf("Screen = kept %v, refused %v; want kept %v, refused %v", kept, refused, aggregates, want)
	}
}

// The importer's screen and the feed's are one rule, judged in the family the kernel files a prefix
// under.
func TestTooBroadJudgesV4MappedAsIPv4(t *testing.T) {
	for in, want := range map[string]bool{
		"::ffff:0.0.0.0/96": true, "::ffff:192.0.0.0/99": true, "::ffff:192.0.0.0/100": false,
		"::ffff:10.0.0.0/104": false, "0.0.0.0/0": true, "0.0.0.0/3": true, "0.0.0.0/4": false,
		"::/0": true, "2000::/3": true, "2000::/7": true, "2000::/8": false, "2001:db8::/16": false,
	} {
		if got := TooBroad(netip.MustParsePrefix(in)); got != want {
			t.Errorf("TooBroad(%s) = %v, want %v", in, got, want)
		}
	}
}
