package server

import (
	"reflect"
	"testing"
)

// The real shape, taken from a live router: the firmware keeps a dozen sets of its own
// (_NDM_*), and WayHop's are the wr_list_* ones. Counting the router's would report someone else's
// memory as the price of a routing list.
const ipsetTerseFixture = `Name: _NDM_BFD_Telnet4
Type: hash:ip
Revision: 0
Header: family inet hashsize 1024 maxelem 1024
Size in memory: 96
References: 2

Name: wr_list_cidr_antifilter_4
Type: hash:net
Revision: 6
Header: family inet hashsize 1024 maxelem 65536
Size in memory: 460832
References: 1

Name: wr_list_cidr_antifilter_6
Type: hash:net
Revision: 6
Header: family inet6 hashsize 1024 maxelem 65536
Size in memory: 1280
References: 1

Name: wr_list_cidr_telegram_4
Type: hash:net
Revision: 6
Header: family inet hashsize 1024 maxelem 65536
Size in memory: 800
References: 1

Name: _NDM_BFD_Http4
Type: hash:ip
Revision: 0
Header: family inet hashsize 1024 maxelem 1024
Size in memory: 96
References: 4
`

func TestParseIpsetSizesCountsOnlyOurSets(t *testing.T) {
	want := map[string]string{
		"wr_list_cidr_antifilter_4": "cidr-antifilter",
		"wr_list_cidr_antifilter_6": "cidr-antifilter",
		"wr_list_cidr_telegram_4":   "cidr-telegram",
	}
	got := parseIpsetSizes(ipsetTerseFixture, want)
	if len(got) != 3 {
		t.Fatalf("parsed %d sets, want 3: %+v", len(got), got)
	}
	total := map[string]int64{}
	for _, s := range got {
		total[s.id] += s.bytes
	}
	// Both families of one list add up; the firmware's sets are not in the answer at all.
	if total["cidr-antifilter"] != 460832+1280 {
		t.Fatalf("antifilter = %d, want %d", total["cidr-antifilter"], 460832+1280)
	}
	if total["cidr-telegram"] != 800 {
		t.Fatalf("telegram = %d, want 800", total["cidr-telegram"])
	}
	if _, leaked := total["_NDM_BFD_Telnet4"]; leaked {
		t.Fatal("a firmware set was counted as a routing list")
	}
}

// A set that exists but is not ours, a header with no size, and a size with no name must all be
// ignored rather than guessed at: this number is shown as a cost the operator is paying.
func TestParseIpsetSizesIgnoresMalformedInput(t *testing.T) {
	want := map[string]string{"wr_list_x_4": "x"}
	for _, text := range []string{
		"Size in memory: 1234\n",                            // a size belonging to no name
		"Name: wr_list_x_4\nType: hash:net\n",               // a name with no size
		"Name: wr_list_x_4\nSize in memory: not-a-number\n", // unparsable
		"",
	} {
		if got := parseIpsetSizes(text, want); len(got) != 0 {
			t.Fatalf("parseIpsetSizes(%q) = %+v, want none", text, got)
		}
	}
	// One size per set: a second "Size in memory" line without a new Name must not double-count.
	twice := "Name: wr_list_x_4\nSize in memory: 100\nSize in memory: 100\n"
	got := parseIpsetSizes(twice, want)
	if len(got) != 1 || got[0].bytes != 100 {
		t.Fatalf("parseIpsetSizes double-counted: %+v", got)
	}
}

func TestParseIpsetSizesKeepsSetNames(t *testing.T) {
	want := map[string]string{"wr_list_cidr_telegram_4": "cidr-telegram"}
	got := parseIpsetSizes(ipsetTerseFixture, want)
	if len(got) != 1 || !reflect.DeepEqual([]string{got[0].set}, []string{"wr_list_cidr_telegram_4"}) {
		t.Fatalf("set name lost: %+v", got)
	}
}
