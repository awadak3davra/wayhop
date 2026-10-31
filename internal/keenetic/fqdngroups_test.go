package keenetic

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// fqdnConfig follows the shape of a live KeeneticOS `show running-config`: groups that mix names and
// prefixes, an escaped UTF-8 description, a dns-proxy block naming the interface for one group. The
// addresses are documentation ranges and the names example ones; only the shape is the router's.
const fqdnConfig = `system
    hostname Keenetic
!
dns-proxy
    rebind-protect auto
    route object-group domain-list8 PPPoE0 auto reject
!
object-group fqdn domain-list7
    description Telegram
    include example.org
    include 192.0.2.0/23
    include 198.51.100.0/22
    include 203.0.113.9
    include 203.0.113.77/24
    include WWW.Example.ORG.
    include example.org
!
object-group fqdn domain-list8
    description "\xd0\x9c\xd0\xb0\xd0\xba\xd1\x81\xd0\xb8\xd0\xbc\xd0\xba\xd0\xb0"
    include example.com
    exclude mail.example.com
    include "not a name"
    include *.example.net
    include .example.net
    include localhost
    include 198.51.100.300/24
    some-future-directive on
    include 2001:db8::/32
!
object-group fqdn domain-list9
    include example.net
interface Wireguard0
    description VPN
    include not-part-of-a-group.example
!
`

func TestParseFQDNGroups_ReadsTheGroupsTheRouterPrints(t *testing.T) {
	got := ParseFQDNGroups(fqdnConfig)
	if len(got) != 3 {
		t.Fatalf("want 3 groups, got %d: %+v", len(got), got)
	}

	tg := got[0]
	if tg.Name != "domain-list7" || tg.Description != "Telegram" || tg.Route != "" {
		t.Errorf("first group header misread: %+v", tg)
	}
	// Names and prefixes from one group land apart; a bare address is a /32, a prefix with host bits
	// is masked, a name is lowercased without its root dot, and a repeat is carried once.
	if want := []string{"example.org", "www.example.org"}; !reflect.DeepEqual(tg.Domains, want) {
		t.Errorf("domains = %v, want %v", tg.Domains, want)
	}
	if want := []string{"192.0.2.0/23", "198.51.100.0/22", "203.0.113.9/32", "203.0.113.0/24"}; !reflect.DeepEqual(tg.CIDRs, want) {
		t.Errorf("cidrs = %v, want %v", tg.CIDRs, want)
	}
	if len(tg.Skipped) != 0 || len(tg.Excludes) != 0 {
		t.Errorf("nothing was skipped or excluded in the first group: %+v", tg)
	}

	m := got[1]
	if m.Description != "Максимка" {
		t.Errorf("the escaped description decoded to %q, want %q", m.Description, "Максимка")
	}
	// The dns-proxy block came BEFORE the group; the route still reaches it.
	if m.Route != "PPPoE0" {
		t.Errorf("route = %q, want PPPoE0 from the dns-proxy block", m.Route)
	}
	if want := []string{"example.com"}; !reflect.DeepEqual(m.Domains, want) {
		t.Errorf("domains = %v, want %v (an exclude must not become an include)", m.Domains, want)
	}
	if want := []string{"mail.example.com"}; !reflect.DeepEqual(m.Excludes, want) {
		t.Errorf("excludes = %v, want %v", m.Excludes, want)
	}
	if want := []string{"2001:db8::/32"}; !reflect.DeepEqual(m.CIDRs, want) {
		t.Errorf("cidrs = %v, want %v", m.CIDRs, want)
	}
	// Each of these is neither a usable name nor an address; an unknown directive is reported with
	// them rather than dropped (the import promises nothing goes missing silently).
	if want := []string{"not a name", "*.example.net", ".example.net", "localhost", "198.51.100.300/24", "some-future-directive on"}; !reflect.DeepEqual(m.Skipped, want) {
		t.Errorf("skipped = %v, want %v", m.Skipped, want)
	}

	// A group with no "!" ends at the next top-level line: the interface's lines are not its entries.
	last := got[2]
	if last.Name != "domain-list9" || !reflect.DeepEqual(last.Domains, []string{"example.net"}) || last.Description != "" {
		t.Errorf("an unterminated group took lines from the next block: %+v", last)
	}
}

func TestParseFQDNGroups_CRLFAndNothingToRead(t *testing.T) {
	crlf := strings.ReplaceAll("object-group fqdn domain-list1\n    description \"Two words\"\n    include example.com\n!\n", "\n", "\r\n")
	got := ParseFQDNGroups(crlf)
	if len(got) != 1 || got[0].Description != "Two words" || !reflect.DeepEqual(got[0].Domains, []string{"example.com"}) {
		t.Errorf("CRLF output misread: %+v", got)
	}
	if got := ParseFQDNGroups(""); got != nil {
		t.Errorf("an empty config yields no groups, got %+v", got)
	}
}

// The interface fixture has descriptions and nested blocks of its own and no object-group: none of it
// may surface as a group.
func TestParseFQDNGroups_IgnoresInterfaces(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "running-config-wg.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got := ParseFQDNGroups(string(raw)); len(got) != 0 {
		t.Errorf("an interface-only config produced groups: %+v", got)
	}
}

func TestNDMUnquote(t *testing.T) {
	for in, want := range map[string]string{
		`Telegram`:                   "Telegram",
		`"Guest VLAN"`:               "Guest VLAN",
		`"\xd0\x9c\xd0\xb0"`:         "Ма",
		`"a\\b"`:                     `a\b`,
		`"say \"hi\""`:               `say "hi"`,
		`"\xZZ stays"`:               `\xZZ stays`,
		`"\x4"`:                      `\x4`,
		`"\q is kept"`:               `\q is kept`,
		`"trailing\"`:                `trailing\`,
		`"\xff\xfe broken"`:          "\uFFFD broken",
		`"`:                          `"`,
		`  "padded"  `:               "padded",
		`"\x41\x42C"`:                "ABC",
		`unquoted\xd0\x9c stays raw`: `unquoted\xd0\x9c stays raw`,
	} {
		if got := ndmUnquote(in); got != want {
			t.Errorf("ndmUnquote(%q) = %q, want %q", in, got, want)
		}
	}
}
