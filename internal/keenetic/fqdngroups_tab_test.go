package keenetic

import (
	"reflect"
	"testing"
)

// A tab after the directive (a hand-edited or pasted config) is read like NDM's space, and a
// directive this reader does not know is reported instead of vanishing.
func TestParseFQDNGroups_TabsAndUnknownDirectives(t *testing.T) {
	g := ParseFQDNGroups("object-group fqdn domain-list1\n\tdescription\tVideo\n\tinclude\ttab.example\n    frobnicate on\n!\n")
	if len(g) != 1 {
		t.Fatalf("groups = %+v", g)
	}
	if g[0].Description != "Video" || !reflect.DeepEqual(g[0].Domains, []string{"tab.example"}) {
		t.Errorf("group = %+v, want description Video and tab.example", g[0])
	}
	if !reflect.DeepEqual(g[0].Skipped, []string{"frobnicate on"}) {
		t.Errorf("skipped = %q, want the unknown directive", g[0].Skipped)
	}
}
