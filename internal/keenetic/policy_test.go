package keenetic

import (
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// showIPPolicyLive is `ndmc -c "show ip policy"` as a live Keenetic printed it (route listings cut to
// one entry each, addresses documentation-range): the terminal's erase-line escape around it, the
// header ending in ':', the bare-hex mark, and a route listing whose keys must not be read as the
// policy's own.
const showIPPolicyLive = "\x1b[K\n" +
	"           policy, name = Policy0, description = Bypass: \n" +
	"                 mark: ffffaaa\n" +
	"               table4: 4096\n" +
	"\n" +
	"               route4: \n" +
	"                    route: \n" +
	"                  destination: 0.0.0.0/0\n" +
	"                      gateway: 192.0.2.1\n" +
	"                    interface: ISP\n" +
	"                       metric: 1000\n" +
	"                        flags: U\n" +
	"                    rejecting: no\n" +
	"\n" +
	"               table6: 4096\n" +
	"\n" +
	"           policy, name = Policy1, description = VPN: \n" +
	"                 mark: ffffaab\n" +
	"               table4: 4098\n" +
	"\n" +
	"               route4: \n" +
	"                    route: \n" +
	"                  destination: 198.51.100.0/24\n" +
	"                    interface: Wireguard6\n" +
	"               table6: 4098\n" +
	"\x1b[K\n"

func TestParsePoliciesLiveShape(t *testing.T) {
	got := ParsePolicies(showIPPolicyLive)
	want := []Policy{
		{Name: "Policy0", Description: "Bypass", Mark: 0x0ffffaaa, Table: 4096},
		{Name: "Policy1", Description: "VPN", Mark: 0x0ffffaab, Table: 4098},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("policies = %#v\nwant %#v", got, want)
	}
	if marks := PolicyMarks(got); marks["Policy1"] != 0x0ffffaab || len(marks) != 2 {
		t.Fatalf("marks = %#v", marks)
	}
}

func TestParsePoliciesRefusesWhatCannotBeRoutedBy(t *testing.T) {
	out := strings.Join([]string{
		"policy, name = NoDesc:", // no description: still a policy
		"  mark: 1a",
		"policy, name = Zero, description = zero mark:", // a zero mark would clear marks, not set one
		"  mark: 0",
		"policy, name = NoMark, description = never marked:",
		"  table4: 5000",
		"policy, name = Bad Name, description = spaces:", // cannot be addressed as ndm-policy:<name>
		"  mark: 1b",
		"policy, name = Garbled, description = bad hex:",
		"  mark: zz",
		"policy, name = NoDesc, description = duplicate:", // the first occurrence wins
		"  mark: 1c",
		"policy, name = Nested, description = only its own mark counts:",
		"  mark: 1d",
		"    route: ",
		"      mark: 99",
		"      table4: 7",
	}, "\n")
	got := ParsePolicies(out)
	want := []Policy{
		{Name: "NoDesc", Mark: 0x1a},
		{Name: "Nested", Description: "only its own mark counts", Mark: 0x1d},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("policies = %#v\nwant %#v", got, want)
	}
	if ParsePolicies("") != nil || PolicyMarks(nil) != nil {
		t.Fatal("an empty listing must yield no policies")
	}
}

// A list sent to a policy is carried by the ipset plane when it is wired; without it NDM has no static
// route that sets a mark, so the compatibility core must take the policy - and Compile must never
// reach a static route for it.
func TestCompileRoutesPolicyListsOnlyThroughAMarkingPlane(t *testing.T) {
	p := &model.Profile{RoutingLists: []model.RoutingList{{
		ID: "rl", Name: "rl", Enabled: true, Outbound: "ndm-policy:Policy1", Manual: []string{"198.51.100.0/24"},
	}}}
	reasons := compatibilityReasons(p, RoutePlanes{})
	if len(reasons) != 1 || !strings.Contains(reasons[0], `access policy "Policy1"`) {
		t.Fatalf("reasons without the ipset plane = %q", reasons)
	}
	if got := compatibilityReasons(p, RoutePlanes{ListsViaIpset: true}); len(got) != 0 {
		t.Fatalf("the ipset plane carries the list, yet: %q", got)
	}
	plan, err := Compile(p, CompileOptions{ListsViaIpset: true, OccupiedInterfaces: map[string]bool{}})
	if err != nil {
		t.Fatalf("compile with the ipset plane: %v", err)
	}
	if plan.CompatibilityRouting || len(plan.Routes) != 0 {
		t.Fatalf("a policy list became NDM routes: compat=%v routes=%q", plan.CompatibilityRouting, plan.Routes)
	}
	plan, err = Compile(p, CompileOptions{OccupiedInterfaces: map[string]bool{}})
	if err != nil || !plan.CompatibilityRouting || len(plan.Routes) != 0 {
		t.Fatalf("without the ipset plane the core must take the policy: compat=%v routes=%q err=%v",
			plan != nil && plan.CompatibilityRouting, plan.Routes, err)
	}
}
