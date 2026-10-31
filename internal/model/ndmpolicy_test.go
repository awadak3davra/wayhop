package model

import (
	"reflect"
	"strings"
	"testing"
)

func ndmPolicyProfile(outbound string) Profile {
	return Profile{RoutingLists: []RoutingList{{
		ID: "rl", Name: "rl", Enabled: true, Outbound: outbound, Manual: []string{"198.51.100.0/24"},
	}}}
}

// The syntax is valid without a host: whether the router has the policy is the review's question.
func TestValidateAcceptsAnAccessPolicyOnARoutingList(t *testing.T) {
	for _, outbound := range []string{"ndm-policy:Policy1", "ndm-policy:my_policy-2"} {
		p := ndmPolicyProfile(outbound)
		if err := p.Validate(); err != nil {
			t.Fatalf("%s refused: %v", outbound, err)
		}
	}
}

func TestValidateRefusesAMalformedAccessPolicy(t *testing.T) {
	for _, outbound := range []string{"ndm-policy:", "ndm-policy:Policy 1", "ndm-policy:a;b", "ndm-policy:" + strings.Repeat("p", 65)} {
		p := ndmPolicyProfile(outbound)
		err := p.Validate()
		if err == nil || !strings.Contains(err.Error(), "access policy name") {
			t.Fatalf("%q: err = %v", outbound, err)
		}
	}
}

// Rules and a list's download detour do not get a policy in this slice, and say so rather than
// reporting a reference that "does not resolve".
func TestValidateRefusesAnAccessPolicyOutsideAListsOutbound(t *testing.T) {
	rule := Profile{Rules: []Rule{{ID: "r", Outbound: "ndm-policy:Policy1", IPCIDR: []string{"198.51.100.0/24"}}}}
	if err := rule.Validate(); err == nil || !strings.Contains(err.Error(), "only a routing list can use") {
		t.Fatalf("rule err = %v", err)
	}
	// A switched-off rule is inert, like any other disabled rule.
	rule.Rules[0].Disabled = true
	if err := rule.Validate(); err != nil {
		t.Fatalf("disabled rule refused: %v", err)
	}

	detour := ndmPolicyProfile("direct")
	detour.RoutingLists[0].Source = "https://example.com/list.srs"
	detour.RoutingLists[0].DownloadVia = "ndm-policy:Policy1"
	if err := detour.Validate(); err == nil || !strings.Contains(err.Error(), "download_via") {
		t.Fatalf("download_via err = %v", err)
	}
}

func TestNDMPoliciesInUse(t *testing.T) {
	p := Profile{RoutingLists: []RoutingList{
		{ID: "a", Enabled: true, Outbound: "ndm-policy:Policy1"},
		{ID: "b", Enabled: true, Outbound: "ndm-policy:Policy0"},
		{ID: "c", Enabled: true, Outbound: "ndm-policy:Policy1"},
		{ID: "d", Enabled: false, Outbound: "ndm-policy:Policy9"},
		{ID: "e", Enabled: true, Outbound: "direct"},
	}}
	if got := NDMPoliciesInUse(&p); !reflect.DeepEqual(got, []string{"Policy0", "Policy1"}) {
		t.Fatalf("in use = %q", got)
	}
	if got := NDMPoliciesInUse(&Profile{}); got != nil {
		t.Fatalf("no list, yet %q", got)
	}
	if name, ok := NDMPolicyName("ndm-policy:Policy1"); !ok || name != "Policy1" {
		t.Fatalf("NDMPolicyName = %q %v", name, ok)
	}
	if _, ok := NDMPolicyName("Policy1"); ok {
		t.Fatal("a bare name is not a policy outbound")
	}
}
