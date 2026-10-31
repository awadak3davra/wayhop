package generator

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// ndmPolicyGenProfile sends one list to the router's access policy Policy1 and one direct, the shape
// the compatibility TUN on KeeneticOS generates.
func ndmPolicyGenProfile() *model.Profile {
	return &model.Profile{RoutingLists: []model.RoutingList{
		{ID: "via-policy", Name: "via-policy", Enabled: true, Outbound: "ndm-policy:Policy1",
			Manual: []string{"198.51.100.0/24", "example.com"}},
		{ID: "plain", Name: "plain", Enabled: true, Outbound: "direct", Manual: []string{"192.0.2.0/24"}},
	}}
}

func TestGenerateRoutesAPolicyListByAMarkedDirectOutbound(t *testing.T) {
	res, err := Generate(ndmPolicyGenProfile(), Options{MixedPort: 7890, TunEnabled: true,
		NDMPolicies: map[string]uint32{"Policy0": 0x0ffffaaa, "Policy1": 0x0ffffaab}})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var policy []map[string]any
	for _, ob := range res.Config["outbounds"].([]map[string]any) {
		if tag, _ := ob["tag"].(string); strings.HasPrefix(tag, model.NDMPolicyPrefix) {
			policy = append(policy, ob)
		}
	}
	// Only the policy a list uses, as a direct outbound whose sockets carry NDM's mark for it.
	if len(policy) != 1 || policy[0]["type"] != "direct" || policy[0]["tag"] != "ndm-policy:Policy1" ||
		policy[0]["routing_mark"] != uint32(0x0ffffaab) {
		t.Fatalf("policy outbounds = %#v", policy)
	}
	routed := false
	route := res.Config["route"].(map[string]any)
	for _, r := range route["rules"].([]map[string]any) {
		if r["outbound"] == "ndm-policy:Policy1" {
			routed = true
		}
	}
	if !routed {
		t.Fatalf("no rule sends the list to its policy: %#v", route["rules"])
	}
}

// Without the mark the list would leave by the WAN while the panel says it goes through the policy.
func TestGenerateRefusesAPolicyItWasNotGivenTheMarkOf(t *testing.T) {
	_, err := Generate(ndmPolicyGenProfile(), Options{MixedPort: 7890, NDMPolicies: map[string]uint32{"Policy0": 0x0ffffaaa}})
	if err == nil || !strings.Contains(err.Error(), `"Policy1"`) {
		t.Fatalf("err = %v", err)
	}
}

// TestNDMPolicySingBoxCheck runs the real `sing-box check` on the policy outbound: the tag with its
// colon and `routing_mark` on a direct outbound. routing_mark is Linux-only in sing-box: measured, the
// Windows builds of 1.12.17, 1.13.21 and 1.14.4 parse it and then answer "`routing_mark` is only
// supported on Linux" at outbound init. That refusal is the one failure accepted off Linux, since it
// still proves the field and the tag were read.
func TestNDMPolicySingBoxCheck(t *testing.T) {
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — set it to a sing-box binary for a real `check`")
	}
	ver := singboxVersionOf(t, bin)
	res, err := Generate(ndmPolicyGenProfile(), Options{MixedPort: 7890, ProbePort: 7891, CoreVersion: ver,
		NDMPolicies: map[string]uint32{"Policy1": 0x0ffffaab}})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	data, _ := json.MarshalIndent(res.Config, "", "  ")
	f := filepath.Join(t.TempDir(), "ndm-policy.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", f).CombinedOutput()
	if err != nil && (runtime.GOOS == "linux" || !strings.Contains(string(out), "`routing_mark` is only supported on Linux")) {
		t.Fatalf("sing-box check rejected the access-policy outbound: %v\n%s", err, out)
	}
}
