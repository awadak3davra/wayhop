package generator

import (
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// TestHybridScopedKernelListStays (RT-06): a device-scoped pure-IP list at a kernel egress compiles
// into a SrcScoped zone, and the hybrid TUN does not exclude those, so the scoped devices' TCP is
// captured by auto_redirect and matched by sing-box. The list must therefore stay in sing-box
// ("only" with its source_ip_cidr; "except" dest-only, the documented P8 limit) and keep its kernel
// outbound alive. Dropping it sent that TCP to route.final, out of the WAN with final=direct. An
// unscoped pure-IP list is still left to pbr alone.
func TestHybridScopedKernelListStays(t *testing.T) {
	p := hybridProfile()
	p.DeviceGroups = []model.DeviceGroup{{ID: "laptop", Name: "Laptop", Members: []model.DeviceMember{{IP: "192.168.1.50/32"}}}}
	p.RoutingLists = append(p.RoutingLists,
		model.RoutingList{ID: "work-only", Name: "Work", Manual: []string{"203.0.113.0/24"}, Outbound: "k-awg",
			Enabled: true, ScopeMode: "only", ScopeGroups: []string{"laptop"}},
		model.RoutingList{ID: "work-except", Name: "WorkX", Manual: []string{"198.51.100.0/24"}, Outbound: "k-awg",
			Enabled: true, ScopeMode: "except", ScopeGroups: []string{"laptop"}},
	)

	// Fold the plan into the TUN excludes the way the server does (executionGeneratorOptions): a
	// SrcScoped zone stays in the TUN.
	plan, _, err := pbr.Compile(p, pbr.Options{})
	if err != nil {
		t.Fatalf("pbr.Compile: %v", err)
	}
	var ex4, ex6 []string
	for _, z := range plan.Zones {
		if z.SrcScoped {
			continue
		}
		ex4 = append(ex4, z.V4...)
		ex6 = append(ex6, z.V6...)
	}
	ex4 = append(ex4, plan.BypassV4...)
	ex6 = append(ex6, plan.BypassV6...)
	for _, cidr := range []string{"203.0.113.0/24", "198.51.100.0/24"} {
		if gen_sliceHas(ex4, cidr) {
			t.Fatalf("fixture: scoped list prefix %s must not be TUN-excluded: %v", cidr, ex4)
		}
	}

	res := gen_must(t, p, Options{MixedPort: 7890, TunEnabled: true, Hybrid: true, KernelExcludeV4: ex4, KernelExcludeV6: ex6})
	byTag := map[string]map[string]any{}
	for _, r := range gen_routeRules(res) {
		if tags, ok := r["rule_set"].([]string); ok && len(tags) > 0 {
			byTag[tags[0]] = r
		}
	}

	only := byTag["rsm-work-only"]
	if only == nil {
		t.Fatalf("the \"only\"-scoped kernel list was dropped from sing-box: its devices' TCP would take route.final")
	}
	if only["outbound"] != "k-awg" {
		t.Errorf("scoped list outbound = %v, want k-awg", only["outbound"])
	}
	if src, _ := only["source_ip_cidr"].([]string); !gen_sliceHas(src, "192.168.1.50/32") {
		t.Errorf("the \"only\" list must keep its device scope as source_ip_cidr, got %v", only["source_ip_cidr"])
	}
	except := byTag["rsm-work-except"]
	if except == nil {
		t.Fatalf("the \"except\"-scoped kernel list was dropped from sing-box: the other devices' TCP would take route.final")
	}
	if except["outbound"] != "k-awg" {
		t.Errorf("except list outbound = %v, want k-awg", except["outbound"])
	}
	if _, ok := byTag["rsm-rl-ip-awg"]; ok {
		t.Error("the unscoped pure-IP kernel list must still be left to pbr (its prefixes are TUN-excluded)")
	}
	if !gen_outboundTags(res)["k-awg"] {
		t.Error("k-awg must be kept: a surviving scoped list references it")
	}
	gen_assertNoDangling(t, res)

	// DNS rules referencing the lists name exactly the sets routingFrom emitted.
	if got := dnsListTags(p, "work-only", true); !gen_sliceHas(got, "rsm-work-only") {
		t.Errorf("dnsListTags(work-only) = %v, want rsm-work-only", got)
	}
	if got := dnsListTags(p, "rl-ip-awg", true); len(got) != 0 {
		t.Errorf("dnsListTags(rl-ip-awg) = %v, want none (pbr-only list)", got)
	}
}
