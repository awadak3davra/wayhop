package server

import (
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// TestKeeneticArtifactCarriesDeviceScope (L5): the Keenetic kernel plane can route a device-scoped
// list on its own, in both scope directions.
//
// This is pinned because the backend currently declares the opposite: compatibilityReasons treats a
// list with ScopeMode only/except as something that needs the proxy core, which folds the WHOLE
// policy into a compatibility TUN. That clause carries no explanation, unlike the group clause beside
// it, and every link of the chain says the kernel is capable — the compiler emits MAC and source-IP
// zones, the ipset renderer emits the match, this artifact assembles with it, and the operator's own
// router accepted `-m mac --mac-source` when it was offered one in a scratch chain.
//
// Whether that clause should go is the operator's call, since it changes what a scoped list makes the
// router build. Either way the capability itself must not be quietly lost: if someone simplifies the
// MAC rendering away, this fails rather than silently making the clause retroactively correct.
func TestKeeneticArtifactCarriesDeviceScope(t *testing.T) {
	tool := func(name, path string) ExecutionToolIdentityV1 {
		return ExecutionToolIdentityV1{Tool: name, ResolvedPath: path, Runnable: true,
			ContentSHA256: strings.Repeat("ab", 32), Version: "test"}
	}
	tools := executionKernelIpsetArtifactV1{
		IpsetTool:    tool(executionToolIpset, "/opt/sbin/ipset"),
		IptablesTool: tool(executionToolIptables, "/opt/sbin/iptables"),
		IP6Tool:      tool(executionToolIp6tables, "/opt/sbin/ip6tables"),
		IPTool:       tool(executionToolIP, "/sbin/ip"),
		DnsmasqTool:  tool(executionToolDnsmasq, "/opt/sbin/dnsmasq"),
		ShellTool:    tool(executionToolShell, "/opt/bin/sh"),
	}
	build := func(t *testing.T, mode string) string {
		t.Helper()
		p := model.Profile{
			Endpoints: []model.Endpoint{{ID: "n", Name: "Native", Enabled: true,
				Engine: model.EngineExternal, Owner: model.OwnerExternal,
				Params: map[string]any{"interface": "nwg0"}}},
			DeviceGroups: []model.DeviceGroup{{ID: "kids", Name: "Kids",
				Members: []model.DeviceMember{{MAC: "aa:bb:cc:dd:ee:01"}, {IP: "192.168.1.50"}}}},
			RoutingLists: []model.RoutingList{{ID: "scoped", Name: "Scoped", Enabled: true, Outbound: "n",
				Manual: []string{"203.0.113.0/24"}, ScopeMode: mode, ScopeGroups: []string{"kids"}}},
		}
		plan, _, err := pbr.Compile(&p, pbr.Options{})
		if err != nil {
			t.Fatalf("compile %s: %v", mode, err)
		}
		art, err := buildKeeneticKernelIpsetArtifact(plan, pbr.Options{}, keeneticPBROptions("ppp0"), tools)
		if err != nil {
			t.Fatalf("artifact %s: %v", mode, err)
		}
		return string(art.Script)
	}

	only := build(t, "only")
	if !strings.Contains(only, "-m mac --mac-source aa:bb:cc:dd:ee:01") {
		t.Errorf("an \"only\" scope must mark just that device:\n%s", only)
	}

	// "except" has to negate BOTH halves of the scope — the MAC and the source-IP set — or the list
	// would still route for the very devices it excludes.
	except := build(t, "except")
	if !strings.Contains(except, "-m mac ! --mac-source aa:bb:cc:dd:ee:01") {
		t.Errorf("an \"except\" scope must negate the MAC:\n%s", except)
	}
	if !strings.Contains(except, "-m set ! --match-set") {
		t.Errorf("and must negate the source-IP set too:\n%s", except)
	}
}
