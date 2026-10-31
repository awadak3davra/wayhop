package server

import (
	"strings"
	"testing"

	"wayhop/internal/dnsaudit"
	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// A list sent to a KeeneticOS access policy with a plaintext default resolver: WayHop cannot see whether
// the policy leaves by a tunnel or by the WAN, and a DNS server's detour cannot name a policy, so the
// usual "point the list's DNS at a server with the same detour" could not be followed. It blocked Apply
// even for a WAN policy (QA-063). Now advice, with steps that can be taken; a tunnel list still blocks.
func TestDNSPathFindingForAPolicyListIsAdvice(t *testing.T) {
	findings := func(outbound string) []PlanFinding {
		p := model.Profile{
			Endpoints:    []model.Endpoint{{ID: "nl", Name: "NL", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "nl.example.net", Port: 443, Params: map[string]any{"uuid": "11111111-2222-3333-4444-555555555555"}}},
			RoutingLists: []model.RoutingList{{ID: "list-1", Name: "Local", Outbound: outbound, Manual: []string{"example.ru"}, Enabled: true}},
			DNS: &model.DNSSettings{Enabled: true,
				Servers: []model.DNSServer{{Tag: "plain", Type: "udp", Server: "198.51.100.53", Enabled: true}}, Final: "plain"},
		}
		var pf []platform.Unsupported
		for _, a := range dnsaudit.DetectAsymmetric(p, dnsaudit.Plane{}) {
			pf = append(pf, dnsPathUnsupported(a))
		}
		return evaluatePlanFindings(platform.CapabilitySet{}, pf)
	}
	policy := findings("ndm-policy:Policy0")
	if len(policy) != 1 || policy[0].Blocks == platform.BlocksApply || !strings.Contains(policy[0].Remedy, "encrypted DNS") {
		t.Errorf("policy list: findings = %+v, want one non-blocking finding with a followable remedy", policy)
	}
	if tunnel := findings("nl"); len(tunnel) != 1 || tunnel[0].Blocks != platform.BlocksApply {
		t.Errorf("tunnel list: findings = %+v, want the plaintext leak still to block Apply", tunnel)
	}
}
