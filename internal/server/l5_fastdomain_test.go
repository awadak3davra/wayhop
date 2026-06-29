package server

import (
	"testing"

	"velinx/internal/model"
)

// TestFastModeDomainWarning (L5): fast mode has no TUN, so domain/geo rules don't apply to LAN
// traffic — handleApply must surface a non-blocking warning. Hybrid/tun (which keep the TUN) and
// IP-only fast configs must NOT warn.
func TestFastModeDomainWarning(t *testing.T) {
	domainRule := &model.Profile{
		Rules: []model.Rule{{ID: "d", Domain: []string{"example.com"}, Outbound: "direct"}},
	}
	if w := fastModeDomainWarning(domainRule, "fast"); w == "" {
		t.Error("fast mode with a domain rule must warn")
	}
	if w := fastModeDomainWarning(domainRule, "hybrid"); w != "" {
		t.Errorf("hybrid mode must NOT warn (the TUN handles domains), got %q", w)
	}
	if w := fastModeDomainWarning(domainRule, "tun"); w != "" {
		t.Errorf("tun mode must NOT warn, got %q", w)
	}

	// A default rule's matcher fields are inert — must not trigger the warning.
	defaultDomain := &model.Profile{
		Rules: []model.Rule{{ID: "def", Default: true, Domain: []string{"x.com"}, Outbound: "direct"}},
	}
	if w := fastModeDomainWarning(defaultDomain, "fast"); w != "" {
		t.Errorf("a default rule's domain field is inert, must not warn: %q", w)
	}

	// IP-only fast config → no warning.
	ipOnly := &model.Profile{
		Rules:        []model.Rule{{ID: "i", IPCIDR: []string{"1.2.3.0/24"}, Outbound: "direct"}},
		RoutingLists: []model.RoutingList{{ID: "l", Manual: []string{"9.9.9.0/24"}, Outbound: "direct", Enabled: true}},
	}
	if w := fastModeDomainWarning(ipOnly, "fast"); w != "" {
		t.Errorf("fast mode with only IP rules/lists must NOT warn, got %q", w)
	}

	// A manual-domain list and a remote rule_set both trigger it in fast mode.
	manualDomainList := &model.Profile{
		RoutingLists: []model.RoutingList{{ID: "l", Manual: []string{"blocked.example"}, Outbound: "direct", Enabled: true}},
	}
	if w := fastModeDomainWarning(manualDomainList, "fast"); w == "" {
		t.Error("fast mode with a manual-domain list must warn")
	}
	remoteList := &model.Profile{
		RoutingLists: []model.RoutingList{{ID: "l", Source: "https://example.com/x.srs", Outbound: "direct", Enabled: true}},
	}
	if w := fastModeDomainWarning(remoteList, "fast"); w == "" {
		t.Error("fast mode with a remote rule_set must warn (sing-box-loaded, no LAN match without TUN)")
	}

	// A DISABLED domain list must not warn.
	disabled := &model.Profile{
		RoutingLists: []model.RoutingList{{ID: "l", Manual: []string{"blocked.example"}, Outbound: "direct", Enabled: false}},
	}
	if w := fastModeDomainWarning(disabled, "fast"); w != "" {
		t.Errorf("a disabled list must not warn: %q", w)
	}
}
