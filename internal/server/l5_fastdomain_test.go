package server

import (
	"testing"

	"wayhop/internal/keenetic"
	"wayhop/internal/model"
)

// TestFastModeDomainWarning (L5): fast mode has no TUN, so domain/geo rules don't apply to LAN
// traffic — handleApply must surface a non-blocking warning. Hybrid/tun (which keep the TUN) and
// IP-only fast configs must NOT warn.
func TestFastModeDomainWarning(t *testing.T) {
	domainRule := &model.Profile{
		Rules: []model.Rule{{ID: "d", Domain: []string{"example.com"}, Outbound: "direct"}},
	}
	if w := fastModeDomainWarning(domainRule, "fast", false); w == "" {
		t.Error("fast mode with a domain rule must warn")
	}
	if w := fastModeDomainWarning(domainRule, "hybrid", false); w != "" {
		t.Errorf("hybrid mode must NOT warn (the TUN handles domains), got %q", w)
	}
	if w := fastModeDomainWarning(domainRule, "tun", false); w != "" {
		t.Errorf("tun mode must NOT warn, got %q", w)
	}

	// A default rule's matcher fields are inert — must not trigger the warning.
	defaultDomain := &model.Profile{
		Rules: []model.Rule{{ID: "def", Default: true, Domain: []string{"x.com"}, Outbound: "direct"}},
	}
	if w := fastModeDomainWarning(defaultDomain, "fast", false); w != "" {
		t.Errorf("a default rule's domain field is inert, must not warn: %q", w)
	}

	// IP-only fast config → no warning.
	ipOnly := &model.Profile{
		Rules:        []model.Rule{{ID: "i", IPCIDR: []string{"1.2.3.0/24"}, Outbound: "direct"}},
		RoutingLists: []model.RoutingList{{ID: "l", Manual: []string{"9.9.9.0/24"}, Outbound: "direct", Enabled: true}},
	}
	if w := fastModeDomainWarning(ipOnly, "fast", false); w != "" {
		t.Errorf("fast mode with only IP rules/lists must NOT warn, got %q", w)
	}

	// A manual-domain list and a remote rule_set both trigger it in fast mode.
	manualDomainList := &model.Profile{
		RoutingLists: []model.RoutingList{{ID: "l", Manual: []string{"blocked.example"}, Outbound: "direct", Enabled: true}},
	}
	if w := fastModeDomainWarning(manualDomainList, "fast", false); w == "" {
		t.Error("fast mode with a manual-domain list must warn")
	}
	remoteList := &model.Profile{
		RoutingLists: []model.RoutingList{{ID: "l", Source: "https://example.com/x.srs", Outbound: "direct", Enabled: true}},
	}
	if w := fastModeDomainWarning(remoteList, "fast", false); w == "" {
		t.Error("fast mode with a remote rule_set must warn (sing-box-loaded, no LAN match without TUN)")
	}

	// A DISABLED domain list must not warn.
	disabled := &model.Profile{
		RoutingLists: []model.RoutingList{{ID: "l", Manual: []string{"blocked.example"}, Outbound: "direct", Enabled: false}},
	}
	if w := fastModeDomainWarning(disabled, "fast", false); w != "" {
		t.Errorf("a disabled list must not warn: %q", w)
	}
}

// TestFastModeDomainWarningKernelPlane (L5): a router that matches domains in the KERNEL must not be
// told its domain lists are inert — and must still be told about the parts the kernel cannot carry.
//
// The warning assumed sing-box owns every domain match, so on KeeneticOS it fired for lists the
// kernel plane was already carrying and advised switching routing mode to repair them. Measured on
// a live router: a list holding teamviewer.com grew wr_list_rl_teamviewer_4 from 15 to 22
// members across three lookups, and that set's mangle MARK rule was counting packets, in fast mode.
func TestFastModeDomainWarningKernelPlane(t *testing.T) {
	domainList := &model.Profile{
		RoutingLists: []model.RoutingList{{ID: "l", Manual: []string{"teamviewer.com"}, Outbound: "direct", Enabled: true}},
	}
	if w := fastModeDomainWarning(domainList, "fast", false); w == "" {
		t.Error("without a resolver plane the warning must still fire")
	}
	if w := fastModeDomainWarning(domainList, "fast", true); w != "" {
		t.Errorf("a kernel-carried domain list must not warn: %q", w)
	}

	// A fetched name feed is the same mechanism as a typed name, and must be judged the same way.
	feedList := &model.Profile{
		RoutingLists: []model.RoutingList{{ID: "l", DomainSource: "https://example.com/names.txt", Outbound: "direct", Enabled: true}},
	}
	if w := fastModeDomainWarning(feedList, "fast", false); w == "" {
		t.Error("a domain feed with no resolver plane must warn")
	}
	if w := fastModeDomainWarning(feedList, "fast", true); w != "" {
		t.Errorf("a kernel-carried domain feed must not warn: %q", w)
	}

	// The flag is NOT a blanket mute. These two are sing-box's own matchers on any router, so fast
	// mode's missing TUN breaks them whatever the resolver is doing.
	ruleSet := &model.Profile{
		RoutingLists: []model.RoutingList{{ID: "srs", Source: "https://example.com/x.srs", Outbound: "direct", Enabled: true}},
	}
	if w := fastModeDomainWarning(ruleSet, "fast", true); w == "" {
		t.Error("a remote rule_set is sing-box-loaded and must warn even with the resolver wired")
	}
	geoRule := &model.Profile{
		Rules: []model.Rule{{ID: "g", GeoSite: []string{"category-ads"}, Outbound: "direct"}},
	}
	if w := fastModeDomainWarning(geoRule, "fast", true); w == "" {
		t.Error("a rule-level geo matcher has no kernel equivalent and must warn")
	}

	// The fact comes from the capture, and both halves of it are recorded there.
	if keeneticKernelCarriesDomains(nil) {
		t.Error("no capture is not evidence of a resolver")
	}
	if keeneticKernelCarriesDomains(&executionNativeCaptureV1{}) {
		t.Error("a capture taken without dnsmasq must not claim kernel domain matching")
	}
	if !keeneticKernelCarriesDomains(&executionNativeCaptureV1{DomainsViaDNSMasq: true}) {
		t.Error("a capture with the resolver wired must report kernel domain matching")
	}

	// Regression guard for the first cut of this fix: it keyed the suppression on the plan NOT
	// materializing a core, and the operator's own router needs one for its DNS plane, so the false
	// warning survived the fix. A core existing for DNS says nothing about who matches list names.
	dnsCore := &model.Profile{
		RoutingLists: []model.RoutingList{{ID: "l", Manual: []string{"teamviewer.com"}, Outbound: "direct", Enabled: true}},
		DNS: &model.DNSSettings{Enabled: true, Servers: []model.DNSServer{
			{Tag: "dns_secure", Type: "https", Server: "1.1.1.1", Detour: "direct", Enabled: true},
		}},
	}
	if !keenetic.PlanRequiresCore(dnsCore, true) {
		t.Skip("premise moved: this profile no longer needs a core, pick another that does")
	}
	if w := fastModeDomainWarning(dnsCore, "fast", keeneticKernelCarriesDomains(
		&executionNativeCaptureV1{DomainsViaDNSMasq: true})); w != "" {
		t.Errorf("a core materialized for DNS must not resurrect the warning: %q", w)
	}
}
