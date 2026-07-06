package generator

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// TestSourceRoutingGenerate covers the sing-box plane of source-based routing (Phase B):
// ruleMatch emits source_ip_cidr/source_port (never source_mac/source_iface — kernel-only);
// ipOnlyKernelRule keeps a source-bearing rule in sing-box; routeFrom skips disabled rules
// AND a kernel-only-source rule (so it can never emit a condition-less match-all).
func TestSourceRoutingGenerate(t *testing.T) {
	// ruleMatch: source_ip_cidr + source_port emitted; MAC/iface NOT.
	rm := ruleMatch(&model.Rule{
		SourceIPCIDR: []string{"192.168.1.50/32"}, SourcePort: []int{51820},
		SourceMAC: []string{"aa:bb:cc:dd:ee:ff"}, SourceIface: []string{"br-guest"},
	})
	if _, ok := rm["source_ip_cidr"]; !ok {
		t.Errorf("ruleMatch must emit source_ip_cidr, got %v", rm)
	}
	if _, ok := rm["source_port"]; !ok {
		t.Errorf("ruleMatch must emit source_port, got %v", rm)
	}
	for _, k := range []string{"source_mac", "source_iface", "source_mac_address", "inbound"} {
		if _, ok := rm[k]; ok {
			t.Errorf("ruleMatch must NOT emit %q (kernel-only / out of v1), got %v", k, rm)
		}
	}

	// ipOnlyKernelRule: a source-bearing rule is KEPT in sing-box (not dropped to pbr).
	if ipOnlyKernelRule(&model.Rule{IPCIDR: []string{"1.2.3.0/24"}, SourceIPCIDR: []string{"10.0.0.5"}}) {
		t.Error("a source-bearing IP rule must NOT be ipOnlyKernelRule (must stay in sing-box)")
	}
	if !ipOnlyKernelRule(&model.Rule{IPCIDR: []string{"1.2.3.0/24"}}) {
		t.Error("a pure dest-IP rule should still be ipOnlyKernelRule")
	}

	// routeFrom: disabled + kernel-only-source rules are absent; only the real rule emits.
	prof := &model.Profile{Rules: []model.Rule{
		{ID: "keep", IPCIDR: []string{"1.2.3.0/24"}, Outbound: model.OutboundDirect},
		{ID: "off", IPCIDR: []string{"5.6.7.0/24"}, Outbound: model.OutboundDirect, Disabled: true},
		{ID: "kernel-only-src", SourceIface: []string{"br-guest"}, Outbound: model.OutboundDirect},
		{ID: "def", Default: true, Outbound: model.OutboundDirect},
	}}
	out, _, _ := routeFrom(prof, false)
	rules, _ := out["rules"].([]map[string]any)
	if len(rules) != 1 {
		t.Fatalf("expected exactly 1 emitted rule (disabled + kernel-only-source skipped), got %d: %v", len(rules), rules)
	}
	if _, ok := rules[0]["ip_cidr"]; !ok {
		t.Errorf("the surviving rule should be the dest-IP one, got %v", rules[0])
	}
	// No emitted rule may be a condition-less match-all (no matcher + no rule_set).
	for i, ru := range rules {
		_, hasIP := ru["ip_cidr"]
		_, hasDom := ru["domain"]
		_, hasDomS := ru["domain_suffix"]
		_, hasPort := ru["port"]
		_, hasSrcIP := ru["source_ip_cidr"]
		_, hasSrcPort := ru["source_port"]
		_, hasSet := ru["rule_set"]
		_, isLogical := ru["type"]
		if !(hasIP || hasDom || hasDomS || hasPort || hasSrcIP || hasSrcPort || hasSet || isLogical) {
			t.Errorf("rule %d is a condition-less match-all (leak): %v", i, ru)
		}
	}
}

// TestSourceRuleSingBoxCheck confirms the real sing-box accepts a config carrying the v1
// source matchers (source_ip_cidr + source_port). Runs only with WR_SINGBOX (CI singbox-check).
func TestSourceRuleSingBoxCheck(t *testing.T) {
	const uuid = "11111111-2222-3333-4444-555555555555"
	ep, err := importer.Parse("vless://" + uuid + "@203.0.113.10:443?encryption=none&security=tls&sni=ex.com&fp=chrome#t")
	if err != nil {
		t.Fatalf("import vless: %v", err)
	}
	ep.ID, ep.Name, ep.Enabled = "p-vless", "p-vless", true
	prof := &model.Profile{
		Endpoints: []model.Endpoint{*ep},
		Rules: []model.Rule{
			{ID: "src", SourceIPCIDR: []string{"192.168.1.50/32"}, SourcePort: []int{443}, IPCIDR: []string{"1.2.3.0/24"}, Outbound: "p-vless"},
			{ID: "def", Default: true, Outbound: model.OutboundDirect},
		},
	}
	res, err := Generate(prof, Options{MixedPort: 7890, CacheFile: filepath.Join(t.TempDir(), "c.db")})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	data, _ := json.MarshalIndent(res.Config, "", "  ")
	if !strings.Contains(string(data), `"source_ip_cidr"`) || !strings.Contains(string(data), `"source_port"`) {
		t.Fatalf("generated config missing source matchers:\n%s", data)
	}

	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — generation-only")
	}
	f := filepath.Join(t.TempDir(), "src.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", f).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check rejected the source-rule config: %v\n%s", err, strings.TrimSpace(string(out)))
	}
}
