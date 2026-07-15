package generator

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// TestRoutingListDeviceScope: the sing-box plane of per-device list scoping. An "only" scope with an
// IP member emits source_ip_cidr (MAC excluded — kernel-only); a MAC-only scope emits NO rule (a
// dest-only rule would over-match in-TUN clients); an unscoped list carries no source_ip_cidr.
func TestRoutingListDeviceScope(t *testing.T) {
	kids := model.DeviceGroup{ID: "kids", Name: "Kids", Members: []model.DeviceMember{{MAC: "aa:bb:cc:dd:ee:ff"}, {IP: "192.168.1.50/32"}}}
	macs := model.DeviceGroup{ID: "macs", Name: "Macs", Members: []model.DeviceMember{{MAC: "11:22:33:44:55:66"}}}
	nl := generator_singBoxEndpoint("nl", model.ProtoVLESS, map[string]any{"uuid": "u"})
	p := &model.Profile{
		Endpoints:    []model.Endpoint{nl},
		DeviceGroups: []model.DeviceGroup{kids, macs},
		RoutingLists: []model.RoutingList{
			{ID: "scoped", Name: "Scoped", Manual: []string{"1.2.3.0/24"}, Outbound: "nl", Enabled: true, ScopeMode: "only", ScopeGroups: []string{"kids"}},
			{ID: "maconly", Name: "MacOnly", Manual: []string{"5.6.7.0/24"}, Outbound: "nl", Enabled: true, ScopeMode: "only", ScopeGroups: []string{"macs"}},
			{ID: "allc", Name: "All", Manual: []string{"9.9.9.0/24"}, Outbound: "nl", Enabled: true},
		},
	}
	_, rules := routingFrom(p, false)
	byTag := map[string]map[string]any{}
	for _, r := range rules {
		if tags, ok := r["rule_set"].([]string); ok && len(tags) > 0 {
			byTag[tags[0]] = r
		}
	}

	sc := byTag["rsm-scoped"]
	if sc == nil {
		t.Fatalf("scoped list rule missing; rules=%v", rules)
	}
	sip, ok := sc["source_ip_cidr"].([]string)
	if !ok || len(sip) != 1 || !strings.Contains(sip[0], "192.168.1.50") {
		t.Errorf("scoped list must carry source_ip_cidr=[IP member], got %v", sc["source_ip_cidr"])
	}
	if strings.Contains(strings.Join(sip, ","), "aa:bb:cc") {
		t.Error("a MAC must NOT leak into the sing-box source_ip_cidr")
	}

	if _, ok := byTag["rsm-maconly"]; ok {
		t.Error("a MAC-only scoped list must produce no sing-box rule (would over-match)")
	}

	all := byTag["rsm-allc"]
	if all == nil {
		t.Fatal("unscoped list rule missing")
	}
	if _, ok := all["source_ip_cidr"]; ok {
		t.Error("an unscoped list must not carry source_ip_cidr")
	}
}
