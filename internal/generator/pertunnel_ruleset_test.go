package generator

import (
	"testing"

	"velinx/internal/model"
)

// --- Feature (1): per-tunnel typed MTU / PersistentKeepalive on WG endpoints ---

// TestEndpointTypedMTUAndKeepalive: the typed per-tunnel controls
// Endpoint.MTU and Endpoint.PersistentKeepalive (the Tunnels-page knobs) must be
// emitted on the sing-box WireGuard endpoint (mtu) and its peer
// (persistent_keepalive_interval). Both > 0 here, set ONLY via the typed fields
// (Params carries neither), so this proves the typed path emits independently of
// the legacy Params path.
func TestEndpointTypedMTUAndKeepalive(t *testing.T) {
	e := generator_singBoxEndpoint("wg-typed", model.ProtoWireGuard, map[string]any{
		"private_key": wgTestPrivKey, "peer_public_key": wgTestPubKey,
	})
	e.MTU = 1320
	e.PersistentKeepalive = 17

	ep, _ := generator_wgEndpoint(t, e)
	if ep["mtu"] != 1320 {
		t.Fatalf("endpoint mtu = %v (%T), want 1320 from Endpoint.MTU", ep["mtu"], ep["mtu"])
	}
	pe := ep["peers"].([]map[string]any)[0]
	if pe["persistent_keepalive_interval"] != 17 {
		t.Fatalf("peer persistent_keepalive_interval = %v (%T), want 17 from Endpoint.PersistentKeepalive",
			pe["persistent_keepalive_interval"], pe["persistent_keepalive_interval"])
	}
}

// TestEndpointTypedMTUKeepaliveOmittedWhenUnset: with neither the typed fields nor
// the legacy Params set, the endpoint must carry NO mtu and the peer NO
// persistent_keepalive_interval — a zero typed field means "current behavior"
// (omit), byte-identical to a profile that never knew the knob.
func TestEndpointTypedMTUKeepaliveOmittedWhenUnset(t *testing.T) {
	e := generator_singBoxEndpoint("wg-unset", model.ProtoWireGuard, map[string]any{
		"private_key": wgTestPrivKey, "peer_public_key": wgTestPubKey,
	})
	// e.MTU == 0 && e.PersistentKeepalive == 0 (zero values).

	ep, _ := generator_wgEndpoint(t, e)
	if _, ok := ep["mtu"]; ok {
		t.Fatalf("mtu must be omitted when both Endpoint.MTU and Params are unset, got %v", ep["mtu"])
	}
	pe := ep["peers"].([]map[string]any)[0]
	if _, ok := pe["persistent_keepalive_interval"]; ok {
		t.Fatalf("persistent_keepalive_interval must be omitted when unset, got %v", pe["persistent_keepalive_interval"])
	}
}

// TestEndpointTypedFieldsWinOverParams: when BOTH the typed per-tunnel control and
// the legacy Params value are present, the typed field wins (the UI Tunnels knob is
// authoritative). A profile that only carries the legacy Params still works (covered
// by the existing TestOutboundWireGuardMTU / ...Keepalive), so the fallback is
// preserved — this asserts the precedence direction.
func TestEndpointTypedFieldsWinOverParams(t *testing.T) {
	e := generator_singBoxEndpoint("wg-precedence", model.ProtoWireGuard, map[string]any{
		"private_key": wgTestPrivKey, "peer_public_key": wgTestPubKey,
		// Legacy Params values that must be OVERRIDDEN by the typed fields below.
		"mtu":                  float64(1408),
		"persistent_keepalive": float64(99),
	})
	e.MTU = 1280
	e.PersistentKeepalive = 25

	ep, _ := generator_wgEndpoint(t, e)
	if ep["mtu"] != 1280 {
		t.Fatalf("endpoint mtu = %v, want 1280 (typed Endpoint.MTU must win over Params 1408)", ep["mtu"])
	}
	pe := ep["peers"].([]map[string]any)[0]
	if pe["persistent_keepalive_interval"] != 25 {
		t.Fatalf("peer persistent_keepalive_interval = %v, want 25 (typed must win over Params 99)",
			pe["persistent_keepalive_interval"])
	}
}

// --- Feature (2): remote rule-set auto-update detour default ---

// pertunnel_setByTag indexes a route's rule_set entries by their tag for assertions.
func pertunnel_setByTag(t *testing.T, res *Result) map[string]map[string]any {
	t.Helper()
	route := res.Config["route"].(map[string]any)
	out := map[string]map[string]any{}
	if raw, ok := route["rule_set"]; ok {
		for _, s := range raw.([]map[string]any) {
			out[s["tag"].(string)] = s
		}
	}
	return out
}

// TestRemoteRuleSetDefaultsDownloadDetour: a REMOTE (URL-based) routing list with
// NO explicit DownloadVia must still emit download_detour=direct (so the list
// downloads over the WAN even before any tunnel route exists and can't be blocked
// by a down proxy it might route around), plus type=remote, format inferred from
// the URL, and an update_interval. This is the auto-update wiring.
func TestRemoteRuleSetDefaultsDownloadDetour(t *testing.T) {
	nl := generator_singBoxEndpoint("nl", model.ProtoVLESS, map[string]any{"uuid": "u"})
	p := &model.Profile{
		Endpoints: []model.Endpoint{nl},
		Rules:     []model.Rule{{ID: "d", Default: true, Outbound: model.OutboundDirect}},
		RoutingLists: []model.RoutingList{
			// Remote, NO DownloadVia → default detour must be direct.
			{ID: "remote-default", Name: "Remote", Source: "https://x/list.srs", Outbound: "nl", Enabled: true},
		},
	}
	res, err := Generate(p, Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	set := pertunnel_setByTag(t, res)["rs-remote-default"]
	if set == nil {
		t.Fatalf("remote rule_set rs-remote-default missing: %v", res.Config["route"])
	}
	if set["type"] != "remote" {
		t.Fatalf("type = %v, want remote", set["type"])
	}
	if set["url"] != "https://x/list.srs" {
		t.Fatalf("url = %v", set["url"])
	}
	if set["format"] != "binary" {
		t.Fatalf("format = %v, want binary (.srs)", set["format"])
	}
	if set["download_detour"] != model.OutboundDirect {
		t.Fatalf("download_detour = %v, want %q (default for a remote list with no DownloadVia)",
			set["download_detour"], model.OutboundDirect)
	}
	if set["update_interval"] != "1d" {
		t.Fatalf("update_interval = %v, want 1d (auto-update default)", set["update_interval"])
	}
}

// TestRemoteRuleSetExplicitDownloadVia: an explicit DownloadVia must be honored
// (not clobbered by the direct default) and the update_interval must follow
// RefreshHours.
func TestRemoteRuleSetExplicitDownloadVia(t *testing.T) {
	nl := generator_singBoxEndpoint("nl", model.ProtoVLESS, map[string]any{"uuid": "u"})
	p := &model.Profile{
		Endpoints: []model.Endpoint{nl},
		Rules:     []model.Rule{{ID: "d", Default: true, Outbound: model.OutboundDirect}},
		RoutingLists: []model.RoutingList{
			{ID: "via-nl", Name: "Via NL", Source: "https://x/geo.json", Outbound: model.OutboundDirect,
				DownloadVia: "nl", RefreshHours: 6, Enabled: true},
		},
	}
	res, err := Generate(p, Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	set := pertunnel_setByTag(t, res)["rs-via-nl"]
	if set == nil {
		t.Fatalf("remote rule_set rs-via-nl missing")
	}
	if set["download_detour"] != "nl" {
		t.Fatalf("download_detour = %v, want nl (explicit DownloadVia honored)", set["download_detour"])
	}
	if set["format"] != "source" {
		t.Fatalf("format = %v, want source (.json)", set["format"])
	}
	if set["update_interval"] != "6h" {
		t.Fatalf("update_interval = %v, want 6h (from RefreshHours)", set["update_interval"])
	}
}

// TestLocalRuleSetUnchanged: a manual-only (local/inline) routing list must remain
// an inline rule_set with NO download_detour / update_interval — only REMOTE
// (URL-based) lists get the auto-update remote wiring. This guards that feature (2)
// touched only the remote branch.
func TestLocalRuleSetUnchanged(t *testing.T) {
	nl := generator_singBoxEndpoint("nl", model.ProtoVLESS, map[string]any{"uuid": "u"})
	p := &model.Profile{
		Endpoints: []model.Endpoint{nl},
		Rules:     []model.Rule{{ID: "d", Default: true, Outbound: model.OutboundDirect}},
		RoutingLists: []model.RoutingList{
			{ID: "manual", Name: "Manual", Manual: []string{"openai.com", "1.2.3.0/24"}, Outbound: "nl", Enabled: true},
		},
	}
	res, err := Generate(p, Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	set := pertunnel_setByTag(t, res)["rsm-manual"]
	if set == nil {
		t.Fatalf("inline rule_set rsm-manual missing")
	}
	if set["type"] != "inline" {
		t.Fatalf("type = %v, want inline (a manual list is local, not remote)", set["type"])
	}
	if _, ok := set["download_detour"]; ok {
		t.Fatalf("inline rule_set must NOT carry download_detour: %v", set["download_detour"])
	}
	if _, ok := set["update_interval"]; ok {
		t.Fatalf("inline rule_set must NOT carry update_interval: %v", set["update_interval"])
	}
	if _, ok := set["url"]; ok {
		t.Fatalf("inline rule_set must NOT carry url: %v", set["url"])
	}
	// The inline matcher still carries the manual entries (unchanged emission).
	m := set["rules"].([]map[string]any)[0]
	if ds, _ := m["domain_suffix"].([]string); len(ds) != 1 || ds[0] != "openai.com" {
		t.Fatalf("inline domain_suffix = %v, want [openai.com]", m["domain_suffix"])
	}
	if ips, _ := m["ip_cidr"].([]string); len(ips) != 1 || ips[0] != "1.2.3.0/24" {
		t.Fatalf("inline ip_cidr = %v, want [1.2.3.0/24]", m["ip_cidr"])
	}
}
