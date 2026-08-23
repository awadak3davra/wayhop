package model

import (
	"encoding/base64"
	"testing"
)

// storemodelconfig_goodEndpoint builds a structurally valid endpoint.
func storemodelconfig_goodEndpoint(id string) Endpoint {
	return Endpoint{
		ID:       id,
		Name:     "ep-" + id,
		Engine:   EngineSingBox,
		Protocol: ProtoVLESS,
		Server:   "1.1.1.1",
		Port:     443,
		Enabled:  true,
	}
}

// storemodelconfig_goodProfile builds a profile that should pass Validate:
// two endpoints, a group over them, and a default rule pointing at the group.
func storemodelconfig_goodProfile() Profile {
	return Profile{
		Endpoints: []Endpoint{
			storemodelconfig_goodEndpoint("e1"),
			storemodelconfig_goodEndpoint("e2"),
		},
		Groups: []Group{
			{ID: "g1", Name: "G1", Type: GroupURLTest, Members: []string{"e1", "e2"}},
		},
		Rules: []Rule{
			{ID: "r1", Default: true, Outbound: "g1"},
		},
	}
}

// TestValidateRejectsConfigBrickingMissingParams: an ENABLED endpoint missing a
// protocol identity field that sing-box hard-rejects (TUIC uuid, SS method/
// password, WG private_key) must fail Validate — Generate calls Validate first,
// so this fails the apply safely instead of bricking the whole live singbox.json.
func TestValidateRejectsConfigBrickingMissingParams(t *testing.T) {
	mk := func(proto Protocol, params map[string]any, enabled bool) Profile {
		return Profile{Endpoints: []Endpoint{{
			ID: "e", Name: "e", Engine: EngineSingBox, Protocol: proto,
			Server: "1.1.1.1", Port: 443, Enabled: enabled, Params: params,
		}}}
	}
	// Each of these ENABLED endpoints must be rejected.
	bad := []struct {
		name   string
		proto  Protocol
		params map[string]any
	}{
		{"tuic-no-uuid", ProtoTUIC, map[string]any{"password": "p"}},
		{"ss-no-method", ProtoShadowsocks, map[string]any{"password": "p"}},
		{"ss-no-password", ProtoShadowsocks, map[string]any{"method": "aes-256-gcm"}},
		{"wg-no-privkey", ProtoWireGuard, map[string]any{"peer_public_key": "k"}},
		{"awg-no-privkey", ProtoAmneziaWG, map[string]any{"peer_public_key": "k"}},
		{"wg-no-peer-pubkey", ProtoWireGuard, map[string]any{"private_key": "k"}},
		{"awg-no-peer-pubkey", ProtoAmneziaWG, map[string]any{"private_key": "k"}},
	}
	for _, c := range bad {
		p := mk(c.proto, c.params, true)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: enabled endpoint with missing mandatory param should be rejected", c.name)
		}
		// The SAME endpoint DISABLED must be accepted (generator skips it).
		pd := mk(c.proto, c.params, false)
		if err := pd.Validate(); err != nil {
			t.Errorf("%s: a DISABLED draft must be exempt, got: %v", c.name, err)
		}
	}
	// Complete endpoints validate fine.
	good := []Profile{
		mk(ProtoTUIC, map[string]any{"uuid": "11111111-2222-3333-4444-555555555555", "password": "p"}, true),
		mk(ProtoShadowsocks, map[string]any{"method": "aes-256-gcm", "password": "p"}, true),
		mk(ProtoWireGuard, map[string]any{"private_key": "k", "peer_public_key": "pk"}, true),
	}
	for i, p := range good {
		if err := p.Validate(); err != nil {
			t.Errorf("good[%d] should validate, got: %v", i, err)
		}
	}
	// sing-box TOLERATES these (no brick) so Validate must NOT reject them.
	tolerated := []Profile{
		mk(ProtoVLESS, map[string]any{}, true),  // empty uuid - tolerated
		mk(ProtoTrojan, map[string]any{}, true), // empty password - tolerated
	}
	for i, p := range tolerated {
		if err := p.Validate(); err != nil {
			t.Errorf("tolerated[%d] must not be rejected (sing-box accepts it), got: %v", i, err)
		}
	}
}

// TestValidateRejectsOversizedRuleSourceMAC: a rule source_mac that net.ParseMAC accepts but the
// kernel ether plane rejects (8-byte EUI-64) must be rejected at Validate — otherwise it bricks
// the WHOLE nft/iptables apply device-wide. Mirrors the device-group MAC guard.
func TestValidateRejectsOversizedRuleSourceMAC(t *testing.T) {
	mkRule := func(mac string) Profile {
		return Profile{Rules: []Rule{{ID: "r", SourceMAC: []string{mac}, Outbound: OutboundDirect}}}
	}
	oversized := mkRule("aa:bb:cc:dd:ee:ff:00:11")
	if err := oversized.Validate(); err == nil {
		t.Error("rule with an 8-byte EUI-64 source_mac must be rejected (kernel ether plane accepts only EUI-48)")
	}
	ok := mkRule("aa:bb:cc:dd:ee:ff")
	if err := ok.Validate(); err != nil {
		t.Errorf("rule with a valid 6-byte source_mac must validate, got: %v", err)
	}
}

// TestValidateRejectsInvalidProtoParams: a PRESENT-but-invalid mandatory value
// that sing-box hard-rejects (a wrong-length SS-2022 PSK) must fail Validate so
// it can't brick the whole shared config on apply.
func TestValidateRejectsInvalidProtoParams(t *testing.T) {
	b64 := func(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }
	mk := func(params map[string]any, enabled bool) Profile {
		return Profile{Endpoints: []Endpoint{{
			ID: "e", Name: "e", Engine: EngineSingBox, Protocol: ProtoShadowsocks,
			Server: "1.1.1.1", Port: 443, Enabled: enabled, Params: params,
		}}}
	}
	bad := []struct {
		name   string
		params map[string]any
	}{
		{"ss2022-aes256-shortkey", map[string]any{"method": "2022-blake3-aes-256-gcm", "password": b64(6)}},
		{"ss2022-aes128-wrong32", map[string]any{"method": "2022-blake3-aes-128-gcm", "password": b64(32)}},
		{"ss2022-not-base64", map[string]any{"method": "2022-blake3-aes-256-gcm", "password": "!!!not base64!!!"}},
		// Unsupported methods sing-box rejects with "unknown method" → would brick the
		// whole shared config; real old-server links use these legacy ciphers.
		{"ss-salsa20", map[string]any{"method": "salsa20", "password": "x"}},
		{"ss-chacha20-bare", map[string]any{"method": "chacha20", "password": "x"}},
		{"ss-rc4", map[string]any{"method": "rc4", "password": "x"}},
		{"ss-camellia", map[string]any{"method": "camellia-256-cfb", "password": "x"}},
		{"ss-typo", map[string]any{"method": "aes-256-gdm", "password": "x"}},
	}
	for _, c := range bad {
		p := mk(c.params, true)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: should be rejected", c.name)
		}
		pd := mk(c.params, false)
		if err := pd.Validate(); err != nil {
			t.Errorf("%s: disabled draft must be exempt, got: %v", c.name, err)
		}
	}
	good := []struct {
		name   string
		params map[string]any
	}{
		{"ss2022-aes256-32B", map[string]any{"method": "2022-blake3-aes-256-gcm", "password": b64(32)}},
		{"ss2022-aes128-16B", map[string]any{"method": "2022-blake3-aes-128-gcm", "password": b64(16)}},
		{"ss-classic-anylen", map[string]any{"method": "aes-256-gcm", "password": "whatever"}}, // non-2022: no key-length rule
		{"ss-chacha20-ietf-poly", map[string]any{"method": "chacha20-ietf-poly1305", "password": "w"}},
		{"ss-legacy-cfb", map[string]any{"method": "aes-256-cfb", "password": "w"}},           // sing-box still ships this
		{"ss-legacy-chacha-ietf", map[string]any{"method": "chacha20-ietf", "password": "w"}}, // valid (bare chacha20 isn't)
		{"ss-none", map[string]any{"method": "none", "password": "w"}},
	}
	for _, c := range good {
		p := mk(c.params, true)
		if err := p.Validate(); err != nil {
			t.Errorf("%s: should validate, got: %v", c.name, err)
		}
	}
}

// TestValidateRejectsMalformedTUICUUID: a TUIC uuid that isn't canonical bricks
// the config (sing-box "invalid uuid"), so Validate must reject an enabled one.
// A valid uuid passes; vless/vmess tolerate a bad uuid so they're unaffected.
func TestValidateRejectsMalformedTUICUUID(t *testing.T) {
	mk := func(proto Protocol, uuid string, enabled bool) Profile {
		return Profile{Endpoints: []Endpoint{{
			ID: "e", Name: "e", Engine: EngineSingBox, Protocol: proto,
			Server: "1.1.1.1", Port: 443, Enabled: enabled,
			Params: map[string]any{"uuid": uuid, "password": "p"},
		}}}
	}
	if p := mk(ProtoTUIC, "not-a-uuid", true); p.Validate() == nil {
		t.Error("enabled tuic with a malformed uuid must be rejected")
	}
	if p := mk(ProtoTUIC, "not-a-uuid", false); p.Validate() != nil {
		t.Error("disabled tuic draft must be exempt")
	}
	if p := mk(ProtoTUIC, "11111111-2222-3333-4444-555555555555", true); p.Validate() != nil {
		t.Errorf("valid tuic uuid must pass: %v", p.Validate())
	}
	// vless tolerates a non-canonical uuid (sing-box doesn't hard-reject it).
	if p := mk(ProtoVLESS, "abc", true); p.Validate() != nil {
		t.Errorf("vless must not enforce uuid format: %v", p.Validate())
	}
}

func TestStoremodelconfigValidateAcceptsGoodProfile(t *testing.T) {
	p := storemodelconfig_goodProfile()
	if err := p.Validate(); err != nil {
		t.Fatalf("good profile should validate, got: %v", err)
	}
}

func TestStoremodelconfigValidateRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Profile)
	}{
		{
			name: "empty-endpoint-id",
			mutate: func(p *Profile) {
				p.Endpoints[0].ID = ""
			},
		},
		{
			name: "duplicate-endpoint-ids",
			mutate: func(p *Profile) {
				p.Endpoints[1].ID = "e1"
				// Keep the group resolvable so the duplicate is the first failure.
				p.Groups[0].Members = []string{"e1"}
			},
		},
		{
			name: "endpoint-and-group-id-collision",
			mutate: func(p *Profile) {
				// Group reuses an endpoint id -> duplicate across the shared namespace.
				p.Groups[0].ID = "e1"
				p.Rules[0].Outbound = "e1"
			},
		},
		{
			name: "group-member-does-not-resolve",
			mutate: func(p *Profile) {
				p.Groups[0].Members = []string{"e1", "ghost"}
			},
		},
		{
			name: "group-no-members",
			mutate: func(p *Profile) {
				p.Groups[0].Members = nil
			},
		},
		{
			name: "group-contains-itself",
			mutate: func(p *Profile) {
				p.Groups[0].Members = []string{"g1"}
			},
		},
		{
			name: "empty-server",
			mutate: func(p *Profile) {
				p.Endpoints[0].Server = ""
			},
		},
		{
			name: "port-out-of-range-high",
			mutate: func(p *Profile) {
				p.Endpoints[0].Port = 70000
			},
		},
		{
			name: "port-zero",
			mutate: func(p *Profile) {
				p.Endpoints[0].Port = 0
			},
		},
		{
			name: "empty-protocol",
			mutate: func(p *Profile) {
				p.Endpoints[0].Protocol = ""
			},
		},
		{
			name: "rule-targets-missing-outbound",
			mutate: func(p *Profile) {
				p.Rules[0].Outbound = "nope"
			},
		},
		{
			name: "more-than-one-default-rule",
			mutate: func(p *Profile) {
				p.Rules = append(p.Rules, Rule{ID: "r2", Default: true, Outbound: "g1"})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := storemodelconfig_goodProfile()
			tc.mutate(&p)
			if err := p.Validate(); err == nil {
				t.Fatalf("expected Validate to reject %q, got nil", tc.name)
			}
		})
	}
}

// TestStoremodelconfigValidateBuiltinOutbounds confirms direct/block (any case)
// resolve as rule targets without a matching id.
func TestStoremodelconfigValidateBuiltinOutbounds(t *testing.T) {
	for _, target := range []string{OutboundDirect, OutboundBlock, "DIRECT", "Block"} {
		p := storemodelconfig_goodProfile()
		p.Rules[0].Outbound = target
		if err := p.Validate(); err != nil {
			t.Fatalf("builtin outbound %q should validate, got: %v", target, err)
		}
	}
}

func TestStoremodelconfigEndpointByID(t *testing.T) {
	p := storemodelconfig_goodProfile()

	got := p.EndpointByID("e2")
	if got == nil {
		t.Fatal("EndpointByID(e2) returned nil")
	}
	if got.ID != "e2" {
		t.Fatalf("EndpointByID(e2) returned %q", got.ID)
	}
	// The returned pointer must alias the stored element (mutations stick).
	got.Name = "renamed"
	if p.Endpoints[1].Name != "renamed" {
		t.Fatal("EndpointByID should return a pointer into the profile, not a copy")
	}

	if miss := p.EndpointByID("ghost"); miss != nil {
		t.Fatalf("EndpointByID(ghost) should be nil, got %+v", miss)
	}
}

func TestStoremodelconfigGroupByID(t *testing.T) {
	p := storemodelconfig_goodProfile()

	got := p.GroupByID("g1")
	if got == nil {
		t.Fatal("GroupByID(g1) returned nil")
	}
	if got.ID != "g1" {
		t.Fatalf("GroupByID(g1) returned %q", got.ID)
	}
	got.Name = "renamed-group"
	if p.Groups[0].Name != "renamed-group" {
		t.Fatal("GroupByID should return a pointer into the profile, not a copy")
	}

	if miss := p.GroupByID("ghost"); miss != nil {
		t.Fatalf("GroupByID(ghost) should be nil, got %+v", miss)
	}
}

// TestStoremodelconfigValidateEmptyProfile confirms an empty profile is valid
// (no ids to clash, no members to resolve, no rules).
func TestStoremodelconfigValidateEmptyProfile(t *testing.T) {
	var p Profile
	if err := p.Validate(); err != nil {
		t.Fatalf("empty profile should validate, got: %v", err)
	}
}

// TestValidateWGRequiresPeerPublicKey: an enabled native-WireGuard endpoint with
// an empty peer_public_key PASSES `sing-box check` (empty key base64-decodes to
// nil at config-load) but FATALs at runtime when the endpoint starts, bringing
// ALL routing down AFTER the pre-apply check already passed. Validate must reject
// it so the apply fails safely (reachable via a wireguard:// link with no
// publickey=, a .conf [Peer] without PublicKey, or a raw POST /api/endpoints).
func TestValidateWGRequiresPeerPublicKey(t *testing.T) {
	wg := func(withPub bool) *Profile {
		params := map[string]any{"private_key": "PRIVKEY"}
		if withPub {
			params["peer_public_key"] = "PUBKEY"
		}
		return &Profile{Endpoints: []Endpoint{{
			ID: "wg", Name: "wg", Engine: EngineSingBox, Protocol: ProtoWireGuard,
			Server: "1.2.3.4", Port: 51820, Enabled: true, Params: params,
		}}}
	}
	if err := wg(false).Validate(); err == nil {
		t.Fatal("WG endpoint with empty peer_public_key must fail Validate (passes sing-box check but FATALs at runtime → bricks routing)")
	}
	if err := wg(true).Validate(); err != nil {
		t.Fatalf("WG endpoint with peer_public_key must pass Validate, got %v", err)
	}
}
