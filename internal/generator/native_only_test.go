package generator

import (
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// ep builds a synthetic endpoint with the given engine/protocol/enabled flag. Params are
// supplied where a downstream consumer would need them (e.g. EngineExternal's interface),
// but EndpointNeedsSingbox itself only reads Engine + Protocol, so most are minimal.
func ep(id string, engine model.Engine, proto model.Protocol, enabled bool) model.Endpoint {
	e := model.Endpoint{
		ID:       id,
		Name:     id,
		Engine:   engine,
		Protocol: proto,
		Server:   "192.0.2.1",
		Port:     443,
		Enabled:  enabled,
	}
	if engine == model.EngineExternal {
		e.Params = map[string]any{"interface": "awg0"}
	}
	return e
}

func TestEndpointNeedsSingbox(t *testing.T) {
	tests := []struct {
		name string
		e    *model.Endpoint
		want bool
	}{
		// Kernel-native engines: never need sing-box.
		{"external", ptr(ep("x", model.EngineExternal, "", true)), false},
		{"amneziawg", ptr(ep("a", model.EngineAmneziaWG, model.ProtoAmneziaWG, true)), false},
		{"amneziawg-wg-proto", ptr(ep("a2", model.EngineAmneziaWG, model.ProtoWireGuard, true)), false},
		// Plain WireGuard on the sing-box engine: a kernel WG data path can carry it.
		{"singbox-wireguard", ptr(ep("wg", model.EngineSingBox, model.ProtoWireGuard, true)), false},

		// sing-box proxy protocols: only the core can carry them.
		{"vless", ptr(ep("v", model.EngineSingBox, model.ProtoVLESS, true)), true},
		{"vmess", ptr(ep("vm", model.EngineSingBox, model.ProtoVMess, true)), true},
		{"trojan", ptr(ep("t", model.EngineSingBox, model.ProtoTrojan, true)), true},
		{"shadowsocks", ptr(ep("ss", model.EngineSingBox, model.ProtoShadowsocks, true)), true},
		{"hysteria2", ptr(ep("h", model.EngineSingBox, model.ProtoHysteria2, true)), true},
		{"tuic", ptr(ep("tu", model.EngineSingBox, model.ProtoTUIC, true)), true},
		// socks/http on the sing-box engine are still real sing-box outbounds → need core.
		{"socks", ptr(ep("sk", model.EngineSingBox, model.ProtoSOCKS, true)), true},
		{"http", ptr(ep("ht", model.EngineSingBox, model.ProtoHTTP, true)), true},

		// olcRTC + other userspace engines: chained-SOCKS via sing-box → need core.
		{"olcrtc", ptr(ep("o", model.EngineOlcRTC, model.ProtoOlcRTC, true)), true},
		{"openvpn", ptr(ep("ov", model.EngineOpenVPN, "", true)), true},
		{"xray", ptr(ep("xr", model.EngineXray, model.ProtoVLESS, true)), true},
		{"mihomo", ptr(ep("mh", model.EngineMihomo, model.ProtoVMess, true)), true},

		// Enabled flag is NOT consulted by the per-endpoint capability question.
		{"disabled-vless-still-needs", ptr(ep("dv", model.EngineSingBox, model.ProtoVLESS, false)), true},
		{"disabled-external-still-native", ptr(ep("dx", model.EngineExternal, "", false)), false},

		// nil is conservative → needs sing-box.
		{"nil", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EndpointNeedsSingbox(tt.e); got != tt.want {
				t.Errorf("EndpointNeedsSingbox(%s) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestProfileNativeOnly(t *testing.T) {
	tests := []struct {
		name string
		p    *model.Profile
		want bool
	}{
		{
			name: "all-external",
			p: &model.Profile{Endpoints: []model.Endpoint{
				ep("x1", model.EngineExternal, "", true),
				ep("x2", model.EngineExternal, "", true),
			}},
			want: true,
		},
		{
			name: "all-amneziawg",
			p: &model.Profile{Endpoints: []model.Endpoint{
				ep("a1", model.EngineAmneziaWG, model.ProtoAmneziaWG, true),
				ep("a2", model.EngineAmneziaWG, model.ProtoAmneziaWG, true),
			}},
			want: true,
		},
		{
			name: "mixed-external-and-awg",
			p: &model.Profile{Endpoints: []model.Endpoint{
				ep("x1", model.EngineExternal, "", true),
				ep("a1", model.EngineAmneziaWG, model.ProtoAmneziaWG, true),
			}},
			want: true,
		},
		{
			name: "external-plus-plain-wireguard",
			p: &model.Profile{Endpoints: []model.Endpoint{
				ep("x1", model.EngineExternal, "", true),
				ep("wg", model.EngineSingBox, model.ProtoWireGuard, true),
			}},
			want: true,
		},
		{
			name: "single-enabled-external",
			p: &model.Profile{Endpoints: []model.Endpoint{
				ep("x1", model.EngineExternal, "", true),
			}},
			want: true,
		},

		// Any enabled sing-box proxy protocol → NOT native-only.
		{
			name: "native-plus-one-vless",
			p: &model.Profile{Endpoints: []model.Endpoint{
				ep("x1", model.EngineExternal, "", true),
				ep("v", model.EngineSingBox, model.ProtoVLESS, true),
			}},
			want: false,
		},
		{
			name: "vmess-only",
			p: &model.Profile{Endpoints: []model.Endpoint{
				ep("vm", model.EngineSingBox, model.ProtoVMess, true),
			}},
			want: false,
		},
		{
			name: "trojan-only",
			p: &model.Profile{Endpoints: []model.Endpoint{
				ep("t", model.EngineSingBox, model.ProtoTrojan, true),
			}},
			want: false,
		},
		{
			name: "shadowsocks-only",
			p: &model.Profile{Endpoints: []model.Endpoint{
				ep("ss", model.EngineSingBox, model.ProtoShadowsocks, true),
			}},
			want: false,
		},
		{
			name: "hysteria2-only",
			p: &model.Profile{Endpoints: []model.Endpoint{
				ep("h", model.EngineSingBox, model.ProtoHysteria2, true),
			}},
			want: false,
		},
		{
			name: "tuic-only",
			p: &model.Profile{Endpoints: []model.Endpoint{
				ep("tu", model.EngineSingBox, model.ProtoTUIC, true),
			}},
			want: false,
		},
		{
			name: "olcrtc-not-native",
			p: &model.Profile{Endpoints: []model.Endpoint{
				ep("o", model.EngineOlcRTC, model.ProtoOlcRTC, true),
			}},
			want: false,
		},

		// Empty / no-enabled-endpoints → NOT native-only (nothing to route).
		{
			name: "empty-profile",
			p:    &model.Profile{},
			want: false,
		},
		{
			name: "all-disabled",
			p: &model.Profile{Endpoints: []model.Endpoint{
				ep("x1", model.EngineExternal, "", false),
				ep("a1", model.EngineAmneziaWG, model.ProtoAmneziaWG, false),
			}},
			want: false,
		},

		// Disabled sing-box endpoints are IGNORED: a profile that is native-only among its
		// ENABLED endpoints stays native-only even with a disabled vless present.
		{
			name: "disabled-singbox-ignored",
			p: &model.Profile{Endpoints: []model.Endpoint{
				ep("x1", model.EngineExternal, "", true),
				ep("v", model.EngineSingBox, model.ProtoVLESS, false),
			}},
			want: true,
		},
		// Conversely, a disabled native endpoint does not rescue an enabled proxy one.
		{
			name: "disabled-native-enabled-vless",
			p: &model.Profile{Endpoints: []model.Endpoint{
				ep("x1", model.EngineExternal, "", false),
				ep("v", model.EngineSingBox, model.ProtoVLESS, true),
			}},
			want: false,
		},

		{
			name: "nil-profile",
			p:    nil,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ProfileNativeOnly(tt.p); got != tt.want {
				t.Errorf("ProfileNativeOnly(%s) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestProtocolNeedsSingbox(t *testing.T) {
	// The floor must equal platform.singboxRequired exactly: vless/vmess/trojan/
	// shadowsocks/hysteria2/tuic in, everything else out.
	in := []model.Protocol{
		model.ProtoVLESS, model.ProtoVMess, model.ProtoTrojan,
		model.ProtoShadowsocks, model.ProtoHysteria2, model.ProtoTUIC,
	}
	for _, p := range in {
		if !ProtocolNeedsSingbox(p) {
			t.Errorf("ProtocolNeedsSingbox(%s) = false, want true", p)
		}
	}
	out := []model.Protocol{
		model.ProtoWireGuard, model.ProtoAmneziaWG, model.ProtoOlcRTC,
		model.ProtoSOCKS, model.ProtoHTTP, "",
	}
	for _, p := range out {
		if ProtocolNeedsSingbox(p) {
			t.Errorf("ProtocolNeedsSingbox(%s) = true, want false", p)
		}
	}
}

// TestSingboxFloorLockstepWithPlatform enforces the invariant native_only.go documents but
// no test previously checked across packages: the generator's sing-box protocol floor must
// equal platform.Capabilities.SingboxRequired EXACTLY. A drift here is a real correctness bug —
// the dangerous direction (a protocol platform requires the core for, but the classifier treats
// as native) makes DatapathNativeOnly skip sing-box and black-hole that protocol's traffic.
// (TestProtocolNeedsSingbox only checks generator against a hardcoded list, so it can't catch a
// platform-side drift.)
func TestSingboxFloorLockstepWithPlatform(t *testing.T) {
	platformFloor := platform.DetectCapabilities().SingboxRequired // SingboxRequired is host-independent
	// (A) the black-hole-risk direction: every protocol platform requires the core for must
	// also force the core in the classifier.
	for _, p := range platformFloor {
		if !ProtocolNeedsSingbox(model.Protocol(p)) {
			t.Errorf("platform requires sing-box for %q but ProtocolNeedsSingbox=false — DatapathNativeOnly would wrongly skip the core for it (drift)", p)
		}
	}
	// (B) equal sizes: (A) gives platform ⊆ generator-floor, so equal sizes ⇒ equal sets — no
	// protocol on either side the other lacks.
	got := SingboxRequiredProtocols()
	if len(got) != len(platformFloor) {
		t.Errorf("sing-box floor size drift: generator=%d %v, platform=%d %v", len(got), got, len(platformFloor), platformFloor)
	}
}

// TestDatapathNativeOnly exercises the FULL "skip sing-box" sufficiency check. The bias is
// fail-safe: true only when fast mode + all-native endpoints + WAN/direct default + nothing
// surviving into sing-box; false on ANY ambiguity. Profiles are synthetic.
func TestDatapathNativeOnly(t *testing.T) {
	// natives: a single enabled kernel-native endpoint, the minimal native-only profile base.
	natives := func() []model.Endpoint {
		return []model.Endpoint{ep("x1", model.EngineExternal, "", true)}
	}

	tests := []struct {
		name string
		p    *model.Profile
		mode string
		want bool
	}{
		// Happy path: fast + all-native + no rules (kernel default = WAN) → skip the core.
		{
			name: "fast-all-native-no-rules",
			p:    &model.Profile{Endpoints: natives()},
			mode: "fast",
			want: true,
		},
		// Same profile but a non-fast mode keeps the TUN/proxy datapath → keep the core.
		{
			name: "hybrid-all-native",
			p:    &model.Profile{Endpoints: natives()},
			mode: "hybrid",
			want: false,
		},
		{
			name: "tun-all-native",
			p:    &model.Profile{Endpoints: natives()},
			mode: "tun",
			want: false,
		},
		{
			name: "mixed-all-native",
			p:    &model.Profile{Endpoints: natives()},
			mode: "mixed",
			want: false,
		},
		{
			name: "empty-mode-all-native",
			p:    &model.Profile{Endpoints: natives()},
			mode: "",
			want: false,
		},
		{
			name: "unknown-mode-all-native",
			p:    &model.Profile{Endpoints: natives()},
			mode: "weird",
			want: false,
		},

		// A default rule egressing direct/"" is fine (kernel default = WAN).
		{
			name: "fast-default-direct",
			p: &model.Profile{
				Endpoints: natives(),
				Rules:     []model.Rule{{ID: "d", Default: true, Outbound: model.OutboundDirect}},
			},
			mode: "fast",
			want: true,
		},
		{
			name: "fast-default-empty-outbound",
			p: &model.Profile{
				Endpoints: natives(),
				Rules:     []model.Rule{{ID: "d", Default: true, Outbound: ""}},
			},
			mode: "fast",
			want: true,
		},
		// canonicalOutbound folds casing: "Direct" still counts as the direct builtin.
		{
			name: "fast-default-direct-cased",
			p: &model.Profile{
				Endpoints: natives(),
				Rules:     []model.Rule{{ID: "d", Default: true, Outbound: "Direct"}},
			},
			mode: "fast",
			want: true,
		},
		// A default routed out a tunnel: no kernel default route exists → keep the core.
		{
			name: "fast-default-to-tunnel",
			p: &model.Profile{
				Endpoints: natives(),
				Rules:     []model.Rule{{ID: "d", Default: true, Outbound: "x1"}},
			},
			mode: "fast",
			want: false,
		},
		// A Block default implies a surviving reject-final → conservative keep.
		{
			name: "fast-default-block",
			p: &model.Profile{
				Endpoints: natives(),
				Rules:     []model.Rule{{ID: "d", Default: true, Outbound: model.OutboundBlock}},
			},
			mode: "fast",
			want: false,
		},

		// A pure-IP rule to a kernel egress is dropped by pbr (hybridReachable stays empty) →
		// still native-only.
		{
			name: "fast-ip-rule-to-kernel-egress",
			p: &model.Profile{
				Endpoints: natives(),
				Rules: []model.Rule{{
					ID: "r", IPCIDR: []string{"198.51.100.0/24"}, Outbound: "x1",
				}},
			},
			mode: "fast",
			want: true,
		},
		// A pure-IP rule to direct: builtin, never a hybridReachable root → still native-only.
		{
			name: "fast-ip-rule-to-direct",
			p: &model.Profile{
				Endpoints: natives(),
				Rules: []model.Rule{{
					ID: "r", IPCIDR: []string{"198.51.100.0/24"}, Outbound: model.OutboundDirect,
				}},
			},
			mode: "fast",
			want: true,
		},
		// A surviving domain rule (pbr can't kernel-route domains) → keep the core.
		{
			name: "fast-domain-rule-to-kernel-egress",
			p: &model.Profile{
				Endpoints: natives(),
				Rules: []model.Rule{{
					ID: "r", Domain: []string{"example.com"}, Outbound: "x1",
				}},
			},
			mode: "fast",
			want: false,
		},
		{
			name: "fast-domain-suffix-rule-to-direct",
			p: &model.Profile{
				Endpoints: natives(),
				Rules: []model.Rule{{
					ID: "r", DomainSuffix: []string{".example.com"}, Outbound: model.OutboundDirect,
				}},
			},
			mode: "fast",
			want: false,
		},
		{
			name: "fast-geoip-rule",
			p: &model.Profile{
				Endpoints: natives(),
				Rules: []model.Rule{{
					ID: "r", GeoIP: []string{"ru"}, Outbound: "x1",
				}},
			},
			mode: "fast",
			want: false,
		},
		// A port matcher makes pbr diverge (no port concept) → rule survives → keep the core.
		{
			name: "fast-ip-rule-with-port",
			p: &model.Profile{
				Endpoints: natives(),
				Rules: []model.Rule{{
					ID: "r", IPCIDR: []string{"198.51.100.0/24"}, Port: []int{443}, Outbound: "x1",
				}},
			},
			mode: "fast",
			want: false,
		},

		// Routing lists: a pure-IP manual list to a kernel egress is pbr-routed → native-only.
		{
			name: "fast-ip-only-manual-list-to-kernel",
			p: &model.Profile{
				Endpoints: natives(),
				RoutingLists: []model.RoutingList{{
					ID: "l", Name: "l", Enabled: true,
					Manual: []string{"203.0.113.0/24"}, Outbound: "x1",
				}},
			},
			mode: "fast",
			want: true,
		},
		// A manual list containing a domain entry can't be kernel-routed → keep the core.
		{
			name: "fast-manual-list-with-domain",
			p: &model.Profile{
				Endpoints: natives(),
				RoutingLists: []model.RoutingList{{
					ID: "l", Name: "l", Enabled: true,
					Manual: []string{"example.com"}, Outbound: "x1",
				}},
			},
			mode: "fast",
			want: false,
		},
		// A remote Source list is a sing-box domain rule_set → keep the core.
		{
			name: "fast-remote-source-list",
			p: &model.Profile{
				Endpoints: natives(),
				RoutingLists: []model.RoutingList{{
					ID: "l", Name: "l", Enabled: true,
					Source: "https://example.com/list.srs", Outbound: "x1",
				}},
			},
			mode: "fast",
			want: false,
		},
		// A disabled list is ignored even if it would otherwise force the core.
		{
			name: "fast-disabled-domain-list-ignored",
			p: &model.Profile{
				Endpoints: natives(),
				RoutingLists: []model.RoutingList{{
					ID: "l", Name: "l", Enabled: false,
					Source: "https://example.com/list.srs", Outbound: "x1",
				}},
			},
			mode: "fast",
			want: true,
		},

		// A profile that is NOT native-only at the endpoint floor → false regardless of mode.
		{
			name: "fast-with-one-vless",
			p: &model.Profile{Endpoints: []model.Endpoint{
				ep("x1", model.EngineExternal, "", true),
				ep("v", model.EngineSingBox, model.ProtoVLESS, true),
			}},
			mode: "fast",
			want: false,
		},
		// A rule pointed at a proxy outbound survives into sing-box → keep the core.
		{
			name: "fast-rule-to-vless",
			p: &model.Profile{
				Endpoints: []model.Endpoint{
					ep("x1", model.EngineExternal, "", true),
					ep("v", model.EngineSingBox, model.ProtoVLESS, true),
				},
				Rules: []model.Rule{{
					ID: "r", IPCIDR: []string{"198.51.100.0/24"}, Outbound: "v",
				}},
			},
			mode: "fast",
			want: false,
		},

		// Ambiguity → fail-safe false.
		{
			name: "nil-profile",
			p:    nil,
			mode: "fast",
			want: false,
		},
		{
			name: "empty-profile",
			p:    &model.Profile{},
			mode: "fast",
			want: false,
		},
		{
			name: "all-disabled-endpoints",
			p: &model.Profile{Endpoints: []model.Endpoint{
				ep("x1", model.EngineExternal, "", false),
			}},
			mode: "fast",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DatapathNativeOnly(tt.p, tt.mode); got != tt.want {
				t.Errorf("DatapathNativeOnly(%s, %q) = %v, want %v", tt.name, tt.mode, got, tt.want)
			}
		})
	}
}

// ptr returns a pointer to a copy of the endpoint (test helper for table rows).
func ptr(e model.Endpoint) *model.Endpoint { return &e }

// TestDatapathNativeOnly_V6External pins the v4-only-External guard (review finding):
// pbr strips IPv6 for EngineExternal egresses, so a v6 carve-out coexisting with an
// External endpoint must KEEP sing-box (else that v6 traffic is routed by neither plane
// once the core stops). A v4-only carve-out to the same External egress stays native-only.
func TestDatapathNativeOnly_V6External(t *testing.T) {
	ext := model.Endpoint{ID: "ext0", Name: "ext0", Engine: model.EngineExternal, Enabled: true, Params: map[string]any{"interface": "awg0"}}
	mk := func(manual, cache []string) *model.Profile {
		return &model.Profile{
			Endpoints:    []model.Endpoint{ext},
			RoutingLists: []model.RoutingList{{ID: "l", Name: "l", Enabled: true, Outbound: "ext0", Manual: manual, CIDRCache: cache}},
		}
	}
	if !DatapathNativeOnly(mk([]string{"198.51.100.0/24"}, nil), "fast") {
		t.Error("v4-only carve-out to an External egress should stay native-only")
	}
	if DatapathNativeOnly(mk([]string{"2001:db8::/32"}, nil), "fast") {
		t.Error("v6 Manual carve-out + External endpoint must keep sing-box (pbr is v4-only for External)")
	}
	if DatapathNativeOnly(mk([]string{"198.51.100.0/24"}, []string{"2001:db8:1::/48"}), "fast") {
		t.Error("v6 in CIDRCache + External endpoint must keep sing-box")
	}
	pr := mk([]string{"198.51.100.0/24"}, nil)
	pr.Rules = []model.Rule{{ID: "r", IPCIDR: []string{"2001:db8:2::/48"}, Outbound: model.OutboundDirect}}
	if DatapathNativeOnly(pr, "fast") {
		t.Error("v6 IPCIDR rule + External endpoint must keep sing-box")
	}
}
