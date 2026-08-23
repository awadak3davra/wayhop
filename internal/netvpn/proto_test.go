package netvpn

import (
	"errors"
	"strings"
	"testing"
)

// The compatibility contract, and it has to be first: an interface built without a Proto renders
// exactly what it rendered before the field existed. Every caller in the tree predates it, including
// four tests in this package and the server's awgInterfaceFromEndpoint. If this fails, the field was
// not additive and something already shipped has quietly changed meaning.
func TestProto_ZeroValueStillRendersAmneziaWG(t *testing.T) {
	iface := AWGInterface{
		Name: "awg9", PrivateKey: "cHJpdmF0ZQ==", Addresses: []string{"10.0.0.30/32"},
		Obfuscation: map[string]string{"jc": "5"},
		Peers:       []AWGPeer{{PublicKey: "cHVibGlj", AllowedIPs: []string{"0.0.0.0/0"}}},
	}
	joined := strings.Join(RenderUCI(iface), "\n")
	for _, want := range []string{
		"uci set network.awg9.proto='amneziawg'",
		"uci set network.awg9.awg_jc='5'",
		"uci set network.awg9_peer1=amneziawg_awg9",
		"uci set network.awg9_peer1.disabled='0'",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("the zero Proto no longer renders %q:\n%s", want, joined)
		}
	}
}

// The second protocol, rendered as itself: proto, peer section type and NO obfuscation namespace.
func TestProto_WireGuardRendersItsOwnShape(t *testing.T) {
	iface := AWGInterface{
		Name: "wg0", Proto: ProtoWireGuard, PrivateKey: "cHJpdmF0ZQ==",
		Addresses: []string{"10.0.0.30/32"},
		Peers:     []AWGPeer{{PublicKey: "cHVibGlj", AllowedIPs: []string{"0.0.0.0/0"}}},
	}
	joined := strings.Join(RenderUCI(iface), "\n")
	if !strings.Contains(joined, "uci set network.wg0.proto='wireguard'") {
		t.Errorf("proto not written as wireguard:\n%s", joined)
	}
	if !strings.Contains(joined, "uci set network.wg0_peer1=wireguard_wg0") {
		t.Errorf("peer section type is not wireguard_wg0:\n%s", joined)
	}
	// luci-proto-wireguard has no per-peer disabled switch. Writing it would put an option there that
	// nothing reads, and the differ would then compare it on every apply forever.
	if strings.Contains(joined, ".disabled=") {
		t.Errorf("a `disabled` option was written for a protocol whose handler has no such control:\n%s", joined)
	}
	if strings.Contains(joined, "awg_") {
		t.Errorf("an amneziawg option namespace leaked into a wireguard interface:\n%s", joined)
	}
}

// The capability gate. The AX3000T has amneziawg and NOT wireguard — measured — so a plan that asks
// for a handler the router does not have must refuse, and say what to install.
func TestBuildPlanFor_RefusesAProtocolTheRouterCannotCarry(t *testing.T) {
	iface := AWGInterface{
		Name: "wg0", Proto: ProtoWireGuard, PrivateKey: "k",
		Peers: []AWGPeer{{PublicKey: "p", AllowedIPs: []string{"0.0.0.0/0"}}},
	}
	// A router with NEITHER handler: nothing to fall back to.
	_, err := BuildPlanFor(iface, RouterProtos{"ppp": true}, "", "", "")
	if err == nil {
		t.Fatal("a plan was built for a protocol with no netifd handler — it would show in LuCI and never come up")
	}
	for _, want := range []string{"wireguard.sh", "kmod-wireguard"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q, so it cannot be acted on: %v", want, err)
		}
	}
}

// The fallback, and the operator's actual case: a plain WireGuard endpoint on a router that carries
// amneziawg only. It is written as amneziawg with no obfuscation, which is plain WireGuard on the
// wire — and Intended must carry the RESOLVED protocol, or the post-write check compares amneziawg
// against wireguard, finds a difference, and reverts every single time.
func TestBuildPlanFor_CarriesWireGuardOnAmneziaWGAndSaysSo(t *testing.T) {
	iface := AWGInterface{
		Name: "wr_44284aea", Proto: ProtoWireGuard, PrivateKey: "cHJpdmF0ZQ==",
		Addresses: []string{"10.0.0.30/32"},
		Peers:     []AWGPeer{{PublicKey: "cHVibGlj", AllowedIPs: []string{"0.0.0.0/0"}}},
	}
	p, err := BuildPlanFor(iface, RouterProtos{"amneziawg": true}, "", "network.lan=interface\n", "")
	if err != nil {
		t.Fatalf("the fallback refused the endpoint it exists for: %v", err)
	}
	if p.Proto != ProtoAmneziaWG || p.RequestedProto != ProtoWireGuard || !p.Fallback {
		t.Fatalf("proto=%q requested=%q fallback=%v", p.Proto, p.RequestedProto, p.Fallback)
	}
	if p.Intended.Proto != ProtoAmneziaWG {
		t.Fatalf("Intended.Proto = %q — the read-back check would compare it against the device's "+
			"amneziawg, differ, and revert on every apply", p.Intended.Proto)
	}
	joined := strings.Join(p.Commands, "\n")
	if !strings.Contains(joined, "proto='amneziawg'") {
		t.Errorf("not written as amneziawg:\n%s", joined)
	}
	// `.awg_`, not `awg_`: the bare substring also matches the peer section TYPE
	// (`=amneziawg_wr_44284aea`), which is correct and required. Only an OPTION in that namespace
	// would put obfuscation on the wire. The first version of this assertion failed a correct plan.
	if strings.Contains(joined, ".awg_") {
		t.Errorf("an obfuscation parameter was written; the tunnel must be plain WireGuard on the wire:\n%s", joined)
	}
	var said bool
	for _, w := range p.Warnings {
		if strings.Contains(w, "plain wireguard on the wire") || strings.Contains(strings.ToLower(w), "plain wireguard on the wire") {
			said = true
		}
	}
	if !said {
		t.Fatalf("the protocol was silently relabelled; warnings were %v", p.Warnings)
	}
}

// And never the other way. Dropping obfuscation to fit an AmneziaWG profile onto a stock wireguard
// handler produces a tunnel that is up, correct-looking, and whose peer will not answer.
func TestBuildPlanFor_NeverDowngradesAmneziaWGOntoWireGuard(t *testing.T) {
	iface := AWGInterface{
		Name: "awg0", Proto: ProtoAmneziaWG, PrivateKey: "k",
		Obfuscation: map[string]string{"jc": "5", "h1": "500000000-900000000"},
		Peers:       []AWGPeer{{PublicKey: "p", AllowedIPs: []string{"0.0.0.0/0"}}},
	}
	if _, err := BuildPlanFor(iface, RouterProtos{"wireguard": true}, "", "", ""); err == nil {
		t.Fatal("an obfuscated profile was accepted onto a router with no amneziawg handler")
	}
}

// A protocol with no obfuscation namespace must refuse parameters rather than drop them.
func TestBuildPlanFor_RefusesObfuscationItCannotWrite(t *testing.T) {
	iface := AWGInterface{
		Name: "wg0", Proto: ProtoWireGuard, PrivateKey: "k",
		Obfuscation: map[string]string{"jc": "5"},
		Peers:       []AWGPeer{{PublicKey: "p", AllowedIPs: []string{"0.0.0.0/0"}}},
	}
	_, err := BuildPlanFor(iface, RouterProtos{"wireguard": true}, "", "", "")
	if err == nil {
		t.Fatal("obfuscation parameters were silently dropped onto a protocol that cannot carry them")
	}
	if !strings.Contains(err.Error(), "obfuscation") {
		t.Errorf("the refusal does not name the reason: %v", err)
	}
}

// An unprobed router is unknown, not supported. Writing anyway can create a LuCI-visible section
// whose handler does not exist, so the native path must fail closed and let the caller return 503.
func TestBuildPlanFor_AnUnprobedRouterFailsClosed(t *testing.T) {
	iface := AWGInterface{
		Name: "awg0", PrivateKey: "k",
		Peers: []AWGPeer{{PublicKey: "p", AllowedIPs: []string{"0.0.0.0/0"}}},
	}
	if _, err := BuildPlanFor(iface, nil, "", "", ""); !errors.Is(err, ErrRouterProtosUnprobed) {
		t.Fatalf("an unprobed router was not refused as unknown: %v", err)
	}
	if (RouterProtos{}).Probed() != true || (RouterProtos(nil)).Probed() != false {
		t.Fatal("Probed does not distinguish an empty set from an unread one")
	}
}

func TestBuildPlanWithoutCapabilityObservationFailsClosed(t *testing.T) {
	iface := AWGInterface{
		Name: "awg0", PrivateKey: "k",
		Peers: []AWGPeer{{PublicKey: "p", AllowedIPs: []string{"0.0.0.0/0"}}},
	}
	if _, err := BuildPlan(iface, "", "", ""); !errors.Is(err, ErrRouterProtosUnprobed) {
		t.Fatalf("legacy planner bypassed the native capability probe: %v", err)
	}
}
