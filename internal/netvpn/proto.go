package netvpn

import (
	"errors"
	"fmt"
)

// ErrRouterProtosUnprobed means WayHop could not establish which netifd protocol handlers the
// router can execute. Native writes fail closed in this state: a UCI section whose handler is absent
// looks configured in LuCI but never creates a tunnel.
var ErrRouterProtosUnprobed = errors.New("router netifd protocol handlers were not probed")

// proto.go is the one place a native protocol's name, its peer-section type and its option namespace
// are spelled. Everything else in this package asks the table.
//
// The writer spoke only AmneziaWG until now, with `amneziawg`, `amneziawg_<iface>` and `awg_` written
// as literals in the renderer, the parser and the differ. A WireGuard endpoint — which is what the
// operator's panel actually holds — was refused at the door.
//
// What makes this more than a second row in a table is the device. Measured read-only on the
// operator's AX3000T (OpenWrt 25.12.2, a router in daily use):
//
//	installed: amneziawg-tools, kmod-amneziawg, luci-proto-amneziawg
//	ABSENT:    kmod-wireguard, wireguard-tools, luci-proto-wireguard
//
// So writing `proto='wireguard'` there would produce a section netifd has no handler for: LuCI shows
// the interface, netifd can never bring it up, and the operator has a tunnel that looks configured
// and carries nothing. A protocol table alone would do exactly that. The router has to be ASKED what
// it can carry — see RouterProtos — and the answer has to be consulted before anything is rendered.

// Proto is a native OpenWrt protocol this package can render.
type Proto string

const (
	// ProtoAmneziaWG is the obfuscating WireGuard fork. It is the zero value's meaning.
	ProtoAmneziaWG Proto = "amneziawg"
	// ProtoWireGuard is stock kernel WireGuard.
	ProtoWireGuard Proto = "wireguard"
)

// resolve maps the zero value onto AmneziaWG.
//
// This is the compatibility contract for every caller written before the field existed: an
// AWGInterface built without a Proto renders exactly the bytes it rendered before — proto='amneziawg',
// amneziawg_<iface> peer sections, awg_* options. There is a test that pins it, because "the default
// is what it always was" is the kind of claim that quietly stops being true.
func (p Proto) resolve() Proto {
	if p == "" {
		return ProtoAmneziaWG
	}
	return p
}

// protoSchema is everything that differs between two native protocols in /etc/config/network.
type protoSchema struct {
	Name Proto
	// PeerType prefixes the peer section's TYPE: `config amneziawg_awg0` / `config wireguard_wg0`.
	PeerType string
	// ObfPrefix namespaces the obfuscation options. Empty means the protocol has none, and any
	// option in another protocol's namespace found on such a section is stale rather than owned.
	ObfPrefix string
	// PeerDisabled records whether the per-peer on/off switch exists in this protocol's LuCI proto
	// handler. It does NOT exist in luci-proto-wireguard — that is written down in openwrt_write.go's
	// AWGPeer.Disabled comment, discovered the hard way — so writing it on a wireguard peer would put
	// an option there that nothing reads and the differ would then compare forever.
	PeerDisabled bool
	// Handler is the netifd handler this protocol needs at /lib/netifd/proto/<Handler>.
	Handler string
	// Packages is what to install when the handler is missing, named so a refusal can be acted on.
	Packages string
}

var protoSchemas = map[Proto]protoSchema{
	ProtoAmneziaWG: {
		Name: ProtoAmneziaWG, PeerType: "amneziawg_", ObfPrefix: "awg_", PeerDisabled: true,
		Handler: "amneziawg.sh", Packages: "kmod-amneziawg amneziawg-tools luci-proto-amneziawg",
	},
	ProtoWireGuard: {
		Name: ProtoWireGuard, PeerType: "wireguard_", ObfPrefix: "", PeerDisabled: false,
		Handler: "wireguard.sh", Packages: "kmod-wireguard wireguard-tools luci-proto-wireguard",
	},
}

// schemaFor returns the schema for p (zero value resolved), and whether p is one this package renders.
func schemaFor(p Proto) (protoSchema, bool) {
	s, ok := protoSchemas[p.resolve()]
	return s, ok
}

// isTunnelProto reports whether a proto value found on a device section is one of ours. The parser
// uses it as an ALLOW-LIST: `proto='static'` and `proto='dhcp'` sections must stay invisible to this
// package, and "any proto with peers" would sweep them in the day something else grows peers.
func isTunnelProto(p Proto) bool {
	_, ok := protoSchemas[p]
	return ok // NOT p.resolve(): an empty proto on a device section is not an AmneziaWG tunnel
}

// RouterProtos is the set of netifd protocol handlers a router actually has, keyed by bare name
// ("amneziawg", "wireguard"). It is the answer to "what can this box carry", read from
// /lib/netifd/proto/*.sh — netifd's shell dispatcher sources those files, so a protocol whose script
// is absent has no proto_<name>_setup to call.
//
// nil means NOT PROBED, which is different from "probed and empty". Both fail closed for a native
// write, but for different reasons: nil is an unavailable probe that may be retried; an empty
// non-nil set proves that no supported handler exists on this router.
type RouterProtos map[string]bool

// Has reports whether the router carries the handler for p. Always false for a nil set — callers must
// ask Probed first, and the gate below does.
func (r RouterProtos) Has(p Proto) bool { return r != nil && r[string(p.resolve())] }

// Probed reports whether the handler set was actually read off a router.
func (r RouterProtos) Probed() bool { return r != nil }

// resolveProto decides which protocol will actually be written for a requested one, given what the
// router can carry. It returns the resolved protocol, whether that is a fallback, and an error when
// there is no honest way to write the request at all.
//
// The one fallback: a plain WireGuard endpoint on a router that has amneziawg and not wireguard is
// carried on the amneziawg proto. That is not a trick — the amneziawg kernel module is a WireGuard
// superset, which this tree already relies on in two other places: internal/platform/capabilities.go
// records "the amneziawg kmod is a WireGuard superset (configure with zero obfuscation = plain WG)",
// and internal/keenetic/nativevpn.go already feeds both an AmneziaWG engine and a WireGuard endpoint
// into the same native primitive, emitting no obfuscation arguments for the latter. With NO
// obfuscation option written, what goes on the wire is plain WireGuard.
//
// The reverse is refused and always will be. Dropping obfuscation to fit an AmneziaWG profile onto a
// stock wireguard handler produces a tunnel whose peer rejects the un-obfuscated handshake — a
// tunnel that is up, correct-looking, and dead.
func resolveProto(want Proto, protos RouterProtos) (Proto, bool, error) {
	w := want.resolve()
	if _, ok := schemaFor(w); !ok {
		return "", false, fmt.Errorf("%q is not a protocol this writer can render", string(w))
	}
	if !protos.Probed() {
		return "", false, fmt.Errorf("%w; refusing to write proto=%q unverified", ErrRouterProtosUnprobed, w)
	}
	if protos.Has(w) {
		return w, false, nil
	}
	if w == ProtoWireGuard && protos.Has(ProtoAmneziaWG) {
		return ProtoAmneziaWG, true, nil
	}
	s, _ := schemaFor(w)
	return "", false, fmt.Errorf(
		"this router has no netifd handler for %s (/lib/netifd/proto/%s is absent), so an interface "+
			"with proto='%s' would be written, shown in LuCI, and never brought up; install %s",
		string(w), s.Handler, string(w), s.Packages)
}
