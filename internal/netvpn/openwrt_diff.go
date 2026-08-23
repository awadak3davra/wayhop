package netvpn

import (
	"fmt"
	"sort"
	"strings"
)

// openwrt_diff.go answers the question the operator's rule turns on: does the router's configuration
// right now match what the plan was computed against?
//
// The plan is built from a snapshot. Between that snapshot and the write, somebody can open LuCI and
// change the tunnel — and applying a plan computed against a config that no longer exists silently
// discards their edit. So the write path re-reads immediately before touching anything and refuses
// on any difference, rather than assuming the world held still.
//
// The same comparison serves the other end: after writing, the section is read back and compared
// against what was intended. "The commands exited 0" and "the configuration says what I meant" are
// separate claims, and only the second one is worth reporting.

// Difference is one field where two views of the same tunnel disagree. Field names are the uci
// option names, not Go field names, so a message can be acted on without a translation step.
type Difference struct {
	Field string
	Want  string
	Got   string
}

func (d Difference) String() string {
	return fmt.Sprintf("%s: want %q, device has %q", d.Field, d.Want, d.Got)
}

// DiffInterface compares two views of one tunnel and returns every field that differs, in a stable
// order so two runs produce the same report.
//
// The private key is compared but never echoed: a diff that prints key material into a log or an
// HTTP response has turned a safety check into a disclosure. Only presence and equality are said out
// loud.
func DiffInterface(want, got AWGInterface) []Difference {
	var out []Difference
	add := func(field, w, g string) {
		if w != g {
			out = append(out, Difference{Field: field, Want: w, Got: g})
		}
	}

	add("name", want.Name, got.Name)
	// The protocol, compared as itself. Without this row a protocol collision surfaces as
	// "interface: absent" or as a spurious addresses mismatch — true statements about the wrong thing,
	// which is how the operator ends up debugging the addresses of a tunnel whose real problem is that
	// it is the wrong kind of tunnel.
	add("proto", string(want.Proto.resolve()), string(got.Proto.resolve()))
	add("mtu", itoa(want.MTU), itoa(got.MTU))
	add("addresses", strings.Join(want.Addresses, " "), strings.Join(got.Addresses, " "))
	if want.PrivateKey != got.PrivateKey {
		out = append(out, Difference{
			Field: "private_key",
			Want:  redact(want.PrivateKey),
			Got:   redact(got.PrivateKey),
		})
	}

	// Obfuscation is compared over the UNION of both key sets. Iterating only over `want` would miss
	// a parameter present on the device and absent from the plan — which is precisely the shape of a
	// hand-edit in LuCI, the thing this comparison exists to catch.
	// Named under the protocol's own namespace, so a report about a WireGuard interface never invents
	// an `awg_` option that could not exist on it.
	wsc, _ := schemaFor(want.Proto)
	obfPrefix := wsc.ObfPrefix
	if obfPrefix == "" {
		obfPrefix = "obfuscation_"
	}
	for _, k := range unionKeys(want.Obfuscation, got.Obfuscation) {
		add(obfPrefix+k, want.Obfuscation[k], got.Obfuscation[k])
	}

	if len(want.Peers) != len(got.Peers) {
		add("peer count", itoa(len(want.Peers)), itoa(len(got.Peers)))
		return out // per-peer comparison below would be comparing different peers
	}
	for i := range want.Peers {
		w, g := want.Peers[i], got.Peers[i]
		p := fmt.Sprintf("peer%d.", i+1)
		add(p+"public_key", redact(w.PublicKey), redact(g.PublicKey))
		add(p+"endpoint_host", w.EndpointHost, g.EndpointHost)
		add(p+"endpoint_port", itoa(w.EndpointPort), itoa(g.EndpointPort))
		add(p+"persistent_keepalive", itoa(w.PersistentKeepalive), itoa(g.PersistentKeepalive))
		add(p+"allowed_ips", strings.Join(w.AllowedIPs, " "), strings.Join(g.AllowedIPs, " "))
		add(p+"description", w.Description, g.Description)
		// The switch that decides whether the peer runs at all. Comparing every other field and
		// not this one is how a verification reports a perfect match on a tunnel that is switched off.
		//
		// Only where the protocol HAS the switch. luci-proto-wireguard does not, so the renderer does
		// not write it there; comparing it anyway would report a difference the writer can never
		// resolve, and every apply would rewrite the interface trying.
		if wsc.PeerDisabled {
			add(p+"disabled", boolOpt(w.Disabled), boolOpt(g.Disabled))
		}
		if (w.PresharedKey == "") != (g.PresharedKey == "") {
			add(p+"preshared_key", redact(w.PresharedKey), redact(g.PresharedKey))
		}
	}
	return out
}

// redact reports a secret's presence and length without revealing it. Length is included because
// "absent" and "present but wrong" are different problems, and the length alone often says which.
func redact(s string) string {
	if s == "" {
		return "(absent)"
	}
	return fmt.Sprintf("(present, %d chars)", len(s))
}

func unionKeys(a, b map[string]string) []string {
	seen := map[string]bool{}
	for k := range a {
		seen[k] = true
	}
	for k := range b {
		seen[k] = true
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
