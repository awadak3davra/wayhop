package keenetic

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"velinx/internal/model"
	"velinx/internal/util"
)

// ascBase is the positional order of the AWG 1.x obfuscation params on KeeneticOS's
// `wireguard asc` command (the 9-arg form validated live on the Hopper SE). ascExt are the
// AWG-2.0 additions (S3/S4 + the I1-I5 hex magic headers), appended only when present.
// ⚠️ The exact KeeneticOS arg ORDER for the 2.0 extension still needs device validation;
// the 9-arg base is confirmed.
var ascBase = []string{"jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"}
var ascExt = []string{"s3", "s4", "i1", "i2", "i3", "i4", "i5"}

// WireguardOpts tune the generated native interface.
type WireguardOpts struct {
	Index       int    // the WireguardN slot
	Metric      int    // `ip global N` routing priority (the failover tier; lower = preferred). 0 → 1000.
	MTU         int    // `ip mtu`; 0 → use the endpoint's mtu param, else NDM default
	PingProfile string // optional `ping-check profile <name>` (native health-check failover)
}

// WireguardCommands renders the NDM command sequence that configures a native KeeneticOS
// `interface WireguardN` from a Velinx AmneziaWG/WireGuard endpoint — the heart of the
// native-first backend (the router runs the tunnel in-kernel, leveraging HW crypto, instead
// of a userspace sing-box/awg-quick tunnel). The lines mirror the live running-config
// structure validated on the Hopper SE; the apply layer submits them over RCI `/rci/parse`.
// PURE — no device I/O. Returns an error for a non-WG/AWG endpoint or missing keys.
func WireguardCommands(e model.Endpoint, o WireguardOpts) ([]string, error) {
	isAWG := e.Engine == model.EngineAmneziaWG
	isWG := e.Engine == model.EngineSingBox && e.Protocol == model.ProtoWireGuard
	if !isAWG && !isWG {
		return nil, fmt.Errorf("endpoint %q is not a WireGuard/AmneziaWG kind (engine=%s proto=%s)", e.ID, e.Engine, e.Protocol)
	}
	p := e.Params
	priv, peer := str(p, "private_key"), str(p, "peer_public_key")
	if priv == "" || peer == "" {
		return nil, fmt.Errorf("endpoint %q: missing private_key/peer_public_key", e.ID)
	}
	if e.Server == "" || e.Port == 0 {
		return nil, fmt.Errorf("endpoint %q: missing server/port", e.ID)
	}
	name := e.Name
	if name == "" {
		name = e.ID
	}
	metric := o.Metric
	if metric <= 0 {
		metric = 1000
	}

	var c []string
	add := func(s string) { c = append(c, s) }
	add(fmt.Sprintf("interface Wireguard%d", o.Index))
	add("description " + ndmQuote(name))
	add("security-level public")

	hasV6 := false
	for _, a := range util.LocalAddrs(p) {
		am, err := cidrToAddrMask(a)
		if err != nil {
			continue
		}
		add("ip address " + am)
		if pfx, e2 := netip.ParsePrefix(a); e2 == nil && pfx.Addr().Is6() {
			hasV6 = true
		}
	}
	if o.MTU > 0 {
		add("ip mtu " + strconv.Itoa(o.MTU))
	} else if m := numStr(p["mtu"]); m != "" { // mtu param may be int (JSON number) or string
		add("ip mtu " + m)
	}
	add("ip global " + strconv.Itoa(metric))
	add("ip tcp adjust-mss pmtu")
	if o.PingProfile != "" {
		add("ping-check profile " + o.PingProfile)
	}
	add("wireguard private-key " + priv)
	if asc := ascArgs(p); asc != "" {
		add("wireguard asc " + asc)
	}
	add("wireguard peer " + peer)
	add("    endpoint " + e.Server + ":" + strconv.Itoa(e.Port))
	if ka := numStr(p["persistent_keepalive"]); ka != "" {
		add("    keepalive-interval " + ka)
	}
	if psk := str(p, "pre_shared_key"); psk != "" {
		add("    preshared-key " + psk)
	}
	// Gateway tunnels carry everything → AllowedIPs 0.0.0.0/0 (KeeneticOS form "0.0.0.0
	// 0.0.0.0"), plus ::/0 ("`:: 0`") when the interface has a v6 address.
	add("    allow-ips 0.0.0.0 0.0.0.0")
	if hasV6 {
		add("    allow-ips :: 0")
	}
	add("    connect")
	add("up")
	return c, nil
}

// ascArgs builds the `wireguard asc` argument string from the model's obfuscation params,
// or "" when the 9-arg base is incomplete (a plain WireGuard endpoint → no asc line).
func ascArgs(p map[string]any) string {
	var args []string
	for _, k := range ascBase {
		v := numStr(p[k])
		if v == "" {
			return "" // not a full AWG param set → plain WireGuard (no obfuscation)
		}
		args = append(args, v)
	}
	ext := make([]string, 0, len(ascExt))
	hasExt := false
	for _, k := range ascExt {
		v := numStr(p[k]) // S3/S4 numeric; I1-I5 are hex strings (numStr returns the string)
		ext = append(ext, v)
		if v != "" {
			hasExt = true
		}
	}
	if hasExt {
		args = append(args, ext...)
	}
	return strings.Join(args, " ")
}

// cidrToAddrMask converts "10.0.0.0/24" → "10.0.0.0 255.255.255.0" (v4 dotted mask) and
// "2001:db8::/32" → "2001:db8:: 32" (v6 prefix length) — the KeeneticOS `ip address` /
// `allow-ips` form. A bare IP becomes /32 or /128.
func cidrToAddrMask(cidr string) (string, error) {
	cidr = strings.TrimSpace(cidr)
	pfx, err := netip.ParsePrefix(cidr)
	if err != nil {
		a, e2 := netip.ParseAddr(cidr)
		if e2 != nil {
			return "", fmt.Errorf("bad cidr %q: %w", cidr, err)
		}
		bits := 32
		if a.Is6() {
			bits = 128
		}
		pfx = netip.PrefixFrom(a, bits)
	}
	if pfx.Addr().Is4() {
		mask := net.CIDRMask(pfx.Bits(), 32)
		return pfx.Addr().String() + " " + net.IP(mask).String(), nil
	}
	return pfx.Addr().String() + " " + strconv.Itoa(pfx.Bits()), nil
}

// ndmQuote quotes an NDM string argument when it contains whitespace (KeeneticOS shows
// `description "Home VLAN"` quoted, `description ND_VPS` bare).
func ndmQuote(s string) string {
	if strings.ContainsAny(s, " \t") {
		return `"` + strings.ReplaceAll(s, `"`, ``) + `"`
	}
	return s
}

func str(p map[string]any, k string) string {
	if s, ok := p[k].(string); ok {
		return s
	}
	return ""
}

func numStr(v any) string {
	switch t := v.(type) {
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64) // no exponent for big H values
	case string:
		return t
	}
	return ""
}
