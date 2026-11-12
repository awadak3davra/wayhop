package keenetic

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"wayhop/internal/awg"
	"wayhop/internal/model"
	"wayhop/internal/util"
)

// wgKey canonicalizes a WireGuard/AmneziaWG key for an NDM command: re-encode as standard
// base64-with-padding (KeeneticOS's key parser rejects url-safe/unpadded forms, like the
// sing-box and awg-quick decoders) AND truncate at the first control char, so a crafted
// "KEY\ncommand …" can't inject extra RCI lines into the line-based command stream. A value
// that doesn't decode to a 32-byte key (a placeholder / injection attempt) is left for the
// control-char guard to sanitize. Mirrors generator.normalizeWGKey + plugin.confLine.
func wgKey(s string) string {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			s = base64.StdEncoding.EncodeToString(b)
			break
		}
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 {
			return s[:i]
		}
	}
	return s
}

// ndmLine truncates one NDM command at the first ASCII control char (< 0x20), so no interpolated
// value can embed a newline and inject an extra command into the batched, line-based /rci/parse
// stream. Applied to every emitted command line as the single injection choke point.
func ndmLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 {
			return s[:i]
		}
	}
	return s
}

// ascBase is the positional order of the AWG 1.x obfuscation params on KeeneticOS's
// `wireguard asc` command (the 9-arg form validated live on the reference router). ascExt are the
// AWG-2.0 additions (S3/S4 + the I1-I5 magic headers), appended only when present. The 9-arg base
// is confirmed. The device prints the 2.0 form as 11 bare arguments then five quoted strings when the
// headers are unset (measured read-only on the test Keenetic, 2026-11-05, and on a KeeneticOS 5.1.8
// router, QA-124); that S3/S4 and I1-I5 sit in those slots in this order is still not proven
// (wgasc.go keeps the tail uninterpreted).
var ascBase = []string{"jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"}
var ascExt = []string{"s3", "s4", "i1", "i2", "i3", "i4", "i5"}

// AWGGeneration is the newest AmneziaWG generation `wireguard asc` is written for: ascBase is 1.x and
// ascExt the 2.0 additions (whose argument order is still unconfirmed on a device, above). NDM has no
// argument for a 3.x setting, so the native planner keeps such an endpoint off this path, and a test
// holds the constant to the two lists.
const AWGGeneration = awg.Gen2

// WireguardOpts tune the generated native interface.
type WireguardOpts struct {
	Index       int    // the WireguardN slot
	Metric      int    // `ip global N` routing priority (the failover tier; lower = preferred). 0 → 1000.
	MTU         int    // `ip mtu`; 0 → use the endpoint's mtu param, else NDM default
	PingProfile string // optional `ping-check profile <name>` (native health-check failover)
	// AWGGeneration caps the AmneziaWG settings written to what this firmware release takes
	// (CompileOptions.AWGGeneration); zero, or anything above AWGGeneration, is AWGGeneration.
	AWGGeneration awg.Generation
}

// WireguardCommands renders the NDM command sequence that configures a native KeeneticOS
// `interface WireguardN` from a WayHop AmneziaWG/WireGuard endpoint — the heart of the
// native-first backend (the router runs the tunnel in-kernel, leveraging HW crypto, instead
// of a userspace sing-box/awg-quick tunnel). The lines mirror the live running-config
// structure validated on the reference router; the strict apply layer sends them to NDM one command per
// `ndmc -c`. PURE — no device I/O. Returns an error for a non-WG/AWG endpoint or missing keys.
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
	// Refused, not skipped, for the reason AWGObfuscationDropped exists: a tunnel without the server's
	// 3.x settings comes up on the router and is never answered. The native planner refuses such an
	// endpoint first; this is the writer holding the same line.
	if e.Protocol == model.ProtoAmneziaWG {
		if beyond := awg.Beyond(p, AWGGeneration); len(beyond) != 0 {
			return nil, fmt.Errorf("endpoint %q uses AmneziaWG %s settings (%s), which `wireguard asc` has no arguments for",
				e.ID, awg.Need(p), strings.Join(beyond, ", "))
		}
		// The arguments exist, but this firmware release does not take them (QA-127): KeeneticOS
		// before 5.1 refuses the AmneziaWG 2 settings, and the whole Apply with them.
		if o.AWGGeneration != awg.GenNone && o.AWGGeneration < AWGGeneration {
			if beyond := awg.Beyond(p, o.AWGGeneration); len(beyond) != 0 {
				return nil, fmt.Errorf("endpoint %q uses AmneziaWG %s settings (%s), which this KeeneticOS release's `wireguard asc` does not take",
					e.ID, awg.Need(p), strings.Join(beyond, ", "))
			}
		}
	}
	if e.Server == "" || e.Port == 0 {
		return nil, fmt.Errorf("endpoint %q: missing server/port", e.ID)
	}
	// `wireguard asc` carries a set I1-I5 with spaces as a quoted string (see ascArgs), so a value
	// holding a quote or a control character cannot be written faithfully. Refused rather than altered
	// (ndmQuote would drop the quote, ndmLine cut the line at the control character): a changed I value
	// is a tunnel the server never answers.
	for _, k := range ascExt {
		if v := numStr(p[k]); strings.HasPrefix(k, "i") &&
			strings.ContainsFunc(v, func(r rune) bool { return r == '"' || r < 0x20 || r == 0x7f }) {
			return nil, fmt.Errorf("endpoint %q: %s holds a quote or control character, which `wireguard asc` cannot carry", e.ID, k)
		}
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
	// Every NDM command is a single line, and the apply layer sends each one to NDM as one command.
	// Truncate each line at the first ASCII control char so NO interpolated value —
	// the endpoint description/name, server, mtu/keepalive, asc hex, or a key — can embed a newline
	// and inject an extra RCI command. One choke point covers every field (wgKey still canonicalizes
	// the key bytes; this is the belt for all the rest).
	add := func(s string) { c = append(c, ndmLine(s)) }
	add(fmt.Sprintf("interface Wireguard%d", o.Index))
	add("description " + ndmQuote(name))
	add("security-level public")

	hasV6 := false
	var v6Addrs []string
	for _, a := range util.LocalAddrs(p) {
		am, err := cidrToAddrMask(a)
		if err != nil {
			continue
		}
		// QA-123. An IPv6 address is not an `ip address`: KeeneticOS prints a WireGuard interface's
		// as `ipv6 address <addr>/<len>` (read from a live KeeneticOS 5.1.8 router, `/128`, after `ip tcp
		// adjust-mss pmtu`). `ip address <v6> 128` was sent instead; it is emitted where the router
		// prints it, below, so the block reads back in the router's own order.
		if addrIsV6(a) {
			v6Addrs = append(v6Addrs, "ipv6 address "+v6Prefix(a))
		} else {
			add("ip address " + am)
		}
		// Detect v6 the SAME bare-IP-tolerant way cidrToAddrMask parses the address: a Clash
		// import stores the ipv6 field as a bare literal (no /prefix), which ParsePrefix rejects.
		// Using ParsePrefix alone left hasV6 false for a bare v6 address, so the `allow-ips :: 0`
		// line was omitted and the tunnel carried no IPv6 — v6 traffic to the peer leaked to the WAN.
		if addrIsV6(a) {
			hasV6 = true
		}
	}
	// The panel's form writes the top-level fields and drops the params (one source of truth, as
	// plugin.go reads them); reading only the params lost both on any edit (QA-038).
	if o.MTU > 0 {
		add("ip mtu " + strconv.Itoa(o.MTU))
	} else if e.MTU > 0 {
		add("ip mtu " + strconv.Itoa(e.MTU))
	} else if m := numStr(p["mtu"]); m != "" { // mtu param may be int (JSON number) or string
		add("ip mtu " + m)
	}
	add("ip global " + strconv.Itoa(metric))
	add("ip tcp adjust-mss pmtu")
	for _, line := range v6Addrs {
		add(line)
	}
	if o.PingProfile != "" {
		add("ping-check profile " + o.PingProfile)
	}
	add("wireguard private-key " + wgKey(priv))
	if asc := ascArgs(p); asc != "" {
		add("wireguard asc " + asc)
	}
	add("wireguard peer " + wgKey(peer))
	// The four-space indent below is structure, not layout: it marks the lines that belong to this peer,
	// as running-config prints them one level deeper. The strict apply layer sends one command per
	// `ndmc -c` and rebuilds `interface WireguardN wireguard peer <key> endpoint …` from it, and its
	// validator accepts exactly this one level, so the indent must stay four spaces.
	//
	// net.JoinHostPort brackets an IPv6 literal ([2001:db8::1]:51820) — a bare `server:port`
	// concatenation makes the port indistinguishable from the address, which KeeneticOS (and the
	// module's own splitEndpoint, which uses net.SplitHostPort) mis-parses so the tunnel never dials.
	add("    endpoint " + net.JoinHostPort(e.Server, strconv.Itoa(e.Port)))
	if e.PersistentKeepalive > 0 {
		add("    keepalive-interval " + strconv.Itoa(e.PersistentKeepalive))
	} else if ka := numStr(p["persistent_keepalive"]); ka != "" {
		add("    keepalive-interval " + ka)
	}
	if psk := str(p, "pre_shared_key"); psk != "" {
		add("    preshared-key " + wgKey(psk))
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

// AWGObfuscationDropped reports that this endpoint is configured as AmneziaWG but its 9-arg
// obfuscation base is incomplete, so the rendered interface carries NO `wireguard asc` line and the
// router runs it as plain WireGuard. Dropping the line is right for a WG endpoint - it has no such
// params - but for an AWG one it is a DOWNGRADE, and it used to happen in silence: the panel showed
// AmneziaWG with the boxes the operator filled in, the router ran an unobfuscated tunnel. Against an
// AmneziaWG peer that simply never answers; against a plain-WG peer it works, and the operator
// believes they have obfuscation they do not have.
func AWGObfuscationDropped(e model.Endpoint) bool {
	return e.Engine == model.EngineAmneziaWG && ascArgs(e.Params) == ""
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
		// Fill any EMPTY ext slot so the positional order survives strings.Join: a partial 2.0
		// set (e.g. I1-I5 present but S3/S4 absent) would otherwise leave empty tokens that
		// collapse into the surrounding spaces when NDM whitespace-tokenizes the `wireguard asc`
		// line, shifting every following value into the wrong slot (I1 binding to the S3
		// position). "0" is the AWG default for the junk-size params (S3/S4). An unset I1-I5 is an
		// empty string, which KeeneticOS writes as `""` (QA-124: a live KeeneticOS 5.1.8 router prints
		// its 2.0 interfaces as `wireguard asc <9 base> <s3> <s4> "" "" "" "" ""`); "0" there is a
		// value the operator never set, and not what the router reads back for an unset one.
		//
		// A set I1-I5 is a packet description such as `<b 0x…>`, with spaces in it. Sent bare, NDM
		// splits it into several arguments and every later value lands in the wrong slot (QA-125).
		// It is quoted the way the router prints a value with spaces (`description "<name>"`; the
		// same router quotes every such value in its configuration).
		for i, key := range ascExt {
			switch {
			case ext[i] != "" && strings.HasPrefix(key, "i"):
				ext[i] = ndmQuote(ext[i])
			case ext[i] == "" && strings.HasPrefix(key, "i"):
				ext[i] = `""`
			case ext[i] == "":
				ext[i] = "0"
			}
		}
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

// v6Prefix renders an IPv6 interface address the way `ipv6 address` takes it, `<addr>/<len>`; a bare
// address (the Clash form, see addrIsV6) is a /128. The address is kept as given, not masked.
func v6Prefix(s string) string {
	s = strings.TrimSpace(s)
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx.String()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, 128).String()
	}
	return s
}

// addrIsV6 reports whether a WireGuard local address is IPv6, tolerating both the CIDR form
// ("fd00::2/64") and the bare-IP form ("fd00::2") — the latter is what a Clash import stores from
// the ipv6 field, and ParsePrefix alone rejects it. Mirrors cidrToAddrMask's parse-with-fallback.
func addrIsV6(s string) bool {
	s = strings.TrimSpace(s)
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx.Addr().Is6()
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Is6()
	}
	return false
}

// ndmQuote quotes an NDM string argument when it contains whitespace (KeeneticOS shows
// `description "LAN segment"` quoted, `description WG_A` bare).
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
