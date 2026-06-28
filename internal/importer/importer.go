// Package importer turns share links and configs into the protocol-agnostic
// model: vless/vmess/trojan/ss/hysteria2/tuic share URIs, and WireGuard/
// AmneziaWG .conf files. AmneziaWG is detected by its junk-packet params and
// routed to the amneziawg engine (see docs/CONFLICTS.md #5).
package importer

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"strconv"
	"strings"

	"wakeroute/internal/model"
	"wakeroute/internal/util"
)

const defaultHealthURL = "http://cp.cloudflare.com/generate_204"

// Parse detects the link type and returns a populated endpoint.
func Parse(raw string) (*model.Endpoint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty link")
	}
	if strings.Contains(raw, "[Interface]") {
		return finalize(parseConf(raw))
	}
	if looksLikeOlcRTC(raw) {
		return finalize(parseOlcRTC(raw))
	}

	scheme := ""
	if i := strings.Index(raw, "://"); i > 0 {
		scheme = strings.ToLower(raw[:i])
		// Normalize the scheme prefix to lowercase so the case-sensitive string parsers
		// (vmess/ss strip "vmess://"/"ss://" via TrimPrefix) accept an upper/mixed-case scheme
		// like VMESS:// or SS:// — which other clients (v2rayN, sing-box) treat case-insensitively.
		// Only the scheme is touched; the body after "://" (incl. base64) is left byte-for-byte intact.
		raw = scheme + raw[i:]
	}

	// vmess/ss carry base64 bodies that are not always valid URLs.
	switch scheme {
	case "vmess":
		return finalize(parseVMess(raw))
	case "ss":
		return finalize(parseShadowsocks(raw))
	}

	// wireguard:// private keys are base64 and routinely carry a raw '/' (which url.Parse would
	// treat as the start of the path, dropping the userinfo + the real host), and an IPv6
	// endpoint may arrive with percent-encoded brackets (%5B…%5D) that url.Parse can't parse.
	// Normalize the wg authority first so url.Parse yields the correct userinfo + host.
	if scheme == "wireguard" || scheme == "wg" {
		raw = normalizeWGURL(raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %q: %w", raw, err)
	}
	switch scheme {
	case "vless":
		return finalize(parseVLESS(u))
	case "trojan":
		return finalize(parseTrojan(u))
	case "anytls":
		return finalize(parseAnyTLS(u))
	case "hysteria2", "hy2":
		return finalize(parseHysteria2(u))
	case "tuic":
		return finalize(parseTUIC(u))
	case "wireguard", "wg":
		return finalize(parseWireGuardURL(u))
	default:
		return nil, fmt.Errorf("unsupported scheme %q", scheme)
	}
}

func finalize(e *model.Endpoint, err error) (*model.Endpoint, error) {
	if err != nil {
		return nil, err
	}
	if e.ID == "" {
		e.ID = genID(e)
	}
	if e.Name == "" {
		e.Name = strings.ToUpper(string(e.Protocol)) + " " + e.Server
	}
	if !e.Enabled {
		e.Enabled = true
	}
	return e, nil
}

// --- protocol parsers ---

func parseVLESS(u *url.URL) (*model.Endpoint, error) {
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoVLESS,
		Server:   u.Hostname(),
		Port:     atoiDefault(u.Port(), 443),
		Name:     fragmentName(u),
		Params:   map[string]any{"uuid": u.User.Username()},
	}
	q := u.Query()
	if flow := q.Get("flow"); flow != "" {
		e.Params["flow"] = flow
	}
	// packet_encoding (xudp / packetaddr) controls UDP-over-VLESS; dropping it makes
	// UDP fall back to sing-box's default, which can break UDP against a server that
	// expects xudp. Carry it; the generator emits packet_encoding (and guards the
	// value, since an unknown one makes sing-box PANIC).
	if pe := util.FirstNonEmpty(q.Get("packetEncoding"), q.Get("packet_encoding")); pe != "" {
		e.Params["packet_encoding"] = pe
	}
	e.Transport = transportFromQuery(q)
	e.TLS = tlsFromQuery(q, false, e.Server)
	return e, nil
}

func parseTrojan(u *url.URL) (*model.Endpoint, error) {
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoTrojan,
		Server:   u.Hostname(),
		Port:     atoiDefault(u.Port(), 443),
		Name:     fragmentName(u),
		Params:   map[string]any{"password": u.User.Username()},
	}
	q := u.Query()
	e.Transport = transportFromQuery(q)
	// Trojan is TLS by default unless explicitly disabled.
	e.TLS = tlsFromQuery(q, true, e.Server)
	return e, nil
}

// parseAnyTLS parses an anytls:// share link (anytls://<password>@<host>:<port>?sni=&insecure=&fp=).
// Like Trojan — the password is the userinfo and TLS comes from the query — but AnyTLS is always TLS
// and has no ws/grpc sub-transport, so no transport is parsed.
func parseAnyTLS(u *url.URL) (*model.Endpoint, error) {
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoAnyTLS,
		Server:   u.Hostname(),
		Port:     atoiDefault(u.Port(), 443),
		Name:     fragmentName(u),
		Params:   map[string]any{"password": u.User.Username()},
	}
	e.TLS = tlsFromQuery(u.Query(), true, e.Server)
	return e, nil
}

func parseHysteria2(u *url.URL) (*model.Endpoint, error) {
	auth := u.User.Username()
	if pw, ok := u.User.Password(); ok && pw != "" {
		auth = auth + ":" + pw
	}
	q := u.Query()
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoHysteria2,
		Server:   u.Hostname(),
		Port:     atoiDefault(u.Port(), 443),
		Name:     fragmentName(u),
		Params:   map[string]any{"password": auth},
	}
	if obfs := q.Get("obfs"); obfs != "" {
		e.Params["obfs"] = obfs
		if op := q.Get("obfs-password"); op != "" {
			e.Params["obfs_password"] = op
		}
	}
	// Port hopping: real Hysteria2 links carry the hop range as mport= or ports=
	// (e.g. "20000-50000" or "443,5000-6000"). Dropping it silently means the
	// tunnel only tries the base port — which breaks entirely if the server hops
	// and isn't listening there. Carry it; the generator emits server_ports.
	if mp := util.FirstNonEmpty(q.Get("mport"), q.Get("ports")); mp != "" {
		e.Params["hop_ports"] = mp
	}
	// Hysteria2 always runs over QUIC+TLS.
	e.TLS = &model.TLS{
		Enabled:  true,
		Type:     "tls",
		SNI:      util.FirstNonEmpty(q.Get("sni"), e.Server),
		Insecure: insecureFromQuery(q),
		ALPN:     splitCSV(q.Get("alpn")),
	}
	return e, nil
}

func parseTUIC(u *url.URL) (*model.Endpoint, error) {
	pw, _ := u.User.Password()
	q := u.Query()
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoTUIC,
		Server:   u.Hostname(),
		Port:     atoiDefault(u.Port(), 443),
		Name:     fragmentName(u),
		Params: map[string]any{
			"uuid":     u.User.Username(),
			"password": pw,
		},
	}
	if cc := q.Get("congestion_control"); cc != "" {
		e.Params["congestion_control"] = cc
	}
	if mode := q.Get("udp_relay_mode"); mode != "" {
		e.Params["udp_relay_mode"] = mode
	}
	// heartbeat keeps an idle TUIC tunnel's NAT mapping alive (the tuic analogue of
	// WireGuard PersistentKeepalive); zero_rtt_handshake and udp_over_stream are
	// connection-behaviour toggles. All were dropped before. The generator guards
	// the heartbeat value (a malformed duration would brick the config).
	if hb := q.Get("heartbeat"); hb != "" {
		e.Params["heartbeat"] = hb
	}
	if truthy(q.Get("zero_rtt_handshake")) {
		e.Params["zero_rtt_handshake"] = true
	}
	if truthy(q.Get("udp_over_stream")) {
		e.Params["udp_over_stream"] = true
	}
	e.TLS = &model.TLS{
		Enabled:  true,
		Type:     "tls",
		SNI:      util.FirstNonEmpty(q.Get("sni"), e.Server),
		Insecure: insecureFromQuery(q),
		ALPN:     splitCSV(q.Get("alpn")),
	}
	return e, nil
}

func parseVMess(raw string) (*model.Endpoint, error) {
	body := strings.TrimPrefix(raw, "vmess://")
	dec := decodeB64(body)
	if dec == "" {
		return nil, errors.New("vmess: invalid base64 body")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(dec), &m); err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
	}
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoVMess,
		Server:   asString(m["add"]),
		Port:     asInt(m["port"], 443),
		Name:     asString(m["ps"]),
		Params: map[string]any{
			"uuid":     asString(m["id"]),
			"alter_id": asInt(m["aid"], 0),
			"security": util.FirstNonEmpty(asString(m["scy"]), "auto"),
		},
	}
	net := util.FirstNonEmpty(asString(m["net"]), "tcp")
	if net == "h2" {
		net = "http" // VMess "h2" is the HTTP/2 transport sing-box calls "http"
	}
	if net == "ws" || net == "grpc" || net == "http" || net == "httpupgrade" {
		t := &model.Transport{Type: net, Path: asString(m["path"]), Host: asString(m["host"])}
		if net == "grpc" {
			t.ServiceName = asString(m["path"])
		}
		e.Transport = t
	}
	// VMess "tls" is normally the string "tls" (or ""), but some generators emit a
	// JSON bool true or "1"/"true" — and a bare `== "tls"` check then silently leaves
	// TLS OFF, so a vmess+TLS endpoint connects in plaintext to a TLS server and fails
	// every connection. Be type-robust here (the importer already does this for the
	// numeric port/aid via asInt): accept "tls" or any truthy value. "" / "none" /
	// "false" / "0" stay OFF (truthy rejects them), so a plaintext vmess is unaffected.
	if tlsv := asString(m["tls"]); tlsv == "tls" || truthy(tlsv) {
		// Carry the uTLS fingerprint (fp) like vless/trojan do — without it a vmess+TLS
		// tunnel meant to mimic e.g. a Chrome handshake silently falls back to vanilla
		// Go TLS, which is exactly the fingerprint the user picked fp to avoid. Also
		// carry allowInsecure: vmess was the ONLY protocol whose importer dropped the
		// skip-cert-verify flag (vless/trojan/hy2/tuic all read it), so a vmess+TLS
		// endpoint with a self-signed cert silently failed certificate verification.
		e.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: util.FirstNonEmpty(asString(m["sni"]), asString(m["host"]), e.Server), Fingerprint: asString(m["fp"]), ALPN: splitCSV(asString(m["alpn"])), Insecure: truthy(asString(m["allowInsecure"]))}
	}
	return e, nil
}

func parseShadowsocks(raw string) (*model.Endpoint, error) {
	body := strings.TrimPrefix(raw, "ss://")
	name := ""
	if i := strings.IndexByte(body, '#'); i >= 0 {
		name = urlDecode(body[i+1:])
		body = body[:i]
	}
	var query string
	if i := strings.IndexByte(body, '?'); i >= 0 { // plugin params aren't supported, but UoT is
		query = body[i+1:]
		body = body[:i]
	}

	var method, password, host string
	var port int
	if at := strings.LastIndexByte(body, '@'); at >= 0 {
		// SIP002: ss://userinfo@host:port. userinfo is EITHER base64(method:password)
		// (classic AEAD links) OR plaintext method:password — the latter is the common
		// real-world form for SS-2022 ciphers, whose PSK is already base64 so clients
		// (sing-box, v2rayN, Shadowrocket) don't double-wrap it. Try base64 first; if it
		// doesn't yield a "method:password" pair, fall back to the raw URL-decoded form.
		ui := body[:at]
		creds := decodeB64(ui)
		if !strings.Contains(creds, ":") {
			// PathUnescape, NOT QueryUnescape: the userinfo is not a query string, so a
			// literal '+' must stay '+' (it isn't a space). An SS-2022 PSK is base64 and
			// routinely contains '+', and QueryUnescape would turn it into a space —
			// corrupting the key so it fails the 32-byte length check.
			if d, err := url.PathUnescape(ui); err == nil {
				creds = d
			} else {
				creds = ui
			}
		}
		method, password = splitColon(creds)
		// The host:port may carry a percent-encoded IPv6 literal ([2001:db8::1] -> %5B…%5D);
		// decode it so splitHostPort/net.SplitHostPort can strip the brackets (else an IPv6 SS
		// link fails "missing host/port"). A bare host or a malformed % is left unchanged.
		hp := body[at+1:]
		if d, err := url.PathUnescape(hp); err == nil {
			hp = d
		}
		host, port = splitHostPort(hp)
	} else {
		// Legacy: ss://base64(method:password@host:port)
		dec := decodeB64(body)
		at2 := strings.LastIndexByte(dec, '@')
		if at2 < 0 {
			return nil, errors.New("ss: cannot parse credentials")
		}
		method, password = splitColon(dec[:at2])
		host, port = splitHostPort(dec[at2+1:])
	}
	if host == "" || port == 0 {
		return nil, errors.New("ss: missing host/port")
	}
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoShadowsocks,
		Server:   host,
		Port:     port,
		Name:     name,
		Params:   map[string]any{"method": method, "password": password},
	}
	// UDP-over-TCP relays SS UDP through the TCP tunnel — needed when the server
	// only exposes TCP; it is built into sing-box, so carry it. Spelled udp-over-tcp /
	// udp_over_tcp / uot in the wild.
	if query != "" {
		// NOT url.ParseQuery: a SIP002 plugin value legitimately contains ';' as its
		// opts separator (plugin=v2ray-plugin;mode=websocket;path=/x), and Go 1.17+
		// url.ParseQuery REJECTS a raw ';' ("invalid semicolon separator") and returns
		// an error with the offending pair dropped — which silently lost the whole
		// plugin (and udp-over-tcp) for a real external SS-plugin link. Split on '&'
		// only so the ';' stays part of the plugin value.
		q := parseSSQuery(query)
		if truthy(q["udp-over-tcp"]) || truthy(q["udp_over_tcp"]) || truthy(q["uot"]) {
			e.Params["udp_over_tcp"] = true
		}
		// SIP002 plugin: "plugin=<name>;<opts>" (e.g. obfs-local;obfs=http;obfs-host=x).
		// sing-box implements obfs-local and v2ray-plugin natively (no external
		// binary), so a plugin SS link is connectable — carry the name + opts; the
		// generator emits only the plugin names it actually supports.
		if pl := q["plugin"]; pl != "" {
			name, opts, _ := strings.Cut(pl, ";")
			e.Params["plugin"] = name
			if opts != "" {
				e.Params["plugin_opts"] = opts
			}
		}
	}
	return e, nil
}

// parseSSQuery splits an ss "?..." query on '&' only (NOT ';') and url-decodes each
// value, so a SIP002 plugin value's ';' opts separator survives. url.ParseQuery is
// unusable here: Go 1.17+ rejects a raw ';' as an "invalid semicolon separator" and
// drops the offending pair, which silently lost the plugin (and udp-over-tcp) for a
// real external SS-plugin link.
func parseSSQuery(query string) map[string]string {
	m := map[string]string{}
	for _, kv := range strings.Split(query, "&") {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		if d, err := url.QueryUnescape(v); err == nil {
			v = d
		}
		m[k] = v
	}
	return m
}

// normalizeWGURL repairs a wireguard:// link's AUTHORITY so the stdlib url.Parse can read it:
//   - a raw '/' in the userinfo (the base64 private key — ~1 in 4 keys contains one, and most
//     real wg:// links carry it un-percent-encoded) is encoded to %2F, so url.Parse keeps it as
//     userinfo instead of treating it as the path start (which silently emptied the key and made
//     the pre-'/' chunk the host — a junk, dead tunnel with no error);
//   - percent-encoded IPv6 endpoint brackets (%5B…%5D) are decoded to literal […] so url.Parse
//     can split host:port (it rejects a colon-bearing host that isn't literally bracketed).
//
// Only the authority (between "://" and the first '?'/'#') is touched; the query + fragment are
// left verbatim so percent-encoded query values (publickey=…%2F…, address=…%2F…) decode normally.
func normalizeWGURL(raw string) string {
	i := strings.Index(raw, "://")
	if i < 0 {
		return raw
	}
	head, rest := raw[:i+3], raw[i+3:]
	tail := ""
	if j := strings.IndexAny(rest, "?#"); j >= 0 {
		tail, rest = rest[j:], rest[:j]
	}
	debracket := func(s string) string {
		s = strings.ReplaceAll(strings.ReplaceAll(s, "%5B", "["), "%5b", "[")
		return strings.ReplaceAll(strings.ReplaceAll(s, "%5D", "]"), "%5d", "]")
	}
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		rest = strings.ReplaceAll(rest[:at], "/", "%2F") + "@" + debracket(rest[at+1:])
	} else {
		rest = debracket(rest)
	}
	return head + rest + tail
}

func parseWireGuardURL(u *url.URL) (*model.Endpoint, error) {
	q := u.Query()
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoWireGuard,
		Server:   u.Hostname(),
		Port:     atoiDefault(u.Port(), 51820),
		Name:     fragmentName(u),
		Params: map[string]any{
			"private_key":     u.User.Username(),
			"peer_public_key": b64Param(q, "publickey"),
		},
	}
	if psk := b64Param(q, "presharedkey"); psk != "" {
		e.Params["pre_shared_key"] = psk
	}
	// Carry PersistentKeepalive (spelled keepalive / persistentkeepalive in the
	// wild) so an idle tunnel behind NAT keeps its UDP mapping alive.
	if ka := atoiDefault(util.FirstNonEmpty(q.Get("keepalive"), q.Get("persistentkeepalive")), 0); ka > 0 {
		e.Params["persistent_keepalive"] = ka
	}
	if addr := q.Get("address"); addr != "" {
		e.Params["local_address"] = splitCSV(addr)
	}
	// Cloudflare WARP encodes 3 client-id bytes as the WG "reserved" field; sing-box
	// puts them on the peer and the WARP server rejects the handshake without them.
	// (Plain-WireGuard only — sing-box's userspace WG; native AmneziaWG has no such
	// field.) Spelled reserved=a,b,c or reserved=[a,b,c] in the wild.
	if r := parseReserved(q.Get("reserved")); r != nil {
		e.Params["reserved"] = r
	}
	// MTU keeps large packets from fragmenting/blackholing — emitted on the sing-box WG
	// endpoint. (e.g. WARP links carry mtu=1280.) Bound to a sane WG range: sing-box's
	// endpoint mtu is a uint32, so an out-of-range value (e.g. a hostile mtu=999999999999)
	// overflows at config decode and FATALs the whole shared singbox.json. Bounding also makes
	// 64-bit and 32-bit (mipsle) builds agree, since strconv.Atoi overflows differently per arch.
	if mtu := atoiDefault(q.Get("mtu"), 0); mtu >= 576 && mtu <= 65535 {
		e.Params["mtu"] = mtu
	}
	return e, nil
}

// parseReserved parses the WireGuard/WARP "reserved" field — exactly three bytes
// (0-255), written "a,b,c" or "[a,b,c]". Returns nil for anything else so a
// malformed value is dropped rather than emitted (sing-box wants a 3-element array).
func parseReserved(s string) []int {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	if len(parts) != 3 {
		return nil
	}
	out := make([]int, 0, 3)
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil || n < 0 || n > 255 {
			return nil
		}
		out = append(out, n)
	}
	return out
}

// --- query/transport/tls helpers ---

func transportFromQuery(q url.Values) *model.Transport {
	switch q.Get("type") {
	case "ws":
		return &model.Transport{Type: "ws", Path: q.Get("path"), Host: q.Get("host")}
	case "grpc":
		// serviceName is the gRPC path segment; the wrong/empty one means the gRPC
		// stream hits the wrong path and never connects (passes `sing-box check`,
		// fails at runtime). Clients spell it three ways — serviceName (v2rayN/Xray
		// URIs), service_name (sing-box JSON → link converters), servicename — so
		// accept all, mirroring the packetEncoding handling above.
		return &model.Transport{Type: "grpc", ServiceName: util.FirstNonEmpty(
			q.Get("serviceName"), q.Get("service_name"), q.Get("servicename"))}
	case "http", "h2":
		return &model.Transport{Type: "http", Path: q.Get("path"), Host: q.Get("host")}
	case "httpupgrade":
		return &model.Transport{Type: "httpupgrade", Path: q.Get("path"), Host: q.Get("host")}
	default:
		return nil // tcp / raw
	}
}

func tlsFromQuery(q url.Values, defaultOn bool, server string) *model.TLS {
	sec := q.Get("security")
	if sec == "" && defaultOn {
		sec = "tls"
	}
	switch sec {
	case "reality":
		return &model.TLS{
			Enabled:     true,
			Type:        "reality",
			SNI:         q.Get("sni"),
			Fingerprint: q.Get("fp"),
			PublicKey:   q.Get("pbk"),
			ShortID:     q.Get("sid"),
			ALPN:        splitCSV(q.Get("alpn")),
		}
	case "tls", "xtls":
		return &model.TLS{
			Enabled: true,
			Type:    "tls",
			// SNI fallback: sni → ws/http host → server. A CDN-fronted ws+tls link
			// points `server` at an IP and carries the real domain in `host` (the ws
			// Host header); when `sni` is omitted the TLS SNI must fall back to that
			// host, not the IP — an SNI-routed frontend rejects a wrong/IP SNI with
			// "tls: unrecognized name" (passes `sing-box check`, fails at runtime).
			// Matches the vmess path and v2rayN's documented "SNI defaults to host".
			SNI:         util.FirstNonEmpty(q.Get("sni"), q.Get("host"), server),
			Fingerprint: q.Get("fp"),
			Insecure:    insecureFromQuery(q),
			ALPN:        splitCSV(q.Get("alpn")),
		}
	default:
		return nil
	}
}

// --- small utilities ---

func decodeB64(s string) string {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b)
		}
	}
	return ""
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return def
}

func splitColon(s string) (a, b string) {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// splitHostPort splits "host:port" for the parsers that do NOT go through
// url.Parse (Shadowsocks SIP002/legacy, WireGuard/AmneziaWG .conf Endpoint). It
// must return a BARE host: an IPv6 literal arrives bracketed ("[2001:db8::1]:443")
// and a naive LastIndexByte(':') split would keep the brackets — sing-box then
// treats "[2001:db8::1]" as a hostname and DNS-resolves it to NXDOMAIN, so every
// connection dies at runtime while `sing-box check` still passes (and the
// exporter's net.JoinHostPort would double-bracket it). net.SplitHostPort strips
// the brackets and handles the v4/hostname cases identically; fall back to the
// no-port form (bare host, port 0) when there is no port, stripping any brackets.
func splitHostPort(s string) (host string, port int) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, atoiDefault(p, 0)
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	return s, 0
}

// b64Param reads a base64 query parameter, restoring a '+' that url.Query()
// decoded to a space. A WireGuard key is standard base64 (its alphabet includes
// '+'); a "wireguard://" link that carries the '+' un-percent-encoded (the common
// real-world form) has it turned into a space by query decoding, which corrupts
// the key — the peer public_key / pre_shared_key no longer match the server and
// the handshake fails. base64 never contains a literal space, so any space here is
// unambiguously a lost '+'. A properly %2B-encoded link already yields '+' (no
// space), so this is a no-op for it.
func b64Param(q url.Values, key string) string {
	return strings.ReplaceAll(q.Get(key), " ", "+")
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// truthy reports whether a query-param value means "yes". Share-links from
// different clients spell booleans as "1", "true", or "yes" (any case).
func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// insecureFromQuery reports whether any of the common "skip TLS verification"
// flags is set. Real-world links spell it three ways — allowInsecure (v2rayN),
// insecure (Hysteria2 / some vless), allow_insecure (tuic / Clash) — with "1" or
// "true". Accepting all of them lets a self-signed endpoint imported from ANY
// client connect, instead of silently failing certificate verification.
func insecureFromQuery(q url.Values) bool {
	for _, k := range []string{"allowInsecure", "insecure", "allow_insecure"} {
		if truthy(q.Get(k)) {
			return true
		}
	}
	return false
}

func fragmentName(u *url.URL) string {
	if u.Fragment != "" {
		return u.Fragment
	}
	return ""
}

func urlDecode(s string) string {
	if d, err := url.QueryUnescape(s); err == nil {
		return d
	}
	return s
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func asInt(v any, def int) int {
	switch t := v.(type) {
	case float64:
		// Reject out-of-int-range floats (incl. NaN/Inf) rather than letting the
		// int(t) conversion overflow into an implementation-defined value. A port /
		// alter_id is small in practice, so anything beyond MaxInt32 is bogus.
		if t < math.MinInt32 || t > math.MaxInt32 {
			return def
		}
		return int(t)
	case string:
		return atoiDefault(t, def)
	case json.Number:
		if n, err := t.Int64(); err == nil {
			// On 32-bit router arches int is 32-bit, so an int64 outside that range
			// would overflow on the int(n) conversion. Clamp-reject to the default.
			if n < math.MinInt32 || n > math.MaxInt32 {
				return def
			}
			return int(n)
		}
	}
	return def
}

func genID(e *model.Endpoint) string {
	base := string(e.Protocol) + "-" + e.Server
	if e.Port != 0 {
		base += "-" + strconv.Itoa(e.Port)
	}
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(base) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}
