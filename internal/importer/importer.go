// Package importer turns share links and configs into the protocol-agnostic
// model: vless/vmess/trojan/ss/hysteria2/tuic share URIs, and WireGuard/
// AmneziaWG .conf files. AmneziaWG is detected by its junk-packet params and
// routed to the amneziawg engine (see docs/CONFLICTS.md #5 in the development repository).
package importer

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"wayhop/internal/model"
	"wayhop/internal/util"
)

// urlParseReason returns WHY a URL failed to parse, without the URL itself. url.Parse wraps its
// failures in *url.Error, whose Error() embeds the raw input — which for a share link is the
// credential. We surface only the inner reason ("missing protocol scheme", "invalid port …", …) so a
// malformed paste can never carry a UUID/password/private key into an error string.
func urlParseReason(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err.Error()
	}
	return "not a valid URL"
}

// schemeLabel names the link type for a user-facing error. The scheme is not a credential (it is
// "vless", "trojan", …); an empty scheme means the input had no "scheme://" prefix at all.
func schemeLabel(scheme string) string {
	if scheme == "" {
		return "share"
	}
	return scheme
}

// utf8BOM is the byte-order mark Windows Notepad (and some exporters) put at the start of a saved
// .conf. TrimSpace keeps it (U+FEFF is not white space), so its first line read as BOM+"[Interface]",
// parseConf never entered the section, and the interface keys - the private key among them - were
// silently dropped.
var utf8BOM = string(rune(0xFEFF))

// Parse detects the link type and returns a populated endpoint.
func Parse(raw string) (*model.Endpoint, error) {
	raw = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), utf8BOM))
	if raw == "" {
		return nil, errors.New("empty link")
	}
	// Detect a URI scheme prefix (a single whitespace-free token before "://") FIRST. A pasted
	// WireGuard .conf or an olcRTC YAML blob is NOT a URI — it has no such prefix — whereas a proxy
	// share link always does. We then gate the .conf / olcRTC content-sniffs on the ABSENCE of a
	// scheme, so a crafted #fragment in a share link (the node name, which is provider/attacker-
	// controlled) can't be misread as "[Interface]" (→ .conf parser, import FAILS: #15) or as olcRTC
	// keys like "provider:…crypto" (→ the real proxy refused as a retired olcRTC config: #14).
	// The whitespace guard means a "://" sitting inside a multi-line config blob (preceded by a
	// newline, e.g. an olcRTC signaling URL) is NOT mistaken for a scheme.
	scheme := ""
	if i := strings.Index(raw, "://"); i > 0 && !strings.ContainsAny(raw[:i], " \t\r\n") {
		scheme = strings.ToLower(raw[:i])
		// Normalize the scheme prefix to lowercase so the case-sensitive string parsers
		// (vmess/ss strip "vmess://"/"ss://" via TrimPrefix) accept an upper/mixed-case scheme
		// like VMESS:// or SS:// — which other clients (v2rayN, sing-box) treat case-insensitively.
		// Only the scheme is touched; the body after "://" (incl. base64) is left byte-for-byte intact.
		raw = scheme + raw[i:]
	}
	if scheme == "" {
		// No URI scheme → a pasted config blob, not a share link: sniff its format.
		if strings.Contains(raw, "[Interface]") {
			return tagged(FormatConf)(finalize(parseConf(raw)))
		}
		if looksLikeOpenVPN(raw) {
			return tagged(FormatOpenVPN)(finalize(parseOpenVPN(raw)))
		}
		// A Clash / mihomo config pasted (or opened with Import file, which accepts .yaml) under Paste
		// link used to fall through to the URL parser and fail as "malformed share link: invalid
		// control character", naming neither the format nor where it imports. One proxy imports
		// here; several need the Subscription tab, which lets the operator choose.
		if looksLikeClash(raw) {
			return tagged(FormatClash)(parseClashSingle(raw))
		}
		// A Surge [Proxy] line ("Name = snell, host, port, psk=..."), the form Snell is handed out in.
		if looksLikeSurge(raw) {
			return tagged(FormatSurge)(parseSurgeSingle(raw))
		}
		if looksLikeOlcRTC(raw) {
			return nil, errOlcRTCRetired
		}
	}

	// vmess/ss carry base64 bodies that are not always valid URLs.
	switch scheme {
	case "vmess":
		return tagged(linkFormat("vmess"))(finalize(parseVMess(raw)))
	case "ss":
		return tagged(linkFormat("ss"))(finalize(parseShadowsocks(raw)))
	}

	// wireguard:// private keys are base64 and routinely carry a raw '/' (which url.Parse would
	// treat as the start of the path, dropping the userinfo + the real host), and an IPv6
	// endpoint may arrive with percent-encoded brackets (%5B…%5D) that url.Parse can't parse.
	// Normalize the wg authority first so url.Parse yields the correct userinfo + host.
	if scheme == "wireguard" || scheme == "wg" {
		raw = normalizeWGURL(raw)
	}
	// The Hysteria 2 URI scheme puts a port-hopping list in the authority itself
	// ("hysteria2://auth@host:123,5000-6000/?..." is the official example), which url.Parse rejects
	// as an invalid port. Lift the list out first; parseHysteria2 gets it back as the hop range.
	hy2Ports := ""
	if scheme == "hysteria2" || scheme == "hy2" {
		raw, hy2Ports = splitAuthorityPortList(raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		// NOT %q of raw, and NOT %w of err: both carry the credential. A share link IS the secret —
		// vless://<uuid>@…, ss://<base64-secret>@…, wireguard://<privkey>@… — and url.Parse wraps its
		// failure in a *url.Error whose Error() embeds the whole raw input. This error is returned
		// verbatim by /api/import and folded into the subscription error list, so echoing raw here put
		// a UUID/password/private key into an API response, a toast, last_error and the log. Surface
		// the scheme (safe, useful) and the parser's REASON with the URL stripped out.
		return nil, fmt.Errorf("malformed %s link: %s", schemeLabel(scheme), urlParseReason(err))
	}
	switch scheme {
	case "vless":
		return tagged(linkFormat("vless"))(finalize(parseVLESS(u)))
	case "trojan":
		return tagged(linkFormat("trojan"))(finalize(parseTrojan(u)))
	case "anytls":
		return tagged(linkFormat("anytls"))(finalize(parseAnyTLS(u)))
	case "hysteria2", "hy2":
		return tagged(linkFormat("hysteria2"))(finalize(parseHysteria2(u, hy2Ports)))
	case "hysteria2+realm", "hy2+realm", "hysteria2+realm+http", "hy2+realm+http":
		return tagged(linkFormat("hysteria2+realm"))(finalize(parseHysteria2Realm(u, strings.HasSuffix(scheme, "+http"))))
	case "tuic":
		return tagged(linkFormat("tuic"))(finalize(parseTUIC(u)))
	case "wireguard", "wg":
		return tagged(linkFormat("wireguard"))(finalize(parseWireGuardURL(u)))
	case "ssh":
		return tagged(linkFormat("ssh"))(finalize(parseSSHURL(u)))
	default:
		return nil, fmt.Errorf("unsupported scheme %q", scheme)
	}
}

func finalize(e *model.Endpoint, err error) (*model.Endpoint, error) {
	if err != nil {
		return nil, err
	}
	// Bound the port at the parse boundary for every share-link protocol in ONE place (mirrors the
	// clash and singbox-config importers). url.Parse only checks a port is digits, not its range, and
	// the store persist path does not re-validate, so an out-of-range port (70000/88888) would be
	// durably persisted and then FATAL every Apply. EngineExternal endpoints (interface-based, no dial
	// port) are exempt here exactly as model.Validate exempts them.
	//
	// A Hysteria2 link in realm mode names a rendezvous instead of a server (parseHysteria2Realm), so
	// it has no server or port to check here.
	realm := e.UsesRealm()
	if e.Engine != model.EngineExternal && !realm && (e.Port < 1 || e.Port > 65535) {
		return nil, fmt.Errorf("port %d out of range (must be 1-65535)", e.Port)
	}
	// A link that yielded no server is not an endpoint. Parse used to return one anyway — with an
	// empty Server, a DEFAULTED port and Enabled=true — so `vless://`, `trojan://pass@` and a
	// truncated vmess payload all imported "successfully". model.Validate does reject it later, so
	// nothing broken reaches the profile, but the user is told `endpoint "x": empty server` from the
	// store: an error about the endpoint, several layers below the thing that was actually wrong.
	// The link is what failed, and this is where that is still known.
	//
	// EngineExternal is exempt for the same reason as the port check: an adopted OS tunnel is
	// identified by its interface, not by a dial target.
	if e.Engine != model.EngineExternal && !realm && strings.TrimSpace(e.Server) == "" {
		return nil, fmt.Errorf("no server address in the link (got %q)", string(e.Protocol))
	}
	// An IPv6 literal must be bracketed in a URI, and the parsers that go through url.Parse take the
	// host from u.Hostname()/u.Port() — which split at the LAST colon without counting them. A pasted
	// link carrying a bare IPv6 therefore did not fail: `trojan://s@::1` produced Server ":" with port
	// 1, and `trojan://s@fe80::1` produced Server "fe80:" with port 1, both accepted with 200 and both
	// copied into the generated config's server AND sni. A host that still holds a colon can only be
	// such a remnant — a bracketed literal has already had its brackets stripped and parses as an IP,
	// and a DNS hostname cannot contain a colon. Say what to do instead of inventing a port.
	if e.Engine != model.EngineExternal && strings.ContainsRune(e.Server, ':') && net.ParseIP(e.Server) == nil {
		return nil, fmt.Errorf("wrap an IPv6 address in brackets, e.g. [2001:db8::1]:443")
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

// What each share link can express (sourceFields, Reimport), read off its parser below: the params it
// writes, the TLS fields tlsFromQuery, hysteria2Query, parseTUIC and parseVMess set, the pins linkPins
// and vmessPins bring, and the transport transportFromQuery sets. No share link sets a top-level
// knob, multiplex included.
var (
	linkTLSFields = []string{"enabled", "type", "sni", "alpn", "cipher_suites", "insecure", "fingerprint", "public_key", "short_id", "ech"}
	// hysteria2Query and parseTUIC set no uTLS fingerprint and no Reality fields.
	quicLinkTLSFields = []string{"enabled", "type", "sni", "alpn", "insecure", "ech"}

	vlessLinkFields = sourceFields{params: []string{"uuid", "flow", "packet_encoding", model.ParamVerifyCertName, model.ParamFinalMask},
		tls: linkTLSFields, pins: true, transport: true}
	vmessLinkFields = sourceFields{params: []string{"uuid", "alter_id", "security", model.ParamVerifyCertName, model.ParamFinalMask},
		tls: []string{"enabled", "type", "sni", "alpn", "cipher_suites", "insecure", "fingerprint"}, pins: true, transport: true}
	trojanLinkFields = sourceFields{params: []string{"password", model.ParamVerifyCertName, model.ParamFinalMask},
		tls: linkTLSFields, pins: true, transport: true}
	anytlsLinkFields = sourceFields{params: []string{"password", model.ParamVerifyCertName, model.ParamFinalMask},
		tls: linkTLSFields, pins: true}
	ssLinkFields = sourceFields{params: []string{"method", "password", "udp_over_tcp", "plugin", "plugin_opts", model.ParamFinalMask}}
	// A Hysteria2 link carries no QUIC tuning (initial_packet_size, disable_path_mtu_discovery,
	// disable_chrome_parrot) and no bandwidth, so those stay as the form or a sing-box config set them.
	// Its pinSHA256 lands in the TLS block now; the param an older WayHop kept it in goes with the link.
	hysteria2LinkFields = sourceFields{params: []string{"password", "hop_ports", "obfs", "obfs_password",
		model.ParamVerifyCertName, model.ParamFinalMask, model.ParamLegacyPin}, tls: quicLinkTLSFields, pins: true}
	hysteria2RealmLinkFields = sourceFields{params: []string{"password", "realm", "realm_stun", "obfs", "obfs_password",
		model.ParamVerifyCertName, model.ParamFinalMask, model.ParamLegacyPin}, tls: quicLinkTLSFields, pins: true}
	tuicLinkFields = sourceFields{params: []string{"uuid", "password", "congestion_control", "udp_relay_mode", "heartbeat",
		"zero_rtt_handshake", "udp_over_stream", model.ParamVerifyCertName, model.ParamFinalMask}, tls: quicLinkTLSFields, pins: true}
	// The link's keepalive and MTU are params; the form's are the top-level knobs, which stay.
	wireguardLinkFields = sourceFields{params: append([]string{"private_key", "peer_public_key", "pre_shared_key",
		"persistent_keepalive", "local_address", "reserved", "mtu"}, awgParamKeys()...)}
)

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
	// Xray's VLESS Encryption (encryption=mlkem768x25519plus..., Xray 25.8+) wraps the stream in a
	// post-quantum layer sing-box does not implement. Ignoring the parameter imported a plain-VLESS
	// endpoint that a server requiring the layer drops on every connection, while `sing-box check`
	// passed. Refuse it instead. The value is key material, so it is not echoed.
	if enc := strings.ToLower(strings.TrimSpace(q.Get("encryption"))); enc != "" && enc != "none" {
		return nil, errors.New("vless: Xray VLESS encryption (encryption=...) is not supported by sing-box")
	}
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
	t, err := transportFromQuery(q)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	e.Transport = t
	e.TLS = tlsFromQuery(q, false, e.Server)
	if err := linkPins(e, q); err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	if err := linkFinalMask(e, linkQueryValue(u.RawQuery, "fm")); err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	// No share link switches multiplex on (model.Multiplex), here or in trojan and vmess. The one
	// convention there is, Hiddify's muxtype, is not a sign the server speaks sing-mux: Hiddify Panel
	// adds it only when that server's core is Xray (hutils/proxy/xray.py is_muxable_agent, for any
	// client that is not sing-box, WayHop's included), and Xray drops every sing-mux connection, so
	// reading it broke a server that worked without it. Multiplex is the operator's choice in the form.
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
	t, err := transportFromQuery(q)
	if err != nil {
		return nil, fmt.Errorf("trojan: %w", err)
	}
	e.Transport = t
	// Trojan is TLS by default unless explicitly disabled.
	e.TLS = tlsFromQuery(q, true, e.Server)
	if err := linkPins(e, q); err != nil {
		return nil, fmt.Errorf("trojan: %w", err)
	}
	if err := linkFinalMask(e, linkQueryValue(u.RawQuery, "fm")); err != nil {
		return nil, fmt.Errorf("trojan: %w", err)
	}
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
	q := u.Query()
	e.TLS = tlsFromQuery(q, true, e.Server)
	if err := linkPins(e, q); err != nil {
		return nil, fmt.Errorf("anytls: %w", err)
	}
	if err := linkFinalMask(e, linkQueryValue(u.RawQuery, "fm")); err != nil {
		return nil, fmt.Errorf("anytls: %w", err)
	}
	return e, nil
}

// parseHysteria2 reads a hysteria2:// / hy2:// link. authorityPorts is the multi-port list Parse
// lifted out of the authority ("" when the authority held a single port, or none).
func parseHysteria2(u *url.URL, authorityPorts string) (*model.Endpoint, error) {
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
	if err := hysteria2Query(e, q, u.RawQuery, e.Server); err != nil {
		return nil, err
	}
	// Port hopping: real Hysteria2 links carry the hop range as mport= or ports=
	// (e.g. "20000-50000" or "443,5000-6000"). Dropping it silently means the
	// tunnel only tries the base port — which breaks entirely if the server hops
	// and isn't listening there. Carry it; the generator emits server_ports.
	// The official URI form carries the list in the authority instead (host:443,5000-6000); the
	// explicit query parameter wins when a link has both.
	if mp := util.FirstNonEmpty(q.Get("mport"), q.Get("ports"), authorityPorts); mp != "" {
		e.Params["hop_ports"] = mp
	}
	return e, nil
}

// hysteria2Query reads the query parameters hysteria2:// and hysteria2+realm:// share: obfuscation
// and TLS, the certificate pin with it, and fm= from the raw query. sniFallback is the server name
// used when the link gives no sni=.
func hysteria2Query(e *model.Endpoint, q url.Values, rawQuery, sniFallback string) error {
	if obfs := q.Get("obfs"); obfs != "" {
		e.Params["obfs"] = obfs
		if op := q.Get("obfs-password"); op != "" {
			e.Params["obfs_password"] = op
		}
	}
	// Hysteria2 always runs over QUIC+TLS. ech= is Hysteria's own (app/v2.10.0): a base64
	// ECHConfigList.
	e.TLS = &model.TLS{
		Enabled:  true,
		Type:     "tls",
		SNI:      util.FirstNonEmpty(q.Get("sni"), sniFallback),
		Insecure: insecureFromQuery(q),
		ALPN:     splitCSV(q.Get("alpn")),
		ECH:      settleECH(echFromLink(q.Get("ech")), "tls"),
	}
	// pinSHA256 hashes the whole certificate, which sing-box checks from 1.15 (generator/pin.go). With
	// insecure=1 the pin is all that authenticates the server; without it Hysteria checks the chain as
	// well, and sing-box checks the pin instead.
	if err := linkPins(e, q); err != nil {
		return fmt.Errorf("hysteria2: %w", err)
	}
	// fm= is Xray's finalmask (v2rayN reads it here too), not Hysteria's own obfs= above.
	if err := linkFinalMask(e, linkQueryValue(rawQuery, "fm")); err != nil {
		return fmt.Errorf("hysteria2: %w", err)
	}
	return nil
}

// parseHysteria2Realm reads Hysteria's realm-mode link (URI scheme, "Realm mode"):
// hysteria2+realm://<token>@<rendezvous>[:port]/<realm name>?auth=<password>&..., or
// hysteria2+realm+http:// for a plain-HTTP rendezvous. The authority and path are a realm address,
// not a server: the userinfo is the rendezvous token, so the Hysteria password moves to auth=.
// The hysteria2:// parameters apply as they do there, and stun= (repeatable) names the STUN servers.
// lport= pins the client's local UDP port, which sing-box has no option for, so it is not carried;
// nor is a port-hopping range, which realm mode does not have.
func parseHysteria2Realm(u *url.URL, plainHTTP bool) (*model.Endpoint, error) {
	q := u.Query()
	addr := url.URL{Scheme: "realm", User: u.User, Host: u.Host, Path: u.Path, RawPath: u.RawPath,
		RawQuery: url.Values{"stun": q["stun"]}.Encode()}
	if plainHTTP {
		addr.Scheme = "realm+http"
	}
	r, err := model.ParseHy2Realm(addr.String())
	if err != nil {
		return nil, fmt.Errorf("hysteria2+realm link: %w", err)
	}
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoHysteria2,
		Name:     fragmentName(u),
		Params:   map[string]any{"password": q.Get("auth"), "realm": r.URI()},
	}
	if len(r.STUN) > 0 {
		e.Params["realm_stun"] = strings.Join(r.STUN, ",")
	}
	// No sni= leaves the name unset, and sing-box then presents the rendezvous host, as Hysteria does.
	if err := hysteria2Query(e, q, u.RawQuery, ""); err != nil {
		return nil, err
	}
	if e.Name == "" {
		e.Name = "HYSTERIA2 realm " + r.Host // not the realm name: knowing it is what reveals the server's address
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
		// No official TUIC URI; v2rayN reads ech= on tuic:// as on its other links.
		ECH: settleECH(echFromLink(q.Get("ech")), "tls"),
	}
	if err := linkPins(e, q); err != nil {
		return nil, fmt.Errorf("tuic: %w", err)
	}
	if err := linkFinalMask(e, linkQueryValue(u.RawQuery, "fm")); err != nil {
		return nil, fmt.Errorf("tuic: %w", err)
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
		// An IPv6 `add` may arrive bracketed ("[2001:db8::1]"); strip the brackets like every other
		// host path (SS/WireGuard go through splitHostPort) so the stored Server is a bare address —
		// else the generator double-brackets it and sing-box rejects the outbound.
		Server: strings.TrimSuffix(strings.TrimPrefix(asString(m["add"]), "["), "]"),
		Port:   asInt(m["port"], 443),
		Name:   asString(m["ps"]),
		Params: map[string]any{
			"uuid":     asString(m["id"]),
			"alter_id": asInt(m["aid"], 0),
			"security": util.FirstNonEmpty(asString(m["scy"]), "auto"),
		},
	}
	net := strings.ToLower(strings.TrimSpace(util.FirstNonEmpty(asString(m["net"]), "tcp")))
	if net == "h2" {
		net = "http" // VMess "h2" is the HTTP/2 transport sing-box calls "http"
	}
	switch net {
	case "ws", "grpc", "http", "httpupgrade":
		t := &model.Transport{Type: net, Path: asString(m["path"]), Host: firstScalar(m["host"])}
		if net == "grpc" {
			t.ServiceName = asString(m["path"])
		}
		e.Transport = t
	case "tcp", "raw", "none":
	default:
		// xhttp / kcp / quic: importing it as raw TCP made an endpoint the server cannot accept.
		return nil, fmt.Errorf("vmess: %w", unsupportedTransport(net))
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
		// v2rayN's own VMess JSON spells it "insecure", "1" or "0" (VmessQRCode), and reads
		// nothing else, so both are read.
		e.TLS = &model.TLS{Enabled: true, Type: "tls", SNI: util.FirstNonEmpty(asString(m["sni"]), firstScalar(m["host"]), e.Server), Fingerprint: asString(m["fp"]), ALPN: asStringList(m["alpn"]), CipherSuites: asStringList(m["cs"]), Insecure: truthy(asString(m["allowInsecure"])) || truthy(asString(m["insecure"]))}
		if err := vmessPins(e, m); err != nil {
			return nil, fmt.Errorf("vmess: %w", err)
		}
	}
	// 3x-ui writes the finalmask into the JSON as "fm", a string of JSON.
	if err := linkFinalMask(e, vmessFinalMask(m["fm"])); err != nil {
		return nil, fmt.Errorf("vmess: %w", err)
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
		// SIP002 permits an optional path '/' between host:port and the '?plugin' query (already
		// stripped above). Trim a trailing '/' so net.SplitHostPort doesn't see port="8388/" and reject
		// the whole node — the spec's own plugin example uses this canonical slash form.
		hp = strings.TrimSuffix(hp, "/")
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
		// 3x-ui writes Xray's finalmask on Shadowsocks links too.
		if err := linkFinalMask(e, linkQueryValue(query, "fm")); err != nil {
			return nil, fmt.Errorf("ss: %w", err)
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

// normalizedQuery indexes a query by its key lowercased with '_' and '-' removed, the spelling-
// insensitive lookup Hiddify applies to wg:// links, so private_key, privateKey and private-key
// all read as "privatekey". The first value of the first spelling seen wins. Values are as
// url.Query decoded them; key params go through wgKey, which undoes the '+' that decoding ate.
func normalizedQuery(q url.Values) map[string]string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic when two spellings of one key are both present
	out := make(map[string]string, len(q))
	for _, k := range keys {
		n := strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(k))
		if _, seen := out[n]; !seen && len(q[k]) > 0 {
			out[n] = q[k][0]
		}
	}
	return out
}

// firstOf returns the first non-empty value among keys of a normalizedQuery.
func firstOf(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(m[k]); v != "" {
			return v
		}
	}
	return ""
}

// wgKey reads a base64 key param (the first of keys that is set), restoring a '+' that url.Query()
// decoded to a space. A WireGuard key is standard base64 (its alphabet includes '+'); a link that
// carries the '+' un-percent-encoded (the common real-world form) has it turned into a space by
// query decoding, which corrupts the key — the peer public_key / pre_shared_key no longer match the
// server and the handshake fails. base64 never contains a literal space, so any space here is
// unambiguously a lost '+', and it is restored BEFORE any trimming: a key may start with '+'.
// A properly %2B-encoded link already yields '+' (no space), so this is a no-op for it.
func wgKey(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := m[k]; strings.TrimSpace(v) != "" {
			return strings.ReplaceAll(v, " ", "+")
		}
	}
	return ""
}

func parseWireGuardURL(u *url.URL) (*model.Endpoint, error) {
	q := normalizedQuery(u.Query())
	// v2rayN puts the private key in the userinfo and names the peer key publickey; Hiddify's wg://
	// form also takes it as a parameter (pk / private_key) and names the peer key peer_public_key,
	// pub or peer_pk. Read every spelling: a key that is not found is an endpoint that never handshakes.
	priv := u.User.Username()
	if priv == "" {
		priv = wgKey(q, "privatekey", "pk")
	}
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoWireGuard,
		Server:   u.Hostname(),
		Port:     atoiDefault(u.Port(), 51820),
		Name:     fragmentName(u),
		Params: map[string]any{
			"private_key":     priv,
			"peer_public_key": wgKey(q, "publickey", "peerpublickey", "pub", "peerpub", "peerpk"),
		},
	}
	if psk := wgKey(q, "presharedkey", "psk"); psk != "" {
		e.Params["pre_shared_key"] = psk
	}
	// Carry PersistentKeepalive (spelled keepalive / persistentkeepalive in the
	// wild) so an idle tunnel behind NAT keeps its UDP mapping alive.
	if ka := atoiDefault(firstOf(q, "keepalive", "persistentkeepalive"), 0); ka > 0 {
		e.Params["persistent_keepalive"] = ka
	}
	if addr := firstOf(q, "address", "localaddress", "ip"); addr != "" {
		e.Params["local_address"] = splitCSV(addr)
	}
	// Cloudflare WARP encodes 3 client-id bytes as the WG "reserved" field; sing-box
	// puts them on the peer and the WARP server rejects the handshake without them.
	// (Plain-WireGuard only — sing-box's userspace WG; native AmneziaWG has no such
	// field.) Spelled reserved=a,b,c or reserved=[a,b,c] in the wild.
	if r := parseReserved(q["reserved"]); r != nil {
		e.Params["reserved"] = r
	}
	// MTU keeps large packets from fragmenting/blackholing — emitted on the sing-box WG
	// endpoint. (e.g. WARP links carry mtu=1280.) Bound to a sane WG range: sing-box's
	// endpoint mtu is a uint32, so an out-of-range value (e.g. a hostile mtu=999999999999)
	// overflows at config decode and FATALs the whole shared singbox.json. Bounding also makes
	// 64-bit and 32-bit (mipsle) builds agree, since strconv.Atoi overflows differently per arch.
	if mtu := atoiDefault(q["mtu"], 0); mtu >= 576 && mtu <= 65535 {
		e.Params["mtu"] = mtu
	}
	// A link carrying AmneziaWG obfuscation parameters (jc/jmin/jmax/s1-s4/h1-h4/i1-i5, the names
	// the .conf uses; Hiddify reads them from wg:// links) is an AmneziaWG peer. Imported as plain
	// WireGuard it would send unobfuscated handshakes the server ignores, so route it to the AWG
	// engine exactly as the same values in a .conf are.
	isAWG, err := applyAWGParams(e, q)
	if err != nil {
		return nil, err
	}
	if isAWG {
		e.Protocol = model.ProtoAmneziaWG
		e.Engine = model.EngineAmneziaWG
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

// unsupportedTransport is the error for a stream transport sing-box has no client for. A link
// naming one used to import as raw TCP - a well-formed endpoint the server can never accept, with
// nothing to say why - so the import now fails and says which transport it was.
func unsupportedTransport(name string) error {
	if len(name) > 24 {
		name = name[:24] + "..."
	}
	switch name {
	case "xhttp", "splithttp":
		return fmt.Errorf("transport %q (Xray XHTTP) is not supported by sing-box", name)
	case "kcp", "mkcp":
		return fmt.Errorf("transport %q (mKCP) is not supported by sing-box", name)
	}
	return fmt.Errorf("transport %q is not supported by sing-box", name)
}

func transportFromQuery(q url.Values) (*model.Transport, error) {
	switch typ := strings.ToLower(strings.TrimSpace(q.Get("type"))); typ {
	case "ws":
		return &model.Transport{Type: "ws", Path: q.Get("path"), Host: q.Get("host")}, nil
	case "grpc":
		// serviceName is the gRPC path segment; the wrong/empty one means the gRPC
		// stream hits the wrong path and never connects (passes `sing-box check`,
		// fails at runtime). Clients spell it three ways — serviceName (v2rayN/Xray
		// URIs), service_name (sing-box JSON → link converters), servicename — so
		// accept all, mirroring the packetEncoding handling above.
		return &model.Transport{Type: "grpc", ServiceName: util.FirstNonEmpty(
			q.Get("serviceName"), q.Get("service_name"), q.Get("servicename"))}, nil
	case "http", "h2":
		return &model.Transport{Type: "http", Path: q.Get("path"), Host: q.Get("host")}, nil
	case "httpupgrade":
		return &model.Transport{Type: "httpupgrade", Path: q.Get("path"), Host: q.Get("host")}, nil
	case "", "tcp", "raw", "none":
		return nil, nil // raw TCP ("raw" is Xray's current name for it)
	default:
		return nil, unsupportedTransport(typ)
	}
}

// hy2PortList is the Hysteria 2 "multi-port" syntax: ports and ranges joined by commas.
var hy2PortList = regexp.MustCompile(`^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$`)

// splitAuthorityPortList rewrites "scheme://auth@host:443,5000-6000/?q" to
// "scheme://auth@host:443/?q" and returns the list ("443,5000-6000"). A single port, a missing port
// and anything that is not a port list are returned unchanged with "" (url.Parse then judges them).
// The list's first port stands in as the endpoint's single port; the generator dials the whole
// list through server_ports.
func splitAuthorityPortList(raw string) (string, string) {
	i := strings.Index(raw, "://")
	if i < 0 {
		return raw, ""
	}
	start := i + 3
	end := len(raw)
	if j := strings.IndexAny(raw[start:], "/?#"); j >= 0 {
		end = start + j
	}
	auth := raw[start:end]
	host := strings.LastIndexByte(auth, '@') + 1
	colon := strings.LastIndexByte(auth, ':')
	if colon < host || strings.ContainsRune(auth[colon:], ']') {
		return raw, ""
	}
	spec := auth[colon+1:]
	if !strings.ContainsAny(spec, ",-") || !hy2PortList.MatchString(spec) {
		return raw, ""
	}
	first, _, _ := strings.Cut(spec, ",")
	first, _, _ = strings.Cut(first, "-")
	return raw[:start] + auth[:colon+1] + first + raw[end:], spec
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
			ECH:         settleECH(echFromLink(q.Get("ech")), "reality"), // kept off: see settleECH
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
			SNI:          util.FirstNonEmpty(q.Get("sni"), q.Get("host"), server),
			Fingerprint:  q.Get("fp"),
			Insecure:     insecureFromQuery(q),
			ALPN:         splitCSV(q.Get("alpn")),
			CipherSuites: splitCSV(q.Get("cs")),
			// Encrypted Client Hello: Xray's ech= (vless, trojan; v2rayN writes it for anytls too).
			ECH: settleECH(echFromLink(q.Get("ech")), "tls"),
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

// asStringList coerces a Params value into a []string for a LIST field (e.g. vmess `alpn`): a
// string is split on commas (the canonical CSV form), while a JSON array yields one entry per
// element. Without this, asString's default fmt.Sprintf("%v") branch renders an array-valued alpn
// (["h2","http/1.1"]) as a single Go-slice-stringified "[h2 http/1.1]" entry that sing-box then
// advertises as one bogus ALPN protocol, breaking TLS ALPN negotiation.
func asStringList(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, it := range t {
			if s := strings.TrimSpace(asString(it)); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		out := make([]string, 0, len(t))
		for _, s := range t {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return splitCSV(asString(v))
	}
}

// firstScalar coerces a Params value into a single string for a SCALAR field (e.g. host / sni): a
// plain string is returned as-is; a JSON array yields its first element rather than asString's
// Go-slice "[a b]" stringification.
func firstScalar(v any) string {
	switch t := v.(type) {
	case []any:
		if len(t) > 0 {
			return strings.TrimSpace(asString(t[0]))
		}
		return ""
	case []string:
		if len(t) > 0 {
			return strings.TrimSpace(t[0])
		}
		return ""
	default:
		return asString(v)
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
	host := e.Server
	if r, _ := model.Hy2RealmOf(e); r != nil {
		// The realm name stays out of the id, as out of the name, but the rendezvous alone is not an
		// identity: two home servers on one public rendezvous made one id, and the second import could
		// only replace the first (QA-058). A short hash of the whole realm address tells them apart.
		sum := sha256.Sum256([]byte(r.URI()))
		host = "realm-" + r.Host + "-" + hex.EncodeToString(sum[:4])
	}
	base := string(e.Protocol) + "-" + host
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
