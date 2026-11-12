// Package exporter renders a model.Endpoint back into a client-importable form:
// a share URI (vless/trojan/hysteria2/tuic/ss/vmess) for proxy protocols, or a
// WireGuard/AmneziaWG .conf. It is the inverse of internal/importer and is used
// for per-connection QR codes and subscription links.
package exporter

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"

	"wayhop/internal/model"
	"wayhop/internal/plugin"
	"wayhop/internal/util"
)

// Result is an exported endpoint.
type Result struct {
	Kind     string `json:"kind"` // "link" (share URI) or "conf" (.conf file)
	Text     string `json:"text"`
	Filename string `json:"filename,omitempty"`
}

// Export renders an endpoint. ok=false for protocols with no client-importable
// representation (socks/http/olcrtc).
func Export(e model.Endpoint) (Result, bool) {
	// EngineExternal routes through an existing OS-owned interface (e.g. a
	// UCI/netifd-brought-up awg0/awg1). It is device-local and has no keys or
	// server of its own to hand to a client, so there is nothing shareable — a
	// share-link/.conf would be wrong, empty, or leak the wrong peer's identity.
	// Degrade gracefully (ok=false) rather than emit a malformed link. It still
	// round-trips through profile-JSON export (plain model marshal). Parallels the
	// EngineAmneziaWG special-case in wgConf below.
	if e.Engine == model.EngineExternal {
		return Result{}, false
	}
	// A link weaker than the connection it shares is not given (Refusal says why).
	if Refusal(e) != "" {
		return Result{}, false
	}
	switch e.Protocol {
	case model.ProtoVLESS:
		return Result{Kind: "link", Text: vlessLink(e)}, true
	case model.ProtoTrojan:
		return Result{Kind: "link", Text: trojanLink(e)}, true
	case model.ProtoAnyTLS:
		return Result{Kind: "link", Text: anytlsLink(e)}, true
	case model.ProtoHysteria2:
		// A realm connection whose address does not parse (a disabled draft) has no server either,
		// so there is no link to give.
		if _, err := model.Hy2RealmOf(&e); err != nil {
			return Result{}, false
		}
		return Result{Kind: "link", Text: hysteria2Link(e)}, true
	case model.ProtoTUIC:
		return Result{Kind: "link", Text: tuicLink(e)}, true
	case model.ProtoShadowsocks:
		return Result{Kind: "link", Text: ssLink(e)}, true
	case model.ProtoVMess:
		return Result{Kind: "link", Text: vmessLink(e)}, true
	case model.ProtoAmneziaWG, model.ProtoWireGuard:
		if conf, ok := wgConf(e); ok {
			return Result{Kind: "conf", Text: conf, Filename: slug(util.FirstNonEmpty(e.Name, e.ID)) + ".conf"}, true
		}
	case model.ProtoOpenVPN:
		if conf, ok := ovpnConf(e); ok {
			return Result{Kind: "conf", Text: conf, Filename: slug(util.FirstNonEmpty(e.Name, e.ID)) + ".ovpn"}, true
		}
	case model.ProtoSSH:
		// Deliberately none. No client reads an SSH share link, and an ssh:// URI holds a user and a
		// password but never the private key or the pinned host keys: a link would hand over a
		// connection that accepts any server, the pin silently gone. The importer still reads
		// ssh://user[:password]@host[:port], because its form then asks for the rest.
		return Result{}, false
	}
	return Result{}, false
}

// ShareLink returns just the URI (used to assemble a subscription). ok is true
// only for protocols with a share-URI form.
func ShareLink(e model.Endpoint) (string, bool) {
	r, ok := Export(e)
	if ok && r.Kind == "link" {
		return r.Text, true
	}
	return "", false
}

func vlessLink(e model.Endpoint) string {
	q := url.Values{}
	q.Set("encryption", "none")
	if f := str(e.Params, "flow"); f != "" {
		q.Set("flow", f)
	}
	if pe := str(e.Params, "packet_encoding"); pe != "" {
		q.Set("packetEncoding", pe) // round-trip UDP-over-VLESS encoding
	}
	setTransportQuery(q, e.Transport)
	setTLSQuery(q, e.TLS)
	setPinQuery(q, e)
	return buildURI("vless", str(e.Params, "uuid"), "", e, q)
}

func trojanLink(e model.Endpoint) string {
	q := url.Values{}
	setTransportQuery(q, e.Transport)
	setTLSQuery(q, e.TLS)
	setPinQuery(q, e)
	return buildURI("trojan", str(e.Params, "password"), "", e, q)
}

// anytlsLink mirrors trojanLink (password + TLS in the query) but emits no transport — AnyTLS has no
// ws/grpc sub-transport.
func anytlsLink(e model.Endpoint) string {
	q := url.Values{}
	setTLSQuery(q, e.TLS)
	setPinQuery(q, e)
	return buildURI("anytls", str(e.Params, "password"), "", e, q)
}

func hysteria2Link(e model.Endpoint) string {
	q := url.Values{}
	if e.TLS != nil {
		if e.TLS.SNI != "" {
			q.Set("sni", e.TLS.SNI)
		}
		if e.TLS.Insecure {
			q.Set("insecure", "1")
		}
		if len(e.TLS.ALPN) > 0 {
			q.Set("alpn", strings.Join(e.TLS.ALPN, ","))
		}
		setECHQuery(q, e.TLS) // Hysteria's own ech= (app/v2.10.0)
	}
	if o := str(e.Params, "obfs"); o != "" {
		q.Set("obfs", o)
		if op := str(e.Params, "obfs_password"); op != "" {
			q.Set("obfs-password", op)
		}
	}
	setHysteria2PinQuery(q, e)
	if r, _ := model.Hy2RealmOf(&e); r != nil {
		return hysteria2RealmLink(e, r, q)
	}
	if hp := str(e.Params, "hop_ports"); hp != "" {
		q.Set("mport", hp) // round-trip the port-hopping range
	}
	return buildURI("hysteria2", str(e.Params, "password"), "", e, q)
}

// hysteria2RealmLink is Hysteria's realm-mode link: the realm address as the authority and path (the
// userinfo is the rendezvous token), the password in auth=, one stun= per STUN server.
func hysteria2RealmLink(e model.Endpoint, r *model.Hy2Realm, q url.Values) string {
	setIf(q, "auth", str(e.Params, "password"))
	for _, s := range r.STUN {
		q.Add("stun", s)
	}
	scheme := "hysteria2+realm"
	if r.HTTP {
		scheme = "hysteria2+realm+http"
	}
	addr := r.Addr(scheme)
	addr.RawQuery = encodeQuery(q, e)
	s := addr.String()
	if e.Name != "" {
		s += "#" + fragmentEscape(e.Name)
	}
	return s
}

func tuicLink(e model.Endpoint) string {
	q := url.Values{}
	if cc := str(e.Params, "congestion_control"); cc != "" {
		q.Set("congestion_control", cc)
	}
	if m := str(e.Params, "udp_relay_mode"); m != "" {
		q.Set("udp_relay_mode", m)
	}
	if hb := str(e.Params, "heartbeat"); hb != "" {
		q.Set("heartbeat", hb)
	}
	if b, _ := e.Params["zero_rtt_handshake"].(bool); b {
		q.Set("zero_rtt_handshake", "1")
	}
	if b, _ := e.Params["udp_over_stream"].(bool); b {
		q.Set("udp_over_stream", "1")
	}
	if e.TLS != nil {
		if e.TLS.SNI != "" {
			q.Set("sni", e.TLS.SNI)
		}
		if e.TLS.Insecure {
			q.Set("allow_insecure", "1")
		}
		if len(e.TLS.ALPN) > 0 {
			q.Set("alpn", strings.Join(e.TLS.ALPN, ","))
		}
		setECHQuery(q, e.TLS) // no official TUIC URI; v2rayN reads ech= on tuic:// too
	}
	setPinQuery(q, e) // v2rayN reads pcs= and vcn= on tuic:// too
	return buildURI("tuic", str(e.Params, "uuid"), str(e.Params, "password"), e, q)
}

func ssLink(e model.Endpoint) string {
	creds := str(e.Params, "method") + ":" + str(e.Params, "password")
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(creds))
	u := userinfo + "@" + hostPort(e)
	q := url.Values{}
	if b, _ := e.Params["udp_over_tcp"].(bool); b {
		q.Set("udp-over-tcp", "1")
	}
	// Re-assemble the SIP002 plugin param "name;opts" so an obfs-local / v2ray-plugin
	// SS endpoint round-trips (the importer split it into plugin + plugin_opts).
	if pl := str(e.Params, "plugin"); pl != "" {
		if opts := str(e.Params, "plugin_opts"); opts != "" {
			q.Set("plugin", pl+";"+opts)
		} else {
			q.Set("plugin", pl)
		}
	}
	if enc := encodeQuery(q, e); enc != "" { // fm= too, as 3x-ui writes it here
		u += "?" + enc
	}
	if e.Name != "" {
		u += "#" + fragmentEscape(e.Name)
	}
	return "ss://" + u
}

func vmessLink(e model.Endpoint) string {
	m := map[string]any{
		"v": "2", "ps": e.Name, "add": e.Server, "port": strconv.Itoa(e.Port),
		"id": str(e.Params, "uuid"), "aid": intStr(e.Params, "alter_id"),
		"scy": util.FirstNonEmpty(str(e.Params, "security"), "auto"), "net": "tcp", "type": "none",
	}
	if e.Transport != nil && e.Transport.Type != "" {
		// VMess JSON names the HTTP/2 transport "h2"; the model (and sing-box) call it
		// "http". The importer maps "h2" -> "http", so the exporter must reverse it —
		// otherwise a shared vmess link carries the non-standard net:"http", which a
		// standard vmess client (v2rayN etc.) won't recognise as HTTP/2.
		net := e.Transport.Type
		if net == "http" {
			net = "h2"
		}
		m["net"] = net
		m["path"] = e.Transport.Path
		m["host"] = e.Transport.Host
		if e.Transport.Type == "grpc" {
			m["path"] = e.Transport.ServiceName
		}
	}
	if e.TLS != nil && e.TLS.Enabled {
		m["tls"] = "tls"
		m["sni"] = e.TLS.SNI
		if e.TLS.Fingerprint != "" {
			m["fp"] = e.TLS.Fingerprint // mirror the import side; else QR/share drops the uTLS fp
		}
		if len(e.TLS.ALPN) > 0 {
			m["alpn"] = strings.Join(e.TLS.ALPN, ",")
		}
		if len(e.TLS.CipherSuites) > 0 {
			m["cs"] = strings.Join(e.TLS.CipherSuites, ",")
		}
		if e.TLS.Insecure {
			m["allowInsecure"] = "true" // round-trip skip-cert-verify (parseVMess reads it)
			m["insecure"] = "1"         // the spelling v2rayN reads and writes (VmessQRCode)
		}
		// v2rayN's VMess JSON carries Xray's pins and verify names as on its other links.
		if pins := model.CertPinsOf(&e); len(pins) > 0 {
			m["pcs"] = strings.Join(pins, ",")
		}
		if v := str(e.Params, model.ParamVerifyCertName); v != "" {
			m["vcn"] = v
		}
	}
	// Xray's finalmask, a string of JSON, as 3x-ui writes it into a VMess link.
	if fm := str(e.Params, model.ParamFinalMask); fm != "" {
		m["fm"] = fm
	}
	b, _ := json.Marshal(m)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func wgConf(e model.Endpoint) (string, bool) {
	if e.Engine == model.EngineAmneziaWG {
		if conf, _, err := plugin.NativeConfig(e, 0); err == nil {
			return conf, true
		}
	}
	if e.Protocol == model.ProtoWireGuard {
		return plainWGConf(e), true
	}
	return "", false
}

// reservedCSV formats a 3-byte WARP "reserved" param as "a,b,c", tolerating the
// []int it is imported as and the []any/[]float64 it becomes after a JSON store
// round-trip. Returns "" for anything that isn't exactly three values.
func reservedCSV(p map[string]any, k string) string {
	v, ok := p[k]
	if !ok {
		return ""
	}
	var nums []int
	switch t := v.(type) {
	case []int:
		nums = t
	case []float64:
		for _, n := range t {
			nums = append(nums, int(n))
		}
	case []any:
		for _, e := range t {
			switch n := e.(type) {
			case int:
				nums = append(nums, n)
			case float64:
				nums = append(nums, int(n))
			default:
				return ""
			}
		}
	default:
		return ""
	}
	if len(nums) != 3 {
		return ""
	}
	parts := make([]string, 3)
	for i, n := range nums {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ",")
}

func plainWGConf(e model.Endpoint) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + str(e.Params, "private_key") + "\n")
	if a := util.LocalAddr(e.Params); a != "" {
		b.WriteString("Address = " + a + "\n")
	}
	// MTU/keepalive now live on typed Endpoint fields (the UI writes them there + drops the
	// legacy Params copy on edit), so prefer the typed value and fall back to Params for
	// not-yet-migrated configs — else a UI-edited tunnel would export WITHOUT its MTU.
	if e.MTU > 0 {
		b.WriteString("MTU = " + strconv.Itoa(e.MTU) + "\n")
	} else if mtu := intStr(e.Params, "mtu"); mtu != "0" {
		b.WriteString("MTU = " + mtu + "\n") // round-trips via parseConf; avoids fragmentation
	}
	if r := reservedCSV(e.Params, "reserved"); r != "" {
		b.WriteString("Reserved = " + r + "\n") // WARP client-id bytes; round-trips via parseConf
	}
	b.WriteString("DNS = 1.1.1.1\n")
	// A multi-[Peer] mesh .conf stores every peer in Params["peers"]; emit one [Peer] block per
	// entry so the exported config describes the SAME tunnel set (the legacy first-peer keys below
	// only carry peer #1, silently dropping the rest and their AllowedIPs on export). The generator
	// (wgPeers) already round-trips multi-peer, so the export path was the sole lossy leg.
	if peers := wgExportPeers(e.Params); len(peers) > 1 {
		for _, pr := range peers {
			b.WriteString("\n[Peer]\n")
			b.WriteString("PublicKey = " + str(pr, "public_key") + "\n")
			if psk := str(pr, "pre_shared_key"); psk != "" {
				b.WriteString("PresharedKey = " + psk + "\n")
			}
			ep := str(pr, "server")
			if port := intStr(pr, "port"); port != "0" {
				ep = net.JoinHostPort(ep, port)
			}
			b.WriteString("Endpoint = " + ep + "\n")
			aips := coerceStrings(pr["allowed_ips"])
			if len(aips) == 0 {
				aips = []string{"0.0.0.0/0", "::/0"}
			}
			b.WriteString("AllowedIPs = " + strings.Join(aips, ", ") + "\n")
			if ka := intStr(pr, "persistent_keepalive"); ka != "0" {
				b.WriteString("PersistentKeepalive = " + ka + "\n")
			}
		}
		return b.String()
	}

	b.WriteString("\n[Peer]\n")
	b.WriteString("PublicKey = " + str(e.Params, "peer_public_key") + "\n")
	if psk := str(e.Params, "pre_shared_key"); psk != "" {
		b.WriteString("PresharedKey = " + psk + "\n")
	}
	b.WriteString("Endpoint = " + hostPort(e) + "\n")
	b.WriteString("AllowedIPs = " + util.WGAllowedIPs(e.Params) + "\n") // ::/0 too for a dual-stack/IPv6 endpoint, else v6 leaks outside the tunnel
	if e.PersistentKeepalive > 0 {
		b.WriteString("PersistentKeepalive = " + strconv.Itoa(e.PersistentKeepalive) + "\n")
	} else if ka := intStr(e.Params, "persistent_keepalive"); ka != "0" {
		b.WriteString("PersistentKeepalive = " + ka + "\n") // else an exported idle tunnel drops behind NAT
	}
	return b.String()
}

// wgExportPeers extracts the structured WireGuard peer list from Params, tolerating both the
// importer's native []map[string]any and the []any a JSON store round-trip produces.
func wgExportPeers(params map[string]any) []map[string]any {
	switch v := params["peers"].(type) {
	case []map[string]any:
		return v
	case []any:
		out := make([]map[string]any, 0, len(v))
		for _, it := range v {
			if m, ok := it.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

// coerceStrings turns a Params value into a []string, tolerating the importer's []string and
// the []any a JSON round-trip yields; empty/whitespace entries are dropped.
func coerceStrings(v any) []string {
	var raw []string
	switch t := v.(type) {
	case []string:
		raw = t
	case []any:
		for _, it := range t {
			if s, ok := it.(string); ok {
				raw = append(raw, s)
			}
		}
	default:
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// --- shared query/tls/transport encoders (inverse of importer helpers) ---

func setTransportQuery(q url.Values, t *model.Transport) {
	if t == nil || t.Type == "" {
		return // raw tcp
	}
	q.Set("type", t.Type)
	switch t.Type {
	case "ws", "http", "httpupgrade":
		if t.Path != "" {
			q.Set("path", t.Path)
		}
		if t.Host != "" {
			q.Set("host", t.Host)
		}
	case "grpc":
		if t.ServiceName != "" {
			q.Set("serviceName", t.ServiceName)
		}
	}
}

func setTLSQuery(q url.Values, t *model.TLS) {
	if t == nil || !t.Enabled {
		return
	}
	switch t.Type {
	case "reality":
		q.Set("security", "reality")
		setIf(q, "sni", t.SNI)
		setIf(q, "fp", t.Fingerprint)
		setIf(q, "pbk", t.PublicKey)
		setIf(q, "sid", t.ShortID)
		if len(t.ALPN) > 0 {
			q.Set("alpn", strings.Join(t.ALPN, ","))
		}
	default:
		q.Set("security", "tls")
		setIf(q, "sni", t.SNI)
		setIf(q, "fp", t.Fingerprint)
		if t.Insecure {
			q.Set("allowInsecure", "1")
		}
		if len(t.ALPN) > 0 {
			q.Set("alpn", strings.Join(t.ALPN, ","))
		}
		if len(t.CipherSuites) > 0 {
			q.Set("cs", strings.Join(t.CipherSuites, ","))
		}
	}
	setECHQuery(q, t)
}

// Refusal returns why e cannot be shared as a link without the link being weaker than the router's
// own connection, or "" when it can. A public-key pin has no share-link form (only sing-box carries
// one): where it is the only pin and the connection's certificate checks are off, the router checks
// the pin (from sing-box 1.13) while the link would carry "insecure" and no pin, and so accept any
// certificate. A whole-certificate pin travels (pcs=, pinSHA256), so with one the link stays pinned;
// Reality uses no pin; with certificate checks on the link checks certificates too.
func Refusal(e model.Endpoint) string {
	t := e.TLS
	if t == nil || !t.Enabled || !t.Insecure || t.Type == "reality" {
		return ""
	}
	switch e.Protocol {
	case model.ProtoVLESS, model.ProtoVMess, model.ProtoTrojan, model.ProtoAnyTLS, model.ProtoHysteria2, model.ProtoTUIC:
	default:
		return ""
	}
	if len(model.PubKeyPinsOf(&e)) == 0 || len(model.CertPinsOf(&e)) > 0 {
		return ""
	}
	return "this connection authenticates its server by a public-key pin, which a share link cannot carry, and its " +
		"certificate checks are off (\"insecure\"), so the link would accept any certificate; add the server's " +
		"whole-certificate pin, or turn \"insecure\" off, to share it"
}

// setPinQuery writes a TLS link's certificate pins as Xray and v2rayN carry them: pcs=, the
// whole-certificate hashes in lowercase hex, comma-separated, and vcn=, the names to check the
// certificate against, kept from the link it came from. Public-key pins have no share-link form
// (only sing-box has them), so they stay with the connection.
func setPinQuery(q url.Values, e model.Endpoint) {
	if e.TLS == nil || !e.TLS.Enabled {
		return
	}
	if pins := model.CertPinsOf(&e); len(pins) > 0 {
		q.Set("pcs", strings.Join(pins, ","))
	}
	setIf(q, "vcn", str(e.Params, model.ParamVerifyCertName))
}

// setHysteria2PinQuery writes a Hysteria2 link's pins: pinSHA256, Hysteria's one pin, as Hysteria's
// own share link writes it (lowercase hex), and, when there are more, all of them in pcs=, which
// v2rayN reads before pinSHA256. The official client then checks the first, so the link is no
// weaker than the connection. A pin an older WayHop kept as the link held it, and which is not a
// SHA-256 hash, is given back as it came.
func setHysteria2PinQuery(q url.Values, e model.Endpoint) {
	pins := model.CertPinsOf(&e)
	switch {
	case len(pins) > 0:
		q.Set("pinSHA256", pins[0])
		if len(pins) > 1 {
			q.Set("pcs", strings.Join(pins, ","))
		}
	default:
		setIf(q, "pinSHA256", str(e.Params, model.ParamLegacyPin))
	}
	setIf(q, "vcn", str(e.Params, model.ParamVerifyCertName))
}

// setECHQuery writes ech= (Xray's standard, read by v2rayN and Hysteria too) with the connection's
// ECH config as standard base64, which url.Values escapes. A config looked up in DNS is not
// exported: the link form names a resolver URL, and the router looks the record up through its own
// DNS instead, so there is none to give. A Reality link gives back the config it brought (kept
// switched off, since sing-box cannot pair the two).
func setECHQuery(q url.Values, t *model.TLS) {
	if t == nil || t.ECH == nil || t.ECH.Config == "" || (!t.ECH.Enabled && t.Type != "reality") {
		return
	}
	q.Set("ech", model.CanonicalECHConfig(t.ECH.Config))
}

// buildURI assembles scheme://user[:pass]@host:port?query#name. The userinfo is encoded by
// the stdlib (url.User/UserPassword) so a credential containing ':' / '@' / '/' is
// percent-escaped — a bare ':' in a password would otherwise be read by every client as the
// user:pass separator and silently truncate the password.
func buildURI(scheme, user, pass string, e model.Endpoint, q url.Values) string {
	u := url.URL{Scheme: scheme, Host: hostPort(e), RawQuery: encodeQuery(q, e)}
	if pass != "" {
		u.User = url.UserPassword(user, pass)
	} else {
		u.User = url.User(user)
	}
	s := u.String()
	if e.Name != "" {
		s += "#" + fragmentEscape(e.Name)
	}
	return s
}

// encodeQuery encodes q, then a link's fm= (Xray's finalmask, model.ParamFinalMask) last, escaped as
// v2rayN escapes it (Uri.EscapeDataString): a space is %20, never '+', which v2rayN and the importer
// (linkQueryValue) read as '+'.
func encodeQuery(q url.Values, e model.Endpoint) string {
	s := q.Encode()
	fm := str(e.Params, model.ParamFinalMask)
	if fm == "" {
		return s
	}
	if s != "" {
		s += "&"
	}
	return s + "fm=" + strings.ReplaceAll(url.QueryEscape(fm), "+", "%20")
}

// fragmentEscape percent-encodes a #name fragment so it decodes IDENTICALLY whether a client
// uses path- or query-unescaping. The only divergence is '+': query-unescape turns a bare
// '+' into a space (SS import + many clients do this). PathEscape already gives %20 for a
// space (safe for both); additionally escaping '+' -> %2B keeps a name like "My+VPS" intact.
func fragmentEscape(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), "+", "%2B")
}

// hostPort joins server+port for a URI/conf, bracketing an IPv6 literal
// ("[2001:db8::1]:443") — a bare "server:port" would be ambiguous/unparseable.
func hostPort(e model.Endpoint) string { return net.JoinHostPort(e.Server, strconv.Itoa(e.Port)) }

func str(p map[string]any, k string) string {
	if v, ok := p[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func intStr(p map[string]any, k string) string {
	switch v := p[k].(type) {
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.Itoa(int(v))
	case string:
		return v
	}
	return "0"
}

func setIf(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "client"
	}
	return out
}
