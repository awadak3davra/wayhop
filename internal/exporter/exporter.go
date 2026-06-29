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

	"velinx/internal/model"
	"velinx/internal/plugin"
	"velinx/internal/util"
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
	switch e.Protocol {
	case model.ProtoVLESS:
		return Result{Kind: "link", Text: vlessLink(e)}, true
	case model.ProtoTrojan:
		return Result{Kind: "link", Text: trojanLink(e)}, true
	case model.ProtoAnyTLS:
		return Result{Kind: "link", Text: anytlsLink(e)}, true
	case model.ProtoHysteria2:
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
	return buildURI("vless", str(e.Params, "uuid"), "", e, q)
}

func trojanLink(e model.Endpoint) string {
	q := url.Values{}
	setTransportQuery(q, e.Transport)
	setTLSQuery(q, e.TLS)
	return buildURI("trojan", str(e.Params, "password"), "", e, q)
}

// anytlsLink mirrors trojanLink (password + TLS in the query) but emits no transport — AnyTLS has no
// ws/grpc sub-transport.
func anytlsLink(e model.Endpoint) string {
	q := url.Values{}
	setTLSQuery(q, e.TLS)
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
	}
	if o := str(e.Params, "obfs"); o != "" {
		q.Set("obfs", o)
		if op := str(e.Params, "obfs_password"); op != "" {
			q.Set("obfs-password", op)
		}
	}
	if hp := str(e.Params, "hop_ports"); hp != "" {
		q.Set("mport", hp) // round-trip the port-hopping range
	}
	return buildURI("hysteria2", str(e.Params, "password"), "", e, q)
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
	}
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
	if enc := q.Encode(); enc != "" {
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
		if e.TLS.Insecure {
			m["allowInsecure"] = "true" // round-trip skip-cert-verify (parseVMess reads it)
		}
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
	b.WriteString("DNS = 1.1.1.1\n\n[Peer]\n")
	b.WriteString("PublicKey = " + str(e.Params, "peer_public_key") + "\n")
	if psk := str(e.Params, "pre_shared_key"); psk != "" {
		b.WriteString("PresharedKey = " + psk + "\n")
	}
	b.WriteString("Endpoint = " + hostPort(e) + "\n")
	b.WriteString("AllowedIPs = 0.0.0.0/0\n")
	if e.PersistentKeepalive > 0 {
		b.WriteString("PersistentKeepalive = " + strconv.Itoa(e.PersistentKeepalive) + "\n")
	} else if ka := intStr(e.Params, "persistent_keepalive"); ka != "0" {
		b.WriteString("PersistentKeepalive = " + ka + "\n") // else an exported idle tunnel drops behind NAT
	}
	return b.String()
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
	}
}

// buildURI assembles scheme://user[:pass]@host:port?query#name. The userinfo is encoded by
// the stdlib (url.User/UserPassword) so a credential containing ':' / '@' / '/' is
// percent-escaped — a bare ':' in a password would otherwise be read by every client as the
// user:pass separator and silently truncate the password.
func buildURI(scheme, user, pass string, e model.Endpoint, q url.Values) string {
	u := url.URL{Scheme: scheme, Host: hostPort(e), RawQuery: q.Encode()}
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
