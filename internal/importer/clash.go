package importer

// Clash / Clash-Meta YAML import. Clash configs are the dominant share format in
// this ecosystem; a user routinely has a `proxies:` list and nothing else handy.
// This file hand-rolls a FOCUSED YAML reader for that one section (mirroring
// olcrtc.go's yamlVal no-dep ethos — the repo deliberately avoids a YAML
// dependency) and maps each proxy to a model.Endpoint with the SAME Engine /
// Protocol / Params keys importer.go produces for share links, so the generator
// accepts the result unchanged. It is purely additive: a proxy it can't map is
// collected as an error string and the rest still parse (partial success), and
// the dispatch in subscription.go only fires for a genuine clash doc.

import (
	"fmt"
	"strconv"
	"strings"

	"wayhop/internal/model"
	"wayhop/internal/util"
)

// looksLikeClash reports whether text is a Clash / Clash-Meta YAML config — i.e.
// it has a top-level `proxies:` key and reads like YAML rather than a share link
// or a base64 subscription blob. The check is intentionally strict so it never
// mis-claims a normal subscription: a share link (vless://…) or a one-line
// base64 body has no newline-anchored `proxies:` at column 0, and a base64 blob
// has no ':' on its own line either. A real clash doc, by contrast, always has
// `proxies:` flush-left (or at most indented under nothing) on its own line.
func looksLikeClash(text string) bool {
	// Defensive BOM strip (ParseSubscription already does this, but ParseClash /
	// looksLikeClash may be called directly): a leading U+FEFF turns the first line
	// into "<BOM>proxies:" so the column-0 key scan misses it.
	text = strings.TrimPrefix(text, "\uFEFF")
	// A scheme:// share link is never a clash doc, even if its fragment/name
	// happened to contain the word "proxies". Reject early \u2014 but ONLY when the
	// document's FIRST LINE actually opens with a real URL scheme prefix (letter-led,
	// RFC-3986 charset, flush-left) immediately before "://", mirroring how Parse
	// detects a share link. Keying on "://" anywhere in the text would drop a genuine
	// clash doc that begins with a URL comment banner such as
	// "# https://sub.example.com/clash" (the "://" there sits at index 7, well inside
	// the old fixed 12-byte window, so the whole config was silently discarded).
	firstLine := text
	if nl := strings.IndexByte(firstLine, '\n'); nl >= 0 {
		firstLine = firstLine[:nl]
	}
	if i := strings.Index(firstLine, "://"); i > 0 && isURLScheme(firstLine[:i]) {
		return false
	}
	for _, ln := range strings.Split(text, "\n") {
		// Top-level key: flush-left, no leading indentation. Accepts `proxies:`
		// and the trailing-content forms `proxies: []` / `proxies:  # comment`.
		if indentOf(ln) == 0 && strings.HasPrefix(strings.TrimRight(ln, " \t\r"), "proxies:") {
			return true
		}
	}
	return false
}

// isURLScheme reports whether s is a valid RFC-3986 URI scheme
// (ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )). It distinguishes a real share-link
// scheme (vless, ss, wireguard, …) sitting flush-left before "://" from an
// incidental "://" inside a comment or text line, so looksLikeClash only
// fast-rejects genuine share links and never a clash doc opening with a banner.
func isURLScheme(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			// ALPHA — always allowed, including as the first char.
		case (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.':
			if i == 0 {
				return false // a scheme must start with a letter
			}
		default:
			return false
		}
	}
	return true
}

// ParseClash parses the `proxies:` sequence of a Clash YAML config into
// endpoints. It returns the successfully-mapped endpoints plus a per-proxy error
// list (an unknown type or a malformed entry is collected and skipped, so one bad
// proxy never sinks the whole import). The reader handles BOTH block style
//
//	proxies:
//	  - name: a
//	    type: ss
//	    server: ...
//
// and inline flow style
//
//	proxies:
//	  - {name: a, type: ss, server: x, port: 8388, cipher: aes-256-gcm, password: p}
func ParseClash(text string) (eps []model.Endpoint, errs []string) {
	// Defensive BOM strip so a directly-pasted clash doc with a leading U+FEFF still
	// parses (TrimSpace does not remove U+FEFF).
	text = strings.TrimPrefix(text, "\uFEFF")
	proxies, err := extractProxies(text)
	if err != nil {
		return nil, []string{fmt.Sprintf("clash: %v", err)}
	}
	if len(proxies) == 0 {
		return nil, []string{"clash: no proxies found under proxies:"}
	}
	seen := map[string]bool{}
	for i, p := range proxies {
		e, err := proxyToEndpoint(p)
		if err != nil {
			label := p["name"]
			if label == "" {
				label = "#" + strconv.Itoa(i+1)
			}
			errs = append(errs, fmt.Sprintf("clash proxy %q: %v", label, err))
			continue
		}
		if e.ID == "" {
			e.ID = genID(e)
		}
		e.ID = uniqueID(e.ID, seen)
		eps = append(eps, *e)
	}
	return eps, errs
}

// proxyMap is one proxy's flattened scalar fields. Nested mapping opts are folded
// into dotted keys so the reader stays a flat map: e.g. ws-opts.path,
// ws-opts.headers.Host, grpc-opts.grpc-service-name, reality-opts.public-key,
// reality-opts.short-id.
type proxyMap map[string]string

// extractProxies locates the top-level `proxies:` sequence and returns each entry
// as a flat proxyMap. It walks line by line: once inside the proxies block, every
// `  - ` starts a new proxy (block or flow). It stops at the next top-level key
// (a non-indented, non-blank line after the block began).
func extractProxies(text string) ([]proxyMap, error) {
	lines := strings.Split(text, "\n")
	// Find the proxies: key and its indentation.
	start := -1
	keyIndent := 0
	for i, ln := range lines {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		ind := indentOf(ln)
		if ind == 0 && (t == "proxies:" || strings.HasPrefix(t, "proxies:")) {
			// Inline-on-the-key form: `proxies: [{...}, {...}]`.
			rest := strings.TrimSpace(strings.TrimPrefix(t, "proxies:"))
			if strings.HasPrefix(rest, "[") {
				return parseInlineSeq(rest)
			}
			start = i + 1
			keyIndent = ind
			break
		}
	}
	if start < 0 {
		return nil, fmt.Errorf("no top-level proxies: key")
	}

	var out []proxyMap
	// cur holds the raw (untrimmed) lines of the current block-style proxy so the
	// block parser can use indentation to resolve nested *-opts mappings.
	var cur []string
	flush := func() error {
		if len(cur) == 0 {
			return nil
		}
		pm, err := parseBlockProxy(cur)
		cur = nil
		if err != nil {
			return err
		}
		if pm != nil {
			out = append(out, pm)
		}
		return nil
	}

	// proxyDash is the column of the dash that begins a top-level proxy entry,
	// captured from the FIRST such entry (-1 until then). A seq item is a NEW proxy
	// only when its dash sits at this column; a MORE-indented `- ` line is a
	// block-sequence item of a list field inside the current proxy (e.g.
	// `alpn:\n      - h3`) and must fall through to cur so parseBlockProxy's
	// existing block-sequence folding handles it. Without this gate the inner
	// `- h3`/`- h2` lines were wrongly treated as new proxies — closing the proxy
	// early, dropping the ALPN, spawning phantom "missing type" errors, and losing
	// every field after the list.
	proxyDash := -1
	for _, ln := range lines[start:] {
		t := strings.TrimSpace(ln)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		ind := indentOf(ln)
		// A non-indented line after the block began ends the proxies section
		// (the next top-level key, e.g. `proxy-groups:` / `rules:`).
		if ind <= keyIndent {
			break
		}
		dash := strings.IndexByte(ln, '-')
		// A new proxy entry: a seq item whose dash sits at the proxy-list column
		// (or the first seq item, which establishes that column).
		if isSeqItem(t) && (proxyDash < 0 || dash == proxyDash) {
			if proxyDash < 0 {
				proxyDash = dash
			}
			// New proxy entry. Flush any pending block proxy first.
			if err := flush(); err != nil {
				return nil, err
			}
			item := strings.TrimSpace(ln[dash+1:])
			// Strip a trailing inline comment (e.g. `- {...}  # node name`) so the
			// flow-mapping `}`-suffix check and the block field below see clean
			// text. stripInlineComment respects quotes/braces, so a `#` inside the
			// mapping survives.
			item = strings.TrimSpace(stripInlineComment(item))
			if strings.HasPrefix(item, "{") {
				// Flow-style on the dash line.
				pm, err := parseFlowMapping(item)
				if err != nil {
					return nil, err
				}
				out = append(out, pm)
				continue
			}
			// Block-style: keep the first field with an indentation that places it
			// just after the dash. We synthesize a column so the block parser sees
			// the dash-line field at the shallowest level, and deeper fields nest
			// under it. The dash column + 2 ("- " width) is the field's real column.
			cur = []string{strings.Repeat(" ", dash+2) + item}
			continue
		}
		// Continuation field of the current block proxy — keep raw indentation.
		cur = append(cur, ln)
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}

// parseInlineSeq parses a flow sequence `[{...}, {...}]` (the proxies value given
// on the key line) into proxyMaps.
func parseInlineSeq(s string) ([]proxyMap, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		return nil, fmt.Errorf("malformed inline proxies sequence")
	}
	inner := s[1 : len(s)-1]
	var out []proxyMap
	for _, frag := range splitTopLevel(inner, ',') {
		frag = strings.TrimSpace(frag)
		if frag == "" {
			continue
		}
		if !strings.HasPrefix(frag, "{") {
			return nil, fmt.Errorf("inline proxies entry is not a mapping: %q", frag)
		}
		pm, err := parseFlowMapping(frag)
		if err != nil {
			return nil, err
		}
		out = append(out, pm)
	}
	return out, nil
}

// parseBlockProxy parses the raw (indentation-preserved) field lines of one
// block-style proxy into a flat proxyMap. Nested mappings (ws-opts, grpc-opts,
// reality-opts, and ws-opts.headers) are folded into dotted keys; indentation
// tracks the nesting. A `key:` with no scalar value opens a child mapping whose
// more-indented lines become prefix.child; an inline `headers: {Host: x}` is
// folded directly. Clash proxy nesting is shallow, so a small indent stack
// suffices and avoids pulling in a YAML dependency.
func parseBlockProxy(lines []string) (proxyMap, error) {
	pm := proxyMap{}
	var stack []struct {
		indent int
		prefix string
	}
	for _, raw := range lines {
		ind := indentOf(raw)
		ln := strings.TrimSpace(raw)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		// Pop stack frames that are no longer ancestors of this indentation. A block-sequence
		// item may sit at the SAME column as its opener key (valid YAML that mihomo/yaml.v3
		// accept: `alpn:` then `- h3` both at column N), so a seq item pops STRICTLY (<) and
		// keeps the equal-indent opener; a key line at equal indent is a SIBLING of the opener
		// and must pop it (<=). Without the distinction the opener was popped before the item
		// was attributed, silently dropping every same-indent list element (alpn emptied).
		seq := isSeqItem(ln)
		for len(stack) > 0 && (ind < stack[len(stack)-1].indent || (!seq && ind == stack[len(stack)-1].indent)) {
			stack = stack[:len(stack)-1]
		}
		// A block-sequence item under an opener (e.g. `alpn:` then `  - h3`):
		// append it to the opener's key as a CSV scalar so splitCSV reads it like
		// the inline `alpn: [h3, h2]` form. (alpn is the only list field we map.)
		if seq && len(stack) > 0 {
			item := unquote(strings.TrimSpace(ln[strings.IndexByte(ln, '-')+1:]))
			k := stack[len(stack)-1].prefix
			if pm[k] == "" {
				pm[k] = item
			} else {
				pm[k] = pm[k] + "," + item
			}
			continue
		}
		key, val, ok := splitYAMLKV(ln)
		if !ok {
			// Unrecognized line shape (e.g. a block-sequence item with no parent
			// opener). Skip it rather than sinking the whole proxy.
			continue
		}
		prefix := ""
		if len(stack) > 0 {
			prefix = stack[len(stack)-1].prefix
		}
		dotted := key
		if prefix != "" {
			dotted = prefix + "." + key
		}
		if val == "" {
			// Mapping opener — push a frame for its children.
			stack = append(stack, struct {
				indent int
				prefix string
			}{indent: ind, prefix: dotted})
			continue
		}
		if strings.HasPrefix(val, "{") {
			// Inline nested mapping, e.g. headers: {Host: a}. Fold its fields.
			sub, err := parseFlowMapping(val)
			if err != nil {
				return nil, fmt.Errorf("nested %q: %w", key, err)
			}
			for k, v := range sub {
				pm[dotted+"."+k] = v
			}
			continue
		}
		pm[dotted] = unquote(val)
	}
	return pm, nil
}

// parseFlowMapping parses an inline flow mapping `{k: v, k2: {a: b}, ...}` into a
// flat proxyMap with dotted keys for nested mappings.
func parseFlowMapping(s string) (proxyMap, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return nil, fmt.Errorf("malformed flow mapping %q", s)
	}
	pm := proxyMap{}
	if err := foldFlowMapping(s, "", pm, 0); err != nil {
		return nil, err
	}
	return pm, nil
}

// maxFlowDepth bounds flow-mapping recursion. foldFlowMapping re-scans the whole
// remaining string via splitTopLevel at EVERY nesting level, so a crafted deeply
// nested mapping ({a:{a:{a:…}}}) is O(n^2) in the input size — a subscription-host-
// controlled Clash body up to the 8 MiB fetch cap could peg a CPU core for hours
// (the 15s fetch timeout does not cover parse time). Real Clash proxy nesting is
// shallow (a couple of levels for reality/ws-opts/etc.), so a small cap both stops
// the quadratic blow-up and prevents unbounded recursion-stack growth.
const maxFlowDepth = 32

// foldFlowMapping recursively flattens a flow mapping into pm using dotted keys.
// depth guards against pathological nesting (see maxFlowDepth).
func foldFlowMapping(s, prefix string, pm proxyMap, depth int) error {
	if depth > maxFlowDepth {
		return fmt.Errorf("flow mapping nested too deep (>%d levels)", maxFlowDepth)
	}
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return fmt.Errorf("malformed flow mapping %q", s)
	}
	inner := s[1 : len(s)-1]
	for _, pair := range splitTopLevel(inner, ',') {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		key, val, ok := splitYAMLKV(pair)
		if !ok {
			return fmt.Errorf("malformed flow pair %q", pair)
		}
		dotted := key
		if prefix != "" {
			dotted = prefix + "." + key
		}
		val = strings.TrimSpace(val)
		switch {
		case strings.HasPrefix(val, "{"):
			if err := foldFlowMapping(val, dotted, pm, depth+1); err != nil {
				return err
			}
		case val == "":
			// empty mapping value; ignore
		default:
			pm[dotted] = unquote(val)
		}
	}
	return nil
}

// --- type mapping ---

// proxyToEndpoint maps one clash proxy to a model.Endpoint, matching the exact
// Engine / Protocol / Params keys importer.go produces for the same protocol.
func proxyToEndpoint(p proxyMap) (*model.Endpoint, error) {
	typ := strings.ToLower(strings.TrimSpace(p["type"]))
	if typ == "" {
		return nil, fmt.Errorf("missing type")
	}
	server := p["server"]
	if server == "" {
		return nil, fmt.Errorf("missing server")
	}
	port := atoiDefault(p["port"], 0)
	// Bound the port at the import boundary (mirrors model/validate.go's 1-65535). The store persist
	// path does NOT re-validate, so an out-of-range port (70000, -1) would otherwise be accepted here,
	// durably persisted, and then FATAL every future Apply until the endpoint is manually removed.
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("port %d out of range (must be 1-65535)", port)
	}
	name := p["name"]

	switch typ {
	case "ss", "shadowsocks":
		return clashShadowsocks(p, server, port, name)
	case "vmess":
		return clashVMess(p, server, port, name)
	case "trojan":
		return clashTrojan(p, server, port, name)
	case "anytls":
		return clashAnyTLS(p, server, port, name)
	case "vless":
		return clashVLESS(p, server, port, name)
	case "hysteria2", "hy2":
		return clashHysteria2(p, server, port, name)
	case "tuic":
		return clashTUIC(p, server, port, name)
	case "wireguard", "wg":
		return clashWireGuard(p, server, port, name)
	default:
		return nil, fmt.Errorf("unsupported clash proxy type %q", typ)
	}
}

func clashShadowsocks(p proxyMap, server string, port int, name string) (*model.Endpoint, error) {
	if port == 0 {
		return nil, fmt.Errorf("ss: missing/invalid port")
	}
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoShadowsocks,
		Server:   server,
		Port:     port,
		Name:     name,
		Enabled:  true,
		Params: map[string]any{
			"method":   p["cipher"],
			"password": p["password"],
		},
	}
	if truthy(p["udp-over-tcp"]) || truthy(p["udp_over_tcp"]) {
		e.Params["udp_over_tcp"] = true
	}
	if name, opts := clashSSPlugin(p); name != "" {
		e.Params["plugin"] = name
		if opts != "" {
			e.Params["plugin_opts"] = opts
		}
	}
	return e, nil
}

// clashSSPlugin maps a clash ss `plugin` + folded `plugin-opts.*` to the (name,
// opts) shape importer.go produces for a SIP002 ss plugin and the generator reads
// (Params["plugin"]/["plugin_opts"]). The clash plugin name `obfs` is the
// simple-obfs plugin, whose sing-box-native equivalent is `obfs-local`;
// `v2ray-plugin` keeps its name. The opts are a `;`-joined string in the form the
// matching sing-box plugin expects: for obfs-local `obfs=<mode>;obfs-host=<host>`,
// for v2ray-plugin `mode=<mode>;host=<host>;path=<path>[;tls]`. An unknown plugin
// name is passed through verbatim (the generator drops names it can't emit).
func clashSSPlugin(p proxyMap) (name, opts string) {
	pl := strings.TrimSpace(p["plugin"])
	if pl == "" {
		return "", ""
	}
	po := func(k string) string {
		return util.FirstNonEmpty(p["plugin-opts."+k], p["plugin_opts."+k])
	}
	var parts []string
	switch strings.ToLower(pl) {
	case "obfs", "simple-obfs", "obfs-local":
		name = "obfs-local"
		if mode := po("mode"); mode != "" {
			parts = append(parts, "obfs="+mode)
		}
		if host := po("host"); host != "" {
			parts = append(parts, "obfs-host="+host)
		}
	case "v2ray-plugin":
		name = "v2ray-plugin"
		if mode := po("mode"); mode != "" {
			parts = append(parts, "mode="+mode)
		}
		if host := po("host"); host != "" {
			parts = append(parts, "host="+host)
		}
		if path := po("path"); path != "" {
			parts = append(parts, "path="+path)
		}
		if truthy(po("tls")) {
			parts = append(parts, "tls")
		}
	default:
		name = pl
	}
	return name, strings.Join(parts, ";")
}

func clashVMess(p proxyMap, server string, port int, name string) (*model.Endpoint, error) {
	if port == 0 {
		return nil, fmt.Errorf("vmess: missing/invalid port")
	}
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoVMess,
		Server:   server,
		Port:     port,
		Name:     name,
		Enabled:  true,
		Params: map[string]any{
			"uuid":     p["uuid"],
			"alter_id": atoiDefault(p["alterId"], 0),
			"security": util.FirstNonEmpty(p["cipher"], "auto"),
		},
	}
	e.Transport = clashTransport(p)
	if clashTLSEnabled(p) {
		e.TLS = &model.TLS{
			Enabled:     true,
			Type:        "tls",
			SNI:         util.FirstNonEmpty(p["servername"], p["sni"], wsHost(p), server),
			Fingerprint: util.FirstNonEmpty(p["client-fingerprint"], p["fingerprint"]),
			Insecure:    clashInsecure(p),
			ALPN:        clashList(p["alpn"]),
		}
	}
	return e, nil
}

func clashTrojan(p proxyMap, server string, port int, name string) (*model.Endpoint, error) {
	if port == 0 {
		return nil, fmt.Errorf("trojan: missing/invalid port")
	}
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoTrojan,
		Server:   server,
		Port:     port,
		Name:     name,
		Enabled:  true,
		Params:   map[string]any{"password": p["password"]},
	}
	e.Transport = clashTransport(p)
	// Trojan is TLS by default unless explicitly disabled (tls: false).
	if clashTLSDefaultOn(p) {
		e.TLS = &model.TLS{
			Enabled:     true,
			Type:        "tls",
			SNI:         util.FirstNonEmpty(p["sni"], p["servername"], wsHost(p), server),
			Fingerprint: util.FirstNonEmpty(p["client-fingerprint"], p["fingerprint"]),
			Insecure:    clashInsecure(p),
			ALPN:        clashList(p["alpn"]),
		}
	}
	return e, nil
}

// clashAnyTLS maps a clash-meta anytls proxy to a model endpoint — like clashTrojan (password + TLS)
// but AnyTLS is always TLS and has no stream transport.
func clashAnyTLS(p proxyMap, server string, port int, name string) (*model.Endpoint, error) {
	if port == 0 {
		return nil, fmt.Errorf("anytls: missing/invalid port")
	}
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoAnyTLS,
		Server:   server,
		Port:     port,
		Name:     name,
		Enabled:  true,
		Params:   map[string]any{"password": p["password"]},
		TLS: &model.TLS{
			Enabled:     true,
			Type:        "tls",
			SNI:         util.FirstNonEmpty(p["sni"], p["servername"], server),
			Fingerprint: util.FirstNonEmpty(p["client-fingerprint"], p["fingerprint"]),
			Insecure:    clashInsecure(p),
			ALPN:        clashList(p["alpn"]),
		},
	}
	return e, nil
}

func clashVLESS(p proxyMap, server string, port int, name string) (*model.Endpoint, error) {
	if port == 0 {
		return nil, fmt.Errorf("vless: missing/invalid port")
	}
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoVLESS,
		Server:   server,
		Port:     port,
		Name:     name,
		Enabled:  true,
		Params:   map[string]any{"uuid": p["uuid"]},
	}
	if flow := p["flow"]; flow != "" {
		e.Params["flow"] = flow
	}
	e.Transport = clashTransport(p)
	// Reality if reality-opts present; otherwise plain TLS when tls: true.
	pbk := util.FirstNonEmpty(p["reality-opts.public-key"], p["reality-opts.publicKey"])
	if pbk != "" {
		e.TLS = &model.TLS{
			Enabled:     true,
			Type:        "reality",
			SNI:         util.FirstNonEmpty(p["servername"], p["sni"]),
			Fingerprint: util.FirstNonEmpty(p["client-fingerprint"], p["fingerprint"]),
			PublicKey:   pbk,
			ShortID:     util.FirstNonEmpty(p["reality-opts.short-id"], p["reality-opts.shortId"]),
			ALPN:        clashList(p["alpn"]),
		}
	} else if clashTLSEnabled(p) {
		e.TLS = &model.TLS{
			Enabled:     true,
			Type:        "tls",
			SNI:         util.FirstNonEmpty(p["servername"], p["sni"], wsHost(p), server),
			Fingerprint: util.FirstNonEmpty(p["client-fingerprint"], p["fingerprint"]),
			Insecure:    clashInsecure(p),
			ALPN:        clashList(p["alpn"]),
		}
	}
	return e, nil
}

func clashHysteria2(p proxyMap, server string, port int, name string) (*model.Endpoint, error) {
	if port == 0 {
		return nil, fmt.Errorf("hysteria2: missing/invalid port")
	}
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoHysteria2,
		Server:   server,
		Port:     port,
		Name:     name,
		Enabled:  true,
		Params:   map[string]any{"password": util.FirstNonEmpty(p["password"], p["auth"])},
	}
	if obfs := p["obfs"]; obfs != "" {
		e.Params["obfs"] = obfs
		if op := util.FirstNonEmpty(p["obfs-password"], p["obfs_password"]); op != "" {
			e.Params["obfs_password"] = op
		}
	}
	// Port hopping (clash-meta `ports`, older `mport`). Carry it as hop_ports — the
	// SAME key importer.go's parseHysteria2 uses — so the generator emits sing-box
	// server_ports. Without this, port-hopping configs lose their hop range.
	if hp := util.FirstNonEmpty(p["ports"], p["mport"]); hp != "" {
		e.Params["hop_ports"] = hp
	}
	// Optional bandwidth hints — clash spells them up/down (may carry " Mbps").
	if up := mbps(p["up"]); up > 0 {
		e.Params["up_mbps"] = up
	}
	if down := mbps(p["down"]); down > 0 {
		e.Params["down_mbps"] = down
	}
	// Hysteria2 always runs over QUIC+TLS.
	e.TLS = &model.TLS{
		Enabled:  true,
		Type:     "tls",
		SNI:      util.FirstNonEmpty(p["sni"], p["servername"], server),
		Insecure: clashInsecure(p),
		ALPN:     clashList(p["alpn"]),
	}
	return e, nil
}

func clashTUIC(p proxyMap, server string, port int, name string) (*model.Endpoint, error) {
	if port == 0 {
		return nil, fmt.Errorf("tuic: missing/invalid port")
	}
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoTUIC,
		Server:   server,
		Port:     port,
		Name:     name,
		Enabled:  true,
		Params: map[string]any{
			"uuid":     p["uuid"],
			"password": p["password"],
		},
	}
	if cc := util.FirstNonEmpty(p["congestion-controller"], p["congestion_control"]); cc != "" {
		e.Params["congestion_control"] = cc
	}
	if mode := util.FirstNonEmpty(p["udp-relay-mode"], p["udp_relay_mode"]); mode != "" {
		e.Params["udp_relay_mode"] = mode
	}
	e.TLS = &model.TLS{
		Enabled:  true,
		Type:     "tls",
		SNI:      util.FirstNonEmpty(p["sni"], p["servername"], server),
		Insecure: clashInsecure(p),
		ALPN:     clashList(p["alpn"]),
	}
	return e, nil
}

func clashWireGuard(p proxyMap, server string, port int, name string) (*model.Endpoint, error) {
	if port == 0 {
		return nil, fmt.Errorf("wireguard: missing/invalid port")
	}
	e := &model.Endpoint{
		Engine:   model.EngineSingBox,
		Protocol: model.ProtoWireGuard,
		Server:   server,
		Port:     port,
		Name:     name,
		Enabled:  true,
		Params: map[string]any{
			"private_key":     util.FirstNonEmpty(p["private-key"], p["private_key"]),
			"peer_public_key": util.FirstNonEmpty(p["public-key"], p["public_key"]),
		},
	}
	if psk := util.FirstNonEmpty(p["pre-shared-key"], p["preshared-key"], p["pre_shared_key"]); psk != "" {
		e.Params["pre_shared_key"] = psk
	}
	// local_address: clash carries ip / ipv6 (and sometimes a CSV). Match the
	// importer's []string shape so the generator emits the interface address.
	var addrs []string
	for _, k := range []string{"ip", "ipv6"} {
		addrs = append(addrs, splitCSV(p[k])...)
	}
	if len(addrs) > 0 {
		e.Params["local_address"] = addrs
	}
	if mtu := atoiDefault(p["mtu"], 0); mtu >= 576 && mtu <= 65535 {
		e.Params["mtu"] = mtu
	}
	if r := parseReserved(p["reserved"]); r != nil {
		e.Params["reserved"] = r
	}
	// PersistentKeepalive keeps the NAT/firewall UDP mapping alive on an idle tunnel; dropping it
	// lets the mapping expire so the link silently dies until new traffic forces a re-handshake.
	// Every other WG import leg reads it (share-link, .conf, sing-box JSON) and WayHop's own clash
	// EXPORT emits `persistent-keepalive` — without this read the export→re-import round-trip
	// silently loses it.
	if ka := atoiDefault(util.FirstNonEmpty(p["persistent-keepalive"], p["persistent_keepalive"]), 0); ka > 0 && ka <= 65535 {
		e.Params["persistent_keepalive"] = ka
	}
	return e, nil
}

// --- clash field helpers ---

// clashTransport maps clash `network` + *-opts to a model.Transport, matching the
// keys importer.go's transportFromQuery produces (ws/grpc/http/httpupgrade).
func clashTransport(p proxyMap) *model.Transport {
	switch strings.ToLower(strings.TrimSpace(p["network"])) {
	case "ws":
		t := &model.Transport{
			Type: "ws",
			Path: util.FirstNonEmpty(p["ws-opts.path"], p["ws-path"]),
			Host: wsHost(p),
		}
		return t
	case "grpc":
		return &model.Transport{
			Type:        "grpc",
			ServiceName: util.FirstNonEmpty(p["grpc-opts.grpc-service-name"], p["grpc-service-name"], p["grpc-opts.serviceName"]),
		}
	case "http", "h2":
		// h2-opts.host / http-opts.headers.Host may be given as a YAML list
		// (`host: [a.com, b.com]`) — a multi-host is the intended domain-fronting rotation feature.
		// Keep EVERY element (comma-joined into the model's CSV convention that generator.splitHosts
		// re-expands into the sing-box host[] list). Keeping only the first element silently
		// discarded the rest of the rotation, which is what this import used to do.
		return &model.Transport{
			Type: "http",
			Path: util.FirstNonEmpty(p["http-opts.path"], p["h2-opts.path"], p["ws-opts.path"]),
			Host: joinListElems(util.FirstNonEmpty(p["h2-opts.host"], p["http-opts.headers.Host"], wsHost(p))),
		}
	case "httpupgrade":
		return &model.Transport{
			Type: "httpupgrade",
			Path: p["ws-opts.path"],
			Host: wsHost(p),
		}
	default:
		return nil // tcp / raw / unset
	}
}

// wsHost returns the ws Host header from ws-opts.headers.Host (case-tolerant).
func wsHost(p proxyMap) string {
	return util.FirstNonEmpty(
		p["ws-opts.headers.Host"], p["ws-opts.headers.host"],
		p["ws-headers.Host"], p["ws-host"],
	)
}

// clashTLSEnabled reports whether `tls: true` is set (default OFF). For vmess/vless.
func clashTLSEnabled(p proxyMap) bool {
	return truthy(p["tls"])
}

// clashTLSDefaultOn reports TLS state for protocols that default TLS ON (trojan):
// enabled unless explicitly `tls: false`.
func clashTLSDefaultOn(p proxyMap) bool {
	v := strings.ToLower(strings.TrimSpace(p["tls"]))
	if v == "false" || v == "0" || v == "no" {
		return false
	}
	return true
}

// clashInsecure reads clash's skip-cert-verify (and the synonyms importer.go's
// insecureFromQuery accepts).
func clashInsecure(p proxyMap) bool {
	return truthy(p["skip-cert-verify"]) || truthy(p["skip_cert_verify"]) ||
		truthy(p["allowInsecure"]) || truthy(p["insecure"]) || truthy(p["allow_insecure"])
}

// --- tiny YAML/string utilities (no external dep) ---

// indentOf returns the count of leading space/tab runes.
func indentOf(s string) int {
	return len(s) - len(strings.TrimLeft(s, " \t"))
}

// isSeqItem reports whether a trimmed line begins a YAML sequence item (`- …`).
func isSeqItem(t string) bool {
	return t == "-" || strings.HasPrefix(t, "- ")
}

// splitYAMLKV splits "key: value" on the FIRST top-level colon (respecting
// braces/brackets/quotes so a colon inside a flow value or quoted string doesn't
// split early). The key is unquoted/trimmed; the value is returned trimmed but
// NOT unquoted (callers decide, since a flow value must keep its braces).
func splitYAMLKV(s string) (key, val string, ok bool) {
	depth := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case '{', '[':
			depth++
		case '}', ']':
			if depth > 0 {
				depth--
			}
		case ':':
			if depth == 0 {
				// A colon is a key/value separator only when followed by a
				// space or end-of-line (YAML rule) — so "http://x" inside a
				// bare value doesn't split. Since we cut on the FIRST such
				// colon and keys never contain "://", this is safe.
				if i+1 >= len(s) || s[i+1] == ' ' || s[i+1] == '\t' {
					// Strip a trailing inline comment from the value (e.g.
					// `port: 8388 # the port`) before returning; the key can't
					// carry one. stripInlineComment respects quotes/braces so a
					// `#` inside a flow value or a quoted string survives.
					val := strings.TrimSpace(stripInlineComment(strings.TrimSpace(s[i+1:])))
					return unquote(strings.TrimSpace(s[:i])), val, true
				}
			}
		}
	}
	return "", "", false
}

// clashList parses a clash list value in either inline-flow form ("[h3, h3.1]") or a
// plain comma/single scalar ("h3"). Surrounding brackets and per-item quotes are stripped
// and empty entries dropped, so `alpn: [h3]` yields []string{"h3"} not {"[h3]"}.
func clashList(v string) []string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
		v = v[1 : len(v)-1]
	}
	var out []string
	for _, part := range splitTopLevel(v, ',') {
		part = strings.Trim(strings.TrimSpace(part), `"'`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// stripInlineComment removes a trailing YAML inline comment from s: an unquoted
// `#` at brace/bracket depth 0 that is PRECEDED BY WHITESPACE (YAML requires a
// space before an inline comment). A `#` with no leading space (it could be part
// of an unquoted value, e.g. a fragment or a password) or one inside quotes /
// braces is preserved. The quote/depth bookkeeping mirrors splitTopLevel.
func stripInlineComment(s string) string {
	depth := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case '{', '[':
			depth++
		case '}', ']':
			if depth > 0 {
				depth--
			}
		case '#':
			if depth == 0 && i > 0 && (s[i-1] == ' ' || s[i-1] == '\t') {
				return strings.TrimRight(s[:i], " \t")
			}
		}
	}
	return s
}

// joinListElems folds a bracketed inline-flow list `[a, b]` into the model's comma-separated
// convention "a,b" (which generator.splitHosts re-expands into a multi-element sing-box host list),
// and returns a scalar / already-CSV value unchanged. It preserves EVERY element rather than
// taking the first, so multi-host h2/http domain-fronting survives a clash import.
func joinListElems(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
		return strings.Join(clashList(v), ",")
	}
	return v
}

// splitTopLevel splits s on sep, but only at brace/bracket depth 0 and outside
// quotes — so a nested flow mapping `{a: {b: c}, d: e}` splits into two pairs.
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth := 0
	var quote byte
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote = c
		case '{', '[':
			depth++
		case '}', ']':
			if depth > 0 {
				depth--
			}
		case sep:
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// unquote strips a single matching pair of surrounding single/double quotes, trims whitespace, and
// DECODES the YAML escape sequences inside — otherwise a double-quoted value containing a backslash,
// quote, tab or newline (a free-form password) re-imports with the escaping intact, corrupting the
// credential so auth silently fails. This mirrors the exporter's yamlScalar (internal/exporter/
// clash.go), so a WayHop clash export round-trips through its own importer, and standard mihomo
// double-quoted values decode correctly.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if s[0] == '"' && s[len(s)-1] == '"' {
			return yamlUnescapeDouble(s[1 : len(s)-1])
		}
		if s[0] == '\'' && s[len(s)-1] == '\'' {
			// YAML single-quoted scalar: the ONLY escape is a doubled quote '' -> '.
			return strings.ReplaceAll(s[1:len(s)-1], "''", "'")
		}
	}
	return s
}

// yamlUnescapeDouble decodes the escape sequences a YAML double-quoted scalar carries — at minimum
// the set the exporter's yamlScalar emits (\\ \" \n \t) plus the other common ones (\r \0 \/). An
// unknown escape is kept verbatim (backslash + char) rather than dropped, so no data is lost.
func yamlUnescapeDouble(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '0':
			b.WriteByte(0)
		case '"':
			b.WriteByte('"')
		case '\\':
			b.WriteByte('\\')
		case '/':
			b.WriteByte('/')
		default:
			b.WriteByte('\\')
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// mbps parses a bandwidth value like "100", "100 Mbps", "50mbps" into an int of
// megabits/sec, or 0 if it isn't a leading-number form.
func mbps(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	// Take the leading run of digits.
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil {
		return 0
	}
	return n
}
