package exporter

// Clash / Clash-Meta YAML export — the inverse of internal/importer/clash.go.
// It renders the enabled, exportable endpoints into a COMPLETE, usable
// clash-meta config so a clash/mihomo client can subscribe to the same
// /api/sub/{token} URL and get a working config (the round-trip completes:
// importer.ParseClash reads it back). Like the importer (and olcrtc.go), this
// hand-writes the YAML — the repo deliberately avoids a YAML dependency.
//
// Only the SAME 7 proxy types the importer maps are rendered
// (ss/vmess/trojan/vless/hysteria2/tuic/plain-wireguard), using the EXACT
// inverse field mapping so each endpoint round-trips. An endpoint whose
// engine/protocol can't be a clash proxy (EngineExternal, olcRTC, socks/http,
// or AmneziaWG — clash-meta has no AmneziaWG obfuscation) is skipped and its
// name is collected in skipped.

import (
	"strconv"
	"strings"

	"wayhop/internal/model"
	"wayhop/internal/util"
)

// ClashConfig renders eps into a complete clash-meta YAML config (no failover
// groups). It returns the YAML plus the names of endpoints that could not be
// represented as a clash proxy (skipped). Output is deterministic: proxies keep
// the input order, and a name shared by two endpoints is de-duplicated (clash
// requires unique proxy names) by appending a numeric suffix.
func ClashConfig(eps []model.Endpoint) (string, []string) {
	return ClashConfigWithGroups(eps, nil)
}

// ClashConfigWithGroups is ClashConfig plus the failover groups: each WayHop
// group becomes a clash proxy-group (url-test / fallback / select mirroring its
// type) so a clash/mihomo client keeps the same auto-failover the panel does,
// instead of a flat manual list. A group's members resolve to their proxy names
// (or, for a nested group member, that group's name); members that aren't
// exportable are dropped and an all-unexportable group is omitted. With groups
// nil/empty the output is byte-identical to the pre-groups ClashConfig.
func ClashConfigWithGroups(eps []model.Endpoint, groups []model.Group) (string, []string) {
	var (
		blocks    []string // rendered `proxies:` entries, in input order
		skipped   []string
		usedNames = map[string]bool{}
		idName    = map[string]string{} // endpoint ID -> its clash proxy name
	)
	type epRef struct{ id, name string }
	var order []epRef
	for _, e := range eps {
		block, name, ok := clashProxy(e, usedNames)
		if !ok {
			skipped = append(skipped, util.FirstNonEmpty(e.Name, e.ID, e.Server))
			continue
		}
		usedNames[name] = true
		blocks = append(blocks, block)
		idName[e.ID] = name
		order = append(order, epRef{e.ID, name})
	}

	type rgrp struct {
		name, gtype string
		members     []string
		test        *model.Health
	}
	// Decide which groups are renderable BEFORE assigning names, so a parent never
	// references — nor reserves a name that collides with — a group that gets omitted.
	// A group is renderable iff it has >=1 exportable endpoint member or >=1 renderable
	// nested-group member; a fixpoint, because a parent renders only once its child does.
	renderable := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for _, g := range groups {
			if renderable[g.ID] {
				continue
			}
			for _, mid := range g.Members {
				if _, ok := idName[mid]; ok || (mid != g.ID && renderable[mid]) {
					renderable[g.ID] = true
					changed = true
					break
				}
			}
		}
	}
	// Name only the renderable groups (so an omitted group neither occupies a name nor
	// can be referenced as a nested member); members then resolve regardless of order.
	groupName := map[string]string{}
	for _, g := range groups {
		if !renderable[g.ID] {
			continue
		}
		gn := uniqueName(util.FirstNonEmpty(g.Name, g.ID), usedNames)
		usedNames[gn] = true
		groupName[g.ID] = gn
	}
	var rendered []rgrp
	grouped := map[string]bool{} // endpoint IDs that belong to some group
	for _, g := range groups {
		if !renderable[g.ID] {
			continue // no exportable members, directly or transitively — omit the group
		}
		var mem []string
		for _, mid := range g.Members {
			if n, ok := idName[mid]; ok {
				mem = append(mem, n)
				grouped[mid] = true
			} else if n, ok := groupName[mid]; ok && mid != g.ID {
				mem = append(mem, n) // nested group (renderable: groupName holds only those)
			}
		}
		if len(mem) == 0 {
			continue // defensive: a renderable group always has >=1 resolvable member
		}
		ct := "select"
		switch g.Type {
		case model.GroupURLTest:
			ct = "url-test"
		case model.GroupFallback:
			ct = "fallback"
		}
		rendered = append(rendered, rgrp{name: groupName[g.ID], gtype: ct, members: mem, test: g.Test})
	}

	var b strings.Builder
	b.WriteString("# WayHop clash-meta subscription\n")
	b.WriteString("mixed-port: 7890\n")
	b.WriteString("mode: rule\n")
	if len(blocks) == 0 {
		// A clash config with no proxies still needs a valid (empty) sequence on
		// the key line itself.
		b.WriteString("proxies: []\n")
	} else {
		b.WriteString("proxies:\n")
		for _, blk := range blocks {
			b.WriteString(blk)
		}
	}
	b.WriteString("proxy-groups:\n")
	// Top-level selector: the failover groups + any endpoints not in a group + DIRECT.
	b.WriteString("  - name: WayHop\n")
	b.WriteString("    type: select\n")
	b.WriteString("    proxies:\n")
	for _, g := range rendered {
		b.WriteString("      - " + yamlScalar(g.name) + "\n")
	}
	for _, r := range order {
		if !grouped[r.id] {
			b.WriteString("      - " + yamlScalar(r.name) + "\n")
		}
	}
	b.WriteString("      - DIRECT\n")
	// The failover groups themselves.
	for _, g := range rendered {
		writeClashGroup(&b, g.name, g.gtype, g.members, g.test)
	}
	b.WriteString("rules:\n")
	b.WriteString("  - MATCH,WayHop\n")
	return b.String(), skipped
}

// writeClashGroup emits one proxy-group block. url-test/fallback carry the health
// url + interval (seconds) — and url-test a tolerance (ms) — defaulting the same
// way the sing-box generator does so the clash client probes equivalently.
func writeClashGroup(b *strings.Builder, name, gtype string, members []string, test *model.Health) {
	b.WriteString("  - name: " + yamlScalar(name) + "\n")
	b.WriteString("    type: " + gtype + "\n")
	if gtype == "url-test" || gtype == "fallback" {
		url, interval, tol := "http://cp.cloudflare.com/generate_204", 300, 50
		if test != nil {
			if test.URL != "" {
				url = test.URL
			}
			if test.Interval > 0 {
				interval = test.Interval
			}
			if test.Tolerance > 0 {
				tol = test.Tolerance
			}
		}
		b.WriteString("    url: " + yamlScalar(url) + "\n")
		b.WriteString("    interval: " + strconv.Itoa(interval) + "\n")
		if gtype == "url-test" {
			b.WriteString("    tolerance: " + strconv.Itoa(tol) + "\n")
		}
	}
	b.WriteString("    proxies:\n")
	for _, m := range members {
		b.WriteString("      - " + yamlScalar(m) + "\n")
	}
}

// clashProxy renders one endpoint as a `proxies:` block entry (a block-style
// mapping under a `  - ` dash). It returns the rendered text, the (possibly
// de-duplicated) proxy name used, and ok=false when the endpoint can't be a
// clash proxy.
func clashProxy(e model.Endpoint, used map[string]bool) (block, name string, ok bool) {
	// EngineExternal / nfqws route through an OS-owned path and have nothing
	// shareable; olcRTC and socks/http have no clash-proxy form here.
	if e.Engine == model.EngineExternal || e.Engine == model.EngineNfqws {
		return "", "", false
	}

	kv := newKV()
	name = uniqueName(util.FirstNonEmpty(e.Name, e.ID, e.Server), used)
	kv.add("name", name)

	switch e.Protocol {
	case model.ProtoShadowsocks:
		clashSS(kv, e)
	case model.ProtoVMess:
		clashVMessOut(kv, e)
	case model.ProtoTrojan:
		clashTrojanOut(kv, e)
	case model.ProtoAnyTLS:
		clashAnyTLSOut(kv, e)
	case model.ProtoVLESS:
		clashVLESSOut(kv, e)
	case model.ProtoHysteria2:
		clashHysteria2Out(kv, e)
	case model.ProtoTUIC:
		clashTUICOut(kv, e)
	case model.ProtoWireGuard:
		clashWireGuardOut(kv, e)
	case model.ProtoAmneziaWG:
		// clash-meta has no AmneziaWG: its Jc/Jmin/Jmax/S1/S2/H1-H4 obfuscation
		// can't be expressed, and emitting a plain wireguard proxy would silently
		// drop the obfuscation (the peer would reject the un-obfuscated handshake).
		// Skip with a note.
		return "", "", false
	default:
		// olcrtc / socks / http and any future protocol with no clash form.
		return "", "", false
	}

	// Defensive: a plain wireguard endpoint that secretly carries AmneziaWG
	// obfuscation params (jc/h1/…) also can't be a clash proxy. Skip it rather
	// than emit a proxy that silently loses the obfuscation.
	if e.Protocol == model.ProtoWireGuard && hasAWGParams(e.Params) {
		return "", "", false
	}

	return kv.render(), name, true
}

// --- per-type inverse renderers (mirror importer/clash.go's clash* mappers) ---

func clashSS(kv *clashKV, e model.Endpoint) {
	kv.add("type", "ss")
	kv.addServerPort(e)
	kv.add("cipher", str(e.Params, "method"))
	kv.add("password", str(e.Params, "password"))
	if b, _ := e.Params["udp_over_tcp"].(bool); b {
		kv.addBool("udp-over-tcp", true)
	}
	// SIP002 plugin -> clash plugin + plugin-opts. The importer joins the opts as
	// "k=v;k2=v2[;flag]"; reverse that into a nested plugin-opts mapping. The
	// sing-box plugin name obfs-local maps back to the clash plugin name "obfs".
	if pl := str(e.Params, "plugin"); pl != "" {
		clashName, opts := ssPluginToClash(pl, str(e.Params, "plugin_opts"))
		kv.add("plugin", clashName)
		if len(opts) > 0 {
			kv.addMap("plugin-opts", opts)
		}
	}
}

// ssPluginToClash reverses importer.clashSSPlugin: it turns a sing-box plugin
// name + ";"-joined opts string into a clash plugin name and an ordered list of
// plugin-opts key/value pairs.
func ssPluginToClash(name, opts string) (string, [][2]string) {
	clashName := name
	if name == "obfs-local" {
		clashName = "obfs"
	}
	var out [][2]string
	for _, part := range strings.Split(opts, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, has := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		switch {
		case k == "obfs":
			out = append(out, [2]string{"mode", strings.TrimSpace(v)})
		case k == "obfs-host":
			out = append(out, [2]string{"host", strings.TrimSpace(v)})
		case k == "tls" && !has:
			out = append(out, [2]string{"tls", "true"})
		default:
			out = append(out, [2]string{k, strings.TrimSpace(v)})
		}
	}
	return clashName, out
}

func clashVMessOut(kv *clashKV, e model.Endpoint) {
	kv.add("type", "vmess")
	kv.addServerPort(e)
	kv.add("uuid", str(e.Params, "uuid"))
	kv.add("alterId", intStr(e.Params, "alter_id"))
	kv.add("cipher", util.FirstNonEmpty(str(e.Params, "security"), "auto"))
	clashTransportOut(kv, e.Transport)
	clashTLSOut(kv, e.TLS, e.Server)
}

func clashTrojanOut(kv *clashKV, e model.Endpoint) {
	kv.add("type", "trojan")
	kv.addServerPort(e)
	kv.add("password", str(e.Params, "password"))
	clashTransportOut(kv, e.Transport)
	// Trojan is TLS by default in clash; emit sni/skip-cert-verify/alpn when set.
	// (The importer treats trojan as TLS-on unless tls:false, so no `tls:` key
	// is required for round-trip.)
	if e.TLS != nil && e.TLS.Enabled {
		kv.addIf("sni", e.TLS.SNI)
		kv.addIf("client-fingerprint", e.TLS.Fingerprint)
		if e.TLS.Insecure {
			kv.addBool("skip-cert-verify", true)
		}
		kv.addList("alpn", e.TLS.ALPN)
	} else if e.TLS != nil {
		// Explicitly TLS-disabled trojan (rare): tell clash so it round-trips.
		kv.addBool("tls", false)
	}
}

// clashAnyTLSOut renders a clash-meta anytls proxy — like clashTrojanOut but with no stream
// transport (AnyTLS has none) and always TLS.
func clashAnyTLSOut(kv *clashKV, e model.Endpoint) {
	kv.add("type", "anytls")
	kv.addServerPort(e)
	kv.add("password", str(e.Params, "password"))
	if e.TLS != nil && e.TLS.Enabled {
		kv.addIf("sni", e.TLS.SNI)
		kv.addIf("client-fingerprint", e.TLS.Fingerprint)
		if e.TLS.Insecure {
			kv.addBool("skip-cert-verify", true)
		}
		kv.addList("alpn", e.TLS.ALPN)
	}
}

func clashVLESSOut(kv *clashKV, e model.Endpoint) {
	kv.add("type", "vless")
	kv.addServerPort(e)
	kv.add("uuid", str(e.Params, "uuid"))
	kv.addIf("flow", str(e.Params, "flow"))
	clashTransportOut(kv, e.Transport)
	if e.TLS != nil && e.TLS.Enabled && e.TLS.Type == "reality" {
		kv.addBool("tls", true)
		kv.addIf("servername", e.TLS.SNI)
		kv.addIf("client-fingerprint", e.TLS.Fingerprint)
		kv.addList("alpn", e.TLS.ALPN)
		opts := [][2]string{{"public-key", e.TLS.PublicKey}}
		if e.TLS.ShortID != "" {
			opts = append(opts, [2]string{"short-id", e.TLS.ShortID})
		}
		kv.addMap("reality-opts", opts)
	} else {
		clashTLSOut(kv, e.TLS, e.Server)
	}
}

func clashHysteria2Out(kv *clashKV, e model.Endpoint) {
	kv.add("type", "hysteria2")
	kv.addServerPort(e)
	kv.add("password", str(e.Params, "password"))
	kv.addIf("obfs", str(e.Params, "obfs"))
	kv.addIf("obfs-password", str(e.Params, "obfs_password"))
	// Port hopping: hop_ports -> clash `ports`.
	kv.addIf("ports", str(e.Params, "hop_ports"))
	if up := intStr(e.Params, "up_mbps"); up != "0" {
		kv.add("up", up+" Mbps")
	}
	if down := intStr(e.Params, "down_mbps"); down != "0" {
		kv.add("down", down+" Mbps")
	}
	// hysteria2 is always TLS+QUIC.
	if e.TLS != nil {
		kv.addIf("sni", e.TLS.SNI)
		if e.TLS.Insecure {
			kv.addBool("skip-cert-verify", true)
		}
		kv.addList("alpn", e.TLS.ALPN)
	}
}

func clashTUICOut(kv *clashKV, e model.Endpoint) {
	kv.add("type", "tuic")
	kv.addServerPort(e)
	kv.add("uuid", str(e.Params, "uuid"))
	kv.add("password", str(e.Params, "password"))
	kv.addIf("congestion-controller", str(e.Params, "congestion_control"))
	kv.addIf("udp-relay-mode", str(e.Params, "udp_relay_mode"))
	if e.TLS != nil {
		kv.addIf("sni", e.TLS.SNI)
		if e.TLS.Insecure {
			kv.addBool("skip-cert-verify", true)
		}
		kv.addList("alpn", e.TLS.ALPN)
	}
}

func clashWireGuardOut(kv *clashKV, e model.Endpoint) {
	kv.add("type", "wireguard")
	kv.addServerPort(e)
	kv.add("private-key", str(e.Params, "private_key"))
	kv.add("public-key", str(e.Params, "peer_public_key"))
	kv.addIf("pre-shared-key", str(e.Params, "pre_shared_key"))
	// local_address -> clash ip / ipv6. The importer reads both keys (CSV-aware)
	// into local_address, so a comma-joined `ip` round-trips. Split v4/v6 so a
	// stricter clash-meta reader accepts each.
	var v4, v6 []string
	for _, a := range util.LocalAddrs(e.Params) {
		if strings.Contains(a, ":") {
			v6 = append(v6, a)
		} else {
			v4 = append(v4, a)
		}
	}
	if len(v4) > 0 {
		kv.add("ip", strings.Join(v4, ","))
	}
	if len(v6) > 0 {
		kv.add("ipv6", strings.Join(v6, ","))
	}
	if e.MTU > 0 {
		kv.add("mtu", strconv.Itoa(e.MTU))
	} else if mtu := intStr(e.Params, "mtu"); mtu != "0" {
		kv.add("mtu", mtu)
	}
	if r := reservedCSV(e.Params, "reserved"); r != "" {
		// clash spells WARP reserved as a flow list [a, b, c]. Use addRaw so it is
		// emitted verbatim as a YAML sequence — add() would scalar-quote the leading
		// '[' into the string "[a,b,c]", which clash/mihomo reject (they type reserved
		// as a list of ints), silently breaking the WARP proxy on the client.
		kv.addRaw("reserved", "["+r+"]")
	}
}

// --- shared transport / TLS inverse renderers ---

// clashTransportOut maps a model.Transport to clash `network` + *-opts, mirroring
// importer.clashTransport.
func clashTransportOut(kv *clashKV, t *model.Transport) {
	if t == nil || t.Type == "" {
		return // raw tcp
	}
	switch t.Type {
	case "ws":
		kv.add("network", "ws")
		var opts [][2]string
		if t.Path != "" {
			opts = append(opts, [2]string{"path", t.Path})
		}
		kv.addOpts("ws-opts", opts, t.Host)
	case "grpc":
		kv.add("network", "grpc")
		if t.ServiceName != "" {
			kv.addMap("grpc-opts", [][2]string{{"grpc-service-name", t.ServiceName}})
		}
	case "http":
		// model "http" is HTTP/2; clash names that network "h2".
		kv.add("network", "h2")
		// h2-opts.host is typed []string by mihomo — it must be a real flow sequence
		// `host: [a.com]`, NOT a scalar-quoted "[a.com]" string. addMap re-quotes every
		// value (the leading '[' trips needsQuote), which the strict decoder rejects,
		// failing the WHOLE config. Build the block verbatim via addRaw (mirrors addList):
		// path stays a quoted scalar, host is a one-element flow sequence.
		var parts []string
		if t.Path != "" {
			parts = append(parts, "path: "+yamlScalar(t.Path))
		}
		if t.Host != "" {
			parts = append(parts, "host: ["+yamlScalar(t.Host)+"]")
		}
		if len(parts) > 0 {
			kv.addRaw("h2-opts", "{"+strings.Join(parts, ", ")+"}")
		}
	case "httpupgrade":
		kv.add("network", "httpupgrade")
		var opts [][2]string
		if t.Path != "" {
			opts = append(opts, [2]string{"path", t.Path})
		}
		kv.addOpts("ws-opts", opts, t.Host)
	}
}

// clashTLSOut renders plain-TLS keys (tls/servername/sni/skip-cert-verify/alpn)
// for vmess/vless. Reality is handled inline by the vless renderer.
func clashTLSOut(kv *clashKV, t *model.TLS, server string) {
	if t == nil || !t.Enabled || t.Type == "reality" {
		return
	}
	kv.addBool("tls", true)
	kv.addIf("servername", t.SNI)
	kv.addIf("client-fingerprint", t.Fingerprint)
	if t.Insecure {
		kv.addBool("skip-cert-verify", true)
	}
	kv.addList("alpn", t.ALPN)
}

// --- AmneziaWG detection ---

// hasAWGParams reports whether p carries any AmneziaWG-specific obfuscation
// param (junk-packet / magic-header tuning). Such an endpoint can't be expressed
// as a clash wireguard proxy.
func hasAWGParams(p map[string]any) bool {
	for _, k := range []string{"jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4"} {
		if v, ok := p[k]; ok {
			// A present, non-zero value means real AWG obfuscation.
			switch n := v.(type) {
			case int:
				if n != 0 {
					return true
				}
			case int64:
				if n != 0 {
					return true
				}
			case float64:
				if n != 0 {
					return true
				}
			case string:
				if n != "" && n != "0" {
					return true
				}
			}
		}
	}
	return false
}

// --- clashKV: ordered block-style YAML mapping builder (no YAML dep) ---

// clashKV accumulates a proxy's fields in insertion order and renders them as a
// block-style YAML mapping under a `  - ` sequence dash. Values that need
// quoting (names with spaces/unicode, passwords with special chars) are quoted;
// flow values (already-bracketed lists / maps) are written verbatim.
type clashKV struct {
	keys []string
	vals []string
	raw  []bool // true: write val verbatim (a flow list/map); false: scalar-quote it
}

func newKV() *clashKV { return &clashKV{} }

// add appends a scalar field (the value is quoted if YAML requires it).
func (k *clashKV) add(key, val string) {
	k.keys = append(k.keys, key)
	k.vals = append(k.vals, val)
	k.raw = append(k.raw, false)
}

// addIf appends a scalar field only when val is non-empty.
func (k *clashKV) addIf(key, val string) {
	if val != "" {
		k.add(key, val)
	}
}

// addRaw appends a field whose value is written verbatim (a flow sequence or a
// pre-formatted value), with no scalar quoting.
func (k *clashKV) addRaw(key, val string) {
	k.keys = append(k.keys, key)
	k.vals = append(k.vals, val)
	k.raw = append(k.raw, true)
}

// addBool appends a YAML boolean, written verbatim as the bare token `true`/`false`.
// It must NOT go through add(): yamlScalar would quote the bool token into the STRING
// "true", and clash/mihomo types fields like tls / skip-cert-verify / udp-over-tcp as
// Go bool — its strict decoder rejects a string source and fails the whole config load.
func (k *clashKV) addBool(key string, v bool) {
	k.addRaw(key, strconv.FormatBool(v))
}

// addServerPort emits the server + port pair shared by every proxy type.
func (k *clashKV) addServerPort(e model.Endpoint) {
	k.add("server", e.Server)
	k.add("port", strconv.Itoa(e.Port))
}

// addList emits `key: [a, b, c]` (a flow sequence) when items is non-empty.
func (k *clashKV) addList(key string, items []string) {
	if len(items) == 0 {
		return
	}
	quoted := make([]string, len(items))
	for i, it := range items {
		quoted[i] = yamlScalar(it)
	}
	k.addRaw(key, "["+strings.Join(quoted, ", ")+"]")
}

// addMap emits a nested mapping `key: {k: v, ...}` (inline flow form) so the
// importer's flow-mapping reader folds it into dotted keys.
func (k *clashKV) addMap(key string, pairs [][2]string) {
	if len(pairs) == 0 {
		return
	}
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		if p[1] == "" {
			continue
		}
		parts = append(parts, p[0]+": "+yamlScalar(p[1]))
	}
	if len(parts) == 0 {
		return
	}
	k.addRaw(key, "{"+strings.Join(parts, ", ")+"}")
}

// addOpts emits a *-opts mapping that may also carry a headers.Host child, the
// way clash spells the ws/httpupgrade Host header (ws-opts.headers.Host).
func (k *clashKV) addOpts(key string, pairs [][2]string, host string) {
	if host != "" {
		pairs = append(pairs, [2]string{"headers", "{Host: " + yamlScalar(host) + "}"})
		// The headers value is itself a flow map; addMap quotes scalars only, so
		// pass it through as a raw nested-map fragment.
		var parts []string
		for _, p := range pairs {
			if p[1] == "" {
				continue
			}
			if p[0] == "headers" {
				parts = append(parts, "headers: "+p[1])
			} else {
				parts = append(parts, p[0]+": "+yamlScalar(p[1]))
			}
		}
		if len(parts) > 0 {
			k.addRaw(key, "{"+strings.Join(parts, ", ")+"}")
		}
		return
	}
	k.addMap(key, pairs)
}

// render writes the accumulated fields as a block-style sequence entry: the
// first field carries the `  - ` dash, the rest are indented under it.
func (k *clashKV) render() string {
	var b strings.Builder
	for i, key := range k.keys {
		prefix := "    "
		if i == 0 {
			prefix = "  - "
		}
		val := k.vals[i]
		if !k.raw[i] {
			val = yamlScalar(val)
		}
		b.WriteString(prefix + key + ": " + val + "\n")
	}
	return b.String()
}

// --- name de-duplication + YAML scalar quoting ---

// uniqueName returns name unchanged if unused, else appends " (n)" until unique.
// clash requires unique proxy names; two endpoints may legitimately share one.
func uniqueName(name string, used map[string]bool) string {
	if name == "" {
		name = "proxy"
	}
	if !used[name] {
		return name
	}
	for i := 2; ; i++ {
		cand := name + " " + strconv.Itoa(i)
		if !used[cand] {
			return cand
		}
	}
}

// yamlScalar renders s as a YAML scalar, double-quoting (with escaping) when the
// value would otherwise be mis-parsed: empty, leading/trailing space, a leading
// indicator char, an embedded ": "/" #"/comma/brace/bracket/colon, or a token
// YAML reads as a non-string (true/false/null/numbers). A plain identifier-like
// value is left bare.
func yamlScalar(s string) string {
	if needsQuote(s) {
		var b strings.Builder
		b.WriteByte('"')
		for _, r := range s {
			switch r {
			case '"':
				b.WriteString("\\\"")
			case '\\':
				b.WriteString("\\\\")
			case '\n':
				b.WriteString("\\n")
			case '\t':
				b.WriteString("\\t")
			default:
				b.WriteRune(r)
			}
		}
		b.WriteByte('"')
		return b.String()
	}
	return s
}

// isInteger reports whether s is a plain (optionally signed) base-10 integer.
func isInteger(s string) bool {
	if s == "" {
		return false
	}
	i := 0
	if s[0] == '-' || s[0] == '+' {
		i = 1
	}
	if i == len(s) {
		return false
	}
	for ; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func needsQuote(s string) bool {
	if s == "" {
		return true
	}
	if s != strings.TrimSpace(s) {
		return true
	}
	// Tokens YAML would read as a bool / null rather than a string.
	switch strings.ToLower(s) {
	case "true", "false", "null", "yes", "no", "on", "off", "~":
		return true
	}
	// A pure integer (e.g. a port or MTU) is fine left bare — clash/our importer
	// read it back as a scalar either way, and quoting it makes the emitted config
	// noisier than a hand-written one. But ONLY a canonical base-10 integer: a
	// YAML resolver re-types "007" as int 7 and "+7" as 7 (and a >int64 digit run
	// as a float), so a leading-zero/plus-signed/overlong "integer" password would
	// silently reach a strict clash client as a DIFFERENT string. Bare only when
	// the YAML int round-trips to the identical text.
	if isInteger(s) {
		if n, err := strconv.ParseInt(s, 10, 64); err != nil || strconv.FormatInt(n, 10) != s {
			return true
		}
	} else {
		// A non-integer float-looking token (e.g. "1.2.3" is not a float; "1.5"
		// is) is quoted via ParseFloat to avoid YAML re-typing it.
		if _, err := strconv.ParseFloat(s, 64); err == nil {
			return true
		}
		// Tokens Go's ParseFloat rejects but YAML resolvers (yaml.v3 / mihomo)
		// still re-type: 0x/0o/0b radix ints (+ "1_0" underscore forms — ParseInt
		// base 0 accepts exactly those) and the .inf/.nan float specials.
		trimmed := s
		if trimmed[0] == '+' || trimmed[0] == '-' {
			trimmed = trimmed[1:]
		}
		if _, err := strconv.ParseInt(trimmed, 0, 64); err == nil && trimmed != "" {
			return true
		}
		switch strings.ToLower(trimmed) {
		case ".inf", ".nan":
			return true
		}
	}
	// Leading indicator characters that start a non-scalar in YAML.
	switch s[0] {
	case '-', '?', ':', ',', '[', ']', '{', '}', '#', '&', '*', '!', '|', '>', '\'', '"', '%', '@', '`', ' ':
		return true
	}
	// Characters that break flow/block parsing if left bare.
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ',', '[', ']', '{', '}', '"', '\'', '\n', '\t', '\\':
			return true
		case ':':
			// ": " (or trailing ':') is a mapping indicator.
			if i+1 >= len(s) || s[i+1] == ' ' {
				return true
			}
		case '#':
			// " #" starts an inline comment.
			if i > 0 && s[i-1] == ' ' {
				return true
			}
		}
	}
	return false
}
