package importer

import (
	"encoding/json"

	"wayhop/internal/model"
)

// The formats an endpoint is read from (model.Endpoint.Import). A share link is "link:" and its
// scheme as Parse settles it (hy2 is hysteria2, wg is wireguard).
const (
	FormatClash   = "clash"
	FormatSingbox = "singbox"
	FormatConf    = "conf"
	FormatOpenVPN = "ovpn"
	FormatSurge   = "surge"
)

func linkFormat(scheme string) string { return "link:" + scheme }

// tagged records the format a parse read its endpoint from, for the save that follows (see
// model.Endpoint.Import): tagged(format)(parse(...)).
func tagged(format string) func(*model.Endpoint, error) (*model.Endpoint, error) {
	return func(e *model.Endpoint, err error) (*model.Endpoint, error) {
		if e != nil {
			e.Import = format
		}
		return e, err
	}
}

func tagAll(format string, eps []model.Endpoint) []model.Endpoint {
	for i := range eps {
		eps[i].Import = format
	}
	return eps
}

// sourceFields is what one source format can say about a connection, read off its parser: the
// params keys it writes, the TLS fields it sets (by JSON name), whether it brings certificate pins,
// whether it sets a stream transport, and which of the top-level knobs it fills. Each format's list
// sits next to its parser.
//
// Importing a link again takes exactly these from the link, clearing one the link no longer carries,
// and keeps everything else as stored (Reimport). The default is to keep: a param a later form adds,
// or one a parser starts writing before its list says so, survives a re-import rather than being
// wiped. What the link does carry is always taken, listed or not.
type sourceFields struct {
	params    []string
	tls       []string
	pins      bool
	transport bool
	mtu       bool // Endpoint.MTU (not params "mtu", which is a params key like any other)
	keepalive bool // Endpoint.PersistentKeepalive
	multiplex bool
}

// formatProtocols are the protocols each format's parser produces. The format tag comes from the
// client (the panel posts the parse back), so a tag that does not fit the endpoint's protocol is not
// believed: a vless re-import tagged link:ssh would otherwise be read with the ssh list, which keeps
// insecure, fingerprint and pins.
var formatProtocols = map[string][]model.Protocol{
	linkFormat("vless"):           {model.ProtoVLESS},
	linkFormat("vmess"):           {model.ProtoVMess},
	linkFormat("trojan"):          {model.ProtoTrojan},
	linkFormat("anytls"):          {model.ProtoAnyTLS},
	linkFormat("ss"):              {model.ProtoShadowsocks},
	linkFormat("hysteria2"):       {model.ProtoHysteria2},
	linkFormat("hysteria2+realm"): {model.ProtoHysteria2},
	linkFormat("tuic"):            {model.ProtoTUIC},
	linkFormat("wireguard"):       {model.ProtoWireGuard, model.ProtoAmneziaWG},
	linkFormat("ssh"):             {model.ProtoSSH},
	FormatConf:                    {model.ProtoWireGuard, model.ProtoAmneziaWG},
	FormatOpenVPN:                 {model.ProtoOpenVPN},
	FormatClash: {model.ProtoShadowsocks, model.ProtoVMess, model.ProtoTrojan, model.ProtoAnyTLS, model.ProtoSnell,
		model.ProtoVLESS, model.ProtoHysteria2, model.ProtoTUIC, model.ProtoWireGuard},
	FormatSurge: {model.ProtoSnell, model.ProtoShadowsocks, model.ProtoTrojan, model.ProtoAnyTLS, model.ProtoHysteria2,
		model.ProtoTUIC},
	FormatSingbox: {model.ProtoVLESS, model.ProtoVMess, model.ProtoTrojan, model.ProtoShadowsocks, model.ProtoHysteria2,
		model.ProtoTUIC, model.ProtoAnyTLS, model.ProtoSOCKS, model.ProtoHTTP, model.ProtoSnell, model.ProtoSSH,
		model.ProtoWireGuard, model.ProtoOpenVPN, model.ProtoOpenConnect},
}

// specOf is the list a re-import of link is read with: its format's, when the tag names a format
// whose parser produces link's protocol; otherwise (no tag, an unknown or a mismatched one) what the
// link carries, with the TLS security fields always the link's (untaggedFields).
func specOf(link model.Endpoint) sourceFields {
	if spec, ok := fieldsOf(link.Import); ok {
		for _, p := range formatProtocols[link.Import] {
			if p == link.Protocol {
				return spec
			}
		}
	}
	return untaggedFields(link)
}

// fieldsOf is the list for one format; false for a format it does not know.
func fieldsOf(format string) (sourceFields, bool) {
	switch format {
	case linkFormat("vless"):
		return vlessLinkFields, true
	case linkFormat("vmess"):
		return vmessLinkFields, true
	case linkFormat("trojan"):
		return trojanLinkFields, true
	case linkFormat("anytls"):
		return anytlsLinkFields, true
	case linkFormat("ss"):
		return ssLinkFields, true
	case linkFormat("hysteria2"):
		return hysteria2LinkFields, true
	case linkFormat("hysteria2+realm"):
		return hysteria2RealmLinkFields, true
	case linkFormat("tuic"):
		return tuicLinkFields, true
	case linkFormat("wireguard"):
		return wireguardLinkFields, true
	case linkFormat("ssh"):
		return sshLinkFields, true
	case FormatClash:
		return clashFields, true
	case FormatSingbox:
		return singboxFields, true
	case FormatConf:
		return confFields, true
	case FormatOpenVPN:
		return openvpnFields, true
	case FormatSurge:
		return surgeLineFields, true
	}
	return sourceFields{}, false
}

// awgParamKeys are the AmneziaWG params applyAWGParams writes, for the formats that carry them.
func awgParamKeys() []string {
	out := append(append([]string{}, awgKeys...), awgKeysHex...)
	for _, k := range awgKeys3 {
		out = append(out, k.param)
	}
	for _, k := range awgBools3 {
		out = append(out, k.param)
	}
	return out
}

// pinFields are the TLS block's pin fields, which Reimport handles apart (userPins).
var pinFields = []string{"pin_cert_sha256", "pin_pubkey_sha256", "pin_cert_may_be_ca", "pin_cert_beside_chain",
	"pin_cert_may_be_ca_of", "pin_cert_beside_chain_of"}

// Reimport is what importing a link again does to the connection that link already made (QA-148).
//
// A bulk import of the same link used to store the bare parse in its place, so everything the user
// had set since (the name, the switch, the health target, multiplex) went back to what the link
// carries. Laying only the values the link carries over the stored connection was not the answer: a
// value the link no longer carries stayed, so a provider that dropped Vision, allowInsecure, a uTLS
// fingerprint or a rotated pin left the connection broken, or accepting any certificate, while the
// import said "unchanged". Taking the link whole was not either: it wiped what no link can carry, an
// ssh host key added in the form (so the exit then accepted any server key), Hysteria2's QUIC tuning,
// a WireGuard keepalive set in the form.
//
// So the link's format decides (sourceFields): what that format can express comes from the link,
// cleared when the link omits it; everything else stays as stored. The format is the tag the parse
// gave the endpoint, believed only when that format produces its protocol (specOf); with none, the
// TLS fields that loosen the server check are the link's whatever else is kept (untaggedFields).
// A WireGuard MTU or keepalive the format can express is the link's in both places it can live. Identity (protocol, engine,
// server, port) is the link's. The name, the switch, owner, health target and the amneziawg-go choice
// are never a link's. Pins follow userPins: the link's own replace the ones an earlier import brought,
// and the ones the user added stay. "Unchanged" (SameEndpoint of the result and the stored one) means
// the part the link can express is identical.
func Reimport(have, link model.Endpoint) model.Endpoint {
	spec := specOf(link)
	out := have
	out.Import = ""
	out.Engine, out.Protocol, out.Server, out.Port = link.Engine, link.Protocol, link.Server, link.Port

	params := make(map[string]any, len(have.Params)+len(link.Params))
	for k, v := range have.Params {
		params[k] = v
	}
	for _, k := range spec.params {
		delete(params, k)
	}
	for k, v := range link.Params {
		params[k] = v
	}
	out.Params = params
	if len(params) == 0 {
		out.Params = nil
	}

	out.TLS = mergeTLS(have.TLS, link.TLS, spec)
	if spec.transport || link.Transport != nil {
		out.Transport = link.Transport
	}
	if spec.mtu {
		out.MTU = link.MTU
	}
	if spec.keepalive {
		out.PersistentKeepalive = link.PersistentKeepalive
	}
	// A WireGuard or AmneziaWG link's MTU and keepalive live in two places: a format's params (a .conf,
	// a wg:// link, Clash) or the top-level knobs (a sing-box config, and the form, which moves them
	// there on any save, a rename included). The generator reads the top-level one first. Where the
	// format can express the value, the link's wins in both places: the twin it does not use is
	// cleared, or a provider's new MTU, or a keepalive it dropped, would lose to the value a rename had
	// moved up. Only a format that cannot express the value leaves the user's.
	if out.Protocol == model.ProtoWireGuard || out.Protocol == model.ProtoAmneziaWG {
		for _, twin := range []struct {
			param string
			knob  *int
			link  int
			own   bool
		}{{"mtu", &out.MTU, link.MTU, spec.mtu}, {"persistent_keepalive", &out.PersistentKeepalive, link.PersistentKeepalive, spec.keepalive}} {
			if !twin.own && !containsPin(spec.params, twin.param) {
				continue
			}
			*twin.knob = twin.link
			if _, carried := link.Params[twin.param]; !carried && out.Params != nil {
				delete(out.Params, twin.param)
			}
		}
		if len(out.Params) == 0 {
			out.Params = nil
		}
	}
	if spec.multiplex {
		out.Multiplex = link.Multiplex
	}
	return out
}

// untaggedFields reads a link of no believable format as expressing what it carries, with one
// exception that fails closed: the TLS fields that loosen or shape how the server is checked
// (insecure, the uTLS fingerprint, ECH) and the pins an import brought are always the link's, so a
// missing or forged tag cannot keep "accept any certificate" that the link no longer asks for. Pins
// the user added stay (userPins): a pin only narrows what is accepted.
func untaggedFields(link model.Endpoint) sourceFields {
	f := carriedFields(link)
	for _, k := range []string{"insecure", "fingerprint", "ech"} {
		if !containsPin(f.tls, k) {
			f.tls = append(f.tls, k)
		}
	}
	f.pins = true
	return f
}

// carriedFields reads a link as expressing exactly what it carries.
func carriedFields(link model.Endpoint) sourceFields {
	f := sourceFields{transport: link.Transport != nil, mtu: link.MTU != 0, keepalive: link.PersistentKeepalive != 0,
		multiplex: link.Multiplex != nil}
	for k := range link.Params {
		f.params = append(f.params, k)
	}
	for k := range jsonFields(link.TLS) {
		f.tls = append(f.tls, k)
	}
	f.pins = link.TLS != nil && (len(link.TLS.PinCertSHA256) > 0 || len(link.TLS.PinPubKeySHA256) > 0)
	return f
}

// mergeTLS is the TLS block of a re-import: the stored block with the fields the format expresses
// replaced by the link's (cleared where the link has none), and the pins as userPins decides.
func mergeTLS(have, link *model.TLS, spec sourceFields) *model.TLS {
	if len(spec.tls) == 0 && !spec.pins && link == nil {
		return have
	}
	m := jsonFields(have)
	for _, k := range spec.tls {
		delete(m, k)
	}
	if spec.pins {
		for _, k := range pinFields {
			delete(m, k)
		}
	}
	for k, v := range jsonFields(link) {
		if !containsPin(pinFields, k) {
			m[k] = v
		}
	}
	var out *model.TLS
	if len(m) > 0 {
		b, err := json.Marshal(m)
		out = new(model.TLS)
		if err != nil || json.Unmarshal(b, out) != nil {
			return link // unreachable for this type; the link's block is the honest fallback
		}
	}
	if !spec.pins {
		return out // have's pins were never removed
	}
	if out == nil {
		return nil // nothing to pin
	}
	// The pins come from the link, and the ones the user added stay beside them.
	if link != nil {
		out.PinCertSHA256 = append([]string(nil), link.PinCertSHA256...)
		out.PinPubKeySHA256 = append([]string(nil), link.PinPubKeySHA256...)
		out.PinCertMayBeCA, out.PinCertBesideChain = link.PinCertMayBeCA, link.PinCertBesideChain
		out.PinCertMayBeCAOf = append([]string(nil), link.PinCertMayBeCAOf...)
		out.PinCertBesideChainOf = append([]string(nil), link.PinCertBesideChainOf...)
	}
	return withUserPins(out, have)
}

// jsonFields is a TLS block as its JSON fields; empty for nil.
func jsonFields(t *model.TLS) map[string]json.RawMessage {
	m := map[string]json.RawMessage{}
	if t == nil {
		return m
	}
	if b, err := json.Marshal(t); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

// KeptServerKeyPin reports whether a re-import kept public-key pins the link did not carry: they
// come from Set up Server or the form, and a server whose key has changed is refused while they stay.
func KeptServerKeyPin(merged, link model.Endpoint) bool {
	if merged.TLS == nil {
		return false
	}
	for _, p := range merged.TLS.PinPubKeySHA256 {
		if link.TLS == nil || !containsPin(link.TLS.PinPubKeySHA256, p) {
			return true
		}
	}
	return false
}
