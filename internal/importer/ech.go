package importer

import (
	"strings"

	"wayhop/internal/model"
)

// Encrypted Client Hello in the formats that carry it (model.ECH):
//
//   - share links (Xray's standard, v2rayN, Hysteria's URI): ech=<base64 ECHConfigList>, or in Xray
//     and v2rayN "[queryName+]dnsURL" for a config looked up in DNS through that resolver;
//   - Clash / mihomo: ech-opts {enable, config (base64), query-server-name};
//   - sing-box: tls.ech {enabled, config (PEM lines), config_path, query_server_name}.
//
// The resolver URL of the DNS form is not carried: sing-box looks the record up through the router's
// own DNS, so only the query name is kept.

// echFromLink reads a share link's ech= value. A '+' the link left unescaped reaches here as a space
// (query decoding), so spaces are read back as '+', which neither form contains otherwise.
func echFromLink(v string) *model.ECH {
	v = strings.TrimSpace(strings.ReplaceAll(v, " ", "+"))
	if v == "" {
		return nil
	}
	if i := strings.Index(v, "://"); i >= 0 {
		qn := ""
		if j := strings.LastIndexByte(v[:i], '+'); j >= 0 {
			qn = v[:j]
		}
		return &model.ECH{Enabled: true, QueryServerName: qn}
	}
	return &model.ECH{Enabled: true, Config: v}
}

// clashECH reads a Clash proxy's ech-opts (folded into dotted keys). mihomo ignores the block unless
// enable is true.
func clashECH(p proxyMap) *model.ECH {
	if !truthy(p["ech-opts.enable"]) {
		return nil
	}
	return &model.ECH{Enabled: true, Config: strings.TrimSpace(p["ech-opts.config"]),
		QueryServerName: strings.TrimSpace(p["ech-opts.query-server-name"])}
}

// singboxECH reads a sing-box tls block's ech. A config_path is refused before this is reached
// (singboxOutboundToEndpoint): the file is on the machine the config came from.
func singboxECH(tl map[string]any) *model.ECH {
	ech, ok := tl["ech"].(map[string]any)
	if !ok || !sbBool(ech, "enabled") {
		return nil
	}
	return &model.ECH{Enabled: true, Config: strings.TrimSpace(sbText(ech, "config")),
		QueryServerName: strings.TrimSpace(sbStr(ech, "query_server_name"))}
}

// settleECH fits an imported ECH to the connection it arrived on:
//
//   - the config is stored as standard base64 (a PEM block or another alphabet is re-encoded); one
//     that does not parse is kept as given, so the import stores the connection disabled and says why;
//   - under Reality it is kept switched off: sing-box refuses the pair, v2rayN writes ech= on Reality
//     links all the same, and the connection works without it. Kept only when it is a config, so an
//     export gives the link back whole; the bulk import says once that it is not used, and so does the
//     connection form;
//   - the DNS form is kept over QUIC (hysteria2, tuic) too, where sing-box never runs the lookup: the
//     import then stores the connection disabled and asks for the server's config (model.Validate),
//     where dropping it would bring the connection up without the ECH the link asked for, unsaid.
func settleECH(ech *model.ECH, tlsType string) *model.ECH {
	if ech == nil || !ech.Enabled {
		return nil
	}
	if ech.Config != "" {
		ech.Config = model.CanonicalECHConfig(ech.Config)
		ech.QueryServerName = "" // only the DNS lookup reads it
	}
	if tlsType == "reality" {
		if _, err := model.ParseECHConfigList(ech.Config); ech.Config == "" || err != nil {
			return nil
		}
		return &model.ECH{Config: ech.Config}
	}
	return ech
}
