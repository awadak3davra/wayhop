package server

import (
	"context"
	"fmt"
	"strings"

	"wakeroute/internal/model"
)

// parseSingboxTags extracts the build-feature set from `sing-box version` output (the
// "Tags: with_quic,with_wireguard,..." line). Pure for unit-testing.
func parseSingboxTags(out string) map[string]bool {
	tags := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "Tags:"); ok {
			for _, t := range strings.Split(rest, ",") {
				if t = strings.TrimSpace(t); t != "" {
					tags[t] = true
				}
			}
		}
	}
	return tags
}

// unsupportedSingboxEndpoints lists enabled, sing-box-carried endpoints whose protocol (or uTLS
// fingerprint) needs a build tag the deployed sing-box lacks — those would fail to apply with a
// cryptic core error. EngineExternal (native-iface) and plugin protocols (AmneziaWG/olcRTC) are
// skipped: they aren't carried by sing-box. Core protocols (vless/vmess/trojan/shadowsocks) need
// no tag. Pure for unit-testing.
func unsupportedSingboxEndpoints(p *model.Profile, tags map[string]bool) []string {
	var bad []string
	for i := range p.Endpoints {
		e := &p.Endpoints[i]
		if !e.Enabled || e.Engine == model.EngineExternal {
			continue
		}
		switch e.Protocol {
		case model.ProtoAmneziaWG, model.ProtoOlcRTC:
			continue // plugin engines — not carried by sing-box
		case model.ProtoHysteria2, model.ProtoTUIC:
			if !tags["with_quic"] {
				bad = append(bad, fmt.Sprintf("%q (%s) needs with_quic", e.Name, e.Protocol))
			}
		case model.ProtoWireGuard:
			if !tags["with_wireguard"] {
				bad = append(bad, fmt.Sprintf("%q (wireguard) needs with_wireguard", e.Name))
			}
		}
		if e.TLS != nil && e.TLS.Fingerprint != "" && !tags["with_utls"] {
			bad = append(bad, fmt.Sprintf("%q uTLS fingerprint %q needs with_utls", e.Name, e.TLS.Fingerprint))
		}
	}
	return bad
}

// singboxBuildCheck is a Diagnostics-battery probe: it reads the deployed sing-box's build tags and
// FAILS if an enabled endpoint uses a protocol/feature that build can't run (e.g. a hysteria2
// endpoint on a sing-box compiled without with_quic) — which would otherwise fail cryptically only
// at apply. Read-only.
func (s *Server) singboxBuildCheck(ctx context.Context) healthRow {
	row := healthRow{ID: "singbox-build", Label: "sing-box build supports your endpoints"}
	if s.singbox == nil {
		row.Status, row.Summary = "warn", "sing-box not configured"
		return row
	}
	out, err := s.singbox.Version(ctx)
	if err != nil {
		row.Status, row.Summary = "warn", "couldn't read sing-box version"
		row.Detail = err.Error()
		return row
	}
	tags := parseSingboxTags(out)
	if len(tags) == 0 {
		row.Status, row.Summary = "warn", "sing-box version reported no build tags"
		return row
	}
	p := s.store.Profile()
	bad := unsupportedSingboxEndpoints(&p, tags)
	if len(bad) == 0 {
		row.Status, row.Summary = "pass", "every endpoint's protocol is supported by this sing-box build"
		return row
	}
	row.Status = "fail"
	row.Summary = fmt.Sprintf("%d endpoint(s) use a feature this sing-box build lacks", len(bad))
	row.Detail = strings.Join(bad, "; ")
	row.Fix = "these will fail to apply — install a sing-box built with the listed tags, or switch those endpoints to a supported protocol"
	return row
}
