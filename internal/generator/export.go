package generator

import "wayhop/internal/model"

// OutboundFor exposes the per-endpoint sing-box outbound builder to the Keenetic native-first
// backend (internal/keenetic), which runs sing-box ONLY for non-native protocols
// (VLESS/Reality/Hysteria2/TUIC) behind per-endpoint TUN devices while AmneziaWG/WireGuard
// stay in the kernel. Returns the sing-box outbound JSON object for e (same builder the full
// Generate path uses, so the fallback inherits its protocol correctness + sing-box-check
// coverage). Kept in a separate file so it never conflicts with edits to singbox.go.
func OutboundFor(e *model.Endpoint) (map[string]any, error) {
	return outboundFor(e)
}

// OutboundForCore is OutboundFor with the options a core version decides, as Generate applies them:
// Hysteria2's 1.14 extras, including a Realm, which a 1.14 core reaches and an older one cannot, and
// SSH's 1.14 algorithm limits, ECH's query server name (1.13) or its absence from a 1.12 core
// built without it, the 1.14 QUIC tuning of Hysteria2 and TUIC, and the certificate pins a 1.13 (public
// key) or 1.15 (whole certificate) core checks. The KeeneticOS fallback core used
// OutboundFor alone, so a Realm connection there had no address on any core and gecko obfuscation was
// always left out.
func OutboundForCore(e *model.Endpoint, coreVersion string) (map[string]any, error) {
	ob, err := outboundFor(e)
	if err != nil {
		return nil, err
	}
	if e.Protocol == model.ProtoHysteria2 {
		if err := hysteria2Extras(e, ob, coreVersion); err != nil {
			return nil, err
		}
	}
	if e.Protocol == model.ProtoSSH {
		sshCoreExtras(e, ob, coreVersion)
	}
	echCoreExtras(e, ob, coreVersion)
	quicTuning(e, ob, coreVersion)
	pinCoreExtras(e, ob, coreVersion)
	return ob, nil
}
