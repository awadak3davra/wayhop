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
