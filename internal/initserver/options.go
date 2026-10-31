package initserver

import "strings"

// Option is a provisionable protocol: presentation metadata for the UI plus the
// install-script fragment and a payload detector. This is the single registration
// point — adding a new server-side VPN means appending one Option here (script +
// detector), with no edits to BuildScript, the extractor, or the orchestration.
type Option struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Summary     string   `json:"summary"`
	Details     []string `json:"details,omitempty"`
	Port        int      `json:"port"`
	Transport   string   `json:"transport"`
	Recommended bool     `json:"recommended"`

	// Script is the shell fragment appended to the installer for this protocol.
	// It MUST print `WR_PROTO=<id>` immediately before its WR_CLIENT_CONFIG line so
	// the client config can be attributed to the right protocol (never by index).
	Script string `json:"-"`
	// Detect recognises this protocol's client config payload (fallback when the
	// WR_PROTO marker is missing, e.g. a hand-run script).
	Detect func(config string) bool `json:"-"`
}

// selfSignedPinNote is what the connection Set up Server adds checks on a self-signed server, which
// depends on the router's sing-box: the public-key pin comes on its own line beside the link (no link
// carries one), and the whole-certificate pin in the link. A 1.12 core, which some routers run, has
// neither and accepts any certificate (QA-138).
const selfSignedPinNote = "The connection WayHop adds also gets the certificate's public-key pin, printed beside the link: " +
	"on sing-box 1.13 and later the router checks the server by that key, on 1.15 by the whole certificate too, " +
	"and on 1.12 it accepts any certificate, as the insecure flag says."

// catalog is the registry of provisionable protocols.
var catalog = []Option{
	{
		ID:      ProtoAmneziaWG,
		Name:    "AmneziaWG",
		Summary: "Censorship-resistant WireGuard with a junk-padded handshake.",
		Details: []string{
			"WireGuard fork that pads/obfuscates the handshake (Jc/Jmin/Jmax/S1/S2/H1-H4) to defeat DPI and TSPU.",
			"Best choice where plain WireGuard is throttled or whitelisted (e.g. RU).",
			"Server listens on UDP :51820; wayhop generates the matching client automatically.",
		},
		Port:        51820,
		Transport:   "udp",
		Recommended: true,
		Script:      scriptAmneziaWG,
		Detect:      func(c string) bool { return strings.Contains(c, "[Interface]") },
	},
	{
		ID:      ProtoWireGuard,
		Name:    "WireGuard",
		Summary: "Standard, interoperable WireGuard — fast and universally supported.",
		Details: []string{
			"Vanilla WireGuard (no DPI-obfuscation overhead), so any stock WireGuard client — mobile apps, in-kernel wg, routers — imports the generated .conf directly.",
			"Best where WireGuard isn't blocked and you want maximum throughput and broad client compatibility; choose AmneziaWG instead where plain WireGuard is throttled or whitelisted.",
			"Server listens on UDP :51821 (subnet 10.14.14.0/24, distinct from AmneziaWG's :51820) so both can run side by side; wayhop generates the matching client automatically.",
		},
		Port:      51821,
		Transport: "udp",
		Script:    scriptWireGuard,
		// A plain WireGuard .conf has an [Interface] block but NONE of AmneziaWG's
		// obfuscation params (Jc/Jmin/Jmax/S1/S2/H1-H4). Both schemes share the
		// "[Interface]" marker, so DetectProto checks AmneziaWG first (registered above)
		// and only falls through to here for a config without those keys — keeping this
		// detector deliberately conservative so it never claims an AmneziaWG payload.
		Detect: func(c string) bool {
			if !strings.Contains(c, "[Interface]") {
				return false
			}
			low := strings.ToLower(c)
			for _, k := range []string{"\njc", "\njmin", "\njmax", "\ns1", "\ns2", "\nh1", "\nh2", "\nh3", "\nh4"} {
				if strings.Contains(low, k+" ") || strings.Contains(low, k+"=") {
					return false
				}
			}
			return true
		},
	},
	{
		ID:      ProtoReality,
		Name:    "VLESS-Reality",
		Summary: "TLS-camouflaged proxy that borrows a real site's certificate.",
		Details: []string{
			"sing-box VLESS with Reality: the TLS handshake impersonates a real HTTPS site (www.microsoft.com), so it looks like ordinary web traffic.",
			"Runs over TCP :443 with xtls-rprx-vision flow — strong against active probing.",
			"No domain or certificate of your own required.",
		},
		Port:        443,
		Transport:   "tcp",
		Recommended: true,
		Script:      scriptReality,
		Detect:      func(c string) bool { return strings.HasPrefix(strings.TrimSpace(c), "vless://") },
	},
	{
		ID:      ProtoVMess,
		Name:    "VMess",
		Summary: "Classic V2Ray protocol over WebSocket + TLS (self-signed).",
		Details: []string{
			"sing-box VMess inbound on TCP :8443, WebSocket transport (path /wayhop) wrapped in TLS.",
			"TLS uses a self-signed certificate (SNI wayhop.local); the client link carries allowInsecure=1 and the certificate's pin (pcs, a hash of the whole certificate).",
			selfSignedPinNote,
			"Per-server uuid is generated once and persisted — re-running the installer never rotates it.",
		},
		Port:      8443,
		Transport: "tcp",
		Script:    scriptVMess,
		Detect:    func(c string) bool { return strings.HasPrefix(strings.TrimSpace(c), "vmess://") },
	},
	{
		ID:      ProtoTrojan,
		Name:    "Trojan",
		Summary: "TLS proxy that mimics plain HTTPS, authenticated by a password.",
		Details: []string{
			"sing-box Trojan inbound on TCP :8444 behind TLS (self-signed cert, SNI wayhop.local).",
			"The client link carries insecure=1 (skip-cert-verify) and the self-signed cert's pin (pcs, a hash of the whole certificate); bring your own domain + real cert for active-probing resistance.",
			selfSignedPinNote,
			"Per-server password is generated once and persisted across re-runs.",
		},
		Port:      8444,
		Transport: "tcp",
		Script:    scriptTrojan,
		Detect:    func(c string) bool { return strings.HasPrefix(strings.TrimSpace(c), "trojan://") },
	},
	{
		ID:      ProtoShadowsocks,
		Name:    "Shadowsocks",
		Summary: "Lightweight AEAD proxy (2022-blake3-aes-256-gcm).",
		Details: []string{
			"sing-box Shadowsocks inbound on TCP/UDP :8388 using the modern 2022-blake3-aes-256-gcm cipher.",
			"No TLS layer — Shadowsocks is its own AEAD encryption; the 32-byte PSK is generated once and persisted.",
			"The client link is the standard SIP002 ss:// form, importable as-is.",
		},
		Port:      8388,
		Transport: "tcp",
		Script:    scriptShadowsocks,
		Detect:    func(c string) bool { return strings.HasPrefix(strings.TrimSpace(c), "ss://") },
	},
	{
		ID:      ProtoHysteria2,
		Name:    "Hysteria2",
		Summary: "High-throughput QUIC proxy that shrugs off lossy links.",
		Details: []string{
			"sing-box Hysteria2 inbound on UDP :8445 over QUIC + TLS (self-signed cert, SNI wayhop.local, ALPN h3).",
			"Excellent on high-loss / high-latency networks; the client link carries insecure=1 and the self-signed cert's pin (pinSHA256, a hash of the whole certificate).",
			selfSignedPinNote,
			"Per-server password is generated once and persisted; the UDP port is opened in iptables best-effort.",
		},
		Port:      8445,
		Transport: "udp",
		Script:    scriptHysteria2,
		Detect:    func(c string) bool { return strings.HasPrefix(strings.TrimSpace(c), "hysteria2://") },
	},
	{
		ID:      ProtoTUIC,
		Name:    "TUIC",
		Summary: "QUIC-based proxy (TUIC v5) with BBR congestion control.",
		Details: []string{
			"sing-box TUIC v5 inbound on UDP :8446 over QUIC + TLS (self-signed cert, SNI wayhop.local, ALPN h3).",
			"Low-latency UDP-native proxy; the client link carries congestion_control=bbr, insecure=1 and the self-signed cert's pin (pcs, a hash of the whole certificate).",
			selfSignedPinNote,
			"Per-server uuid + password are generated once and persisted; the UDP port is opened in iptables best-effort.",
		},
		Port:      8446,
		Transport: "udp",
		Script:    scriptTUIC,
		Detect:    func(c string) bool { return strings.HasPrefix(strings.TrimSpace(c), "tuic://") },
	},
	{
		ID:      ProtoAnyTLS,
		Name:    "AnyTLS",
		Summary: "TLS proxy that pads away the TLS-in-TLS pattern DPI looks for.",
		Details: []string{
			"sing-box AnyTLS inbound on TCP :8447 behind TLS (self-signed cert, SNI wayhop.local); needs sing-box 1.12 or newer on the server.",
			"Pads and splits records so the inner TLS handshake does not show through the outer one; the client link carries insecure=1 and the self-signed cert's pin (pcs, a hash of the whole certificate).",
			selfSignedPinNote,
			"Per-server password is generated once and persisted across re-runs.",
		},
		Port:      8447,
		Transport: "tcp",
		Script:    scriptAnyTLS,
		Detect:    func(c string) bool { return strings.HasPrefix(strings.TrimSpace(c), "anytls://") },
	},
	{
		ID:      ProtoSnell,
		Name:    "Snell",
		Summary: "Surge's lean proxy (Snell v6) with traffic shaping derived from its key.",
		Details: []string{
			"sing-box Snell v6 inbound on TCP :8448; UDP is carried over the same TCP connection. No certificate and no obfuscation settings.",
			"Needs sing-box 1.14 or newer on the server and on this router; the client config is a Surge line, importable as-is.",
			"The pre-shared key (24 random bytes) is generated once and persisted across re-runs.",
		},
		Port:      8448,
		Transport: "tcp",
		Script:    scriptSnell,
		Detect:    func(c string) bool { return strings.Contains(c, "= snell,") },
	},
	{
		ID:      ProtoMTProto,
		Name:    "MTProto (Telegram proxy)",
		Summary: "A Telegram proxy for phones: a tg://proxy link that works on mobile data, no VPN app.",
		Details: []string{
			"telemt " + TelemtVersion + " on TCP :" + mtprotoPort + ", fake-TLS imitating " + mtprotoCover + "; the static build is checked against its published sha256 before it is installed.",
			"Not a connection for this router: the result is a link to open on the phone (Telegram -> Settings -> Data and Storage -> Proxy).",
			"The secret is generated once and persisted, so re-running keeps the link working; runs as its own user under systemd.",
		},
		Port:      8449,
		Transport: "tcp",
		Script:    scriptMTProto,
		Detect:    func(c string) bool { return strings.HasPrefix(strings.TrimSpace(c), "tg://proxy") },
	},
}

// Options returns the provisionable-protocol catalog.
func Options() []Option { return catalog }

// optionByID returns the catalog entry for id, or nil.
func optionByID(id string) *Option {
	for i := range catalog {
		if catalog[i].ID == id {
			return &catalog[i]
		}
	}
	return nil
}

// ValidOption reports whether id is a known provisionable protocol.
func ValidOption(id string) bool { return optionByID(id) != nil }

// OptionName returns the display name for a protocol id (falls back to the id).
func OptionName(id string) string {
	if o := optionByID(id); o != nil {
		return o.Name
	}
	return id
}

// DetectProto identifies the protocol of a client config payload via the catalog
// detectors (used when a config has no WR_PROTO marker).
func DetectProto(config string) string {
	for i := range catalog {
		if catalog[i].Detect != nil && catalog[i].Detect(config) {
			return catalog[i].ID
		}
	}
	return ""
}
