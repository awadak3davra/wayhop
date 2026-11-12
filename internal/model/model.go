// Package model is the protocol-agnostic configuration model. The UI and
// importers speak this; generators translate it into core-native configs
// (e.g. sing-box JSON). See docs/ARCHITECTURE.md (development repository) §3.
package model

// Engine identifies which core/binary realizes an endpoint.
type Engine string

const (
	EngineSingBox   Engine = "singbox"
	EngineAmneziaWG Engine = "amneziawg"
	EngineOpenVPN   Engine = "openvpn"
	EngineXray      Engine = "xray"
	EngineMihomo    Engine = "mihomo"
	// EngineOlcRTC is retired: WayHop no longer runs olcRTC (upstream ended in 2026-09). The value
	// stays so a profile saved by an older build still loads; Apply refuses it while enabled.
	EngineOlcRTC Engine = "olcrtc"
	// EngineExternal routes through an existing OS interface that WayHop does
	// NOT manage (e.g. a UCI/netifd-brought-up awg0/awg1). It becomes a sing-box
	// `direct` outbound bound to params["interface"]; no tunnel is created.
	EngineExternal Engine = "external"
	// EngineNfqws is the DPI-desync engine (nfqws2): a long-running process on a
	// netfilter NFQUEUE that mangles handshake packets in place so the DPI can't
	// block them. Unlike every other engine it provides NO egress — traffic stays on
	// the DIRECT path; the `desync` routing target installs the NFQUEUE divert
	// separately. See docs/ARCHITECTURE_DESYNC.md in the development repository.
	EngineNfqws Engine = "nfqws"
	// EngineByeDPI runs ciadpi (hufrea/byedpi), a local SOCKS5 proxy that rewrites the start of each
	// connection against DPI and sends it on from the router. A routing list reaches it as a sing-box
	// SOCKS outbound; it has no server of its own (byedpi.go).
	EngineByeDPI Engine = "byedpi"
)

// Protocol is the wire protocol of an endpoint.
type Protocol string

const (
	ProtoVLESS       Protocol = "vless"
	ProtoVMess       Protocol = "vmess"
	ProtoTrojan      Protocol = "trojan"
	ProtoShadowsocks Protocol = "shadowsocks"
	ProtoHysteria2   Protocol = "hysteria2"
	ProtoTUIC        Protocol = "tuic"
	ProtoAnyTLS      Protocol = "anytls"
	ProtoWireGuard   Protocol = "wireguard"
	ProtoAmneziaWG   Protocol = "amneziawg"
	// ProtoOpenVPN is an OpenVPN client, carried by sing-box's openvpn-client endpoint (1.14+).
	ProtoOpenVPN Protocol = "openvpn"
	// ProtoSnell is Surge's Snell (v4, or v6 with traffic shaping), a sing-box 1.14+ outbound.
	ProtoSnell Protocol = "snell"
	// ProtoOpenConnect is an OpenConnect client (AnyConnect/ocserv, GlobalProtect, Fortinet, F5, Pulse,
	// NC), a sing-box 1.14+ endpoint.
	ProtoOpenConnect Protocol = "openconnect"
	// ProtoSSH is an SSH server used as an exit: sing-box's ssh outbound (1.12+) forwards each
	// connection through it, so a VPS with only sshd needs nothing installed (ssh.go).
	ProtoSSH    Protocol = "ssh"
	ProtoOlcRTC Protocol = "olcrtc" // retired with EngineOlcRTC; kept so old profiles load
	ProtoSOCKS  Protocol = "socks"
	ProtoHTTP   Protocol = "http"
)

// TLS holds transport security settings (plain TLS, Reality, uTLS fingerprint).
type TLS struct {
	Enabled bool     `json:"enabled,omitempty"`
	Type    string   `json:"type,omitempty"` // "tls" | "reality"
	SNI     string   `json:"sni,omitempty"`
	ALPN    []string `json:"alpn,omitempty"`
	// CipherSuites restricts TLS 1.0-1.2 suites (share-link cs= / sing-box cipher_suites). TLS 1.3
	// suites are fixed by Go and are intentionally not represented here.
	CipherSuites []string `json:"cipher_suites,omitempty"`
	Insecure     bool     `json:"insecure,omitempty"`
	Fingerprint  string   `json:"fingerprint,omitempty"` // uTLS, e.g. "chrome"
	// Reality
	PublicKey string `json:"public_key,omitempty"`
	ShortID   string `json:"short_id,omitempty"`
	// TLS handshake fragmentation (anti-DPI, sing-box 1.12+, client-only): split the ClientHello so a
	// plaintext SNI-matching firewall can't fingerprint it. Opt-in — a zero value is omitted, so this
	// is byte-identical for existing profiles. Not applied to Reality (it has its own evasion, and a
	// fragmented ClientHello would disturb its fingerprint mimicry).
	Fragment       bool `json:"fragment,omitempty"`
	RecordFragment bool `json:"record_fragment,omitempty"` // fragment into TLS records (sing-box: "performs better")
	// Encrypted Client Hello (ech.go). Never with Reality: sing-box refuses the pair, so a Reality
	// link's ech= is kept switched off, only to be exported again.
	ECH *ECH `json:"ech,omitempty"`
	// Certificate pins (pin.go): SHA-256 of the server's whole certificate (64 lowercase hex) and of
	// its public key (standard base64). A pin replaces the chain-and-name check. Not used with
	// Reality, which authenticates the server by its own key; a Reality link's pins are kept only
	// to be exported again.
	PinCertSHA256   []string `json:"pin_cert_sha256,omitempty"`
	PinPubKeySHA256 []string `json:"pin_pubkey_sha256,omitempty"`
	// Where the whole-certificate pins came from, for the Apply review (pin.go): PinCertMayBeCA when
	// a format that also matches a CA certificate in the chain brought one (Xray's pcs=, mihomo's
	// fingerprint), PinCertBesideChain when Hysteria's pinSHA256 did, which Hysteria checks beside the
	// chain while certificate checks are on. Not rendered. A pin typed in the form has neither, so
	// each flag holds while a pin it came with remains, and the ...Of list then names those pins (64
	// lowercase hex) when they are not all of PinCertSHA256; empty means all of them.
	PinCertMayBeCA       bool     `json:"pin_cert_may_be_ca,omitempty"`
	PinCertBesideChain   bool     `json:"pin_cert_beside_chain,omitempty"`
	PinCertMayBeCAOf     []string `json:"pin_cert_may_be_ca_of,omitempty"`
	PinCertBesideChainOf []string `json:"pin_cert_beside_chain_of,omitempty"`
}

// Transport is the stream transport when not raw TCP (ws/grpc/http/httpupgrade).
type Transport struct {
	Type        string            `json:"type,omitempty"` // "" (tcp) | ws | grpc | http | httpupgrade
	Path        string            `json:"path,omitempty"`
	Host        string            `json:"host,omitempty"`
	ServiceName string            `json:"service_name,omitempty"` // grpc
	Headers     map[string]string `json:"headers,omitempty"`
}

// Multiplex carries many connections over a few proxy connections (sing-box's outbound "multiplex",
// the sing-mux protocol). Only the VLESS, VMess, Trojan and Shadowsocks outbounds take it, and the
// server must accept it: a sing-box server only with multiplex enabled in that inbound (route.go
// refuses the connection otherwise), a mihomo listener always; an Xray one (3x-ui, Marzban) drops
// every connection. multiplex.go says what is refused and why; nil or Enabled false is off.
type Multiplex struct {
	Enabled bool `json:"enabled,omitempty"`
	// Protocol is "" (h2mux, sing-box's default), "h2mux", "smux" or "yamux".
	Protocol string `json:"protocol,omitempty"`
	// The pool: MaxConnections with MinStreams, or MaxStreams alone (sing-box documents the two as
	// conflicting, and sing-mux ignores MaxStreams once MaxConnections is set). With neither, only
	// an idle connection is reused, so each concurrent stream opens its own.
	MaxConnections int  `json:"max_connections,omitempty"`
	MinStreams     int  `json:"min_streams,omitempty"`
	MaxStreams     int  `json:"max_streams,omitempty"`
	Padding        bool `json:"padding,omitempty"`
	// Brutal is TCP Brutal congestion control: one connection at a fixed rate, the pool ignored, so
	// the save refuses a pool beside it and the importers drop one. The server needs Linux, the
	// tcp-brutal kernel module and brutal in its inbound's multiplex.
	Brutal *Brutal `json:"brutal,omitempty"`
}

// Brutal is Multiplex's TCP Brutal block, rates in megabits per second.
type Brutal struct {
	Enabled  bool `json:"enabled,omitempty"`
	UpMbps   int  `json:"up_mbps,omitempty"`
	DownMbps int  `json:"down_mbps,omitempty"`
}

// Health configures an availability check (used by endpoints and groups).
type Health struct {
	URL       string `json:"url,omitempty"`       // default http://cp.cloudflare.com/generate_204
	Interval  int    `json:"interval,omitempty"`  // seconds
	Tolerance int    `json:"tolerance,omitempty"` // ms
}

// Endpoint is one server traffic can be routed out through.
//
// Protocol-specific fields live in Params with these conventional keys:
//
//	vless:       uuid, flow
//	vmess:       uuid, alter_id, security
//	trojan:      password
//	shadowsocks: method, password
//	hysteria2:   password, obfs, obfs_password, up_mbps, down_mbps; realm, realm_stun in place of
//	             server and port for a server reached through a Hysteria realm (hysteria2_realm.go)
//	tuic:        uuid, password, congestion_control, udp_relay_mode
//	hysteria2, tuic: initial_packet_size, disable_path_mtu_discovery (QUIC tuning, quic.go)
//	wireguard:   private_key, peer_public_key, pre_shared_key, local_address, reserved
//	amneziawg:   (wireguard keys) + jc, jmin, jmax, s1, s2, h1, h2, h3, h4
//
// Owner classifies who owns the underlying resource an Endpoint points at — the basis for the
// never-destroy-external invariant. WayHop may freely reconfigure, stop, or remove a resource it
// created (OwnerWayHop); it must NEVER stop, delete, or rewrite the underlying tunnel/interface of an
// externally-owned or imported one — it only routes traffic THROUGH those. Empty ("") means
// OwnerWayHop so existing profiles need no migration. See the deep-integration ownership model.
type Owner string

const (
	// OwnerWayHop: WayHop created this endpoint's underlying resource and fully controls it.
	OwnerWayHop Owner = ""
	// OwnerExternal: a native router tunnel/interface owned by the OS or another service, discovered
	// by WayHop. Routed THROUGH, never modified/stopped/deleted.
	OwnerExternal Owner = "external"
	// OwnerImported: an external resource the user explicitly imported into WayHop routing. Still an
	// external resource (same never-destroy protection); the import is an acknowledgement, not ownership.
	OwnerImported Owner = "imported"
	// OwnerSystem: owned by the router OS itself (netifd/NDM-managed interfaces, firmware VPN
	// clients). A finer-grained OwnerExternal — same never-destroy protection, but it tells the user
	// WHO owns the thing, which is what they need in order to go and change it.
	OwnerSystem Owner = "system"
	// OwnerThirdParty: owned by another package or service sharing the router (a separately-installed
	// VPN client, another routing tool). Also a finer-grained OwnerExternal.
	OwnerThirdParty Owner = "third-party"
	// OwnerUnknown: ownership could not be determined; treated as non-owned for safety.
	OwnerUnknown Owner = "unknown"
)

// externalOwners are every ownership class WayHop may route THROUGH but must never destroy. Kept as
// a set rather than a chain of != comparisons so adding a class cannot accidentally grant authority:
// a new Owner is non-owning until someone deliberately says otherwise in OwnsResource.
var externalOwners = map[Owner]bool{
	OwnerExternal: true, OwnerImported: true, OwnerSystem: true,
	OwnerThirdParty: true, OwnerUnknown: true,
}

// IsExternal reports whether this endpoint's resource belongs to something other than WayHop.
func (e Endpoint) IsExternal() bool { return externalOwners[e.Owner] }

// OwnerLabel is a human label for an ownership class, for UI badges. Unknown values get a generic
// label rather than being rendered raw.
func OwnerLabel(o Owner) string {
	switch o {
	case OwnerWayHop:
		return "Managed by WayHop"
	case OwnerExternal:
		return "External"
	case OwnerImported:
		return "Imported (read-only)"
	case OwnerSystem:
		return "Managed by the router"
	case OwnerThirdParty:
		return "Managed by another service"
	case OwnerUnknown:
		return "Owner unknown"
	}
	return "Owner unknown"
}

// OwnsResource reports whether WayHop created and may freely stop/delete/rewrite this endpoint's
// underlying tunnel/interface. FALSE for any external, imported, or unknown resource — WayHop routes
// through those but must never destroy them. Every destructive native operation (interface down /
// teardown / uninstall) MUST gate on this being true.
//
// The spec's sixth class — "imported AND WayHop-managed", where an adopted resource becomes
// destroyable — is deliberately NOT implemented. Granting destroy authority over something WayHop
// did not create is a product decision with irreversible consequences for the user's router, and
// defaulting it on would be exactly the never-destroy-external violation this model exists to
// prevent. Until that is explicitly designed, every non-WayHop class stays non-owning.
func (e Endpoint) OwnsResource() bool { return e.Owner == OwnerWayHop }

type Endpoint struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Engine   Engine   `json:"engine"`
	Protocol Protocol `json:"protocol"`
	// Owner is who owns the underlying resource (see Owner). "" = OwnerWayHop. Discovered native
	// tunnels are OwnerExternal so WayHop never destroys them.
	Owner     Owner          `json:"owner,omitempty"`
	Server    string         `json:"server"`
	Port      int            `json:"port"`
	Params    map[string]any `json:"params,omitempty"`
	Transport *Transport     `json:"transport,omitempty"`
	TLS       *TLS           `json:"tls,omitempty"`
	// Multiplex is sing-mux on a VLESS, VMess, Trojan or Shadowsocks connection. nil is off and
	// leaves an existing profile byte-identical.
	Multiplex *Multiplex `json:"multiplex,omitempty"`
	Health    *Health    `json:"health,omitempty"`
	Enabled   bool       `json:"enabled"`
	// MTU is the WireGuard/AmneziaWG link MTU. 0 = unset (omitted from output,
	// engine default applies). Protocol-agnostic field; only meaningful for the
	// WG-family engines, but harmless when unset for any protocol.
	MTU int `json:"mtu,omitempty"`
	// PersistentKeepalive is the WireGuard/AmneziaWG keepalive interval in seconds.
	// 0 = unset (omitted; no keepalive). Useful behind NAT to keep the tunnel warm.
	PersistentKeepalive int `json:"persistent_keepalive,omitempty"`
	// AWGUserspace runs a WayHop-owned AmneziaWG connection on amneziawg-go, the newest AmneziaWG WayHop
	// ships, even where the router's own AmneziaWG (its kernel module, or KeeneticOS's and OpenWrt's
	// native tunnels) could carry the settings. false = automatic: the router's own AmneziaWG when it
	// can, amneziawg-go when the settings need a newer generation than it has. Only an AmneziaWG
	// endpoint may set it (Validate); an adopted tunnel is the router's and has no such choice.
	AWGUserspace bool `json:"awg_userspace,omitempty"`
	// Import names the format an importer read this endpoint from ("link:vless", "clash", "singbox",
	// "conf", "ovpn", "surge"; importer.Format*). It travels from a parse to the save that follows -
	// the panel posts a parsed subscription back - so that importing a link again takes from it
	// exactly what its format can express (importer.Reimport). It is never stored: the store clears
	// it on every write, so a stored endpoint, a backup and a revision never carry it.
	Import string `json:"import,omitempty"`
}

// GroupType selects how a group chooses among its members.
type GroupType string

const (
	GroupURLTest  GroupType = "urltest"  // automatic, lowest latency working member
	GroupSelector GroupType = "selector" // manual selection
	GroupFallback GroupType = "fallback" // strict ordered preference
)

// Group is a failover/selection set over endpoints (or nested groups).
type Group struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Type    GroupType `json:"type"`
	Members []string  `json:"members"` // endpoint or group IDs, in preference order
	Test    *Health   `json:"test,omitempty"`
	// KillSwitch, when true, DROPs traffic that selects this group while ALL of
	// its members are down — instead of leaking to the WAN. Default false keeps
	// the current behavior (WAN fallback). Opt-in, so an unset/zero value is a
	// byte-identical no-op for existing profiles.
	KillSwitch bool `json:"kill_switch,omitempty"`
	// InterruptOnSwitch, when true, drops this group's existing connections whenever it switches the
	// selected member (a urltest/fallback failover or a manual selector change), so in-flight
	// connections re-establish through the NEW exit instead of staying pinned to the old/dead one.
	// Default false keeps sing-box's behavior (existing connections survive a switch — convenient for
	// long-lived transfers, but ones stuck on a just-failed exit hang until the app times out and
	// retries). Opt-in, so an unset/zero value is a byte-identical no-op for existing profiles.
	InterruptOnSwitch bool `json:"interrupt_on_switch,omitempty"`
	// Managed, when true, hands this group's member selection to the WAYHOP DAEMON control loop
	// (internal/failover) instead of sing-box's own urltest prober — unlocking rise/fall hysteresis,
	// honest strict-order fallback, failback dampening, and passive ejection that sing-box 1.12.x
	// can't do natively. A managed group is emitted as a sing-box `selector` (so the two don't fight)
	// and the daemon drives it via clash.Select. Default false keeps today's exact behavior; a
	// managed group does NOTHING useful until the daemon runner (F4b) is wired — emitting a selector
	// without the runner is a static pick. Opt-in, so an unset/zero value is byte-identical for
	// existing profiles. See docs/FAILOVER_CONTROL_LOOP.md in the development repository.
	Managed bool `json:"managed,omitempty"`
}

// Rule routes matching traffic to a target outbound.
type Rule struct {
	ID           string   `json:"id"`
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	Domain       []string `json:"domain,omitempty"`
	GeoSite      []string `json:"geosite,omitempty"`
	GeoIP        []string `json:"geoip,omitempty"`
	IPCIDR       []string `json:"ip_cidr,omitempty"`
	Port         []int    `json:"port,omitempty"`

	// Source matchers (v1): select traffic by WHERE it comes from, not just where it is
	// going. Each source group is AND-combined with the destination matchers and the
	// other source groups; entries WITHIN a group are OR'd. Every field is omitempty with
	// a match-anything zero value, so adding them is byte-identical for existing profiles
	// (the KillSwitch zero-value-is-a-no-op convention, above). MAC and iface are
	// KERNEL-ONLY (no sing-box matcher pre-1.14); see docs/SPEC_SOURCE_BASED_ROUTING.md (development repository) in the
	// development repository.
	SourceIPCIDR []string `json:"source_ip_cidr,omitempty"` // src IP/CIDR (v4+v6); kernel ip/ip6 saddr + sing-box source_ip_cidr
	SourceMAC    []string `json:"source_mac,omitempty"`     // src MAC(s); KERNEL-ONLY (nft ether saddr); same-L2 clients only
	SourceIface  []string `json:"source_iface,omitempty"`   // ingress iface name(s); KERNEL-ONLY (nft iifname)
	SourcePort   []int    `json:"source_port,omitempty"`    // src L4 port(s); kernel th sport + sing-box source_port

	Default bool `json:"default,omitempty"` // catch-all (route final)
	// Disabled is an INVERTED on/off toggle: zero (false) = enabled = today's behavior;
	// true = the rule is skipped on every plane. Inverted (NOT "Enabled") on purpose —
	// Endpoint/RoutingList use json:"enabled" WITHOUT omitempty, so a positive Enabled
	// here would decode every existing keyless rule to false and silently disable them
	// all. omitempty + zero-default keeps existing profiles byte-identical.
	Disabled bool   `json:"disabled,omitempty"`
	Outbound string `json:"outbound"` // endpoint id | group id | "direct" | "block"
}

// RoutingList steers traffic matching a domain/IP set to a chosen outbound. The
// set comes from a rule-set URL (a curated preset or a custom .srs/.json) and/or
// manually entered domains/IPs. It becomes a sing-box route.rule_set (remote for
// a URL — fetched through DownloadVia — or inline for Manual entries) plus a
// route.rule that points the set at Outbound. This is the "Routing" page model.
type RoutingList struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Source       string   `json:"source,omitempty"`        // rule-set URL (.srs or .json); empty for manual-only
	Format       string   `json:"format,omitempty"`        // "binary" (.srs) | "source" (.json) | "" (infer from URL)
	Manual       []string `json:"manual,omitempty"`        // user-entered domains/IPs (inline rule-set)
	Outbound     string   `json:"outbound"`                // route matched traffic here: endpoint/group id | "direct" | "block"
	DownloadVia  string   `json:"download_via,omitempty"`  // outbound used to FETCH the URL (sing-box download_detour) and the CIDR and domain feeds (a socket bound to its link; see server/listfeedbind.go); "" = direct
	RefreshHours int      `json:"refresh_hours,omitempty"` // remote update_interval in hours; 0 = default (24h); also the CIDRSource auto-refresh cadence
	Enabled      bool     `json:"enabled"`
	// CIDRSource auto-populates this list's KERNEL CIDRs from a feed so a hybrid/fast
	// carve-out self-maintains instead of relying on a frozen Manual list. Scheme:
	// "https://…"/"http://…" → a plain-text CIDR feed; "asn:13238,47541,…" → RIPEstat
	// announced-prefixes per ASN. Distinct from Source (a sing-box domain rule_set, which
	// is inactive for LAN traffic in fast mode). Empty → no auto-refresh. Cadence reuses
	// RefreshHours. See docs/ARCHITECTURE_NATIVE_FIRST.md (development repository) "RU / remote CIDR auto-refresh".
	CIDRSource string `json:"cidr_source,omitempty"`
	// CIDRCache is the last-good result of fetching CIDRSource (system-managed, persisted
	// so a fetch failure or restart keeps the carve-out). The kernel zone = Manual ∪
	// CIDRCache. Not user-edited; the refresh loop maintains it.
	CIDRCache []string `json:"cidr_cache,omitempty"`
	// CIDRRefreshed is when CIDRCache was last successfully written (unix seconds; system-managed,
	// piggybacking on the cache write so it costs no extra flash). The auto-refresh ticker seeds
	// its schedule from it across daemon restarts — without it a router restarted more often than
	// a list's interval would NEVER auto-refresh. 0 = never refreshed.
	CIDRRefreshed int64 `json:"cidr_refreshed,omitempty"`
	// DomainSource is CIDRSource's counterpart for names: a plain-text feed of domains, one per
	// line, that the resolver plane turns into ipset members at query time. It exists because the
	// same projects publish their lists BOTH as a compiled sing-box .srs and as text — and only the
	// second can be read by a router with no proxy core. A list that used to need the core for its
	// format alone becomes native by changing which of the two files it points at.
	//
	// Cost is not symmetric with CIDRSource and that decides what belongs here: a CIDR feed lands in
	// a kernel hash set where 27k prefixes are a couple of megabytes, while every domain costs a
	// dnsmasq directive. Curated lists (~10^3) belong here; a full registry dump (~10^6 domains,
	// measured at 28.8 MB) does not — its coverage belongs on the CIDR side.
	DomainSource string `json:"domain_source,omitempty"`
	// DomainCache is the last-good fetch of DomainSource (system-managed, same contract as
	// CIDRCache): persisted so a failed fetch or a restart keeps the carve-out, and unioned into the
	// zone alongside Manual entries. Not user-edited.
	DomainCache []string `json:"domain_cache,omitempty"`
	// DomainRefreshed is when DomainCache was last successfully written (unix seconds), so the
	// refresh schedule survives a restart exactly as CIDRRefreshed does.
	DomainRefreshed int64 `json:"domain_refreshed,omitempty"`
	// Scope narrows this list to specific devices instead of ALL clients. ScopeMode "" or "all" =
	// everyone (byte-identical to today for existing profiles); "only" = ONLY devices in the referenced
	// DeviceGroups; "except" = everyone EXCEPT them (kernel nft negation — a fast-follow). ScopeGroups
	// holds DeviceGroup IDs. Resolves to the pbr source-scoped-zone Src* fields at compile time; a
	// SourceMAC member is same-L2 only. An empty/unset scope keeps today's all-clients behaviour.
	ScopeMode   string   `json:"scope_mode,omitempty"`
	ScopeGroups []string `json:"scope_groups,omitempty"`
	// TLSFragment splits the TLS ClientHello of this list's DIRECT connections so a DPI box matching
	// the server name in one packet misses it: "record" (several TLS records; sing-box's advice is to
	// try this first) or "handshake" (several TCP segments, slower). sing-box 1.12+ route options
	// tls_record_fragment / tls_fragment. Only a list whose outbound is direct uses it, and only for
	// flows the core carries.
	TLSFragment string `json:"tls_fragment,omitempty"`
}

// TLSFragment modes for RoutingList.TLSFragment.
const (
	TLSFragmentRecord    = "record"
	TLSFragmentHandshake = "handshake"
)

// DeviceMember identifies one LAN device by MAC and/or IP; at least one must be set. MAC is the stable,
// IP-independent matcher (nft `ether saddr`; same-L2 clients only), IP/CIDR is broader and survives
// behind a repeater. Both set ⇒ that device on that address.
type DeviceMember struct {
	MAC string `json:"mac,omitempty"` // e.g. aa:bb:cc:dd:ee:ff
	IP  string `json:"ip,omitempty"`  // IPv4/IPv6 address or CIDR
}

// DeviceGroup is a named set of LAN devices (e.g. "Kids", "IoT"). A RoutingList references groups via
// ScopeGroups to apply or block that list only for those devices. Persisted in the Profile; a group
// with no members matches nothing.
type DeviceGroup struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	Members []DeviceMember `json:"members,omitempty"`
}

// Profile is the whole user configuration.
type Profile struct {
	Endpoints    []Endpoint    `json:"endpoints"`
	Groups       []Group       `json:"groups"`
	Rules        []Rule        `json:"rules"`
	RoutingLists []RoutingList `json:"routing_lists,omitempty"`
	// DeviceGroups: named sets of LAN devices (MAC/IP) a RoutingList can scope to (apply/block a list
	// for only those devices). omitempty ⇒ nil ⇒ byte-identical for existing profiles.
	DeviceGroups []DeviceGroup `json:"device_groups,omitempty"`
	// DNS is the optional DNS plane (the "DNS" panel section). POINTER + omitempty is the
	// backward-compat lever: nil ⇒ marshals to nothing ⇒ existing profiles byte-identical ⇒ the
	// generator emits no dns block (today's behaviour). See dns.go.
	DNS *DNSSettings `json:"dns,omitempty"`
}

// Builtin outbound tags that are always available.
const (
	OutboundDirect = "direct"
	OutboundBlock  = "block"
)

// EndpointByID returns the endpoint with the given id, or nil.
func (p *Profile) EndpointByID(id string) *Endpoint {
	for i := range p.Endpoints {
		if p.Endpoints[i].ID == id {
			return &p.Endpoints[i]
		}
	}
	return nil
}

// GroupByID returns the group with the given id, or nil.
func (p *Profile) GroupByID(id string) *Group {
	for i := range p.Groups {
		if p.Groups[i].ID == id {
			return &p.Groups[i]
		}
	}
	return nil
}

// RoutingListByID returns the routing list with the given id, or nil.
func (p *Profile) RoutingListByID(id string) *RoutingList {
	for i := range p.RoutingLists {
		if p.RoutingLists[i].ID == id {
			return &p.RoutingLists[i]
		}
	}
	return nil
}
