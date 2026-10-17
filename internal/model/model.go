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
	EngineOlcRTC    Engine = "olcrtc"
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
	ProtoOlcRTC      Protocol = "olcrtc"
	ProtoSOCKS       Protocol = "socks"
	ProtoHTTP        Protocol = "http"
)

// TLS holds transport security settings (plain TLS, Reality, uTLS fingerprint).
type TLS struct {
	Enabled     bool     `json:"enabled,omitempty"`
	Type        string   `json:"type,omitempty"` // "tls" | "reality"
	SNI         string   `json:"sni,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Insecure    bool     `json:"insecure,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"` // uTLS, e.g. "chrome"
	// Reality
	PublicKey string `json:"public_key,omitempty"`
	ShortID   string `json:"short_id,omitempty"`
	// TLS handshake fragmentation (anti-DPI, sing-box 1.12+, client-only): split the ClientHello so a
	// plaintext SNI-matching firewall can't fingerprint it. Opt-in — a zero value is omitted, so this
	// is byte-identical for existing profiles. Not applied to Reality (it has its own evasion, and a
	// fragmented ClientHello would disturb its fingerprint mimicry).
	Fragment       bool `json:"fragment,omitempty"`
	RecordFragment bool `json:"record_fragment,omitempty"` // fragment into TLS records (sing-box: "performs better")
}

// Transport is the stream transport when not raw TCP (ws/grpc/http/httpupgrade).
type Transport struct {
	Type        string            `json:"type,omitempty"` // "" (tcp) | ws | grpc | http | httpupgrade
	Path        string            `json:"path,omitempty"`
	Host        string            `json:"host,omitempty"`
	ServiceName string            `json:"service_name,omitempty"` // grpc
	Headers     map[string]string `json:"headers,omitempty"`
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
//	hysteria2:   password, obfs, obfs_password, up_mbps, down_mbps
//	tuic:        uuid, password, congestion_control, udp_relay_mode
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
	Health    *Health        `json:"health,omitempty"`
	Enabled   bool           `json:"enabled"`
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
	DownloadVia  string   `json:"download_via,omitempty"`  // outbound used to FETCH the URL (sing-box download_detour); "" = direct
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
}

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
