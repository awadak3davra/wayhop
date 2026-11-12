// Package dnscheck answers three questions about a router's DNS by measuring instead of reading
// configuration: which path lookups really leave by, who can read them, and whether the resolver that
// answers is the one it claims to be. The panel renders a Report; it never decides a verdict itself.
//
// Report is the contract between the engine, the server job and the page. Text a person reads is the
// page's job: the engine sends stable codes and raw facts, so every sentence stays translatable.
package dnscheck

import "time"

// Status is the outcome of one probe. NoData is "asked, and nothing can be concluded": a timeout, or a
// connection the line refused. It never counts against a resolver, because a blocked connection and a
// silent filter say nothing about who answered.
type Status string

const (
	StatusPass    Status = "pass"
	StatusWarn    Status = "warn"
	StatusFail    Status = "fail"
	StatusNoData  Status = "no_data"
	StatusSkipped Status = "skipped"
)

// PathKind is where a probe's socket leaves from. PathRouter asks the router's own :53, which is what a
// LAN client sees.
type PathKind string

const (
	PathWAN    PathKind = "wan"
	PathTunnel PathKind = "tunnel"
	PathRouter PathKind = "router"
)

// Path is one way out of the router.
type Path struct {
	Iface string   `json:"iface,omitempty"`
	Kind  PathKind `json:"kind"`
	Label string   `json:"label,omitempty"` // the endpoint's name in the profile
}

// Verdict is what the probes say about one resolver on one path.
type Verdict string

const (
	VerdictGenuine         Verdict = "genuine"          // every identity and validation probe passed
	VerdictPartial         Verdict = "partial"          // nothing wrong, but a probe got no answer
	VerdictForged          Verdict = "forged"           // something other than the named resolver answered
	VerdictUnreachable     Verdict = "unreachable"      // the base query got no reply
	VerdictUnknownOperator Verdict = "unknown_operator" // a resolver with no known fingerprint, nothing wrong seen
)

// Probe ids.
const (
	ProbeBase         = "base"          // an ordinary A lookup
	ProbeIdentity     = "identity"      // the operator's own fingerprint
	ProbeBogus        = "dnssec_bogus"  // dnssec-failed.org must SERVFAIL on a validator
	ProbeSigned       = "dnssec_signed" // cloudflare.com with DO must carry AD and an RRSIG
	ProbeNXDomain     = "nxdomain"      // a random name must be NXDOMAIN
	ProbeSecondReply  = "second_reply"  // a second, different answer to one query is injection
	ProbeSource       = "source"        // the reply must come from the address that was asked
	ProbeCanary       = "canary"        // a popular name's answer must hold a real certificate
	ProbeInterception = "decoy"         // nothing serves DNS at the decoy, so a reply is interception
)

// Reason codes the page translates. The list is closed: a new code needs a sentence in the page.
const (
	CodeOK               = "ok"
	CodeNoReply          = "no_reply"
	CodeDecoyAnswered    = "decoy_answered"
	CodePathIntercepted  = "path_intercepted"
	CodeBogusAccepted    = "bogus_accepted"
	CodeADMissing        = "ad_missing"
	CodeIdentityMismatch = "identity_mismatch"
	CodeIdentitySilent   = "identity_silent"
	CodeNXRewritten      = "nx_rewritten"
	CodeNXUnclear        = "nx_unclear"
	CodeSecondReply      = "second_reply"
	CodeForeignSource    = "foreign_source"
	CodeCanaryBogon      = "canary_bogon"
	CodeCanaryBadCert    = "canary_bad_cert"
	CodeCanaryUnverified = "canary_unverified"
	CodeCanaryOnWANOff   = "canary_wan_off"
	CodeNotValidating    = "not_validating"
)

// Probe is one measured question. Detail holds raw facts (an address, a site code), never a sentence.
type Probe struct {
	ID     string `json:"id"`
	Status Status `json:"status"`
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
	Ms     int    `json:"ms,omitempty"`
}

// ResolverResult is one resolver as seen from one path.
type ResolverResult struct {
	Address  string  `json:"address"`
	Operator string  `json:"operator,omitempty"` // cloudflare | google | quad9 | "" when unknown
	Path     Path    `json:"path"`
	Verdict  Verdict `json:"verdict"`
	RttMs    int     `json:"rtt_ms,omitempty"`
	Site     string  `json:"site,omitempty"`   // the site that answered, when the operator tells
	Egress   string  `json:"egress,omitempty"` // the address the resolver's own queries leave from
	Probes   []Probe `json:"probes"`
}

// Interception is the decoy probe for one path: a reply from an address where nothing serves DNS means
// something on this path answers port 53 itself, whatever address was asked.
type Interception struct {
	Path        Path   `json:"path"`
	Status      Status `json:"status"`
	Code        string `json:"code"`
	Intercepted bool   `json:"intercepted"`
	Detail      string `json:"detail,omitempty"`
}

// EncryptedResult says whether an encrypted transport works on a path, and so which upgrades are real.
type EncryptedResult struct {
	Address  string `json:"address"`
	Operator string `json:"operator,omitempty"`
	Path     Path   `json:"path"`
	Proto    string `json:"proto"` // dot | doh
	Status   Status `json:"status"`
	CertName string `json:"cert_name,omitempty"`
	RttMs    int    `json:"rtt_ms,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// Upstream is one row of the chain the answering program forwards to, as configured.
type Upstream struct {
	Address    string `json:"address"`
	Port       int    `json:"port,omitempty"`
	Iface      string `json:"iface,omitempty"`
	Kind       string `json:"kind"` // plain | doh | dot | local
	ViaTunnel  bool   `json:"via_tunnel,omitempty"`
	LastResort bool   `json:"last_resort,omitempty"` // a plaintext row on the ordinary path, behind tunnel rows
	Label      string `json:"label,omitempty"`
	// LeavesBy is the interface a local DoH or DoT proxy reaches its resolver through, from the routing
	// table. Its own row is on loopback, so nothing else says which way the lookups really leave.
	LeavesBy string `json:"leaves_by,omitempty"`
}

// Flow counts lookups the router itself sent during the sample, read from the connection table.
type Flow struct {
	Iface      string   `json:"iface,omitempty"`
	Kind       PathKind `json:"kind"`
	Server     string   `json:"server"`
	Port       int      `json:"port"`
	Proto      string   `json:"proto"`
	Flows      int      `json:"flows"`
	Replied    int      `json:"replied"`
	FromCanary bool     `json:"from_canary,omitempty"` // this flow appeared for the unique test name
}

// Exposure is who can read lookup names on the measured path.
type Exposure string

const (
	ExposureProvider Exposure = "provider" // plaintext on the provider's line
	ExposureExit     Exposure = "exit"     // plaintext inside a tunnel: the exit and the resolver can read them
	ExposureResolver Exposure = "resolver" // encrypted: only the resolver can
	ExposureUnknown  Exposure = "unknown"
)

// PathReport is the "which way does DNS go" half.
type PathReport struct {
	Answering string `json:"answering,omitempty"` // the program on :53, as nativedns measured it
	Measured  bool   `json:"measured"`
	// FirstRowAnswered: a local or encrypted first row, asked directly, gave a real answer. dnsmasq asks in
	// order, so that row takes the lookups, and a flow to a later row's address is someone else's.
	FirstRowAnswered bool       `json:"first_row_answered,omitempty"`
	Upstreams        []Upstream `json:"upstreams,omitempty"`
	Flows            []Flow     `json:"flows,omitempty"`
	SampleSec        int        `json:"sample_sec,omitempty"`
	Exposure         Exposure   `json:"exposure"`
	OwnResolvConf    []string   `json:"own_resolv_conf,omitempty"` // the router's own lookups, which do not use the chain
}

// Level is the rung of the ladder the router stands on.
type Level string

const (
	LevelUnknown           Level = "unknown"
	LevelProviderPlain     Level = "provider_plain"     // 0: the provider reads every name
	LevelTunnelPlain       Level = "tunnel_plain"       // 1: hidden from the provider, plaintext inside the tunnel
	LevelProviderEncrypted Level = "provider_encrypted" // 2: encrypted, but the provider sees which resolver
	LevelTunnelEncrypted   Level = "tunnel_encrypted"   // 3: encrypted inside the tunnel
)

// Severity orders warnings.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityWarn     Severity = "warn"
	SeverityInfo     Severity = "info"
)

// Warning ids.
const (
	WarnPlainOnProvider  = "plain_on_provider"  // lookups leave in plaintext on the provider's line
	WarnPlainLastResort  = "plain_last_resort"  // a plaintext row behind the tunnels: SERVFAIL reaches it too
	WarnResolverForged   = "resolver_forged"    // a resolver in the chain failed authentication
	WarnPathIntercepted  = "path_intercepted"   // something on a path answers port 53 itself
	WarnClientsBypass    = "clients_bypass"     // clients can reach another resolver past the router
	WarnEncryptedEscape  = "encrypted_escape"   // clients can use their own DoH or DoT
	WarnIPv6Gap          = "ipv6_gap"           // an IPv6 route around the rules
	WarnSinglePath       = "single_path"        // one tunnel row and nothing behind it
	WarnProfileNotServed = "profile_not_served" // the page's encrypted resolvers do not answer clients
	WarnEncryptedDirect  = "encrypted_direct"   // an encrypted resolver leaves on the provider's line
	WarnNotMeasured      = "not_measured"       // no router DNS stack to read here
	WarnOwnLookupsPlain  = "own_lookups_plain"  // the router's own lookups are plaintext, which is deliberate
)

// Option ids: what the page offers, cheapest first.
const (
	OptChainIntoTunnels  = "chain_into_tunnels"
	OptRemoveLastResort  = "remove_last_resort"
	OptReplaceResolver   = "replace_resolver"
	OptInterceptOn       = "intercept_on"
	OptBlockEncrypted    = "block_encrypted_escape"
	OptFixIPv6           = "fix_ipv6"
	OptAddSecondTunnel   = "add_second_tunnel"
	OptEncryptedUpstream = "encrypted_upstream"
	OptEncryptedInTunnel = "encrypted_in_tunnel"
)

// Action is what an option's button does. It only ever opens a control, already filled in: every write
// still goes through that control's own review, so nothing changes without the person seeing it.
type Action struct {
	Kind   string      `json:"kind"`             // chain | section | none
	Target string      `json:"target,omitempty"` // the section to scroll to
	Rows   []ChainHint `json:"rows,omitempty"`   // the chain to open the editor with
}

// ChainHint is one proposed chain row.
type ChainHint struct {
	Address string `json:"address"`
	Port    int    `json:"port,omitempty"`
	Via     string `json:"via,omitempty"` // an outbound id, as the chain editor takes it
	Iface   string `json:"iface,omitempty"`
}

// Warning is one problem found. Facts are raw values for the page's sentence.
type Warning struct {
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	Facts    []string `json:"facts,omitempty"`
}

// Option is one thing the person can do about it.
type Option struct {
	ID          string   `json:"id"`
	Recommended bool     `json:"recommended,omitempty"`
	Gives       Level    `json:"gives,omitempty"` // the rung it reaches, when it changes the rung
	Facts       []string `json:"facts,omitempty"`
	Action      Action   `json:"action"`
}

// Report is one finished check.
type Report struct {
	Version      int               `json:"version"`
	Demo         bool              `json:"demo,omitempty"`
	Scenario     string            `json:"scenario,omitempty"`
	StartedAt    time.Time         `json:"started_at"`
	FinishedAt   time.Time         `json:"finished_at"`
	FullAt       *time.Time        `json:"full_at,omitempty"`
	Full         bool              `json:"full"` // false: the path half only, no outbound probes
	Level        Level             `json:"level"`
	Path         PathReport        `json:"path"`
	Interception []Interception    `json:"interception,omitempty"`
	Resolvers    []ResolverResult  `json:"resolvers,omitempty"`
	Encrypted    []EncryptedResult `json:"encrypted,omitempty"`
	Warnings     []Warning         `json:"warnings,omitempty"`
	Options      []Option          `json:"options,omitempty"`
}

// Request starts a check. Full adds the outbound probes. CanariesOnWAN is opt-in because it sends
// lookups for popular blocked names in plaintext past the provider, which is what a careful household
// is trying to stop doing.
type Request struct {
	Full          bool     `json:"full"`
	CanariesOnWAN bool     `json:"canaries_on_wan,omitempty"`
	ExtraNames    []string `json:"extra_names,omitempty"`
}

// Progress is the running job's state, for the page's progress line.
type Progress struct {
	Done  int    `json:"done"`
	Total int    `json:"total"`
	Stage string `json:"stage,omitempty"` // path | decoys | resolvers | encrypted
}

// State is what GET /api/dns/check answers.
type State struct {
	Running   bool     `json:"running"`
	Progress  Progress `json:"progress"`
	Report    *Report  `json:"report,omitempty"`
	Scenarios []string `json:"scenarios,omitempty"` // demo only: the canned reports the page can show
}
