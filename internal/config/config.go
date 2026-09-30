// Package config loads and persists the wayhop daemon configuration.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"wayhop/internal/atomicfile"
)

// Ports is the reserved port block wayhop owns. Each is user-editable so the
// daemon can dodge conflicts with the router OS and other services
// (see docs/CONFLICTS.md #1 in the development repository).
type Ports struct {
	UI    int `json:"ui"`    // web panel
	Clash int `json:"clash"` // sing-box Clash API (external_controller)
	DNS   int `json:"dns"`   // local DNS
	Mixed int `json:"mixed"` // local mixed (socks+http) inbound
}

// Clash describes how to reach sing-box's Clash API.
type Clash struct {
	Controller string `json:"controller"` // host:port, e.g. 127.0.0.1:9090
	Secret     string `json:"secret"`     // bearer secret, may be empty
}

// SingBox locates the sing-box binary and its generated config.
type SingBox struct {
	Bin    string `json:"bin"`    // path to the sing-box executable
	Config string `json:"config"` // path to the generated config.json
}

// Updater configures engine-binary version management (see internal/updater).
type Updater struct {
	Arch    string   `json:"arch"`    // override; empty = autodetect from the running binary
	Mirrors []string `json:"mirrors"` // GitHub URL prefixes tried in order; "" = direct
	// SelfRepo is the GitHub "owner/name" WayHop updates ITSELF from (its own
	// CI release builds). Empty → the built-in default (updater.DefaultSelfRepo).
	SelfRepo string `json:"self_repo,omitempty"`
	// AutoUpdate, when true, lets WayHop auto-install a newer release of ITSELF
	// (checked daily in the background) and restart. Default off — opt-in.
	AutoUpdate bool `json:"auto_update,omitempty"`
	// DownloadVia is the outbound a component download leaves through: an endpoint or group id, or
	// empty for the router's ordinary path (the provider).
	//
	// It exists because the ordinary path is exactly what may be unusable. On a live network
	// GitHub is reachable today and may not be tomorrow, and a router that cannot reach a release
	// cannot install the very engine that would carry it around the block — the failure feeds itself.
	// Routing lists already carry this idea per list (RoutingList.DownloadVia); this is the same
	// question for the one download the router makes about itself.
	//
	// Enforced by binding the download socket to that outbound's interface, so it holds for the
	// release metadata and the asset bytes alike, without touching the routing plane.
	DownloadVia string `json:"download_via,omitempty"`
}

// FailSafe configures Apply rollback behaviour (see internal/failsafe).
type FailSafe struct {
	Target     string `json:"target"`      // connectivity-check host (default 1.1.1.1)
	AutoReboot bool   `json:"auto_reboot"` // allow auto-reboot as the last resort (opt-in)
}

// Watchdog configures crash-restart supervision (see internal/watchdog).
type Watchdog struct {
	// NotifyURL, when set, receives a POST {"text":"…"} on each crash-restart
	// (e.g. a Telegram bot webhook). Empty = alerts off (the default).
	NotifyURL string `json:"notify_url"`
}

// Auth stores only the operator identity and a versioned password KDF record. Session and CSRF
// tokens are process-local and never persisted. Empty fields mean first-run setup is required.
type Auth struct {
	Username     string `json:"username,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`
	// Disabled records that the operator was asked for a password and deliberately declined. It is a
	// THIRD state, distinct from the empty struct: empty means "nobody has answered the question yet"
	// and the panel blocks on first-run setup, while Disabled means "answered, and the answer was no".
	//
	// Persisted on purpose. The alternative — treating a missing password as "open" — would make an
	// interrupted first run indistinguishable from a decision, and a panel that holds every tunnel's
	// private key would then open itself because somebody closed the tab. This way the open state is
	// something a human chose, survives restarts, and can be read back and shown.
	Disabled bool `json:"disabled,omitempty"`
}

// Subscription configures import and optional refresh of an upstream subscription.
type Subscription struct {
	// URL is the last imported subscription URL, kept so an opt-in periodic
	// refresh can re-fetch it and ADD any newly-rotated endpoints. Empty when
	// the user only ever pasted text (nothing to refresh).
	URL string `json:"url,omitempty"`
	// RefreshHours controls auto-refresh of URL: 0 = OFF (opt-in default); >0 =
	// re-fetch every N hours and add new endpoints (never deletes).
	RefreshHours int `json:"refresh_hours,omitempty"`
}

// Backup configures the scheduled LOCAL auto-backup — a safety net so the whole setup
// (profile + saved servers + routing knobs) is recoverable before a firmware reflash or a
// bad change. Opt-in: AutoHours<=0 disables it (the default). Never touches routing; only
// writes files under Dir. Same bundle format as GET /api/backup, restorable via the panel.
type Backup struct {
	AutoHours int    `json:"auto_hours,omitempty"` // write a backup every N hours; 0 = OFF (default)
	KeepN     int    `json:"keep_n,omitempty"`     // retain the newest N backups; <=0 → 14
	Dir       string `json:"dir,omitempty"`        // backup directory; "" → <DataDir>/backups
}

// Telegram configures the built-in Telegram bot (see internal/tgbot). It is written only by its own
// panel endpoints and by the bot itself (pairing adds a chat), never by the bulk Settings PUT, so a
// Settings save cannot drop a paired chat or blank the token.
type Telegram struct {
	Enabled bool `json:"enabled,omitempty"`
	// Token is the @BotFather token: a bearer credential for the whole bot. Never returned by the
	// API, masked in exports, scrubbed from errors.
	Token string `json:"token,omitempty"`
	// APIBase replaces https://api.telegram.org, e.g. a self-hosted telegram-bot-api server or a
	// reverse proxy where Telegram is blocked. Empty = the public Bot API.
	APIBase string `json:"api_base,omitempty"`
	// Via is the outbound the bot's API traffic leaves through: an endpoint or group id, or empty
	// for the router's ordinary path. Same socket-binding mechanism as Updater.DownloadVia.
	Via string `json:"via,omitempty"`
	// Chats are the paired chats. Nothing else can talk to the bot.
	Chats []TelegramChat `json:"chats,omitempty"`
	// AlertsOff lists alert kinds switched off (see tgbot.AlertKinds). Empty = every alert on.
	AlertsOff []string `json:"alerts_off,omitempty"`
	// QuietFrom/QuietTo ("23:00", "07:30", router local time) hold non-critical alerts, which are
	// delivered as one summary when the window ends. Both empty = no quiet hours.
	QuietFrom string `json:"quiet_from,omitempty"`
	QuietTo   string `json:"quiet_to,omitempty"`
	// Digest is the local time ("08:30") of the daily summary; empty = no digest.
	Digest string `json:"digest,omitempty"`
	// StaleMenus lists chats that stopped being an owner or a viewer (unpaired, or made alerts-only)
	// and may still show the command menu the bot gave them. The bot takes each menu back and drops
	// the chat from the list, whether the change was made while it ran or while it was off.
	StaleMenus []int64 `json:"stale_menus,omitempty"`
}

// TelegramChat is one paired chat.
type TelegramChat struct {
	ID   int64  `json:"id"`
	Name string `json:"name,omitempty"`
	// Role: "owner" (everything, confirms changes), "viewer" (read-only + alerts), "alerts" (a
	// group or channel that only receives alerts).
	Role string `json:"role"`
	// Lang overrides the language picked from the Telegram client ("en", "ru", "uk"); empty = auto.
	Lang     string `json:"lang,omitempty"`
	PairedAt int64  `json:"paired_at,omitempty"` // unix seconds
	// AlertsOff lists the alert kinds this chat switched off for itself, from the bot's /alerts. A
	// kind in Telegram.AlertsOff (the panel's switches) is off for every chat regardless.
	AlertsOff []string `json:"alerts_off,omitempty"`
}

// Telegram chat roles.
const (
	TelegramOwner  = "owner"
	TelegramViewer = "viewer"
	TelegramAlerts = "alerts"
)

var validClock = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// Validate checks the Telegram block. An empty block is valid (the bot is off).
func (t Telegram) Validate() error {
	if t.Enabled && strings.TrimSpace(t.Token) == "" {
		return errors.New("telegram: a bot token is required to enable the bot")
	}
	if t.Token != "" && t.Token != RedactedMark && !validBotToken(t.Token) {
		return errors.New("telegram: the token should look like 123456789:AA... (copy it from @BotFather)")
	}
	if t.APIBase != "" && !isHTTPURL(t.APIBase) {
		return fmt.Errorf("telegram: api_base %q must start with http:// or https://", t.APIBase)
	}
	if (t.QuietFrom == "") != (t.QuietTo == "") {
		return errors.New("telegram: quiet hours need both a start and an end")
	}
	for _, v := range []string{t.QuietFrom, t.QuietTo, t.Digest} {
		if v != "" && !validClock.MatchString(v) {
			return fmt.Errorf("telegram: %q is not a time of day (HH:MM)", v)
		}
	}
	seen := map[int64]bool{}
	for _, c := range t.Chats {
		if c.ID == 0 {
			return errors.New("telegram: a paired chat has no id")
		}
		if seen[c.ID] {
			return fmt.Errorf("telegram: chat %d is paired twice", c.ID)
		}
		seen[c.ID] = true
		switch c.Role {
		case TelegramOwner, TelegramViewer, TelegramAlerts:
		default:
			return fmt.Errorf("telegram: chat %d has an unknown role %q", c.ID, c.Role)
		}
	}
	return nil
}

// botTokenShape is the shape @BotFather issues: a numeric bot id, a colon, and a secret of URL-safe
// characters. The token goes into a URL path, so anything else is refused outright.
var botTokenShape = regexp.MustCompile(`^[0-9]{3,20}:[A-Za-z0-9_-]{20,100}$`)

func validBotToken(s string) bool { return botTokenShape.MatchString(s) }

// FeatureConfig is the per-plugin state in Config.Features: whether the optional module is
// installed (Enabled) + an opaque per-module Settings blob the module owns (so the config package
// stays decoupled from each module's schema). Enabled is toggled via PUT /api/features/{id}.
type FeatureConfig struct {
	Enabled  bool            `json:"enabled"`
	Settings json.RawMessage `json:"settings,omitempty"`
}

// Config is the full daemon configuration, persisted as JSON.
type Config struct {
	Listen      string `json:"listen"`                    // UI bind address, e.g. :8088
	DataDir     string `json:"data_dir"`                  // runtime state directory
	Demo        bool   `json:"demo"`                      // synthesize traffic when sing-box is absent
	Gateway     bool   `json:"gateway"`                   // TUN gateway mode: capture LAN traffic via a tun inbound + auto_route (vs the default mixed-proxy-only parallel mode)
	GatewayMTU  int    `json:"gateway_mtu,omitempty"`     // TUN device MTU when gateway=true (0 → 1500). Lower it (e.g. 1280) if large packets stall over a tunnel exit.
	GatewayAddr string `json:"gateway_address,omitempty"` // TUN host address/CIDR when gateway=true ("" → 172.31.3.1/30); not the LAN subnet (auto_route excludes it).
	// RoutingMode selects the routing architecture (see docs/ARCHITECTURE_NATIVE_FIRST.md (development repository)):
	//   "" (default) → derive from Gateway (back-compat); "tun" → all traffic via the sing-box TUN;
	//   "hybrid" → capture-all TUN + kernel PBR for IP/CIDR carve-outs (general traffic still
	//   transits the userspace TUN — domain carve-outs work but throughput is CPU-bound);
	//   "fast" → like hybrid BUT with NO capture-all TUN: general traffic stays on the kernel
	//   fast-path (no userspace tax → near-line-rate), only IP/CIDR carve-outs are kernel-PBR'd
	//   (TG-calls/VoWiFi etc.); domain carve-outs are INACTIVE for LAN traffic in this mode
	//   (no TUN to sniff them) — a Phase-2 DNS→nftset bridge would restore them. flow_offloading
	//   is left as-is in Phase 1 (Phase 1b enables HW offload with carve-out-mark exclusion);
	//   "mixed" → no TUN, sing-box mixed-proxy only (no kernel PBR).
	RoutingMode string `json:"routing_mode,omitempty"`
	// Offload enables Phase-1b kernel flow-offload for GENERAL traffic in "fast" mode (a
	// no-op in other modes): "" / "off" (default) → none; "sw" → software flowtable; "hw"
	// → also hardware PPE (`flags offload`). Carve-out flows (TG-calls/VoWiFi/RU — any
	// owned fwmark) are EXCLUDED so their per-packet PBR, and the UDP calls it carries,
	// keep working (see docs/ARCHITECTURE_NATIVE_FIRST.md (development repository) "Phase 1a/1b"). Deploy-gated —
	// validate TG/VoWiFi survive before relying on it.
	Offload string `json:"offload,omitempty"`
	// IgnoredDrift holds endpoint IDs the user has explicitly dismissed as "not a problem" — the
	// spec's "ignore this unmanaged object" drift action. A tunnel deliberately removed from the
	// router would otherwise be reported as missing on every refresh, forever, and a warning that
	// cannot be dismissed is one people learn to ignore wholesale.
	//
	// Stores IDs, never a suppress-everything flag: dismissing one stale tunnel must not blind the
	// user to the next one that disappears unexpectedly. omitempty, so a config that never used it
	// stays byte-identical.
	IgnoredDrift []string `json:"ignored_drift,omitempty"`
	// RuleSetDetour is the DEFAULT outbound remote routing-list rule-sets are DOWNLOADED through
	// (a per-list DownloadVia still wins). "" keeps the historical `direct` behaviour.
	//
	// Set this to a working tunnel/proxy tag on a CENSORED network: the rule-set sources (GitHub and
	// friends) are blocked on the raw WAN there, so a direct download either times out or returns a
	// block page that sing-box rejects as an "invalid rule-set file" — and because ANY failing
	// rule-set aborts the whole core at startup, that silently prevents sing-box from EVER running.
	// Not circular: the chosen outbound works independently of any rule-set.
	RuleSetDetour string `json:"rule_set_detour,omitempty"`
	// NativeFirewallZone is the exact OpenWrt firewall zone used for WayHop-created native
	// interfaces. Empty means native create/manage is unavailable; WayHop never guesses a zone.
	NativeFirewallZone string `json:"native_firewall_zone,omitempty"`
	// OffloadDevices are the netdevs flow-offload attaches to (the WAN uplink + LAN bridge,
	// e.g. ["wan","br-lan"]); awg* tunnels are intentionally absent (carve-out traffic must
	// not be offloaded). Empty → offload is skipped (a future auto-probe will fill these
	// from the default route + br-lan).
	OffloadDevices []string     `json:"offload_devices,omitempty"`
	Ports          Ports        `json:"ports"`
	Clash          Clash        `json:"clash"`
	SingBox        SingBox      `json:"singbox"`
	Updater        Updater      `json:"updater"`
	FailSafe       FailSafe     `json:"failsafe"`
	Watchdog       Watchdog     `json:"watchdog"`
	Auth           Auth         `json:"auth,omitempty"`
	Subscription   Subscription `json:"subscription"`
	Backup         Backup       `json:"backup,omitempty"`
	// Telegram is the built-in bot. HOT and written only by /api/telegram/* and by pairing, so —
	// like Subscription — it is NOT copied by applyConfigFields.
	Telegram Telegram `json:"telegram,omitempty"`
	// AllowedHosts lists EXTRA Host header values the panel will serve, on top of the ones this
	// router answers to by itself (its interface IPs, loopback, its OS hostname) — a DNS-rebinding
	// defense; see docs/SECURITY.md (development repository). Additive, so a wrong entry cannot lock the UI out: the LAN IP
	// keeps working. Set it for a custom name or a reverse proxy, e.g. ["wayhop.home"].
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
	// AllowAnyHost disables the Host allow-list entirely. It re-opens DNS rebinding — any web page
	// can then rebind a name to the router and drive this unauthenticated API — so it exists only as
	// an explicit, recoverable escape hatch for a deployment the allow-list cannot express yet.
	// Never a default.
	AllowAnyHost bool `json:"allow_any_host,omitempty"`
	// Features holds per-plugin (optional-module) state: whether each module is installed (enabled)
	// + an opaque per-module settings blob it owns. Toggled via PUT /api/features/{id} — a HOT field
	// (no restart) — so, like Subscription, it is NOT copied by applyConfigFields.
	Features map[string]FeatureConfig `json:"features,omitempty"`

	path string // source file, used by Save()
}

// Default returns a Config with router-friendly defaults.
func Default() *Config {
	return &Config{
		Listen:   ":8088",
		DataDir:  "/opt/var/wayhop",
		Demo:     false,
		Ports:    Ports{UI: 8088, Clash: 9090, DNS: 5353, Mixed: 7890},
		Clash:    Clash{Controller: "127.0.0.1:9090", Secret: ""},
		SingBox:  SingBox{Bin: "/opt/sbin/sing-box", Config: "/opt/etc/wayhop/singbox.json"},
		Updater:  Updater{Arch: "", Mirrors: []string{"", "https://ghproxy.net/", "https://mirror.ghproxy.com/"}},
		FailSafe: FailSafe{Target: "1.1.1.1", AutoReboot: false},
	}
}

// Load reads config from path, creating it with defaults if it does not exist.
func Load(path string) (*Config, error) {
	c := Default()
	c.path = path

	data, err := os.ReadFile(path)
	// Treat a missing OR empty/whitespace-only file identically: create defaults and
	// rewrite a valid file. An existing zero-length / whitespace-only file is the
	// canonical power-loss / jffs2 / overlayfs artifact on a router; it reads as
	// (nil, nil), would otherwise reach json.Unmarshal([]byte{}) → "unexpected end
	// of JSON input" → the daemon refuses to boot (panel brick — see atomicfile.go).
	// A genuinely-corrupt NON-empty file still falls through to the parse error below.
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(bytes.TrimSpace(data)) == 0) {
		if err == nil {
			log.Printf("wayhop: config %s is empty; recreating with defaults", path)
		}
		if err := c.Save(); err != nil {
			return nil, fmt.Errorf("write default config: %w", err)
		}
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	c.path = path
	// Warn (don't fail) on a config that looks unstartable: a tolerated-but-odd
	// file must never brick boot, but surfacing the problem in the log lets the
	// operator fix it in Settings instead of debugging a silent failure later.
	if verr := c.Validate(); verr != nil {
		log.Printf("wayhop: config %s has problems (using it anyway; fix in Settings): %v", path, verr)
	}
	return c, nil
}

// Save writes the config atomically + durably (temp file, fsync, rename), mode 0600.
func (c *Config) Save() error {
	if c.path == "" {
		return errors.New("config has no path")
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return atomicfile.Write(c.path, data, 0o600)
}

// validRoutingModes / validOffloads are the accepted enum values (see the
// RoutingMode / Offload field docs). Empty means "unset/default" and is allowed.
var (
	validRoutingModes = map[string]bool{"": true, "tun": true, "hybrid": true, "fast": true, "mixed": true}
	validOffloads     = map[string]bool{"": true, "off": true, "sw": true, "hw": true, "auto": true}
	// validIfaceName matches a real Linux netdev name: leading alnum then alnum/dot/underscore/
	// hyphen, 1-15 chars (IFNAMSIZ-1). OffloadDevices are rendered UNQUOTED into the root nft
	// ruleset (`devices = { … }` fed to `nft -f -`), so a name carrying nft/shell metacharacters
	// must be rejected here — not only defended at the render sink. See internal/pbr.
	validIfaceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$`)
	validZoneName  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`)
)

// Validate checks the config for self-consistency and obviously-unstartable
// values. It is PERMISSIVE on empty optional fields (empty == unset/default), so
// a minimal config is always valid. Two callers: Load() logs the result as a
// warning (a tolerated file must never brick boot) and the Settings PUT/import
// handlers fail closed (the UI must not persist a config that would not start).
func (c *Config) Validate() error {
	if c.Listen == "" {
		return errors.New("listen address is required")
	}
	if err := c.Ports.Validate(); err != nil {
		return err
	}
	if !validHostPort(c.Listen) {
		return fmt.Errorf("listen %q must be host:port (e.g. \":8088\")", c.Listen)
	}
	if c.Clash.Controller != "" && !validHostPort(c.Clash.Controller) {
		return fmt.Errorf("clash controller %q must be host:port", c.Clash.Controller)
	}
	if !validRoutingModes[c.RoutingMode] {
		return fmt.Errorf("routing_mode %q must be one of tun, hybrid, fast, mixed (or empty for auto)", c.RoutingMode)
	}
	if !validOffloads[c.Offload] {
		return fmt.Errorf("offload %q must be one of auto, off, sw, hw (or empty)", c.Offload)
	}
	if c.NativeFirewallZone != "" && !validZoneName.MatchString(c.NativeFirewallZone) {
		return fmt.Errorf("native_firewall_zone %q must contain only letters, digits, _ or - (1-32 chars)", c.NativeFirewallZone)
	}
	for _, d := range c.OffloadDevices {
		if !validIfaceName.MatchString(d) {
			return fmt.Errorf("offload_devices entry %q must be a valid interface name (letters, digits, . _ -, 1-15 chars)", d)
		}
	}
	if c.GatewayMTU != 0 && (c.GatewayMTU < 576 || c.GatewayMTU > 9000) {
		return fmt.Errorf("gateway_mtu %d is out of range (576-9000, or 0 for default)", c.GatewayMTU)
	}
	if c.GatewayAddr != "" {
		if _, _, err := net.ParseCIDR(c.GatewayAddr); err != nil {
			return fmt.Errorf("gateway_address %q must be a CIDR (e.g. 172.31.3.1/30)", c.GatewayAddr)
		}
	}
	if c.Watchdog.NotifyURL != "" && !isHTTPURL(c.Watchdog.NotifyURL) {
		return fmt.Errorf("watchdog notify_url %q must start with http:// or https://", c.Watchdog.NotifyURL)
	}
	if err := c.Telegram.Validate(); err != nil {
		return err
	}
	for _, h := range c.AllowedHosts {
		// Reject an entry with no HOST part (blank, or port-only like ":8088", or bare "[]"): it
		// normalizes to empty in hostAllowGuard, and a list of only such entries would otherwise
		// silently disable the DNS-rebinding host allow-list. Mirrors middleware.normalizeHost.
		ht := strings.TrimSpace(h)
		if host, _, err := net.SplitHostPort(ht); err == nil {
			ht = host
		}
		if strings.Trim(ht, "[]") == "" {
			return fmt.Errorf("allowed_hosts entry %q has no host (a port-only or empty entry would disable the host allow-list)", h)
		}
	}
	return nil
}

// Validate checks the reserved port block: each in range (1-65535) and all
// distinct (the daemon binds all four, so a clash would fail at startup).
func (p Ports) Validate() error {
	named := []struct {
		name string
		v    int
	}{{"ui", p.UI}, {"clash", p.Clash}, {"dns", p.DNS}, {"mixed", p.Mixed}}
	seen := map[int]string{}
	for _, pp := range named {
		if pp.v < 1 || pp.v > 65535 {
			return fmt.Errorf("port %s=%d is out of range (1-65535)", pp.name, pp.v)
		}
		if other, ok := seen[pp.v]; ok {
			return fmt.Errorf("ports %s and %s cannot both be %d", pp.name, other, pp.v)
		}
		seen[pp.v] = pp.name
	}
	return nil
}

// RedactedMark replaces secret values in an exported/displayed config. The import
// path treats a field still equal to this sentinel as "leave the current secret
// unchanged", so a redacted backup round-trips without wiping credentials.
const RedactedMark = "***"

// Redacted returns a copy with secrets masked — the clash secret, the
// subscription URL and the watchdog webhook URL (both of which commonly embed a
// per-account token) — for a backup that is safe to share.
// Empty secrets stay empty. Round-trips safely: the import path never copies the
// Subscription block, so a re-imported "***" URL is ignored, not persisted.
func (c Config) Redacted() Config {
	if c.Clash.Secret != "" {
		c.Clash.Secret = RedactedMark
	}
	if c.Subscription.URL != "" {
		c.Subscription.URL = RedactedMark
	}
	if c.Watchdog.NotifyURL != "" {
		c.Watchdog.NotifyURL = RedactedMark
	}
	if c.Auth.PasswordHash != "" {
		c.Auth.PasswordHash = RedactedMark
	}
	c.Telegram = c.Telegram.Redacted()
	return c
}

// Redacted returns a copy with the bot token masked. The chat list is copied, not aliased.
func (t Telegram) Redacted() Telegram {
	t = t.Clone()
	if t.Token != "" {
		t.Token = RedactedMark
	}
	return t
}

// Clone returns a copy that shares no slice with t, down to each chat's own alert switches: a
// copy edited in place must never change the settings it was taken from.
func (t Telegram) Clone() Telegram {
	t.Chats = append([]TelegramChat(nil), t.Chats...)
	for i := range t.Chats {
		t.Chats[i].AlertsOff = append([]string(nil), t.Chats[i].AlertsOff...)
	}
	t.AlertsOff = append([]string(nil), t.AlertsOff...)
	t.StaleMenus = append([]int64(nil), t.StaleMenus...)
	return t
}

// validHostPort reports whether s is "host:port" / ":port" with a port in
// 1-65535 (host may be empty for a bind-any address).
func validHostPort(s string) bool {
	_, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	p, err := strconv.Atoi(port)
	return err == nil && p >= 1 && p <= 65535
}

func isHTTPURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}
