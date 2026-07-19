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
	"strconv"
	"strings"

	"wayhop/internal/atomicfile"
)

// Ports is the reserved port block wayhop owns. Each is user-editable so the
// daemon can dodge conflicts with the router OS and other services
// (see docs/CONFLICTS.md #1).
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
}

// FailSafe configures Apply rollback behaviour (see internal/failsafe).
type FailSafe struct {
	Target     string `json:"target"`      // connectivity-check host (default 1.1.1.1)
	AutoReboot bool   `json:"auto_reboot"` // allow auto-reboot as the last resort (opt-in)
}

// Watchdog configures crash-restart supervision (see internal/watchdog).
type Watchdog struct {
	// NotifyURL, when set, receives a POST {"text":"…"} on each crash-restart
	// (e.g. a WGBot webhook). Empty = alerts off (the default).
	NotifyURL string `json:"notify_url"`
}

// Subscription configures the client subscription endpoint.
type Subscription struct {
	// Token guards /api/sub/<token>. Auto-generated on first use if empty.
	Token string `json:"token"`
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
	GatewayAddr string `json:"gateway_address,omitempty"` // TUN host address/CIDR when gateway=true ("" → 172.19.0.1/30); not the LAN subnet (auto_route excludes it).
	// RoutingMode selects the routing architecture (see docs/ARCHITECTURE_NATIVE_FIRST.md):
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
	// keep working (see docs/ARCHITECTURE_NATIVE_FIRST.md "Phase 1a/1b"). Deploy-gated —
	// validate TG/VoWiFi survive before relying on it.
	Offload string `json:"offload,omitempty"`
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
	Subscription   Subscription `json:"subscription"`
	Backup         Backup       `json:"backup,omitempty"`
	// AllowedHosts, when non-empty, restricts which Host header values the panel
	// will serve (host-only, port-stripped, case-insensitive) — a DNS-rebinding
	// defense (see docs/SECURITY.md). EMPTY (the default) allows any Host, so this
	// changes nothing until an operator opts in by listing the names/IPs they use
	// to reach the panel, e.g. ["192.168.2.1","10.0.0.30","router.lan"]. Misconfig
	// locks out the UI (recoverable: clear it in config.json + restart).
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
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
	validOffloads     = map[string]bool{"": true, "off": true, "sw": true, "hw": true}
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
		return fmt.Errorf("offload %q must be one of off, sw, hw (or empty)", c.Offload)
	}
	if c.GatewayMTU != 0 && (c.GatewayMTU < 576 || c.GatewayMTU > 9000) {
		return fmt.Errorf("gateway_mtu %d is out of range (576-9000, or 0 for default)", c.GatewayMTU)
	}
	if c.GatewayAddr != "" {
		if _, _, err := net.ParseCIDR(c.GatewayAddr); err != nil {
			return fmt.Errorf("gateway_address %q must be a CIDR (e.g. 172.19.0.1/30)", c.GatewayAddr)
		}
	}
	if c.Watchdog.NotifyURL != "" && !isHTTPURL(c.Watchdog.NotifyURL) {
		return fmt.Errorf("watchdog notify_url %q must start with http:// or https://", c.Watchdog.NotifyURL)
	}
	for _, h := range c.AllowedHosts {
		if strings.TrimSpace(h) == "" {
			return errors.New("allowed_hosts entries must not be blank")
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
// subscription token, the subscription URL and the watchdog webhook URL (both of
// which commonly embed a per-account token) — for a backup that is safe to share.
// Empty secrets stay empty. Round-trips safely: the import path never copies the
// Subscription block, so a re-imported "***" URL is ignored, not persisted.
func (c Config) Redacted() Config {
	if c.Clash.Secret != "" {
		c.Clash.Secret = RedactedMark
	}
	if c.Subscription.Token != "" {
		c.Subscription.Token = RedactedMark
	}
	if c.Subscription.URL != "" {
		c.Subscription.URL = RedactedMark
	}
	if c.Watchdog.NotifyURL != "" {
		c.Watchdog.NotifyURL = RedactedMark
	}
	return c
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
