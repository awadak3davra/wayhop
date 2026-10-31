package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// TelegramBridge configures the Telegram-over-WebSocket bridge the daemon runs as a router service
// (competitor gap 13: tg-ws-proxy-rs, server/tgbridge.go). It is a local MTProto proxy on the LAN
// address: a phone or desktop on the LAN points Telegram at it, and the bridge carries each
// connection to Telegram's own web domains over WebSocket and TLS, so Telegram works where plain TCP
// to its servers is blocked, with no tunnel.
//
// Written only by PUT /api/telegram-bridge, never by the bulk Settings PUT (applyConfigFields): the
// Settings page holds the masked secret, and copying it would store the mask as the secret.
type TelegramBridge struct {
	Enabled bool `json:"enabled,omitempty"`
	// Port is the listener's port on the LAN address; 0 means DefaultTelegramBridgePort.
	Port int `json:"port,omitempty"`
	// Secret is the MTProto proxy secret, 32 hex digits: what a client needs besides the address,
	// and so a credential. Generated when the bridge is enabled without one, masked in exports.
	Secret string `json:"secret,omitempty"`
	// CFDomain and CFWorkerDomain are the bridge's optional Cloudflare routes to Telegram, for when
	// even its web domains are blocked: a domain of the operator's own proxied by Cloudflare
	// (--cf-domain), or a Cloudflare Worker (--cf-worker-domain). Comma-separated, tried in order.
	CFDomain       string `json:"cf_domain,omitempty"`
	CFWorkerDomain string `json:"cf_worker_domain,omitempty"`
}

// DefaultTelegramBridgePort is tg-ws-proxy-rs's own default port.
const DefaultTelegramBridgePort = 1443

// Plugin SOCKS block: the generator hands these ports to engine plugins (generator basePluginPort).
const (
	pluginPortFirst = 17900
	pluginPortEnd   = 18000
)

// EffectivePort is the port the bridge listens on.
func (b TelegramBridge) EffectivePort() int {
	if b.Port == 0 {
		return DefaultTelegramBridgePort
	}
	return b.Port
}

var bridgeSecretShape = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)

// ValidTelegramBridgeSecret reports whether s is a secret the bridge takes: 32 hex digits, without
// the "dd" or "ee" a tg:// link prefixes (the link adds it).
func ValidTelegramBridgeSecret(s string) bool { return bridgeSecretShape.MatchString(s) }

// NewTelegramBridgeSecret is a fresh random secret.
func NewTelegramBridgeSecret() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("telegram bridge: generate a secret: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// hostLabel is one DNS label; the domains go to the bridge as argv values, so anything else - a
// scheme, a path, a leading '-' the bridge would read as a flag - is refused at save.
var hostLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// validDomainList checks a comma-separated list of DNS names (at least one dot each).
func validDomainList(list string) error {
	for _, d := range strings.Split(list, ",") {
		d = strings.TrimSpace(d)
		if strings.Contains(d, "://") || strings.Contains(d, "/") {
			return fmt.Errorf("%q: give the domain name only, without https:// or a path", d)
		}
		labels := strings.Split(strings.ToLower(d), ".")
		if len(d) > 253 || len(labels) < 2 {
			return fmt.Errorf("%q is not a domain name", d)
		}
		for _, l := range labels {
			if !hostLabel.MatchString(l) {
				return fmt.Errorf("%q is not a domain name", d)
			}
		}
	}
	return nil
}

// Validate checks the block's own values. An empty block is valid (the bridge is off), and the
// redaction mark stands for the saved secret, as a Settings page round trip sends it back.
func (b TelegramBridge) Validate() error {
	if b.Port != 0 && (b.Port < 1024 || b.Port > 65535) {
		// The bridge runs unprivileged (tgbridge.UID): below 1024 the bind is refused and the process
		// would exit at every start instead of serving.
		return fmt.Errorf("telegram bridge: port %d is out of range (1024-65535; it runs without root, which cannot listen below 1024)", b.Port)
	}
	if b.Secret != "" && b.Secret != RedactedMark && !ValidTelegramBridgeSecret(b.Secret) {
		return errors.New("telegram bridge: the secret must be 32 hex digits (without the dd or ee prefix of a tg:// link)")
	}
	if b.CFDomain != "" {
		if err := validDomainList(b.CFDomain); err != nil {
			return fmt.Errorf("telegram bridge: cf_domain %w", err)
		}
	}
	if b.CFWorkerDomain != "" {
		if err := validDomainList(b.CFWorkerDomain); err != nil {
			return fmt.Errorf("telegram bridge: cf_worker_domain %w", err)
		}
	}
	return nil
}

// TelegramBridgePortConflict refuses an enabled bridge on a port WayHop itself uses: the panel, the
// Clash API, DNS, the mixed and probe inbounds, and the engine plugins' SOCKS block. The panel binds
// every address, so a second listener on its port fails outright; the loopback ones would not clash
// with the LAN address on Linux, but one rule - none of WayHop's ports - is the one an operator can
// predict. A disabled bridge binds nothing and is not checked, so a dormant value cannot refuse an
// unrelated Settings save.
func (c *Config) TelegramBridgePortConflict() error {
	b := c.TelegramBridge
	if !b.Enabled {
		return nil
	}
	port := b.EffectivePort()
	named := []struct {
		name string
		v    int
	}{
		{"the panel (ui)", c.Ports.UI}, {"the panel's listen address", portOf(c.Listen)},
		{"the Clash API", c.Ports.Clash}, {"the Clash controller", portOf(c.Clash.Controller)},
		{"DNS", c.Ports.DNS}, {"the mixed inbound", c.Ports.Mixed}, {"the probe inbound", c.Ports.Probe()},
	}
	for _, n := range named {
		if n.v != 0 && n.v == port {
			return fmt.Errorf("telegram bridge: port %d is %s's port; choose another", port, n.name)
		}
	}
	if port >= pluginPortFirst && port < pluginPortEnd {
		return fmt.Errorf("telegram bridge: port %d is in the engine plugins' block (%d-%d); choose another", port, pluginPortFirst, pluginPortEnd-1)
	}
	return nil
}

// portOf is the port of a host:port, 0 when there is none.
func portOf(hostport string) int {
	_, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

// Redacted returns a copy with the secret masked.
func (b TelegramBridge) Redacted() TelegramBridge {
	if b.Secret != "" {
		b.Secret = RedactedMark
	}
	return b
}
