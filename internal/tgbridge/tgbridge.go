// Package tgbridge holds what the daemon needs to run tg-ws-proxy-rs (github.com/valnesfjord/
// tg-ws-proxy-rs, MIT) as the router's Telegram bridge: its argv, the tg:// link a client is given,
// and the LAN address it listens on (competitor gap 13). The process itself is supervised by the
// plugin manager (plugin.RunService); server/tgbridge.go decides when it runs.
//
// The bridge is a local MTProto proxy. A Telegram client connects to it with a secret; the bridge
// reads the data-center id from the client's obfuscated init and opens a WebSocket over TLS to
// Telegram's own web domains for that DC (kwsN.web.telegram.org), optionally through a Cloudflare
// domain or Worker. Telegram then works where plain TCP to its servers is blocked, without a tunnel.
package tgbridge

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"wayhop/internal/platform"
)

// BinName is the binary upstream's static musl archives hold, installed under that name by the
// Components entry (updater "tg-ws-proxy").
const BinName = "tg-ws-proxy"

// UID is the uid (and gid) the bridge runs as when the daemon is root. It parses an obfuscated
// protocol from every host on the LAN, so it gets no privilege it does not need: it only listens on
// a port above 1024 and makes outbound connections. Its own uid rather than ByeDPI's 65530: the TUN
// excludes 65530 (generator exclude_uid), and sharing it would take the bridge's connections out of
// the operator's routing in tun and hybrid mode for no reason - nothing loops back through the
// bridge, since sing-box never sends traffic to it. 65531: no account by default on OpenWrt or
// Entware (nobody is 65534).
const UID = 65531

// Settings are what the argv is built from.
type Settings struct {
	Listen         netip.Addr
	Port           int
	CFDomain       string // comma-separated, validated by config.TelegramBridge
	CFWorkerDomain string
}

// Args is the bridge's argv after the binary. --host pins the listener to the LAN address: left
// out, upstream binds 0.0.0.0 whenever it detects a LAN address, which on a router includes the
// WAN side. --quiet keeps per-connection log lines out of the router's log and, with them, the
// startup banner, which prints the secret and the tg:// link; errors that stop the process are
// still written to stderr, which is where the daemon reads the last error from. The secret is not
// here: see Env.
func Args(s Settings) ([]string, error) {
	if !s.Listen.IsValid() || s.Listen.IsUnspecified() {
		return nil, errors.New("no listen address")
	}
	if s.Port < 1 || s.Port > 65535 {
		return nil, fmt.Errorf("port %d is out of range", s.Port)
	}
	args := []string{"--host", s.Listen.String(), "--port", strconv.Itoa(s.Port), "--quiet"}
	if d := compactList(s.CFDomain); d != "" {
		args = append(args, "--cf-domain", d)
	}
	if d := compactList(s.CFWorkerDomain); d != "" {
		args = append(args, "--cf-worker-domain", d)
	}
	return args, nil
}

// Env carries the secret. Upstream reads TG_SECRET as --secret (clap's env fallback); on the command
// line it would be in /proc/<pid>/cmdline, which every local user can read, while a process's
// environment is readable only by its own uid and root.
func Env(secret string) []string { return []string{"TG_SECRET=" + secret} }

// compactList drops the spaces an operator types after a comma.
func compactList(s string) string {
	var out []string
	for _, d := range strings.Split(s, ",") {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return strings.Join(out, ",")
}

// Link is the tg://proxy link a client imports, in upstream's own shape (server, port, secret). The
// secret carries the "dd" prefix, as upstream's link_secret_for prints it: dd asks the client for the
// padded intermediate transport, which the bridge serves.
func Link(server netip.Addr, port int, secret string) string {
	if !server.IsValid() || port == 0 || secret == "" {
		return ""
	}
	return "tg://proxy?server=" + url.QueryEscape(server.String()) +
		"&port=" + strconv.Itoa(port) + "&secret=dd" + url.QueryEscape(strings.ToLower(secret))
}

// LANIface is the bridge every LAN client arrives on: br-lan on OpenWrt (the lan network's device),
// br0 on KeeneticOS (the Home segment, as server/applykeeneticpbr.go binds DNS interception to). ""
// where WayHop does not know the router's layout - the bridge then does not start, rather than guess.
func LANIface(p platform.Platform) string {
	switch p {
	case platform.OpenWrt:
		return "br-lan"
	case platform.Keenetic:
		return "br0"
	}
	return ""
}

// IfaceAddrs reads an interface's addresses; net.InterfaceByName in production, a fixture in tests.
type IfaceAddrs func(name string) ([]net.Addr, error)

// SystemIfaceAddrs is IfaceAddrs on this host.
func SystemIfaceAddrs(name string) ([]net.Addr, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return ifc.Addrs()
}

// LANAddress is the first IPv4 address on iface: what the bridge binds and what the link names.
// IPv4 only, because a link carries one address and every Telegram client on a LAN can reach the
// router's IPv4 address, while a LAN may have no IPv6 at all.
func LANAddress(iface string, read IfaceAddrs) (netip.Addr, error) {
	if iface == "" {
		return netip.Addr{}, errors.New("WayHop does not know this router's LAN interface (only OpenWrt's br-lan and KeeneticOS's br0)")
	}
	addrs, err := read(iface)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("cannot read %s: %w", iface, err)
	}
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil {
			addr, _ := netip.AddrFromSlice(ip4)
			if addr.IsLinkLocalUnicast() || addr.IsLoopback() {
				continue
			}
			return addr, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%s has no IPv4 address", iface)
}

// cgnat is 100.64.0.0/10: shared address space, which IsPrivate does not cover and which is not
// reachable from the internet either.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// Public reports whether addr is reachable from the internet: anything but private, CGNAT, loopback
// and link-local. The bridge refuses to listen on such an address: a LAN bridge holding one is a
// router whose "LAN" is the internet, and an MTProto proxy there is an open proxy for anybody who
// learns the secret, and a port anybody can find.
func Public(addr netip.Addr) bool {
	return addr.IsValid() && addr.IsGlobalUnicast() && !addr.IsPrivate() && !cgnat.Contains(addr)
}
