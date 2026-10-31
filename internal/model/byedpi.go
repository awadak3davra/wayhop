package model

import (
	"fmt"
	"strings"
)

// ByeDPI (hufrea/byedpi, the `ciadpi` binary) is a local SOCKS5 proxy that rewrites the start of
// each connection - splits, reorders, fakes the TLS ClientHello - so a DPI box cannot read the
// site name, then sends it on from the router itself. It routes nothing: sing-box sends a routing
// list to it as a SOCKS outbound (competitor gap 4: ByeDPI-OpenWrt and Podkop-Manager ship it).
//
// The connection stores the bypass strategy as ciadpi's own flags (params["strategy"]). The daemon
// adds the listener; everything else is the operator's, checked against the documented flag list so
// a typo is refused at save rather than found when the process will not start.

// ByeDPIUID is the uid (and gid) ciadpi runs as when the daemon is root, and the one the TUN inbound
// excludes. In tun and hybrid mode sing-box captures the router's own sockets as well; its own escape
// by mark, ciadpi's have none, so without this a list sent to ByeDPI would loop back into sing-box
// and into ciadpi again. 65530: no account by default on OpenWrt or Entware (nobody is 65534), so
// nothing else running on the router shares the exclusion. ciadpi needs no privilege: its tricks
// are options on its own sockets.
const ByeDPIUID = 65530

// DefaultByeDPIStrategy is the upstream README's first example, used when the field is empty.
const DefaultByeDPIStrategy = "--disorder 1 --auto=torst --tlsrec 1+s"

// byedpiFlag is one documented ciadpi option: its short and long names and whether it takes a value.
type byedpiFlag struct {
	short, long string
	arg         bool
}

// byedpiFlags is ciadpi's option list (byedpi README, v0.17.3).
var byedpiFlags = []byedpiFlag{
	{"i", "ip", true}, {"p", "port", true}, {"D", "daemon", false}, {"w", "pidfile", true},
	{"E", "transparent", false}, {"c", "max-conn", true}, {"b", "buf-size", true}, {"g", "def-ttl", true},
	{"N", "no-domain", false}, {"U", "no-udp", false}, {"F", "tfo", false}, {"A", "auto", true},
	{"L", "auto-mode", true}, {"u", "cache-ttl", true}, {"y", "cache-dump", true}, {"T", "timeout", true},
	{"K", "proto", true}, {"H", "hosts", true}, {"j", "ipset", true}, {"V", "pf", true},
	{"R", "round", true}, {"s", "split", true}, {"d", "disorder", true}, {"o", "oob", true},
	{"q", "disoob", true}, {"f", "fake", true}, {"t", "ttl", true}, {"S", "md5sig", false},
	{"O", "fake-offset", true}, {"l", "fake-data", true}, {"e", "oob-data", true}, {"n", "fake-sni", true},
	{"Q", "fake-tls-mod", true}, {"M", "mod-http", true}, {"r", "tlsrec", true}, {"m", "tlsminor", true},
	{"a", "udp-fake", true}, {"Y", "drop-sack", false},
}

// byedpiRefused are the options the daemon owns or that would take ciadpi off the loopback listener:
// where it listens, running as a daemon (the supervisor would lose it), a pid file, transparent mode,
// and writing its cache to a file.
var byedpiRefused = map[string]string{
	"ip": "the daemon sets where it listens", "port": "the daemon sets where it listens",
	"daemon": "the daemon supervises it", "pidfile": "the daemon supervises it",
	"transparent": "it runs as a SOCKS proxy here", "cache-dump": "it writes a file",
}

// byedpiInlineOnly take a file name or, with a leading ':', the data itself; only the inline form is
// accepted, so a strategy cannot point ciadpi at a file on the router.
var byedpiInlineOnly = map[string]bool{"hosts": true, "ipset": true, "fake-data": true}

// ByeDPIStrategy returns the strategy argv for a ByeDPI connection: params["strategy"] split on
// white space (the default when empty), every token checked. It never contains the listener flags.
func ByeDPIStrategy(params map[string]any) ([]string, error) {
	raw, _ := params["strategy"].(string)
	if strings.TrimSpace(raw) == "" {
		raw = DefaultByeDPIStrategy
	}
	toks := strings.Fields(raw)
	if len(toks) > 64 {
		return nil, fmt.Errorf("strategy has %d words; at most 64", len(toks))
	}
	for i := 0; i < len(toks); i++ {
		tok := toks[i]
		for _, r := range tok {
			if r < 0x21 || r > 0x7e {
				return nil, fmt.Errorf("strategy word %q has a character ciadpi flags never use", tok)
			}
		}
		var f *byedpiFlag
		var val string
		hasVal := false
		switch {
		case strings.HasPrefix(tok, "--"):
			name := tok[2:]
			if k := strings.IndexByte(name, '='); k >= 0 {
				name, val, hasVal = name[:k], name[k+1:], true
			}
			for j := range byedpiFlags {
				if byedpiFlags[j].long == name {
					f = &byedpiFlags[j]
				}
			}
		case strings.HasPrefix(tok, "-") && len(tok) >= 2:
			for j := range byedpiFlags {
				if byedpiFlags[j].short == tok[1:2] {
					f = &byedpiFlags[j]
				}
			}
			if len(tok) > 2 {
				val, hasVal = tok[2:], true
			}
		default:
			return nil, fmt.Errorf("strategy word %q is not a ciadpi flag", tok)
		}
		if f == nil {
			return nil, fmt.Errorf("strategy word %q is not a ciadpi flag", tok)
		}
		if why, ok := byedpiRefused[f.long]; ok {
			return nil, fmt.Errorf("strategy flag --%s is not allowed: %s", f.long, why)
		}
		if !f.arg {
			if hasVal {
				return nil, fmt.Errorf("strategy flag --%s takes no value", f.long)
			}
			continue
		}
		if !hasVal {
			if i+1 >= len(toks) {
				return nil, fmt.Errorf("strategy flag --%s needs a value", f.long)
			}
			i++
			val = toks[i]
		}
		if val == "" {
			return nil, fmt.Errorf("strategy flag --%s needs a value", f.long)
		}
		if byedpiInlineOnly[f.long] && !strings.HasPrefix(val, ":") {
			return nil, fmt.Errorf("strategy flag --%s takes inline data only (\":...\"), not a file", f.long)
		}
	}
	return toks, nil
}
