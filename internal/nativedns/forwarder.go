package nativedns

import (
	"strconv"
	"strings"
)

// A DNS loop is judged from where the router's forwarder (dnsmasq) sends the queries it cannot
// answer itself, never from /etc/resolv.conf (QA-117).
//
// /etc/resolv.conf is for the router's own programs. On OpenWrt it is the libc stub,
// `nameserver 127.0.0.1` and `nameserver ::1`, which hands their lookups to the local dnsmasq; dnsmasq
// forwards to what `uci show dhcp` names: its `server` list, plus the resolvfile (resolv.conf.auto,
// the WAN's servers) unless noresolv is on. Reading the stub as dnsmasq's upstream turned every stock
// OpenWrt into two confirmed "self" loops.

const (
	// openwrtResolvFile is where dnsmasq reads the WAN's servers when the dhcp config names no
	// resolvfile; releases before 21.02 kept it at openwrtLegacyResolvFile.
	openwrtResolvFile       = "/tmp/resolv.conf.d/resolv.conf.auto"
	openwrtLegacyResolvFile = "/tmp/resolv.conf.auto"
	// dnsmasqDefaultResolvFile is dnsmasq's own default when its config has no resolv-file.
	dnsmasqDefaultResolvFile = "/etc/resolv.conf"

	// keeneticDnsmasqRead prints the Entware dnsmasq main config, the sentinel, then its conf-dir: the
	// order dnsmasq reads them in.
	keeneticDnsmasqRead = "cat /opt/etc/dnsmasq.conf 2>/dev/null; echo '" + DnsmasqDirSentinel +
		"'; cat /opt/etc/dnsmasq.d/*.conf 2>/dev/null"
)

// forwarder is one dnsmasq instance: the port it answers DNS on and the upstreams it forwards to.
type forwarder struct {
	port      string
	upstreams []string
}

// forwarderLoops reads each dnsmasq instance's upstreams and reports those that resolve back into
// that instance: on its own port, at an address netstat shows dnsmasq listening on (detectLoops).
// Nothing is reported when the configuration cannot be read, or when :53 is served by another program
// only: dnsmasq forwarding to loopback :53 then hands the query to that program, and whether it comes
// back depends on that program's configuration, which is not read here. Two dnsmasq instances bound to
// different addresses on :53 are not told apart: both count as the forwarder on that port.
func forwarderLoops(run Runner, listeners []DNSListener, routerAddrs []string) []DNSLoop {
	fwds, ok := readForwarders(run)
	if !ok {
		return nil
	}
	var own []DNSListener
	for _, l := range listeners {
		if l.Process == "" || strings.HasPrefix(l.Process, "dnsmasq") { // "" = netstat could not say
			own = append(own, l)
		}
	}
	if len(listeners) > 0 && len(own) == 0 {
		return nil
	}
	var out []DNSLoop
	seen := map[string]bool{}
	for _, f := range fwds {
		for _, l := range detectLoops(own, f.upstreams, routerAddrs, f.port) {
			if !seen[l.Upstream] {
				seen[l.Upstream] = true
				out = append(out, l)
			}
		}
	}
	return out
}

// readForwarders returns each dnsmasq instance with its upstreams, and whether the configuration was
// read at all: OpenWrt's `uci show dhcp` when uci answers, else an Entware dnsmasq config (KeeneticOS).
func readForwarders(run Runner) ([]forwarder, bool) {
	resolv := resolvFileReader(run)
	if dhcp, err := run("uci", "-q", "show", "dhcp"); err == nil && strings.Contains(dhcp, "=dnsmasq") {
		return dnsmasqForwardersUCI(dhcp, resolv), true
	}
	conf, _ := run("sh", "-c", keeneticDnsmasqRead)
	return dnsmasqForwardersConf(conf, resolv)
}

// dnsmasqForwardersUCI reads, from `uci show dhcp`, each dnsmasq section's port and its forwarding
// servers (split-DNS "/domain/…" entries excluded), plus its resolv file's nameservers unless noresolv
// is on. A section with port 0 serves no DNS and is left out.
func dnsmasqForwardersUCI(dhcp string, resolv func(string) []string) []forwarder {
	type section struct {
		dnsmasq, noresolv bool
		resolvfile, port  string
		servers           []string
	}
	sections := map[string]*section{}
	var order []string
	get := func(id string) *section {
		if sections[id] == nil {
			// `uci show` declares a section before its options; an anonymous one names its type anyway.
			sections[id] = &section{dnsmasq: strings.HasPrefix(id, "@dnsmasq[")}
			order = append(order, id)
		}
		return sections[id]
	}
	for _, ln := range strings.Split(dhcp, "\n") {
		key, vals := parseUCILine(ln)
		parts := strings.SplitN(key, ".", 3)
		if len(parts) < 2 {
			continue
		}
		s := get(parts[1])
		if len(parts) == 2 {
			s.dnsmasq = len(vals) > 0 && vals[0] == "dnsmasq"
			continue
		}
		if len(vals) == 0 {
			continue
		}
		switch parts[2] {
		case "noresolv":
			s.noresolv = uciTrue(vals[0])
		case "resolvfile":
			s.resolvfile = strings.TrimSpace(vals[0])
		case "port":
			s.port = dnsPort(vals[0])
		case "server":
			for _, v := range vals {
				if v = strings.TrimSpace(v); v != "" && !strings.HasPrefix(v, "/") {
					s.servers = append(s.servers, v)
				}
			}
		}
	}
	var out []forwarder
	for _, id := range order {
		s := sections[id]
		if !s.dnsmasq || s.port == "0" {
			continue
		}
		f := forwarder{port: s.port, upstreams: s.servers}
		if f.port == "" {
			f.port = "53"
		}
		if !s.noresolv {
			file := s.resolvfile
			if file == "" {
				file = openwrtResolvFile
			}
			f.upstreams = append(f.upstreams, resolv(file)...)
		}
		out = append(out, f)
	}
	return out
}

// dnsmasqForwardersConf does the same for a dnsmasq config file (the blob keeneticDnsmasqRead prints),
// which configures one instance. ok is false when it holds no directive at all, i.e. there is no
// dnsmasq config to judge.
func dnsmasqForwardersConf(conf string, resolv func(string) []string) (fwds []forwarder, ok bool) {
	noresolv := false
	resolvFile := ""
	f := forwarder{port: "53"}
	for _, ln := range strings.Split(conf, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		ok = true
		switch {
		case ln == "no-resolv":
			noresolv = true
		case strings.HasPrefix(ln, "resolv-file="):
			resolvFile = strings.TrimSpace(strings.TrimPrefix(ln, "resolv-file="))
		case strings.HasPrefix(ln, "port="):
			f.port = dnsPort(strings.TrimPrefix(ln, "port="))
		case strings.HasPrefix(ln, "server="):
			if v := strings.TrimSpace(strings.TrimPrefix(ln, "server=")); v != "" && !strings.HasPrefix(v, "/") {
				f.upstreams = append(f.upstreams, v)
			}
		}
	}
	if !ok {
		return nil, false
	}
	if f.port == "0" {
		return nil, true // DNS is off in this dnsmasq
	}
	if !noresolv {
		if resolvFile == "" {
			resolvFile = dnsmasqDefaultResolvFile
		}
		f.upstreams = append(f.upstreams, resolv(resolvFile)...)
	}
	return []forwarder{f}, true
}

// dnsPort normalises a configured dnsmasq port ("053" is "53"); an unreadable one is kept as written.
func dnsPort(v string) string {
	v = strings.TrimSpace(v)
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return strconv.Itoa(n)
	}
	return v
}

// resolvFileReader returns the nameservers of a resolv file, reading each file once.
func resolvFileReader(run Runner) func(string) []string {
	cache := map[string][]string{}
	return func(f string) []string {
		if ns, ok := cache[f]; ok {
			return ns
		}
		text, err := run("cat", f)
		if err != nil && f == openwrtResolvFile {
			text, _ = run("cat", openwrtLegacyResolvFile)
		}
		cache[f] = resolvNameservers(text)
		return cache[f]
	}
}

// resolvNameservers returns the nameserver addresses of a resolv.conf-format text.
func resolvNameservers(text string) []string {
	var out []string
	for _, ln := range strings.Split(text, "\n") {
		f := strings.Fields(strings.TrimSpace(ln))
		if len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
	}
	return out
}

// uciTrue reads a uci boolean the way OpenWrt's config_get_bool does.
func uciTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "on", "true", "yes", "enabled":
		return true
	}
	return false
}
