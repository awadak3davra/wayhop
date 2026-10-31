package nativedns

import (
	"strings"
	"testing"
)

// QA-117: the loop check read /etc/resolv.conf as if it held the router's forwarder upstreams. On
// OpenWrt it holds the libc stub instead, `nameserver 127.0.0.1` and `nameserver ::1`, which point the
// router's own programs at the local dnsmasq; dnsmasq itself forwards to what `uci show dhcp` names
// (server, or the resolvfile when noresolv is off). So every stock OpenWrt was reported with two
// confirmed "self" loops. A loop is judged from where dnsmasq really forwards.

const (
	stubResolvConf = "search lan\nnameserver 127.0.0.1\nnameserver ::1\n"
	dnsmasqNetstat = `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:53              0.0.0.0:*               LISTEN      1234/dnsmasq
tcp        0      0 :::53                   :::*                    LISTEN      1234/dnsmasq
udp        0      0 0.0.0.0:53              0.0.0.0:*                           1234/dnsmasq
udp        0      0 :::53                   :::*                                1234/dnsmasq
`
	lanAddrs = "1: lo    inet 127.0.0.1/8 scope host lo\n4: br-lan    inet 192.0.2.1/24 brd 192.0.2.255 scope global br-lan\n"

	// A stock OpenWrt dnsmasq: no noresolv, so it forwards to the WAN servers in resolv.conf.auto.
	stockDHCP = `dhcp.@dnsmasq[0]=dnsmasq
dhcp.@dnsmasq[0].domainneeded='1'
dhcp.@dnsmasq[0].local='/lan/'
dhcp.@dnsmasq[0].domain='lan'
dhcp.@dnsmasq[0].resolvfile='/tmp/resolv.conf.d/resolv.conf.auto'
dhcp.lan=dhcp
dhcp.lan.interface='lan'
`
	stockResolvAuto = "# Interface wan\nnameserver 198.51.100.53\nnameserver 203.0.113.53\n"

	// https-dns-proxy installed: noresolv on, dnsmasq forwards to the proxies on loopback ports.
	proxiedDHCP = `dhcp.@dnsmasq[0]=dnsmasq
dhcp.@dnsmasq[0].noresolv='1'
dhcp.@dnsmasq[0].resolvfile='/tmp/resolv.conf.d/resolv.conf.auto'
dhcp.@dnsmasq[0].server='/canary.example.com/' '127.0.0.1#5053' '127.0.0.1#5054'
`
)

// openwrtRouter answers RunEffectivePath's probes like an OpenWrt box with the given dhcp config.
func openwrtRouter(dhcp string, files map[string]string) Runner {
	return func(name string, args ...string) (string, error) {
		switch cmd := name + " " + strings.Join(args, " "); {
		case name == "cat":
			if body, ok := files[args[0]]; ok {
				return body, nil
			}
			return "", errMissing
		case cmd == "netstat -tulnp":
			return dnsmasqNetstat, nil
		case cmd == "ip -o addr":
			return lanAddrs, nil
		case cmd == "uci -q show dhcp":
			return dhcp, nil
		case name == "iptables":
			return "-P INPUT ACCEPT\n", nil
		}
		return "", errMissing
	}
}

type missingErr struct{}

func (missingErr) Error() string { return "not found" }

var errMissing error = missingErr{}

func TestDetectEffectivePath_StockOpenWrtStubIsNotALoop(t *testing.T) {
	ep := DetectEffectivePath(stubResolvConf, dnsmasqNetstat, "", "")
	if len(ep.Loops) != 0 {
		t.Errorf("resolv.conf's stub is not where dnsmasq forwards; reported loops: %+v", ep.Loops)
	}
}

func TestRunEffectivePath_StockOpenWrtReportsNoLoop(t *testing.T) {
	for name, c := range map[string]struct {
		dhcp  string
		files map[string]string
	}{
		"stock dnsmasq": {stockDHCP, map[string]string{
			"/etc/resolv.conf": stubResolvConf, "/tmp/resolv.conf.d/resolv.conf.auto": stockResolvAuto}},
		"https-dns-proxy": {proxiedDHCP, map[string]string{
			"/etc/resolv.conf": stubResolvConf, "/tmp/resolv.conf.d/resolv.conf.auto": "# Interface wan\n"}},
	} {
		t.Run(name, func(t *testing.T) {
			ep := RunEffectivePath(openwrtRouter(c.dhcp, c.files))
			if len(ep.Loops) != 0 {
				t.Errorf("a stock OpenWrt has no DNS loop; reported: %+v", ep.Loops)
			}
		})
	}
}

// The check must still find the real thing: dnsmasq told to forward to the router itself.
func TestRunEffectivePath_DnsmasqForwardingToItselfIsALoop(t *testing.T) {
	for name, c := range map[string]struct {
		dhcp     string
		files    map[string]string
		upstream string
	}{
		"server is the router's LAN address": {
			"dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].noresolv='1'\ndhcp.@dnsmasq[0].server='192.0.2.1'\n",
			map[string]string{"/etc/resolv.conf": stubResolvConf}, "192.0.2.1"},
		"server is loopback on :53": {
			"dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].noresolv='1'\ndhcp.@dnsmasq[0].server='127.0.0.1#53'\n",
			map[string]string{"/etc/resolv.conf": stubResolvConf}, "127.0.0.1#53"},
		"resolvfile names the router": {
			"dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].resolvfile='/tmp/resolv.conf'\n",
			map[string]string{"/etc/resolv.conf": stubResolvConf, "/tmp/resolv.conf": "nameserver 192.0.2.1\n"}, "192.0.2.1"},
	} {
		t.Run(name, func(t *testing.T) {
			ep := RunEffectivePath(openwrtRouter(c.dhcp, c.files))
			l := loopFor(ep.Loops, c.upstream)
			if l == nil || l.Kind != "self" || !l.Confirmed {
				t.Fatalf("dnsmasq forwarding to %s is a loop; got %+v", c.upstream, ep.Loops)
			}
			if len(ep.Loops) != 1 {
				t.Errorf("only %s loops; the stub in resolv.conf does not: %+v", c.upstream, ep.Loops)
			}
		})
	}
}

// keeneticRouter answers like a KeeneticOS box with Entware dnsmasq: no uci, the dnsmasq config read
// the way AdoptKeenetic reads it.
func keeneticRouter(conf, resolvConf string) Runner {
	return func(name string, args ...string) (string, error) {
		switch {
		case name == "sh" && len(args) == 2 && strings.Contains(args[1], "/opt/etc/dnsmasq.conf"):
			return conf + "\n" + DnsmasqDirSentinel + "\n", nil
		case name == "cat" && args[0] == "/etc/resolv.conf":
			return resolvConf, nil
		case name == "netstat":
			return dnsmasqNetstat, nil
		case name == "ip":
			return lanAddrs, nil
		case name == "iptables":
			return "-P INPUT ACCEPT\n", nil
		}
		return "", errMissing
	}
}

func TestRunEffectivePath_KeeneticJudgesLoopsFromDnsmasqServers(t *testing.T) {
	ep := RunEffectivePath(keeneticRouter("no-resolv\nstrict-order\nserver=198.51.100.53\nserver=/corp.example.com/192.0.2.10\n", "nameserver 127.0.0.1\n"))
	if len(ep.Loops) != 0 {
		t.Errorf("dnsmasq forwards to a public resolver; a loopback resolv.conf is not its upstream: %+v", ep.Loops)
	}
	ep = RunEffectivePath(keeneticRouter("no-resolv\nserver=198.51.100.53\nserver=127.0.0.1\n", "nameserver 198.51.100.53\n"))
	if l := loopFor(ep.Loops, "127.0.0.1"); l == nil || l.Kind != "self" {
		t.Errorf("dnsmasq server=127.0.0.1 with dnsmasq on :53 is a loop; got %+v", ep.Loops)
	}
	// Without no-resolv dnsmasq reads /etc/resolv.conf, so there a loopback nameserver IS its upstream.
	ep = RunEffectivePath(keeneticRouter("strict-order\n", "nameserver 127.0.0.1\n"))
	if l := loopFor(ep.Loops, "127.0.0.1"); l == nil {
		t.Errorf("dnsmasq reading a resolv.conf that points at itself is a loop; got %+v", ep.Loops)
	}
}

// A dnsmasq server reference carries its port after '#'. A proxy on its own loopback port is not
// the resolver on :53; the same address on :53 is.
func TestDetectDNSLoops_DnsmasqPortRefs(t *testing.T) {
	if got := DetectDNSLoops(dnsListeners, []string{"127.0.0.1#5053", "127.0.0.1#5054"}, nil); len(got) != 0 {
		t.Errorf("DoH proxies on loopback ports are not this resolver: %+v", got)
	}
	if got := DetectDNSLoops(dnsListeners, []string{"127.0.0.1#5053", "127.0.0.1#53"}, nil); loopFor(got, "127.0.0.1#53") == nil {
		t.Errorf("127.0.0.1#53 is the resolver itself; got %+v", got)
	}
	if got := DetectDNSLoops(dnsListeners, []string{"192.0.2.1#53"}, []string{"192.0.2.1/24"}); loopFor(got, "192.0.2.1#53") == nil {
		t.Errorf("the router's own address on #53 is a loop; got %+v", got)
	}
}

// When another program owns :53 (dnsmasq moved aside), dnsmasq forwarding to loopback :53 hands the
// query to that program. Whether it comes back is that program's configuration, not visible here.
func TestRunEffectivePath_AnotherProgramOnPort53IsNotDnsmasqLooping(t *testing.T) {
	run := func(name string, args ...string) (string, error) {
		if name == "netstat" {
			return strings.ReplaceAll(dnsmasqNetstat, "1234/dnsmasq", "1234/AdGuardHome"), nil
		}
		return openwrtRouter("dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].noresolv='1'\ndhcp.@dnsmasq[0].server='127.0.0.1'\n",
			map[string]string{"/etc/resolv.conf": stubResolvConf})(name, args...)
	}
	if ep := RunEffectivePath(run); len(ep.Loops) != 0 {
		t.Errorf("dnsmasq does not own :53 here, so this is not a proven self-loop: %+v", ep.Loops)
	}
}

// withNetstat answers netstat with the given table and everything else like openwrtRouter.
func withNetstat(netstat, dhcp string) Runner {
	return func(name string, args ...string) (string, error) {
		if name == "netstat" {
			return netstat, nil
		}
		return openwrtRouter(dhcp, map[string]string{"/etc/resolv.conf": stubResolvConf})(name, args...)
	}
}

// dnsmasq bound to the LAN address and another resolver on loopback, both on :53. dnsmasq forwarding
// to 127.0.0.1#53 reaches the other resolver, not itself: a loop needs dnsmasq listening on the
// upstream's own address (or on the wildcard of its family).
func TestRunEffectivePath_LoopNeedsDnsmasqOnTheUpstreamAddress(t *testing.T) {
	netstat := `Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 192.0.2.1:53            0.0.0.0:*               LISTEN      1234/dnsmasq
udp        0      0 192.0.2.1:53            0.0.0.0:*                           1234/dnsmasq
tcp        0      0 127.0.0.1:53            0.0.0.0:*               LISTEN      2345/unbound
udp        0      0 127.0.0.1:53            0.0.0.0:*                           2345/unbound
`
	dhcp := "dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].noresolv='1'\ndhcp.@dnsmasq[0].server='127.0.0.1#53'\n"
	if ep := RunEffectivePath(withNetstat(netstat, dhcp)); len(ep.Loops) != 0 {
		t.Errorf("127.0.0.1:53 is another resolver, not dnsmasq: %+v", ep.Loops)
	}
	dhcp = "dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].noresolv='1'\ndhcp.@dnsmasq[0].server='192.0.2.1'\n"
	if l := loopFor(RunEffectivePath(withNetstat(netstat, dhcp)).Loops, "192.0.2.1"); l == nil || l.Kind != "self" || !l.Confirmed {
		t.Errorf("dnsmasq forwarding to the address it listens on is a loop; got %+v", l)
	}
}

// Each dnsmasq instance is judged against its own port. A second instance on 5353 forwarding to the
// main one on :53 is a chain, not a loop; the main one forwarding to its own :53 still is.
func TestRunEffectivePath_SecondDnsmasqInstanceForwardingToTheFirstIsNotALoop(t *testing.T) {
	second := "dhcp.@dnsmasq[1]=dnsmasq\ndhcp.@dnsmasq[1].port='5353'\ndhcp.@dnsmasq[1].noresolv='1'\n" +
		"dhcp.@dnsmasq[1].server='127.0.0.1' '192.0.2.1#53'\n"
	dhcp := "dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].noresolv='1'\ndhcp.@dnsmasq[0].server='198.51.100.53'\n" + second
	if ep := RunEffectivePath(withNetstat(dnsmasqNetstat, dhcp)); len(ep.Loops) != 0 {
		t.Errorf("the instance on 5353 forwards to the one on :53; reported loops: %+v", ep.Loops)
	}
	dhcp = "dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].noresolv='1'\ndhcp.@dnsmasq[0].server='127.0.0.1'\n" + second
	ep := RunEffectivePath(withNetstat(dnsmasqNetstat, dhcp))
	if l := loopFor(ep.Loops, "127.0.0.1"); l == nil || l.Kind != "self" {
		t.Errorf("the instance on :53 forwarding to 127.0.0.1 is a loop; got %+v", ep.Loops)
	}
	if len(ep.Loops) != 1 {
		t.Errorf("only the main instance loops: %+v", ep.Loops)
	}
	// An instance with port 0 serves no DNS at all.
	dhcp = "dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].port='0'\ndhcp.@dnsmasq[0].server='127.0.0.1'\n"
	if ep := RunEffectivePath(withNetstat(dnsmasqNetstat, dhcp)); len(ep.Loops) != 0 {
		t.Errorf("a dnsmasq with port 0 answers no DNS, so it cannot loop: %+v", ep.Loops)
	}
}

// A wildcard bind covers its own family only: dnsmasq opens IPv6 sockets IPv6-only.
func TestDetectDNSLoops_WildcardCoversItsOwnFamily(t *testing.T) {
	v4 := []DNSListener{{Proto: "udp", Addr: "0.0.0.0:53", Process: "dnsmasq"}}
	if got := DetectDNSLoops(v4, []string{"::1#53"}, nil); len(got) != 0 {
		t.Errorf("dnsmasq listens on IPv4 only, so ::1:53 is not dnsmasq: %+v", got)
	}
	v6 := []DNSListener{{Proto: "udp", Addr: ":::53", Process: "dnsmasq"}}
	if got := DetectDNSLoops(v6, []string{"::1#53"}, nil); loopFor(got, "::1#53") == nil {
		t.Errorf("dnsmasq on :::53 answers ::1; got %+v", got)
	}
}
