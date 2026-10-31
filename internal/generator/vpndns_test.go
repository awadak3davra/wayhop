package generator

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"wayhop/internal/importer"
	"wayhop/internal/model"
)

// vpnDNSGenProfile has an OpenVPN and an OpenConnect connection (documentation addresses, so nothing
// connects), each with a DNS server that asks its pushed resolvers and a DNS rule sending the VPN's
// domains there, beside a local resolver and an encrypted default.
func vpnDNSGenProfile(t *testing.T) *model.Profile {
	t.Helper()
	ca, _ := openvpnTestPEM(t)
	ovpn, err := importer.Parse("client\ndev tun\nproto udp\nremote 192.0.2.10 1194\nauth-user-pass\n<ca>\n" + ca + "</ca>\n")
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	ovpn.ID, ovpn.Name, ovpn.Enabled = "ovpn", "Office", true
	ovpn.Params["username"], ovpn.Params["password"] = "user", "pass"
	oc := model.Endpoint{ID: "oc", Name: "Lab", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoOpenConnect,
		Server: "192.0.2.11", Port: 443, Params: map[string]any{"username": "u", "password": "p"}}
	return &model.Profile{
		Endpoints: []model.Endpoint{*ovpn, oc},
		Rules: []model.Rule{
			{ID: "office", DomainSuffix: []string{"corp.example"}, Outbound: "ovpn"},
			{ID: "lab", DomainSuffix: []string{"lab.example"}, Outbound: "oc"},
			{ID: "def", Default: true, Outbound: model.OutboundDirect},
		},
		DNS: &model.DNSSettings{
			Enabled: true,
			Servers: []model.DNSServer{
				{Tag: "local", Type: "local", Enabled: true},
				{Tag: "doh", Type: "https", Server: "192.0.2.53", Enabled: true},
				{Tag: "office-dns", Type: "openvpn", Endpoint: "ovpn", AcceptDefaultResolvers: true, AcceptSearchDomain: true, Enabled: true},
				{Tag: "lab-dns", Type: "openconnect", Endpoint: "oc", Enabled: true},
			},
			Rules: []model.DNSRule{
				{ID: "office", DomainSuffix: []string{"corp.example"}, Server: "office-dns"},
				{ID: "lab", DomainSuffix: []string{"lab.example"}, Server: "lab-dns"},
			},
			Final: "doh",
		},
	}
}

func dnsServersByTag(block map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	servers, _ := block["servers"].([]map[string]any)
	for _, s := range servers {
		out[s["tag"].(string)] = s
	}
	return out
}

func dnsRuleServers(block map[string]any) []string {
	rules, _ := block["rules"].([]map[string]any)
	var out []string
	for _, r := range rules {
		s, _ := r["server"].(string)
		out = append(out, s)
	}
	return out
}

// The two types render as sing-box documents them: the endpoint tag and the two switches, nothing else
// (an unknown field is a decode error), with their rules, and never as the default domain resolver.
func TestVPNDNSServerRender(t *testing.T) {
	for _, ver := range []string{"", "1.14.4", "1.15.0-alpha.13"} {
		res, err := Generate(vpnDNSGenProfile(t), Options{MixedPort: 7890, CoreVersion: ver})
		if err != nil {
			t.Fatalf("%q: %v", ver, err)
		}
		dns := res.Config["dns"].(map[string]any)
		byTag := dnsServersByTag(dns)
		want := map[string]map[string]any{
			"office-dns": {"tag": "office-dns", "type": "openvpn", "endpoint": "ovpn", "accept_default_resolvers": true, "accept_search_domain": true},
			"lab-dns":    {"tag": "lab-dns", "type": "openconnect", "endpoint": "oc"},
		}
		for tag, w := range want {
			if !reflect.DeepEqual(byTag[tag], w) {
				t.Errorf("%q: %s = %v, want %v", ver, tag, byTag[tag], w)
			}
		}
		if got := dnsRuleServers(dns); !reflect.DeepEqual(got, []string{"office-dns", "lab-dns"}) {
			t.Errorf("%q: rule servers = %v", ver, got)
		}
		if r := res.Config["route"].(map[string]any)["default_domain_resolver"]; !reflect.DeepEqual(r, map[string]any{"server": "local"}) {
			t.Errorf("%q: default_domain_resolver = %v", ver, r)
		}
	}
}

// Without a local resolver, the default domain resolver was the first server with no detour key - and a
// VPN's pushed resolvers have none. Then the OpenVPN server's own hostname would be resolved through
// the tunnel it is needed to build. The real default is picked instead.
func TestVPNDNSServerNeverDefaultDomainResolver(t *testing.T) {
	p := vpnDNSGenProfile(t)
	p.DNS.Servers = []model.DNSServer{p.DNS.Servers[2], p.DNS.Servers[3],
		{Tag: "doh", Type: "https", Server: "192.0.2.53", Detour: "ovpn", Enabled: true}}
	res, err := Generate(p, Options{MixedPort: 7890, CoreVersion: "1.14.4"})
	if err != nil {
		t.Fatal(err)
	}
	if r := res.Config["route"].(map[string]any)["default_domain_resolver"]; !reflect.DeepEqual(r, map[string]any{"server": "doh"}) {
		t.Errorf("default_domain_resolver = %v, want doh", r)
	}
	block := map[string]any{"servers": []map[string]any{
		{"tag": "a", "type": "openvpn", "endpoint": "ovpn"}, {"tag": "b", "type": "openconnect", "endpoint": "oc"},
		{"tag": "c", "type": "udp", "server": "192.0.2.53", "detour": "ovpn"},
	}}
	if got := dnsDefaultResolverTag(block); got != "c" {
		t.Errorf("dnsDefaultResolverTag = %q, want c", got)
	}
}

// Validation refuses these planes; the generator still never lets a VPN's pushed resolvers answer what
// no rule matches. A FakeIP final is dropped in fast or mixed mode with the final, and sing-box then
// takes the first server (1.14.4 dns/transport_manager.go): an openvpn one first gets a final naming
// the first other server instead, and is never the default domain resolver.
func TestVPNDNSServerNeverTheFallbackDefault(t *testing.T) {
	plane := func(servers ...model.DNSServer) *model.Profile {
		p := vpnDNSGenProfile(t)
		p.DNS.Servers, p.DNS.Rules, p.DNS.Final = servers, nil, "fake"
		p.DNS.FakeIP, p.DNS.IndependentCache = true, true
		return p
	}
	vpn := model.DNSServer{Tag: "office-dns", Type: "openvpn", Endpoint: "ovpn", Enabled: true}
	fake := model.DNSServer{Tag: "fake", Type: "fakeip", Inet4Range: "198.18.0.0/15", Enabled: true}
	doh := model.DNSServer{Tag: "doh", Type: "https", Server: "192.0.2.53", Detour: "ovpn", Enabled: true}

	block, _ := dnsFrom(plane(vpn, fake, doh), Options{CoreVersion: "1.14.4"}, map[string]bool{})
	if block["final"] != "doh" || dnsDefaultResolverTag(block) != "doh" {
		t.Errorf("[vpn, fake, doh] without TUN: final %v, default domain resolver %q", block["final"], dnsDefaultResolverTag(block))
	}
	// With TUN the FakeIP final stays, and nothing changes.
	block, _ = dnsFrom(plane(vpn, fake, doh), Options{CoreVersion: "1.14.4", TunEnabled: true}, map[string]bool{})
	if block["final"] != "fake" {
		t.Errorf("[vpn, fake, doh] with TUN: final %v", block["final"])
	}
	// Nothing else to name: no final, and no default domain resolver rather than the VPN's.
	block, _ = dnsFrom(plane(fake, vpn), Options{CoreVersion: "1.14.4"}, map[string]bool{})
	if _, ok := block["final"]; ok || dnsDefaultResolverTag(block) != "" {
		t.Errorf("[fake, vpn] without TUN: final %v, default domain resolver %q", block["final"], dnsDefaultResolverTag(block))
	}
}

// A known core before 1.14 refuses the whole config over either type, so dnsFrom leaves the servers out
// with the rules that name them, as it does a fakeip server without TUN, and the default stays.
func TestVPNDNSServerGatedByCore(t *testing.T) {
	for _, ver := range []string{"1.12.17", "sing-box version 1.13.21\n\nEnvironment: go1.25.12 linux/amd64", "garbage"} {
		block, _ := dnsFrom(vpnDNSGenProfile(t), Options{CoreVersion: ver}, map[string]bool{})
		byTag := dnsServersByTag(block)
		if byTag["office-dns"] != nil || byTag["lab-dns"] != nil || byTag["doh"] == nil || byTag["local"] == nil {
			t.Errorf("%q: servers = %v", ver, byTag)
		}
		if _, ok := block["rules"]; ok {
			t.Errorf("%q: rules to dropped servers kept: %v", ver, block["rules"])
		}
		if block["final"] != "doh" {
			t.Errorf("%q: final = %v", ver, block["final"])
		}
	}
	for _, c := range []struct {
		ver        string
		carried    bool
		needsNewer bool
	}{
		{"", true, false}, {"1.12.17", false, true}, {"1.13.21", false, true},
		{"1.14.4", true, false}, {"1.15.0-alpha.13", true, false},
	} {
		s := &model.DNSServer{Tag: "x", Type: "openvpn", Endpoint: "ovpn", Enabled: true}
		if VPNDNSCarried(c.ver) != c.carried || VPNDNSNeedsNewerCore(s, c.ver) != c.needsNewer {
			t.Errorf("%q: carried %v, needs newer %v", c.ver, VPNDNSCarried(c.ver), VPNDNSNeedsNewerCore(s, c.ver))
		}
		s.Enabled = false
		if VPNDNSNeedsNewerCore(s, c.ver) {
			t.Errorf("%q: a switched-off server is named", c.ver)
		}
		if VPNDNSNeedsNewerCore(&model.DNSServer{Tag: "y", Type: "udp", Server: "192.0.2.53", Enabled: true}, c.ver) {
			t.Errorf("%q: a udp server is named", c.ver)
		}
	}
}

// A profile without these servers renders byte for byte as before, on every core: the three fields left
// behind on a resolver of another type (a type switched in the form) change nothing, and neither does a
// switched-off VPN resolver with its switched-off rule.
func TestVPNDNSAbsentRendersIdentically(t *testing.T) {
	render := func(p *model.Profile, ver string) []byte {
		res, err := Generate(p, Options{MixedPort: 7890, CoreVersion: ver, CacheFile: "/opt/var/wayhop/cache.db"})
		if err != nil {
			t.Fatalf("%q: %v", ver, err)
		}
		b, _ := json.MarshalIndent(res.Config, "", "  ")
		return b
	}
	for _, ver := range []string{"", "1.12.17", "1.13.21", "1.14.4", "1.15.0-alpha.13"} {
		base := render(genDNSProfile(secureDNS()), ver)
		leftover := genDNSProfile(secureDNS())
		leftover.DNS.Servers[0].Endpoint, leftover.DNS.Servers[0].AcceptDefaultResolvers = "nl", true
		leftover.DNS.Servers[2].AcceptSearchDomain = true
		if got := render(leftover, ver); !bytes.Equal(got, base) {
			t.Errorf("%q: VPN fields on other resolver types changed the config", ver)
		}
		parked := genDNSProfile(secureDNS())
		parked.DNS.Servers = append(parked.DNS.Servers, model.DNSServer{Tag: "vpn", Type: "openvpn", Endpoint: "gone"})
		parked.DNS.Rules = append(parked.DNS.Rules, model.DNSRule{ID: "vpn", DomainSuffix: []string{"corp.example"}, Server: "vpn", Disabled: true})
		if got := render(parked, ver); !bytes.Equal(got, base) {
			t.Errorf("%q: a switched-off VPN resolver changed the config", ver)
		}
	}
}

// An ECH lookup a DNS rule gives to a VPN's pushed resolvers goes through that tunnel, not out over the
// WAN in the clear; on a core without the type the rule is left out and the default answers.
func TestVPNDNSServerECHLookup(t *testing.T) {
	nl := echTestEndpoint("nl", model.ProtoVLESS, &model.ECH{Enabled: true})
	p := &model.Profile{
		Endpoints: []model.Endpoint{nl, {ID: "ovpn", Name: "ovpn", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoOpenVPN,
			Server: "192.0.2.10", Port: 1194, Params: map[string]any{"ca": "x"}}},
		DNS: &model.DNSSettings{Enabled: true, Final: "doh", Servers: []model.DNSServer{
			{Tag: "doh", Type: "https", Server: "192.0.2.53", Enabled: true},
			{Tag: "vpn", Type: "openvpn", Endpoint: "ovpn", Enabled: true},
		}, Rules: []model.DNSRule{{ID: "r", DomainSuffix: []string{"com"}, Server: "vpn"}}},
	}
	if got := ECHLookupFor(p, &nl, "1.14.4"); got == nil || *got != (ECHLookup{Name: "example.com", Server: "vpn"}) {
		t.Errorf("1.14: %+v", got)
	}
	if got := ECHLookupFor(p, &nl, echCore1321); got == nil || *got != (ECHLookup{Name: "example.com", Server: "doh"}) {
		t.Errorf("1.13: %+v", got)
	}
}

// dnsQueryRcode sends one A query for name to addr over UDP and returns the response code.
func dnsQueryRcode(addr, name string) (int, error) {
	msg := []byte{0x47, 0x22, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		msg = append(append(msg, byte(len(label))), label...)
	}
	msg = append(msg, 0, 0, 1, 0, 1)
	c, err := net.Dial("udp", addr)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(msg); err != nil {
		return 0, err
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return 0, err
	}
	if n < 4 {
		return 0, fmt.Errorf("short answer (%d bytes)", n)
	}
	return int(binary.BigEndian.Uint16(buf[2:4]) & 0xF), nil
}

// TestVPNDNSServerSingBoxCheck runs the real core. On 1.14+ the config rendered for the version
// WR_SINGBOX reports passes `sing-box check` with no deprecation warning, and then RUNS: the startup
// that `check` does not reach is where a dangling or doubled endpoint reference would kill the core.
// With the VPNs unreachable (documentation addresses), a name sent to either server is answered
// NXDOMAIN - not handed to another resolver. Before 1.14 the generator leaves both servers and their
// rules out of the DNS block, which that core accepts, and the 1.14 rendering of the same block is
// refused over the type itself.
func TestVPNDNSServerSingBoxCheck(t *testing.T) {
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — set it to a sing-box binary for a real `check`")
	}
	ver := singboxVersionOf(t, bin)
	name := strings.SplitN(ver, "\n", 2)[0]
	dir := t.TempDir()
	write := func(cfg map[string]any, file string) string {
		data, _ := json.MarshalIndent(cfg, "", "  ")
		f := filepath.Join(dir, file)
		if err := os.WriteFile(f, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return f
	}
	check := func(cfg map[string]any, file string) (string, error) {
		out, err := exec.Command(bin, "check", "-c", write(cfg, file)).CombinedOutput()
		return string(out), err
	}
	// The DNS block alone, with nothing in the config that is new in 1.14 but the server types.
	dnsOnly := func(coreVersion string) map[string]any {
		block, _ := dnsFrom(vpnDNSGenProfile(t), Options{CoreVersion: coreVersion}, map[string]bool{})
		return map[string]any{
			"dns":       block,
			"outbounds": []map[string]any{{"type": "direct", "tag": "direct"}},
			"route":     map[string]any{"default_domain_resolver": map[string]any{"server": dnsDefaultResolverTag(block)}},
		}
	}
	if coreMinor(ver) < vpnDNSMinMinor {
		if out, err := check(dnsOnly(ver), "old.json"); err != nil {
			t.Fatalf("%s: the DNS block without the VPN servers was refused: %v\n%s", name, err, out)
		}
		out, err := check(dnsOnly("1.14.4"), "new.json")
		if err == nil || !strings.Contains(out, "unknown transport type: open") {
			t.Fatalf("%s: the 1.14 DNS block was not refused over the server type (err=%v):\n%s", name, err, out)
		}
		t.Logf("%s refuses the 1.14 block: %s", name, strings.TrimSpace(out))
		return
	}

	ln, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsPort := ln.LocalAddr().(*net.UDPAddr).Port
	_ = ln.Close()
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mixed := tl.Addr().(*net.TCPAddr).Port
	_ = tl.Close()
	res, err := Generate(vpnDNSGenProfile(t), Options{MixedPort: mixed, CoreVersion: ver, CacheFile: filepath.Join(dir, "cache.db")})
	if err != nil {
		t.Fatalf("generate for %s: %v", name, err)
	}
	if byTag := dnsServersByTag(res.Config["dns"].(map[string]any)); byTag["office-dns"] == nil || byTag["lab-dns"] == nil {
		t.Fatalf("%s: rendered without the VPN servers: %v", name, byTag)
	}
	out, err := check(res.Config, "vpndns.json")
	if err != nil {
		t.Fatalf("%s: sing-box check rejected the config: %v\n%s", name, err, out)
	}
	if strings.Contains(out, "deprecated") {
		t.Fatalf("%s: sing-box warned about a deprecated field:\n%s", name, out)
	}

	// Run it, with a loopback DNS inbound so the two servers can be asked.
	inbounds := res.Config["inbounds"].([]map[string]any)
	res.Config["inbounds"] = append(inbounds, map[string]any{"type": "direct", "tag": "dns-in", "listen": "127.0.0.1",
		"listen_port": dnsPort, "network": "udp"})
	route := res.Config["route"].(map[string]any)
	rules, _ := route["rules"].([]map[string]any)
	route["rules"] = append([]map[string]any{{"inbound": "dns-in", "action": "hijack-dns"}}, rules...)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var log bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "run", "-c", write(res.Config, "run.json"))
	cmd.Stdout, cmd.Stderr = &log, &log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case err := <-exited:
		t.Fatalf("%s: sing-box exited at startup (%v):\n%s", name, err, log.String())
	case <-time.After(2 * time.Second):
	}
	addr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
	for _, q := range []string{"host.corp.example", "x.lab.example"} {
		rcode, err := dnsQueryRcode(addr, q)
		if err != nil || rcode != 3 {
			t.Errorf("%s: %s with the VPN down: rcode %d, err %v; want NXDOMAIN (3)", name, q, rcode, err)
		}
	}
	_ = cmd.Process.Kill()
	<-exited
	if s := log.String(); strings.Contains(s, "FATAL") {
		t.Fatalf("%s: sing-box reported a fatal error:\n%s", name, s)
	}
}
