package nativedns

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// The OpenWrt write-back plan is shown to the user to run by hand, so what matters is what the router
// holds AFTER those commands, not which strings the plan mentions. uciSim is just enough of uci to run
// a RenderUCI plan against a router's `uci show` output and print the result the way `uci show` would.
// It knows only the command forms the renderer emits and fails the test on any other, so a new form
// cannot slip past it unread.

type uciSimOpt struct {
	name string
	vals []string
}

type uciSimSect struct {
	name, typ string // name "" = anonymous, shown as @typ[N]
	opts      []*uciSimOpt
}

type uciSim struct {
	t     *testing.T
	order []string
	cfgs  map[string][]*uciSimSect
}

// newUCISim loads `uci show` output. A section line (`cfg.sect=type`) always precedes its options.
func newUCISim(t *testing.T, show ...string) *uciSim {
	t.Helper()
	s := &uciSim{t: t, cfgs: map[string][]*uciSimSect{}}
	for _, text := range show {
		for _, ln := range strings.Split(text, "\n") {
			key, vals := parseUCILine(ln)
			if key == "" {
				continue
			}
			parts := strings.SplitN(key, ".", 3)
			switch len(parts) {
			case 2:
				name := parts[1]
				if strings.HasPrefix(name, "@") {
					name = ""
				}
				s.addSection(parts[0], name, strings.Join(vals, ""))
			case 3:
				sec := s.section(parts[0], parts[1])
				if sec == nil {
					t.Fatalf("uci show line for a section that was never declared: %q", ln)
				}
				sec.opts = append(sec.opts, &uciSimOpt{name: parts[2], vals: vals})
			}
		}
	}
	return s
}

func (s *uciSim) addSection(cfg, name, typ string) {
	if _, ok := s.cfgs[cfg]; !ok {
		s.order = append(s.order, cfg)
	}
	s.cfgs[cfg] = append(s.cfgs[cfg], &uciSimSect{name: name, typ: typ})
}

// section resolves "name" or "@type[N]" (N may be -1, the last one).
func (s *uciSim) section(cfg, ref string) *uciSimSect {
	if !strings.HasPrefix(ref, "@") {
		for _, sec := range s.cfgs[cfg] {
			if sec.name == ref {
				return sec
			}
		}
		return nil
	}
	lb, rb := strings.IndexByte(ref, '['), strings.IndexByte(ref, ']')
	typ := ref[1:lb]
	idx, err := strconv.Atoi(ref[lb+1 : rb])
	if err != nil {
		s.t.Fatalf("bad section index in %q", ref)
	}
	var of []*uciSimSect
	for _, sec := range s.cfgs[cfg] {
		if sec.typ == typ {
			of = append(of, sec)
		}
	}
	if idx < 0 {
		idx += len(of)
	}
	if idx < 0 || idx >= len(of) {
		return nil
	}
	return of[idx]
}

// target splits "cfg.sect.opt='v'" into its parts; opt and v are empty when absent.
func (s *uciSim) target(arg string) (cfg string, sec *uciSimSect, opt, val string) {
	if i := strings.IndexByte(arg, '='); i >= 0 {
		arg, val = arg[:i], strings.Trim(arg[i+1:], "'")
	}
	parts := strings.SplitN(arg, ".", 3)
	if len(parts) < 2 {
		s.t.Fatalf("uci target %q names no section", arg)
	}
	if len(parts) == 3 {
		opt = parts[2]
	}
	return parts[0], s.section(parts[0], parts[1]), opt, val
}

func (sec *uciSimSect) opt(name string) *uciSimOpt {
	for _, o := range sec.opts {
		if o.name == name {
			return o
		}
	}
	return nil
}

// delete runs `uci -q delete X` and reports whether it removed something (its exit status).
func (s *uciSim) delete(arg string) bool {
	cfg, sec, opt, _ := s.target(arg)
	if sec == nil {
		return false
	}
	if opt == "" {
		list := s.cfgs[cfg]
		for i := range list {
			if list[i] == sec {
				s.cfgs[cfg] = append(list[:i:i], list[i+1:]...)
				return true
			}
		}
		return false
	}
	for i, o := range sec.opts {
		if o.name == opt {
			sec.opts = append(sec.opts[:i:i], sec.opts[i+1:]...)
			return true
		}
	}
	return false
}

// run applies one plan line.
func (s *uciSim) run(cmd string) {
	s.t.Helper()
	switch {
	case strings.HasPrefix(cmd, "#"):
	case strings.HasPrefix(cmd, "while uci -q delete ") && strings.HasSuffix(cmd, "; do :; done"):
		arg := strings.TrimSuffix(strings.TrimPrefix(cmd, "while uci -q delete "), "; do :; done")
		for s.delete(arg) {
		}
	case strings.HasPrefix(cmd, "uci -q delete "):
		s.delete(strings.TrimPrefix(cmd, "uci -q delete "))
	case strings.HasPrefix(cmd, "uci add "):
		f := strings.Fields(strings.TrimPrefix(cmd, "uci add "))
		if len(f) != 2 {
			s.t.Fatalf("uci add takes a config and a type: %q", cmd)
		}
		s.addSection(f[0], "", f[1])
	case strings.HasPrefix(cmd, "uci set "):
		_, sec, opt, val := s.target(strings.TrimPrefix(cmd, "uci set "))
		if sec == nil || opt == "" {
			s.t.Fatalf("uci set on a section that does not exist: %q", cmd)
		}
		if o := sec.opt(opt); o != nil {
			o.vals = []string{val}
		} else {
			sec.opts = append(sec.opts, &uciSimOpt{name: opt, vals: []string{val}})
		}
	case strings.HasPrefix(cmd, "uci add_list "):
		_, sec, opt, val := s.target(strings.TrimPrefix(cmd, "uci add_list "))
		if sec == nil || opt == "" {
			s.t.Fatalf("uci add_list on a section that does not exist: %q", cmd)
		}
		if o := sec.opt(opt); o != nil {
			o.vals = append(o.vals, val)
		} else {
			sec.opts = append(sec.opts, &uciSimOpt{name: opt, vals: []string{val}})
		}
	case strings.HasPrefix(cmd, "uci -q del_list "):
		_, sec, opt, val := s.target(strings.TrimPrefix(cmd, "uci -q del_list "))
		if sec == nil {
			return
		}
		if o := sec.opt(opt); o != nil {
			kept := o.vals[:0]
			for _, v := range o.vals {
				if v != val {
					kept = append(kept, v)
				}
			}
			o.vals = kept
			if len(o.vals) == 0 {
				s.delete(strings.SplitN(strings.TrimPrefix(cmd, "uci -q del_list "), "=", 2)[0])
			}
		}
	default:
		s.t.Fatalf("the uci simulator does not know this plan line: %q", cmd)
	}
}

// show prints one config the way `uci show <cfg>` does.
func (s *uciSim) show(cfg string) string {
	var b strings.Builder
	count := map[string]int{}
	for _, sec := range s.cfgs[cfg] {
		id := sec.name
		if id == "" {
			id = "@" + sec.typ + "[" + strconv.Itoa(count[sec.typ]) + "]"
		}
		count[sec.typ]++
		b.WriteString(cfg + "." + id + "=" + sec.typ + "\n")
		for _, o := range sec.opts {
			q := make([]string, len(o.vals))
			for i, v := range o.vals {
				q[i] = "'" + v + "'"
			}
			b.WriteString(cfg + "." + id + "." + o.name + "=" + strings.Join(q, " ") + "\n")
		}
	}
	return b.String()
}

func (s *uciSim) values(cfg, sect, opt string) []string {
	sec := s.section(cfg, sect)
	if sec == nil {
		return nil
	}
	if o := sec.opt(opt); o != nil {
		return o.vals
	}
	return nil
}

// A router running https-dns-proxy with split-DNS entries beside the proxy references, a bootstrap
// resolver and one more option on each instance, and the package's own global section.
const (
	keepHTTPSDNSProxy = `https-dns-proxy.config=main
https-dns-proxy.config.listen_addr='127.0.0.1'
https-dns-proxy.config.force_dns='1'
https-dns-proxy.@https-dns-proxy[0]=https-dns-proxy
https-dns-proxy.@https-dns-proxy[0].bootstrap_dns='192.0.2.53,198.51.100.53'
https-dns-proxy.@https-dns-proxy[0].resolver_url='https://dns.example.com/dns-query'
https-dns-proxy.@https-dns-proxy[0].listen_addr='127.0.0.1'
https-dns-proxy.@https-dns-proxy[0].listen_port='5053'
https-dns-proxy.@https-dns-proxy[0].dscp_codepoint='46'
https-dns-proxy.@https-dns-proxy[1]=https-dns-proxy
https-dns-proxy.@https-dns-proxy[1].bootstrap_dns='203.0.113.53'
https-dns-proxy.@https-dns-proxy[1].resolver_url='https://doh.example.net/dns-query'
https-dns-proxy.@https-dns-proxy[1].listen_addr='127.0.0.1'
https-dns-proxy.@https-dns-proxy[1].listen_port='5054'
`
	keepDHCP = `dhcp.@dnsmasq[0]=dnsmasq
dhcp.@dnsmasq[0].domainneeded='1'
dhcp.@dnsmasq[0].noresolv='1'
dhcp.@dnsmasq[0].strictorder='1'
dhcp.@dnsmasq[0].server='/canary.example.com/' '/corp.example.com/192.0.2.10' '127.0.0.1#5053' '127.0.0.1#5054' '/home.example.net/198.51.100.1'
dhcp.@dnsmasq[0].doh_backup_server='192.0.2.1'
dhcp.lan=dhcp
dhcp.lan.interface='lan'
`
)

// QA-116: the write-back plan ran `uci -q delete dhcp.@dnsmasq[0].server` and deleted and recreated
// every https-dns-proxy instance. ReadUCI does not model split-DNS entries or any instance option but
// the resolver URL and port, so a user who ran the previewed commands lost their split-DNS entries,
// every bootstrap_dns and every other per-instance option, with nothing in the preview saying so.
func TestRenderUCI_WriteBackKeepsWhatItDoesNotManage(t *testing.T) {
	nd := ReadUCI(keepHTTPSDNSProxy, keepDHCP)
	if err := ValidateForWrite(nd); err != nil {
		t.Fatal(err)
	}
	plan := RenderUCI(nd)
	joined := strings.Join(plan, "\n")
	for _, wipe := range []string{"uci -q delete dhcp.@dnsmasq[0].server", "delete https-dns-proxy.@https-dns-proxy"} {
		if strings.Contains(joined, wipe) {
			t.Errorf("the plan still wipes what it does not model (%q):\n%s", wipe, joined)
		}
	}

	router := newUCISim(t, keepHTTPSDNSProxy, keepDHCP)
	for _, c := range plan {
		router.run(c)
	}

	// Split-DNS entries stay, in their order.
	var split []string
	for _, v := range router.values("dhcp", "@dnsmasq[0]", "server") {
		if strings.HasPrefix(v, "/") {
			split = append(split, v)
		}
	}
	if want := []string{"/canary.example.com/", "/corp.example.com/192.0.2.10", "/home.example.net/198.51.100.1"}; strings.Join(split, " ") != strings.Join(want, " ") {
		t.Errorf("split-DNS entries after the write-back = %q, want %q\n%s", split, want, router.show("dhcp"))
	}
	// Every instance option WayHop does not set stays on its own instance.
	for _, c := range []struct{ sect, opt, want string }{
		{"@https-dns-proxy[0]", "bootstrap_dns", "192.0.2.53,198.51.100.53"},
		{"@https-dns-proxy[0]", "dscp_codepoint", "46"},
		{"@https-dns-proxy[1]", "bootstrap_dns", "203.0.113.53"},
		{"config", "force_dns", "1"},
	} {
		if got := router.values("https-dns-proxy", c.sect, c.opt); len(got) != 1 || got[0] != c.want {
			t.Errorf("https-dns-proxy %s.%s after the write-back = %q, want %q\n%s", c.sect, c.opt, got, c.want, router.show("https-dns-proxy"))
		}
	}
	// Each proxy is referenced once, not twice.
	refs := map[string]int{}
	for _, v := range router.values("dhcp", "@dnsmasq[0]", "server") {
		refs[v]++
	}
	for _, r := range []string{"127.0.0.1#5053", "127.0.0.1#5054"} {
		if refs[r] != 1 {
			t.Errorf("dnsmasq references %s %d times, want once\n%s", r, refs[r], router.show("dhcp"))
		}
	}
	if n := len(router.values("dhcp", "@dnsmasq[0]", "doh_backup_server")); n != 1 {
		t.Errorf("doh_backup_server holds %d values, want the 1 it had\n%s", n, router.show("dhcp"))
	}

	// And the router reads back as the plane that was written.
	back := ReadUCI(router.show("https-dns-proxy"), router.show("dhcp"))
	if back.NoResolv != nd.NoResolv || back.StrictOrder != nd.StrictOrder || len(back.Resolvers) != len(nd.Resolvers) {
		t.Fatalf("read back %+v, wrote %+v", back, nd)
	}
	for i := range nd.Resolvers {
		if back.Resolvers[i].Kind != nd.Resolvers[i].Kind || back.Resolvers[i].Address != nd.Resolvers[i].Address {
			t.Errorf("resolver %d read back as %+v, wrote %+v", i, back.Resolvers[i], nd.Resolvers[i])
		}
	}
}

// A DoH resolver the plane adds gets an instance of its own on a port no adopted proxy uses, and the
// adopted instances keep theirs: two proxies on one port means one of them cannot start.
func TestRenderUCI_NewDoHResolverDoesNotTakeAnAdoptedPort(t *testing.T) {
	nd := ReadUCI(keepHTTPSDNSProxy, keepDHCP)
	nd.Resolvers = append(nd.Resolvers, NativeResolver{Kind: KindDoH, Address: "https://resolver.example.org/dns-query", Tier: TierHidden})
	if err := ValidateForWrite(nd); err != nil {
		t.Fatal(err)
	}
	router := newUCISim(t, keepHTTPSDNSProxy, keepDHCP)
	for _, c := range RenderUCI(nd) {
		router.run(c)
	}
	ports := map[string]string{}
	for i := 0; i < 3; i++ {
		sect := "@https-dns-proxy[" + strconv.Itoa(i) + "]"
		url := router.values("https-dns-proxy", sect, "resolver_url")
		port := router.values("https-dns-proxy", sect, "listen_port")
		if len(url) != 1 || len(port) != 1 {
			t.Fatalf("instance %d after the write-back: url %q port %q\n%s", i, url, port, router.show("https-dns-proxy"))
		}
		if prev, dup := ports[port[0]]; dup {
			t.Errorf("%s and %s both listen on %s", prev, url[0], port[0])
		}
		ports[port[0]] = url[0]
	}
	if ports["5053"] != "https://dns.example.com/dns-query" || ports["5054"] != "https://doh.example.net/dns-query" {
		t.Errorf("adopted proxies moved ports: %v", ports)
	}
	if got := router.values("https-dns-proxy", "@https-dns-proxy[0]", "bootstrap_dns"); len(got) != 1 {
		t.Errorf("adding a resolver cost instance 0 its bootstrap_dns\n%s", router.show("https-dns-proxy"))
	}
}

// runPlan applies a plan to a simulated router holding the given `uci show` outputs.
func runPlan(t *testing.T, nd NativeDNS, show ...string) *uciSim {
	t.Helper()
	if err := ValidateForWrite(nd); err != nil {
		t.Fatal(err)
	}
	router := newUCISim(t, show...)
	for _, c := range RenderUCI(nd) {
		router.run(c)
	}
	return router
}

// An adopted proxy keeps its listen_addr, so dnsmasq must be pointed at that address. The plan used to
// write 127.0.0.1#<port> whatever the instance listened on, so a proxy on ::1 got a dead loopback
// reference ahead of its real one. The package's own reference for a wildcard bind is the loopback of
// the same family (0.0.0.0 -> 127.0.0.1, :: -> ::1); an instance without listen_addr takes the global
// one from the package's `config` section.
func TestRenderUCI_ProxyReferenceFollowsTheInstanceListenAddr(t *testing.T) {
	for _, c := range []struct{ global, listen, ref string }{
		{"", "::1", "::1#5053"},
		{"", "192.0.2.1", "192.0.2.1#5053"},
		{"", "::", "::1#5053"},
		{"", "0.0.0.0", "127.0.0.1#5053"},
		{"192.0.2.1", "", "192.0.2.1#5053"},
	} {
		proxy := "https-dns-proxy.config=main\n"
		if c.global != "" {
			proxy += "https-dns-proxy.config.listen_addr='" + c.global + "'\n"
		}
		proxy += "https-dns-proxy.@https-dns-proxy[0]=https-dns-proxy\n" +
			"https-dns-proxy.@https-dns-proxy[0].resolver_url='https://dns.example.com/dns-query'\n"
		if c.listen != "" {
			proxy += "https-dns-proxy.@https-dns-proxy[0].listen_addr='" + c.listen + "'\n"
		}
		proxy += "https-dns-proxy.@https-dns-proxy[0].listen_port='5053'\n"
		dhcp := "dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].noresolv='1'\n" +
			"dhcp.@dnsmasq[0].server='/corp.example.com/192.0.2.10' '" + c.ref + "'\n"

		nd := ReadUCI(proxy, dhcp)
		if len(nd.Resolvers) != 1 {
			t.Errorf("listen_addr %q (global %q): dnsmasq's reference to the proxy was adopted as an upstream of its own: %+v", c.listen, c.global, nd.Resolvers)
		}
		router := runPlan(t, nd, proxy, dhcp)
		got := router.values("dhcp", "@dnsmasq[0]", "server")
		if want := []string{"/corp.example.com/192.0.2.10", c.ref}; strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("listen_addr %q (global %q): dnsmasq servers after the write-back = %q, want %q", c.listen, c.global, got, want)
		}
		if got := router.values("https-dns-proxy", "@https-dns-proxy[0]", "listen_addr"); strings.Join(got, "") != c.listen {
			t.Errorf("listen_addr %q (global %q): the instance's listen_addr became %q", c.listen, c.global, got)
		}
	}
}

// listen_addr comes back from the client and is written into a uci command, so it must be an address.
func TestValidateForWrite_RejectsAListenAddrThatIsNotAnAddress(t *testing.T) {
	var nd NativeDNS
	if err := json.Unmarshal([]byte(`{"platform":"openwrt","resolvers":[{"kind":"doh",
		"address":"https://dns.example.com/dns-query","source":"https-dns-proxy[0]",
		"listen_addr":"127.0.0.1'; reboot; '"}]}`), &nd); err != nil {
		t.Fatal(err)
	}
	if err := ValidateForWrite(nd); err == nil {
		t.Errorf("a listen_addr that is not an IP address was accepted for write-back:\n%s", strings.Join(RenderUCI(nd), "\n"))
	}
}

// The plane is one dnsmasq: the first section, the one the plan writes. A second instance (another
// port, its own upstreams and switches) used to be read into it, so the plan copied the second's
// noresolv, strictorder and upstreams onto the first.
func TestReadUCI_ReadsOnlyTheDnsmasqSectionItWrites(t *testing.T) {
	for name, first := range map[string]string{"anonymous": "@dnsmasq[0]", "named": "main"} {
		t.Run(name, func(t *testing.T) {
			dhcp := "dhcp." + first + "=dnsmasq\n" +
				"dhcp." + first + ".server='/corp.example.com/192.0.2.10' '198.51.100.53'\n" +
				"dhcp.@dnsmasq[1]=dnsmasq\n" +
				"dhcp.@dnsmasq[1].port='5353'\n" +
				"dhcp.@dnsmasq[1].noresolv='1'\n" +
				"dhcp.@dnsmasq[1].strictorder='1'\n" +
				"dhcp.@dnsmasq[1].server='203.0.113.9'\n" +
				"dhcp.@dnsmasq[1].doh_backup_server='203.0.113.10'\n"
			nd := ReadUCI("", dhcp)
			if nd.NoResolv || nd.StrictOrder {
				t.Errorf("the second instance's switches were adopted: noresolv %v strictorder %v", nd.NoResolv, nd.StrictOrder)
			}
			if len(nd.Resolvers) != 1 || nd.Resolvers[0].Address != "198.51.100.53" {
				t.Errorf("resolvers = %+v, want only the first instance's 198.51.100.53", nd.Resolvers)
			}

			router := runPlan(t, nd, dhcp)
			for _, opt := range []string{"noresolv", "strictorder", "doh_backup_server"} {
				if v := router.values("dhcp", "@dnsmasq[0]", opt); len(v) != 0 {
					t.Errorf("the first instance gained %s=%q\n%s", opt, v, router.show("dhcp"))
				}
			}
			if v := router.values("dhcp", "@dnsmasq[0]", "server"); strings.Join(v, " ") != "/corp.example.com/192.0.2.10 198.51.100.53" {
				t.Errorf("first instance servers = %q\n%s", v, router.show("dhcp"))
			}
			for opt, want := range map[string]string{"port": "5353", "noresolv": "1", "strictorder": "1",
				"server": "203.0.113.9", "doh_backup_server": "203.0.113.10"} {
				if v := router.values("dhcp", "@dnsmasq[1]", opt); strings.Join(v, " ") != want {
					t.Errorf("second instance %s = %q, want %q", opt, v, want)
				}
			}
		})
	}
}

// An instance with no listen_port listens where https-dns-proxy starts it, 5053 plus its index, on its
// own listen_addr; dnsmasq already points there. The plan used to move it to the next free port and to
// 127.0.0.1, so the reference that worked (adopted as a plain upstream) went dead.
func TestRenderUCI_PortlessInstanceStaysWhereItListens(t *testing.T) {
	proxy := "https-dns-proxy.config=main\n" +
		"https-dns-proxy.@https-dns-proxy[0]=https-dns-proxy\n" +
		"https-dns-proxy.@https-dns-proxy[0].resolver_url='https://dns.example.com/dns-query'\n" +
		"https-dns-proxy.@https-dns-proxy[0].listen_addr='192.0.2.1'\n"
	dhcp := "dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].noresolv='1'\ndhcp.@dnsmasq[0].server='192.0.2.1#5053'\n"

	nd := ReadUCI(proxy, dhcp)
	router := runPlan(t, nd, proxy, dhcp)
	if v := router.values("dhcp", "@dnsmasq[0]", "server"); strings.Join(v, " ") != "192.0.2.1#5053" {
		t.Errorf("dnsmasq servers after the write-back = %q, want the proxy's own 192.0.2.1#5053 only\n%s", v, router.show("https-dns-proxy"))
	}
	if v := router.values("https-dns-proxy", "@https-dns-proxy[0]", "listen_addr"); strings.Join(v, "") != "192.0.2.1" {
		t.Errorf("the instance's listen_addr became %q", v)
	}
	if v := router.values("https-dns-proxy", "@https-dns-proxy[0]", "listen_port"); len(v) != 0 && strings.Join(v, "") != "5053" {
		t.Errorf("the instance moved to port %q", v)
	}

	// A plane that names the instance without a port (the panel cleared it) gets a port written, and
	// still keeps the address the instance has.
	for i := range nd.Resolvers {
		if nd.Resolvers[i].Kind == KindDoH {
			nd.Resolvers[i].Port = 0
		}
	}
	plan := strings.Join(RenderUCI(nd), "\n")
	if strings.Contains(plan, "listen_addr") {
		t.Errorf("the plan rewrites the listen_addr of an instance that has one:\n%s", plan)
	}
	if !strings.Contains(plan, "server='192.0.2.1#") {
		t.Errorf("dnsmasq is not pointed at the instance's own address:\n%s", plan)
	}
}

// dnsmasq writes a port before an interface or source binding: `ip#port@wan`. That entry was read
// with port 0, so the plan kept it and added the bare address as well, without the binding.
func TestRenderUCI_ServerWithPortAndBindingRoundTrips(t *testing.T) {
	dhcp := "dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].noresolv='1'\n" +
		"dhcp.@dnsmasq[0].server='127.0.0.1#5053' '127.0.0.1#5054' '198.51.100.1#53@wan'\n"
	nd := ReadUCI(keepHTTPSDNSProxy, dhcp)
	router := runPlan(t, nd, keepHTTPSDNSProxy, dhcp)
	got := router.values("dhcp", "@dnsmasq[0]", "server")
	if want := []string{"127.0.0.1#5053", "127.0.0.1#5054", "198.51.100.1#53@wan"}; strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("dnsmasq servers after the write-back = %q, want %q\n%s", got, want, router.show("dhcp"))
	}
	if v := router.values("dhcp", "@dnsmasq[0]", "doh_backup_server"); len(v) != 0 {
		t.Errorf("the bound upstream was moved to doh_backup_server: %q", v)
	}
}
