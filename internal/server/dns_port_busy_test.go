package server

import (
	"errors"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/platform"
)

func TestDNSPortHolder(t *testing.T) {
	cases := []struct {
		name, netstat string
		want          string
	}{
		{"dnsmasq on loopback", "udp 0 0 127.0.0.1:5353 0.0.0.0:* 1234/dnsmasq\n", "dnsmasq"},
		{"mDNS on every address", "udp 0 0 0.0.0.0:5353 0.0.0.0:* 88/umdnsd\n", "umdnsd"},
		{"over TCP", "tcp 0 0 127.0.0.1:5353 0.0.0.0:* LISTEN 77/coredns\n", "coredns"},
		{"IPv6 wildcard", "udp 0 0 :::5353 :::* 9/avahi-daemon\n", "avahi-daemon"},
		{"our own core", "udp 0 0 127.0.0.1:5353 0.0.0.0:* 6290/sing-box\n", ""},
		{"another address does not collide", "udp 0 0 192.0.2.1:5353 0.0.0.0:* 1234/dnsmasq\n", ""},
		{"another port that ends the same", "udp 0 0 127.0.0.1:15353 0.0.0.0:* 1234/dnsmasq\n", ""},
		{"no process name to report", "udp 0 0 127.0.0.1:5353 0.0.0.0:* -\n", ""},
		{"a header and nothing else", "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address\n", ""},
	}
	for _, c := range cases {
		run := func(string, ...string) (string, error) { return c.netstat, nil }
		if got := dnsPortHolder(run, 5353); got != c.want {
			t.Errorf("%s: holder = %q, want %q", c.name, got, c.want)
		}
	}
	// A router whose netstat cannot say must not be stopped from applying.
	fails := func(string, ...string) (string, error) { return "", errors.New("netstat: invalid option") }
	if got := dnsPortHolder(fails, 5353); got != "" {
		t.Errorf("failed netstat: holder = %q", got)
	}
	if got := dnsPortHolder(nil, 5353); got != "" {
		t.Errorf("no runner: holder = %q", got)
	}
}

func TestDNSPortFindings(t *testing.T) {
	s := bindTestServer(t, feedProfile(), "")
	s.dnsRunnerOf = func(string, ...string) (string, error) {
		return "udp 0 0 127.0.0.1:5353 0.0.0.0:* 1234/dnsmasq\n", nil
	}
	prof := s.store.Profile()
	cfg := *config.Default()

	// Nothing asks for the port, so nothing can collide over it.
	if got := s.dnsPortFindings(cfg, prof); len(got) != 0 {
		t.Fatalf("answering off: %+v", got)
	}

	dns := secureDNSTemplate(&prof)
	dns.ServeClients = true
	withServe := prof
	withServe.DNS = dns
	got := s.dnsPortFindings(cfg, withServe)
	if len(got) != 1 {
		t.Fatalf("port held by dnsmasq: %+v", got)
	}
	f := got[0]
	if f.ID != "dns.port_busy" || f.Blocks != platform.BlocksApply || f.Severity != platform.SeverityBlocked {
		t.Errorf("finding = %+v", f)
	}
	if f.Item != "dnsmasq :5353" {
		t.Errorf("item = %q", f.Item)
	}
	_, title, detail, remedy := findingTemplate(f)
	if title == "" || detail == "" || remedy == "" {
		t.Errorf("template is incomplete: %q / %q / %q", title, detail, remedy)
	}

	// The demo has no router to ask.
	demo := cfg
	demo.Demo = true
	if got := s.dnsPortFindings(demo, withServe); len(got) != 0 {
		t.Errorf("demo: %+v", got)
	}
}
