package server

import (
	"strconv"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// Found by a hunter on an emulated OpenWrt 23.05: "Intercept clients' DNS", "Break hardcoded encrypted
// resolvers" and "Answer clients through these encrypted resolvers" were applied with "Applied & saved",
// and no device saw a change. The review now says so before the Apply.
func dnsPlaneIDs(t *testing.T, p platform.Platform, mode, dhcp string) []string {
	t.Helper()
	s := opshandlers_server(t)
	s.cfg.Demo = false
	s.platformOf = func() platform.Platform { return p }
	s.dnsRunnerOf = func(name string, args ...string) (string, error) {
		if strings.Contains(strings.Join(args, " "), "show dhcp") {
			return dhcp, nil
		}
		return "", nil
	}
	c := *config.Default()
	c.RoutingMode = mode
	prof := model.Profile{DNS: &model.DNSSettings{Enabled: true, ServeClients: true, Intercept: true, InterceptRejectEncrypted: true}}
	var ids []string
	for _, f := range s.dnsPlaneFindings(c, prof) {
		ids = append(ids, f.ID)
		if _, title, detail, remedy := findingTemplate(f); title == "" || detail == "" || remedy == "" {
			t.Errorf("%s has no words", f.ID)
		}
	}
	return ids
}

func TestDNSPlaneFindingsNameWhatTheRouterDoesNotCarry(t *testing.T) {
	const dhcp = "dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].port='53'\n"
	if got := strings.Join(dnsPlaneIDs(t, platform.OpenWrt, "fast", dhcp), " "); got !=
		"dns.intercept.not_installed dns.serve_clients.not_wired" {
		t.Fatalf("OpenWrt fast: %q", got)
	}
	if got := dnsPlaneIDs(t, platform.Keenetic, "fast", ""); len(got) != 0 {
		t.Fatalf("KeeneticOS fast installs the redirect: %q", got)
	}
	if got := strings.Join(dnsPlaneIDs(t, platform.Keenetic, "tun", ""), " "); got != "dns.intercept.not_installed" {
		t.Fatalf("KeeneticOS tun: %q", got)
	}

	// dnsmasq already forwards to WayHop's resolver, as the remedy asks: devices reach it.
	port := config.Default().Ports.DNS
	forwarded := dhcp + "dhcp.@dnsmasq[0].server='127.0.0.1#" + strconv.Itoa(port) + "'\n"
	if got := strings.Join(dnsPlaneIDs(t, platform.OpenWrt, "fast", forwarded), " "); got != "dns.intercept.not_installed" {
		t.Fatalf("OpenWrt forwarding to WayHop: %q", got)
	}
}
