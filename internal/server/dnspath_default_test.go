package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// dnsPathReview runs the pre-Apply review for a profile under one routing mode and returns the DNS
// path findings as the Apply gate sees them.
func dnsPathReview(t *testing.T, p model.Profile, mode string) []Finding {
	t.Helper()
	return dnsPathReviewOn(t, p, mode, platform.Capabilities{
		Platform: "openwrt", Accel: platform.Accel{Kind: "nft-flowtable"}, SingboxPresent: true,
	})
}

func dnsPathReviewOn(t *testing.T, p model.Profile, mode string, caps platform.Capabilities) []Finding {
	t.Helper()
	if err := p.Validate(); err != nil {
		t.Fatalf("fixture must be a valid profile: %v", err)
	}
	s := opshandlers_server(t)
	c := config.Default()
	c.RoutingMode = mode
	pf := s.preflightFor(*c, p, caps, platform.OffloadState{})
	var out []Finding
	for _, f := range foldFindings(evaluatePlanFindings(platform.CapabilitySet{}, pf), nil) {
		if f.Code == "DNS_PATH_EXPOSED" || f.Code == "DNS_PATH_MISMATCH" {
			out = append(out, f)
		}
	}
	return out
}

func dnsDefaultFixture() model.Profile {
	return model.Profile{
		Endpoints: []model.Endpoint{{ID: "nl", Name: "nl", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
			Server: "198.51.100.20", Port: 443, Enabled: true}},
		RoutingLists: []model.RoutingList{{ID: "list-1", Name: "list-1", Outbound: "nl", Enabled: true,
			Manual: []string{"example.com"}}},
	}
}

// QA-105. No DNS rule covers a tunnelled list and no default resolver is chosen, so sing-box answers
// the list's lookups with the first server: the router's plaintext `local` resolver. The audit skipped
// every uncovered list when `final` was empty, so the plaintext gate never fired; the same plane with
// final set to that resolver was refused.
func TestDNSPath_EmptyFinalIsJudgedAsTheFirstResolver(t *testing.T) {
	p := dnsDefaultFixture()
	p.DNS = &model.DNSSettings{Enabled: true, Strategy: "ipv4_only",
		Servers: []model.DNSServer{
			{Tag: "dns_local", Type: "local", Enabled: true},
			{Tag: "cf", Type: "https", Server: "192.0.2.53", Path: "/dns-query", Detour: "nl", Enabled: true},
		}}
	for _, mode := range []string{"tun", "mixed"} {
		got := dnsPathReview(t, p, mode)
		if len(got) != 1 || got[0].Code != "DNS_PATH_EXPOSED" || got[0].Blocks != platform.BlocksApply {
			t.Errorf("%s: an implicit plaintext default must block Apply like an explicit one, got %+v", mode, got)
		}
	}

	// Unchanged: an encrypted resolver first, riding the list's tunnel, is coherent.
	p.DNS.Servers[0], p.DNS.Servers[1] = p.DNS.Servers[1], p.DNS.Servers[0]
	if got := dnsPathReview(t, p, "tun"); len(got) != 0 {
		t.Errorf("an encrypted first resolver through the list's tunnel raises nothing, got %+v", got)
	}
}

// QA-106. A FakeIP server sends no query anywhere: it hands out a synthetic address and the name is
// resolved at the tunnel exit. The audit read its empty detour as "direct" and its type as plaintext,
// so the catalog's FakeIP domain-routing preset was refused as a plaintext leak in every mode. Outside
// TUN the generator drops the fakeip rule and the list falls through to the default resolver, which is
// what has to be judged there.
func TestDNSPath_FakeIPRuleIsNotAPlaintextLeak(t *testing.T) {
	p := dnsDefaultFixture()
	p.DNS = &model.DNSSettings{Enabled: true, LeakProof: true, FakeIP: true, IndependentCache: true,
		Servers: []model.DNSServer{
			{Tag: "dns_secure", Type: "https", Server: "192.0.2.53", Path: "/dns-query", Detour: "nl", Enabled: true},
			{Tag: "fake", Type: "fakeip", Inet4Range: "198.18.0.0/15", Enabled: true},
		},
		Rules: []model.DNSRule{{ID: "r1", RuleSets: []string{"list-1"}, Server: "fake"}},
		Final: "dns_secure"}
	for _, mode := range []string{"tun", "hybrid", "mixed"} {
		if got := dnsPathReview(t, p, mode); len(got) != 0 {
			t.Errorf("%s: a fakeip rule (or, outside TUN, its tunnelled fallback) is not a leak, got %+v", mode, got)
		}
	}

	// Outside TUN the fallback is really judged, not waved through: a plaintext default resolver that
	// dials direct is the leak it always was. Inside TUN the fakeip rule still answers the list.
	p.DNS.LeakProof = false
	p.DNS.Servers = append(p.DNS.Servers, model.DNSServer{Tag: "plain", Type: "udp", Server: "198.51.100.53", Enabled: true})
	p.DNS.Final = "plain"
	if got := dnsPathReview(t, p, "mixed"); len(got) != 1 || got[0].Code != "DNS_PATH_EXPOSED" || got[0].Blocks != platform.BlocksApply {
		t.Errorf("mixed: the list falls through to a plaintext direct default, which must block Apply, got %+v", got)
	}
	if got := dnsPathReview(t, p, "tun"); len(got) != 0 {
		t.Errorf("tun: the fakeip rule answers the list, so the plaintext default never sees it, got %+v", got)
	}
	// KeeneticOS generates every core config with its TUN, fast mode included, so there the fakeip
	// rule is kept and answers the list.
	keenetic := platform.Capabilities{Platform: string(platform.Keenetic), Accel: platform.Accel{Kind: "ppe", HW: true}, SingboxPresent: true}
	if got := dnsPathReviewOn(t, p, "fast", keenetic); len(got) != 0 {
		t.Errorf("keenetic fast: the core keeps its TUN and the fakeip rule, got %+v", got)
	}
}

// The DNS page names the catch-all resolver from the same reading of the plane as the Apply check:
// a fakeip server is kept in tun and hybrid mode and on KeeneticOS, and dropped in fast and mixed mode
// elsewhere, where the page showed an enabled fakeip server at the top as the one answering.
func TestHandleGetDNS_ReportsTheTUNPlane(t *testing.T) {
	for _, c := range []struct {
		mode string
		plat platform.Platform
		demo bool
		want bool
	}{
		{"tun", platform.OpenWrt, false, true},
		{"hybrid", platform.OpenWrt, false, true},
		{"mixed", platform.OpenWrt, false, false},
		{"fast", platform.OpenWrt, false, false},
		{"fast", platform.Keenetic, false, true},
		{"mixed", platform.Keenetic, true, false}, // the demo stands in for an OpenWrt router
	} {
		s := opshandlers_server(t)
		s.cfg.RoutingMode, s.cfg.Demo = c.mode, c.demo
		s.platformOf = func() platform.Platform { return c.plat }
		w := httptest.NewRecorder()
		s.handleGetDNS(w, httptest.NewRequest(http.MethodGet, "/api/dns", nil))
		var resp struct {
			TUN *bool `json:"tun"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.TUN == nil || *resp.TUN != c.want {
			t.Errorf("%s on %s (demo=%v): tun=%v, want %v (%v)", c.mode, c.plat, c.demo, resp.TUN, c.want, err)
		}
	}
}
