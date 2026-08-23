package server

import (
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// A DNS/traffic exit mismatch is a profile-policy problem, not a statement about router hardware.
// The gate distinguishes encrypted resolver visibility from a plaintext WAN leak.

func dnsPathProfile(t *testing.T, detour string) model.Profile {
	return dnsPathProfileWithType(t, detour, "https")
}

func dnsPathProfileWithType(t *testing.T, detour, serverType string) model.Profile {
	t.Helper()
	p := model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "nl", Name: "nl", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
				Server: "198.51.100.20", Port: 443, Enabled: true},
		},
		Groups: []model.Group{
			{ID: "auto", Name: "auto", Type: model.GroupURLTest, Members: []string{"nl"}},
		},
		RoutingLists: []model.RoutingList{
			{ID: "streaming", Name: "streaming", Outbound: "nl", Enabled: true, Manual: []string{"example.com"}},
		},
		DNS: &model.DNSSettings{
			Enabled: true,
			Servers: []model.DNSServer{
				{Tag: "dns_secure", Type: serverType, Server: "1.1.1.1", Path: "/dns-query", Detour: detour, Enabled: true},
			},
			Rules: []model.DNSRule{{ID: "streaming", RuleSets: []string{"streaming"}, Server: "dns_secure"}},
			Final: "dns_secure",
		},
	}
	return p
}

func dnsPathFindings(t *testing.T, detour string) []platform.Unsupported {
	t.Helper()
	s := opshandlers_server(t)
	if err := s.store.Replace(dnsPathProfile(t, detour)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return s.preflight(platform.Capabilities{
		Platform: "openwrt", Accel: platform.Accel{Kind: "nft-flowtable"}, SingboxPresent: true,
	}, platform.OffloadState{})
}

func dnsPathOnly(fs []platform.Unsupported) []platform.Unsupported {
	var out []platform.Unsupported
	for _, f := range fs {
		if len(f.Setting) > 9 && f.Setting[:9] == "dns_path:" {
			out = append(out, f)
		}
	}
	return out
}

// Direct DoH is a privacy-policy mismatch, not a plaintext leak or a router capability failure.
func TestDNSPath_EncryptedDirectLookupIsAPrivacyFinding(t *testing.T) {
	got := dnsPathOnly(dnsPathFindings(t, "direct"))
	if len(got) != 1 {
		t.Fatalf("expected one dns_path finding, got %+v", got)
	}
	f := got[0]
	if f.Severity != platform.SeverityPrivacy {
		t.Errorf("severity = %q, want %q — an exposed lookup is not a statement about the hardware",
			f.Severity, platform.SeverityPrivacy)
	}
	if f.Severity == platform.SeverityDegraded {
		t.Error("an exposed lookup must never be filed as a mere degradation")
	}
	for _, want := range []string{"encrypted DNS", "WAN path cannot read", "WAN address"} {
		if !contains(f.Reason, want) {
			t.Errorf("the reason does not say %q: %s", want, f.Reason)
		}
	}
}

// Encrypted DNS may intentionally use the WAN exit. It must be reviewed and acknowledged, but it
// must not make Apply impossible.
// The encrypted mismatch is a PRIVACY report: the lookup works, and the resolver sees it from a
// different address than the traffic. It is folded into one review entry and left visible — it does
// not block Apply and does not ask for a signature, because nothing about it is broken.
func TestDNSPath_EncryptedMismatchIsReportedNotGated(t *testing.T) {
	s := opshandlers_server(t)
	if err := s.store.Replace(dnsPathProfile(t, "direct")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	pf := s.preflight(platform.Capabilities{
		Platform: "openwrt", Accel: platform.Accel{Kind: "nft-flowtable"}, SingboxPresent: true,
	}, platform.OffloadState{})
	findings := evaluatePlanFindings(platform.CapabilitySet{}, pf)

	var seen bool
	for _, f := range findings {
		if len(f.Setting) > 9 && f.Setting[:9] == "dns_path:" {
			seen = true
			if f.Blocks == platform.BlocksApply {
				t.Errorf("encrypted direct DNS must be acknowledgeable, got blocks=%q", f.Blocks)
			}
			if f.Severity != platform.SeverityPrivacy {
				t.Errorf("severity = %q, want privacy", f.Severity)
			}
		}
	}
	if !seen {
		t.Fatal("the dns_path finding disappeared from the plan findings")
	}
	review := foldFindings(findings, nil)
	if len(review) != 1 || review[0].Code != "DNS_EXIT_MISMATCH_ENCRYPTED" {
		t.Fatalf("encrypted mismatch must fold into one review entry: %+v", review)
	}
	if review[0].AckRequired || review[0].hard() {
		t.Fatalf("a privacy report must not gate Apply: %+v", review[0])
	}
}

func TestDNSPath_PlaintextMismatchBlocksApply(t *testing.T) {
	s := opshandlers_server(t)
	if err := s.store.Replace(dnsPathProfileWithType(t, "direct", "udp")); err != nil {
		t.Fatalf("seed: %v", err)
	}
	pf := s.preflight(platform.Capabilities{
		Platform: "openwrt", Accel: platform.Accel{Kind: "nft-flowtable"}, SingboxPresent: true,
	}, platform.OffloadState{})
	findings := evaluatePlanFindings(platform.CapabilitySet{}, pf)
	review := foldFindings(findings, nil)
	if len(review) != 1 || review[0].Code != "DNS_PATH_EXPOSED" ||
		review[0].Blocks != platform.BlocksApply || review[0].AckRequired {
		t.Fatalf("plaintext mismatch must remain a non-overridable blocker: %+v", review)
	}
}

// A lookup that rides the same tunnel as its traffic is coherent and must produce nothing. Without
// this the privacy finding could be raised for every profile and still pass the test above.
func TestDNSPath_MatchedDetourRaisesNothing(t *testing.T) {
	if got := dnsPathOnly(dnsPathFindings(t, "nl")); len(got) != 0 {
		t.Errorf("a lookup that follows its traffic must raise nothing, got %+v", got)
	}
}

// A failover group as the detour is not an exposure: the lookup rides a tunnel, whichever member is
// up. The auditor may still note that the group and the list name different outbounds — a
// geo-targeted answer from one exit need not suit another — and that observation is a degradation,
// not a leak. Asserting "no finding at all" was the wrong claim: it would have failed a correct
// remark for saying something true.
func TestDNSPath_FailoverGroupDetourIsNotALeak(t *testing.T) {
	for _, f := range dnsPathOnly(dnsPathFindings(t, "auto")) {
		if f.Severity == platform.SeverityPrivacy {
			t.Errorf("a lookup riding a failover group was reported as an exposure: %+v", f)
		}
	}
}

func contains(hay, needle string) bool {
	return len(hay) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(hay); i++ {
			if hay[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
