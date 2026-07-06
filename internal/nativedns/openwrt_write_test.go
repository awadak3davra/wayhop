package nativedns

import (
	"strings"
	"testing"
)

// Round-trip: adopt the OpenWrt fixture → render uci → the plan must preserve every DoH resolver (in
// order, sequential ports), noresolv, the dnsmasq proxy refs, and the plaintext fallbacks.
func TestRenderUCI_RoundTripResolvers(t *testing.T) {
	nd := ReadUCI(fixtureHTTPSDNSProxy, fixtureDHCP) // 3 DoH + 3 plain-fallback
	plan := strings.Join(RenderUCI(nd), "\n")

	for _, url := range []string{"https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query", "https://8.8.8.8/dns-query"} {
		if !strings.Contains(plan, "resolver_url='"+url+"'") {
			t.Errorf("plan missing DoH %s", url)
		}
	}
	for _, p := range []string{"5053", "5054", "5055"} {
		if !strings.Contains(plan, "listen_port='"+p+"'") {
			t.Errorf("plan missing listen_port %s", p)
		}
		if !strings.Contains(plan, "server='127.0.0.1#"+p+"'") {
			t.Errorf("plan missing dnsmasq server ref 127.0.0.1#%s", p)
		}
	}
	if !strings.Contains(plan, "dhcp.@dnsmasq[0].noresolv='1'") {
		t.Error("plan should set noresolv")
	}
	for _, ip := range []string{"1.1.1.1", "1.0.0.1", "9.9.9.9"} {
		if !strings.Contains(plan, "doh_backup_server='"+ip+"'") {
			t.Errorf("plan missing doh_backup_server %s", ip)
		}
	}
	// commit/restart are NOT part of the render plan — they are the user-gated device step.
	if strings.Contains(plan, "uci commit") || strings.Contains(plan, "restart") {
		t.Error("RenderUCI must not include commit/restart (those are UCICommitCmds, user-gated)")
	}
}

func TestValidateForWrite(t *testing.T) {
	ok := NativeDNS{Resolvers: []NativeResolver{{Kind: KindDoH, Address: "https://1.1.1.1/dns-query"}, {Kind: KindPlain, Address: "77.88.8.8"}}}
	if err := ValidateForWrite(ok); err != nil {
		t.Errorf("valid plane rejected: %v", err)
	}
	if ValidateForWrite(NativeDNS{}) == nil {
		t.Error("empty resolvers must be rejected")
	}
	if ValidateForWrite(NativeDNS{Resolvers: []NativeResolver{{Kind: KindDoH, Address: "1.1.1.1"}}}) == nil {
		t.Error("DoH without https:// must be rejected")
	}
	if ValidateForWrite(NativeDNS{Resolvers: []NativeResolver{{Kind: KindPlain, Address: "  "}}}) == nil {
		t.Error("empty address must be rejected")
	}
}

func TestUCICommitCmds_Separate(t *testing.T) {
	c := strings.Join(UCICommitCmds(), "\n")
	if !strings.Contains(c, "uci commit https-dns-proxy") || !strings.Contains(c, "https-dns-proxy restart") {
		t.Errorf("commit cmds incomplete: %s", c)
	}
}
