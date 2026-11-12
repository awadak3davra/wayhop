package generator

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"

	"wayhop/internal/model"
)

// The dnsmasq-facing inbound is a direct inbound in both sing-box 1.12 and 1.13, and hijack-dns is
// their route-rule action for sending that inbound to the DNS module. Keep it with the leading guards,
// ahead of every ordinary and routing-list rule. singboxCheckDNS proves the real core accepts it when
// WR_SINGBOX is set, as the neighbouring DNS tests do.
func TestGenerateDNSSecureDefaultServeClients(t *testing.T) {
	dns := secureDNS()
	dns.ServeClients = true
	res, err := Generate(genDNSProfile(dns), Options{MixedPort: 7890, DNSPort: 5353})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	inbounds := res.Config["inbounds"].([]map[string]any)
	wantInbound := map[string]any{"type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 5353}
	if len(inbounds) < 2 || !reflect.DeepEqual(inbounds[1], wantInbound) {
		t.Fatalf("DNS inbound = %+v, want second inbound %+v", inbounds, wantInbound)
	}

	rules := res.Config["route"].(map[string]any)["rules"].([]map[string]any)
	dnsRule, listRule := -1, -1
	for i, rule := range rules {
		if inbound, _ := rule["inbound"].([]string); len(inbound) == 1 && inbound[0] == "dns-in" {
			if dnsRule >= 0 || rule["action"] != "hijack-dns" || len(rule) != 2 {
				t.Fatalf("DNS route rule %d = %+v", i, rule)
			}
			dnsRule = i
		}
		if _, ok := rule["rule_set"]; ok && listRule < 0 {
			listRule = i
		}
	}
	if dnsRule < 0 {
		t.Fatal("hijack-dns route rule is missing")
	}
	if listRule < 0 || dnsRule > listRule {
		t.Fatalf("DNS guard at %d, first list rule at %d; the guard must lead", dnsRule, listRule)
	}
	singboxCheckDNS(t, res.Config)
}

// A false ServeClients is the same zero value as a profile saved before the field existed. The DNS
// port may be populated either way; it must not change one byte until the new switch is explicitly on.
func TestGenerateDNSServeClientsOffByteIdentical(t *testing.T) {
	render := func(p *model.Profile) []byte {
		res, err := Generate(p, Options{MixedPort: 7890, DNSPort: 5353})
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		out, err := json.MarshalIndent(res.Config, "", "  ")
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return out
	}
	for _, enabled := range []bool{true, false} {
		dns := secureDNS()
		dns.Enabled = enabled
		before := genDNSProfile(dns) // no field set: ServeClients has its zero value
		off := genDNSProfile(dns)
		off.DNS.ServeClients = false
		if got, want := render(off), render(before); !bytes.Equal(got, want) {
			t.Errorf("DNS enabled=%v: false ServeClients changed the config\n got: %s\nwant: %s", enabled, got, want)
		}
	}
}
