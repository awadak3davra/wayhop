package server

import (
	"strings"
	"testing"
)

// Live 22.11 (KN-3812, iptables 1.4.21): every fast-mode rule the program installs is found in the
// dump in the form iptables -S prints it (a protocol's match module inserted, the REJECT type spelled),
// and no rule uses a match KeeneticOS does not load (addrtype).
func TestKeeneticFastRulesMatchPrintedForm(t *testing.T) {
	k := keeneticK1Artifact(t, false)
	script := string(k.Ipset.Script)
	if strings.Contains(script, "addrtype") {
		t.Fatalf("addrtype rendered (not loaded on KeeneticOS):\n%s", script)
	}
	printed := map[keeneticChainRef]string{
		{tool: "iptables", table: "nat", chain: "PREROUTING"}: "-P PREROUTING ACCEPT\n" +
			"-A PREROUTING -i br0 -p udp -m udp --dport 53 -j REDIRECT --to-ports 53\n" +
			"-A PREROUTING -i br0 -p tcp -m tcp --dport 53 -j REDIRECT --to-ports 53\n",
		{tool: "iptables", table: "filter", chain: "FORWARD"}: "-P FORWARD ACCEPT\n" +
			"-A FORWARD -i br0 -p tcp -m tcp --dport 853 -j REJECT --reject-with tcp-reset\n",
		{tool: "ip6tables", table: "filter", chain: "FORWARD"}: "-P FORWARD ACCEPT\n" +
			"-A FORWARD -i br0 -p tcp -m tcp --dport 853 -j REJECT --reject-with tcp-reset\n" +
			"-A FORWARD -i br0 -p tcp -m tcp --dport 53 -j REJECT --reject-with tcp-reset\n" +
			"-A FORWARD -i br0 -p udp -m udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable\n",
	}
	rules := keeneticDNSRules(k.Ipset.Script)
	if len(rules) != 6 {
		t.Fatalf("rules = %+v", rules)
	}
	for _, r := range rules {
		if !iptablesDumpHasRule(printed[r.keeneticChainRef], r.chain, r.spec) {
			t.Errorf("%s %s %s: %q not found in its printed form", r.tool, r.table, r.chain, r.spec)
		}
	}
}
