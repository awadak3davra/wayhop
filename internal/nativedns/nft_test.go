package nativedns

import "testing"

// Fixtures are shaped like real `nft list ruleset` output from OpenWrt fw4, which is what the test
// AX3000T runs. The point of each is a distinction the iptables scanner never had to make, because
// `iptables -t nat -S` prints only the nat table while nft prints everything at once.

const fw4Redirect = `table inet fw4 {
	chain input {
		type filter hook input priority filter; policy drop;
		udp dport 53 counter packets 12 bytes 900 accept comment "!fw4: Allow-DNS"
	}
	chain dstnat {
		type nat hook prerouting priority dstnat; policy accept;
		meta nfproto ipv4 udp dport 53 counter packets 4 bytes 300 redirect to :41100 comment "!fw4: Divert-DNS"
		meta nfproto ipv4 tcp dport 53 counter packets 0 bytes 0 redirect to :41100 comment "!fw4: Divert-DNS"
	}
}
`

const fw4DnatSet = `table inet fw4 {
	chain dstnat {
		type nat hook prerouting priority dstnat; policy accept;
		ip saddr 10.0.0.0/24 meta l4proto { tcp, udp } th dport { 53, 5353 } dnat ip to 10.0.0.1:5353
	}
}
`

// The trap this parser exists for: a :53 rule that is NOT a redirect, in a chain that is not nat.
const fw4AcceptOnly = `table inet fw4 {
	chain input {
		type filter hook input priority filter; policy drop;
		udp dport 53 counter accept comment "!fw4: Allow-DNS"
		tcp dport 53 counter accept comment "!fw4: Allow-DNS"
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
		udp dport 53 counter accept
	}
}
`

const fw4WithDoT = `table inet fw4 {
	chain dstnat {
		type nat hook prerouting priority dstnat; policy accept;
		udp dport 53 redirect to :41100
	}
	chain forward {
		type filter hook forward priority filter; policy drop;
		tcp dport 853 counter packets 3 bytes 180 reject comment "!fw4: block-DoT"
	}
}
`

func TestDetectFromNft_RedirectInNatPrerouting(t *testing.T) {
	f := DetectFromNft(fw4Redirect)
	if !f.Parsed {
		t.Fatal("a real ruleset must parse")
	}
	if !f.Hijack53 {
		t.Error("a redirect of :53 in the nat prerouting chain is a hijack")
	}
	if f.Hijack53To != "41100" {
		t.Errorf("target should be read from the rule, got %q", f.Hijack53To)
	}
	if f.DoTHandled {
		t.Error("nothing in this ruleset touches :853")
	}
}

// The distinction that does not exist in the iptables path: accepting :53 in a filter chain is not
// a redirect. Reading it as one would report every OpenWrt box as hijacking DNS.
func TestDetectFromNft_AcceptIsNotAHijack(t *testing.T) {
	f := DetectFromNft(fw4AcceptOnly)
	if !f.Parsed {
		t.Fatal("a real ruleset must parse")
	}
	if f.Hijack53 {
		t.Error("an accept rule in a filter chain is not a :53 redirect")
	}
	if f.Hijack53To != "" {
		t.Errorf("no target should have been recorded, got %q", f.Hijack53To)
	}
}

// nft port sets and dnat targets are both idioms iptables output never produces.
func TestDetectFromNft_DnatAndPortSets(t *testing.T) {
	f := DetectFromNft(fw4DnatSet)
	if !f.Hijack53 {
		t.Error("a dnat of a port SET containing 53 is still a hijack")
	}
	if f.Hijack53To != "10.0.0.1:5353" {
		t.Errorf("target should be the dnat destination, got %q", f.Hijack53To)
	}
}

func TestDetectFromNft_DoTHandledAnywhere(t *testing.T) {
	f := DetectFromNft(fw4WithDoT)
	if !f.Hijack53 {
		t.Error("the :53 redirect should still be seen")
	}
	if !f.DoTHandled {
		t.Error("a reject of :853 in the forward chain means the router manages DoT bypass")
	}
}

// Nothing usable in, nothing asserted out. Parsed=false is what stops an empty read being reported
// as "this router has no redirect" — the absence-as-evidence mistake AUD-43 was about.
func TestDetectFromNft_UnparseableInputAssertsNothing(t *testing.T) {
	for _, in := range []string{
		"",
		"   \n\t\n",
		"sh: nft: not found",
		"Error: Could not process rule: Operation not permitted",
	} {
		f := DetectFromNft(in)
		if f.Parsed {
			t.Errorf("%q is not a ruleset, Parsed must be false", in)
		}
		if f.Hijack53 || f.DoTHandled {
			t.Errorf("%q established nothing, yet something was reported: %+v", in, f)
		}
	}
}

// A ruleset that genuinely contains no DNS rule parses fine and asserts nothing about DNS — which
// is a different answer from "could not read", and the caller relies on telling them apart.
func TestDetectFromNft_EmptyRulesetParsesButFindsNothing(t *testing.T) {
	f := DetectFromNft("table inet fw4 {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n")
	if !f.Parsed {
		t.Fatal("a well-formed ruleset with no DNS rule still parsed")
	}
	if f.Hijack53 || f.DoTHandled {
		t.Errorf("no DNS rule present, nothing should be claimed: %+v", f)
	}
}

// Captured verbatim from the test AX3000T (OpenWrt 25.12.2, fw4, https-dns-proxy installed). This
// is the shape the synthetic fixtures above got WRONG: fw4 does not put per-zone dstnat rules in the
// base chain. The base `dstnat` chain carries only a jump, and the redirect lives in `dstnat_lan`,
// a regular chain with no hook declaration of its own.
//
// The first parser required the rule to sit in a chain that was itself hooked to nat prerouting, so
// on the real device it reported hijack53=false while 309,402 UDP packets had been redirected
// through that very rule. The DNS page then told the user their clients could bypass the router's
// DNS — the exact opposite of what the firewall was doing.
const fw4RealZoneSubchain = `table inet fw4 {
	chain dstnat {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "br-lan" jump dstnat_lan comment "!fw4: Handle lan IPv4/IPv6 dstnat traffic"
	}

	chain dstnat_lan {
		tcp dport 53 counter packets 83736 bytes 4355752 redirect to :53 comment "!fw4: ubus:https-dns-proxy[instance1] redirect 0"
		udp dport 53 counter packets 309402 bytes 21436231 redirect to :53 comment "!fw4: ubus:https-dns-proxy[instance1] redirect 0"
	}
}
`

func TestDetectFromNft_RedirectInAZoneSubchain(t *testing.T) {
	f := DetectFromNft(fw4RealZoneSubchain)
	if !f.Parsed {
		t.Fatal("a real ruleset must parse")
	}
	if !f.Hijack53 {
		t.Error("a redirect reached by a jump FROM nat prerouting is still a :53 hijack — " +
			"fw4 puts per-zone rules in dstnat_<zone>, never in the base chain")
	}
	if f.Hijack53To != "53" {
		t.Errorf("target should be read from the rule, got %q", f.Hijack53To)
	}
}

// The jump must be followed only from a chain that is actually in the prerouting path. A redirect in
// a chain reached from OUTPUT or from a filter chain is not a LAN hijack, and treating every regular
// chain as reachable would turn this fix into the opposite error.
func TestDetectFromNft_JumpFromANonPreroutingChainIsNotAHijack(t *testing.T) {
	ruleset := `table inet fw4 {
	chain output {
		type nat hook output priority dstnat; policy accept;
		jump local_redirects
	}

	chain local_redirects {
		udp dport 53 counter redirect to :5353
	}
}
`
	if f := DetectFromNft(ruleset); f.Hijack53 {
		t.Error("a redirect reached only from the OUTPUT hook does not force LAN DNS through the router")
	}
}

// A chain closing must not leak its hook into the next one, or a filter rule following a nat chain
// would be counted as a redirect.
func TestDetectFromNft_ChainContextDoesNotLeak(t *testing.T) {
	ruleset := `table inet fw4 {
	chain dstnat {
		type nat hook prerouting priority dstnat; policy accept;
		udp dport 5353 redirect to :41100
	}
	chain input {
		type filter hook input priority filter; policy drop;
		udp dport 53 counter accept
	}
}
`
	if f := DetectFromNft(ruleset); f.Hijack53 {
		t.Error("the :53 accept sits in the filter chain that FOLLOWS the nat chain — context leaked")
	}
}
