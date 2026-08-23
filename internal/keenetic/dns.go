package keenetic

// dns.go builds the fakeip DNS plane that hides censored-domain lookups from the RU ISP DPI
// (the red-team's #1 anti-leak item — the generator emits NO dns{} today, sniff-only, which
// leaks plaintext DNS/SNI). Mechanism: censored domains resolve to a synthetic fakeip range
// (so the routing decision is made at DNS time, robust to no-SNI/ECH/QUIC); the real answer
// is fetched over a tunnel via DoH PINNED-BY-IP (never a hostname → no bootstrap A-lookup,
// no cleartext leak). Non-censored lookups use the local resolver (keeps RU GeoDNS + the
// device AdGuard filtering). Validated against the device's sing-box 1.13.3.

// DNSOptions configure the fakeip DNS block.
type DNSOptions struct {
	DoHServer    string   // IP-literal DoH upstream for censored real-answer resolution, e.g. "1.1.1.1" (NEVER a hostname)
	DoHDetour    string   // outbound tag the DoH query is routed through (a tunnel, e.g. "wgtest") — no cleartext WAN leak
	FakeIPRange  string   // synthetic v4 range, e.g. "198.18.0.0/15" (must NOT overlap the TUN host address)
	CensoredSets []string // route rule_set tags whose domains resolve to fakeip
}

func (o *DNSOptions) defaults() {
	if o.DoHServer == "" {
		o.DoHServer = "1.1.1.1"
	}
	if o.FakeIPRange == "" {
		o.FakeIPRange = "198.18.0.0/15"
	}
}

// fakeipDNS builds the sing-box (≥1.12 typed-server format) dns{} block: a DoH server routed
// over a tunnel for censored real-answer resolution, a `local` server for everything else,
// and a fakeip server that the censored rule_sets resolve to. `final: dns_local` keeps
// non-censored lookups on the system resolver.
func fakeipDNS(o DNSOptions) map[string]any {
	o.defaults()
	rules := []map[string]any{}
	if len(o.CensoredSets) > 0 {
		rules = append(rules, map[string]any{"rule_set": o.CensoredSets, "server": "dns_fakeip"})
	}
	return map[string]any{
		"servers": []map[string]any{
			{"tag": "dns_doh", "type": "https", "server": o.DoHServer, "detour": o.DoHDetour},
			{"tag": "dns_local", "type": "local"},
			{"tag": "dns_fakeip", "type": "fakeip", "inet4_range": o.FakeIPRange},
		},
		"rules":             rules,
		"final":             "dns_local",
		"independent_cache": true,
	}
}

// keeneticTUN is the routing TUN inbound for KeeneticOS: NDM owns the default route into it
// (auto_route:false — sing-box does NOT install routes), gvisor stack (no TUN-module privilege
// issues), a fixed interface_name so NDM can `ip route … dev <name>`.
func keeneticTUN(tag, ifname, addr string, mtu int) map[string]any {
	if mtu == 0 {
		mtu = 1400
	}
	return map[string]any{
		"type": "tun", "tag": tag, "interface_name": ifname,
		"address": []string{addr}, "mtu": mtu,
		"auto_route": false, "strict_route": false, "stack": "gvisor",
	}
}
