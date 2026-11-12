package dnscheck

import "time"

// DemoScenarios names the canned reports the demo panel shows, so every state of the page can be seen
// and tested without a router. Addresses of the household's own side are documentation ranges.
func DemoScenarios() []string {
	return []string{"leak", "tunnel_plain", "encrypted", "forged", "partial", "unknown"}
}

var (
	demoWAN  = Path{Iface: "eth3", Kind: PathWAN, Label: "provider"}
	demoFI   = Path{Iface: "nwg1", Kind: PathTunnel, Label: "Norway"}
	demoCY   = Path{Iface: "nwg0", Kind: PathTunnel, Label: "Malta"}
	demoHome = Path{Kind: PathRouter, Label: "router"}
)

func demoGenuine(addr, op string, p Path, ms int, site string) ResolverResult {
	return ResolverResult{
		Address: addr, Operator: op, Path: p, Verdict: VerdictGenuine, RttMs: ms, Site: site,
		Probes: []Probe{
			{ID: ProbeBase, Status: StatusPass, Code: CodeOK, Ms: ms},
			{ID: ProbeIdentity, Status: StatusPass, Code: CodeOK, Detail: site},
			{ID: ProbeBogus, Status: StatusPass, Code: CodeOK},
			{ID: ProbeSigned, Status: StatusPass, Code: CodeOK},
			{ID: ProbeNXDomain, Status: StatusPass, Code: CodeOK},
			{ID: ProbeSecondReply, Status: StatusPass, Code: CodeOK},
			{ID: ProbeSource, Status: StatusPass, Code: CodeOK},
			{ID: ProbeCanary, Status: StatusPass, Code: CodeOK, Detail: "6/6"},
		},
	}
}

func demoClear(p Path) Interception {
	return Interception{Path: p, Status: StatusPass, Code: CodeOK}
}

func demoEnc(addr, op string, p Path, proto, cert string, ms int) EncryptedResult {
	return EncryptedResult{Address: addr, Operator: op, Path: p, Proto: proto, Status: StatusPass, CertName: cert, RttMs: ms}
}

// DemoReport returns the named canned report, or the first one for an unknown name.
func DemoReport(scenario string) Report {
	now := time.Now().UTC()
	r := Report{Version: 1, Demo: true, Scenario: scenario, StartedAt: now.Add(-8 * time.Second), FinishedAt: now, Full: true}
	tunnelRows := []ChainHint{{Address: "1.1.1.1", Via: "norway"}, {Address: "8.8.8.8", Via: "malta"}}
	switch scenario {
	case "tunnel_plain":
		r.Level = LevelTunnelPlain
		r.Path = PathReport{
			Answering: "dnsmasq", Measured: true, SampleSec: 12, Exposure: ExposureExit,
			Upstreams: []Upstream{
				{Address: "1.1.1.1", Iface: "nwg1", Kind: "plain", ViaTunnel: true, Label: "Norway"},
				{Address: "8.8.8.8", Iface: "nwg0", Kind: "plain", ViaTunnel: true, Label: "Malta"},
				{Address: "1.0.0.1", Kind: "plain", LastResort: true},
			},
			Flows: []Flow{
				{Iface: "nwg1", Kind: PathTunnel, Server: "1.1.1.1", Port: 53, Proto: "udp", Flows: 121, Replied: 121, FromCanary: true},
				{Iface: "nwg0", Kind: PathTunnel, Server: "8.8.8.8", Port: 53, Proto: "udp", Flows: 1, Replied: 1},
				{Iface: "eth3", Kind: PathWAN, Server: "1.0.0.1", Port: 53, Proto: "udp", Flows: 2, Replied: 2},
				{Iface: "eth3", Kind: PathWAN, Server: "1.1.1.1", Port: 53, Proto: "udp", Flows: 12, Replied: 12},
			},
			OwnResolvConf: []string{"1.1.1.1"},
		}
		r.Interception = []Interception{demoClear(demoWAN), demoClear(demoFI), demoClear(demoCY)}
		r.Resolvers = []ResolverResult{
			demoGenuine("1.1.1.1", "cloudflare", demoFI, 53, "arn02"),
			demoGenuine("8.8.8.8", "google", demoCY, 155, ""),
			demoGenuine("1.1.1.1", "cloudflare", demoWAN, 18, "dme06"),
		}
		r.Encrypted = []EncryptedResult{
			demoEnc("1.1.1.1", "cloudflare", demoFI, "doh", "cloudflare-dns.com", 182),
			demoEnc("1.1.1.1", "cloudflare", demoFI, "dot", "cloudflare-dns.com", 241),
			demoEnc("8.8.8.8", "google", demoFI, "doh", "dns.google", 214),
		}
		r.Warnings = []Warning{
			{ID: WarnPlainLastResort, Severity: SeverityWarn, Facts: []string{"1.0.0.1", "2"}},
			{ID: WarnProfileNotServed, Severity: SeverityInfo},
			{ID: WarnOwnLookupsPlain, Severity: SeverityInfo, Facts: []string{"1.1.1.1"}},
		}
		r.Options = []Option{
			{ID: OptEncryptedUpstream, Recommended: true, Gives: LevelTunnelEncrypted, Action: Action{Kind: "section", Target: "dns-fast"}},
			{ID: OptRemoveLastResort, Action: Action{Kind: "chain", Rows: tunnelRows}},
		}
	case "encrypted":
		r.Level = LevelTunnelEncrypted
		r.Path = PathReport{
			Answering: "dnsmasq", Measured: true, SampleSec: 12, Exposure: ExposureResolver,
			Upstreams: []Upstream{
				{Address: "127.0.0.1", Port: 5353, Kind: "local", Label: "sing-box"},
				{Address: "1.1.1.1", Iface: "nwg1", Kind: "plain", ViaTunnel: true, Label: "Norway"},
			},
			OwnResolvConf: []string{"1.1.1.1"},
		}
		r.Interception = []Interception{demoClear(demoWAN), demoClear(demoFI)}
		r.Resolvers = []ResolverResult{demoGenuine("1.1.1.1", "cloudflare", demoFI, 53, "arn02")}
		r.Encrypted = []EncryptedResult{demoEnc("1.1.1.1", "cloudflare", demoFI, "doh", "cloudflare-dns.com", 182)}
		r.Warnings = []Warning{{ID: WarnOwnLookupsPlain, Severity: SeverityInfo, Facts: []string{"1.1.1.1"}}}
	case "forged":
		r.Level = LevelProviderPlain
		r.Path = PathReport{
			Answering: "dnsmasq", Measured: true, SampleSec: 12, Exposure: ExposureProvider,
			Upstreams: []Upstream{{Address: "8.8.8.8", Kind: "plain"}},
			Flows:     []Flow{{Iface: "eth3", Kind: PathWAN, Server: "8.8.8.8", Port: 53, Proto: "udp", Flows: 40, Replied: 40, FromCanary: true}},
		}
		r.Interception = []Interception{
			{Path: demoWAN, Status: StatusFail, Code: CodeDecoyAnswered, Intercepted: true, Detail: "192.0.2.1"},
			demoClear(demoFI),
		}
		forged := ResolverResult{
			Address: "8.8.8.8", Operator: "google", Path: demoWAN, Verdict: VerdictForged, RttMs: 2,
			Probes: []Probe{
				{ID: ProbeBase, Status: StatusPass, Code: CodeOK, Ms: 2},
				{ID: ProbeInterception, Status: StatusFail, Code: CodePathIntercepted, Detail: "192.0.2.1"},
				{ID: ProbeIdentity, Status: StatusFail, Code: CodeIdentityMismatch, Detail: "203.0.113.53"},
				{ID: ProbeBogus, Status: StatusFail, Code: CodeBogusAccepted, Detail: "203.0.113.80"},
				{ID: ProbeSigned, Status: StatusWarn, Code: CodeADMissing},
				{ID: ProbeNXDomain, Status: StatusFail, Code: CodeNXRewritten, Detail: "203.0.113.80"},
				{ID: ProbeSecondReply, Status: StatusFail, Code: CodeSecondReply, Detail: "facebook.com"},
				{ID: ProbeCanary, Status: StatusFail, Code: CodeCanaryBadCert, Detail: "facebook.com 203.0.113.80"},
			},
		}
		r.Resolvers = []ResolverResult{forged, demoGenuine("8.8.8.8", "google", demoFI, 63, "")}
		r.Encrypted = []EncryptedResult{
			{Address: "8.8.8.8", Operator: "google", Path: demoWAN, Proto: "dot", Status: StatusNoData},
			demoEnc("8.8.8.8", "google", demoFI, "doh", "dns.google", 214),
		}
		r.Warnings = []Warning{
			{ID: WarnPathIntercepted, Severity: SeverityCritical, Facts: []string{"eth3"}},
			{ID: WarnResolverForged, Severity: SeverityCritical, Facts: []string{"8.8.8.8", "eth3"}},
			{ID: WarnPlainOnProvider, Severity: SeverityCritical, Facts: []string{"8.8.8.8"}},
			{ID: WarnClientsBypass, Severity: SeverityWarn, Facts: []string{"br1"}},
		}
		r.Options = []Option{
			{ID: OptChainIntoTunnels, Recommended: true, Gives: LevelTunnelPlain, Action: Action{Kind: "chain", Rows: tunnelRows}},
			{ID: OptInterceptOn, Action: Action{Kind: "section", Target: "dns-toggles"}},
		}
	case "partial":
		r.Level = LevelTunnelPlain
		r.Path = PathReport{
			Answering: "dnsmasq", Measured: true, SampleSec: 12, Exposure: ExposureExit,
			Upstreams: []Upstream{{Address: "1.1.1.1", Iface: "nwg4", Kind: "plain", ViaTunnel: true, Label: "Poland"}},
			Flows:     []Flow{{Iface: "nwg4", Kind: PathTunnel, Server: "1.1.1.1", Port: 53, Proto: "udp", Flows: 30, Replied: 30, FromCanary: true}},
		}
		poland := Path{Iface: "nwg4", Kind: PathTunnel, Label: "Poland"}
		ca := Path{Iface: "awg1", Kind: PathTunnel, Label: "Canada"}
		r.Interception = []Interception{demoClear(poland), demoClear(ca), {Path: demoWAN, Status: StatusNoData, Code: CodeNoReply}}
		r.Resolvers = []ResolverResult{
			{Address: "1.1.1.1", Operator: "cloudflare", Path: poland, Verdict: VerdictPartial, RttMs: 70, Probes: []Probe{
				{ID: ProbeBase, Status: StatusPass, Code: CodeOK, Ms: 70},
				{ID: ProbeIdentity, Status: StatusNoData, Code: CodeIdentitySilent},
				{ID: ProbeBogus, Status: StatusPass, Code: CodeOK},
				{ID: ProbeSigned, Status: StatusPass, Code: CodeOK},
				{ID: ProbeNXDomain, Status: StatusPass, Code: CodeOK},
				{ID: ProbeCanary, Status: StatusNoData, Code: CodeCanaryUnverified, Detail: "2/6"},
			}},
			{Address: "1.1.1.1", Operator: "cloudflare", Path: ca, Verdict: VerdictUnreachable, Probes: []Probe{
				{ID: ProbeBase, Status: StatusNoData, Code: CodeNoReply},
			}},
			{Address: "198.51.100.53", Path: poland, Verdict: VerdictUnknownOperator, RttMs: 90, Probes: []Probe{
				{ID: ProbeBase, Status: StatusPass, Code: CodeOK, Ms: 90},
				{ID: ProbeNXDomain, Status: StatusPass, Code: CodeOK},
				{ID: ProbeSigned, Status: StatusWarn, Code: CodeNotValidating},
				{ID: ProbeCanary, Status: StatusPass, Code: CodeOK, Detail: "6/6"},
			}},
			{Address: "127.0.0.1", Path: demoHome, Verdict: VerdictUnknownOperator, Probes: []Probe{
				{ID: ProbeCanary, Status: StatusSkipped, Code: CodeCanaryOnWANOff},
			}},
		}
		r.Warnings = []Warning{
			{ID: WarnSinglePath, Severity: SeverityWarn, Facts: []string{"nwg4"}},
			{ID: WarnEncryptedEscape, Severity: SeverityWarn},
			{ID: WarnIPv6Gap, Severity: SeverityWarn, Facts: []string{"br0"}},
		}
		r.Options = []Option{
			{ID: OptAddSecondTunnel, Recommended: true, Action: Action{Kind: "chain", Rows: []ChainHint{
				{Address: "1.1.1.1", Via: "poland"},
				{Address: "8.8.8.8", Via: "canada"},
			}}},
			{ID: OptBlockEncrypted, Action: Action{Kind: "section", Target: "dns-toggles"}},
		}
	case "unknown":
		r.Level = LevelUnknown
		r.Full = false
		r.Path = PathReport{Exposure: ExposureUnknown}
		r.Warnings = []Warning{{ID: WarnNotMeasured, Severity: SeverityInfo}}
	default: // leak
		r.Scenario = "leak"
		r.Level = LevelProviderPlain
		r.Path = PathReport{
			Answering: "dnsmasq", Measured: true, SampleSec: 12, Exposure: ExposureProvider,
			Upstreams: []Upstream{{Address: "1.1.1.1", Kind: "plain"}, {Address: "8.8.8.8", Kind: "plain"}},
			Flows: []Flow{
				{Iface: "eth3", Kind: PathWAN, Server: "1.1.1.1", Port: 53, Proto: "udp", Flows: 406, Replied: 406, FromCanary: true},
				{Iface: "eth3", Kind: PathWAN, Server: "8.8.8.8", Port: 53, Proto: "udp", Flows: 5, Replied: 5},
			},
			OwnResolvConf: []string{"1.1.1.1"},
		}
		r.Interception = []Interception{demoClear(demoWAN), demoClear(demoFI), demoClear(demoCY)}
		r.Resolvers = []ResolverResult{
			demoGenuine("1.1.1.1", "cloudflare", demoWAN, 18, "dme06"),
			demoGenuine("8.8.8.8", "google", demoWAN, 48, ""),
			demoGenuine("1.1.1.1", "cloudflare", demoFI, 53, "arn02"),
		}
		r.Encrypted = []EncryptedResult{
			demoEnc("1.1.1.1", "cloudflare", demoWAN, "dot", "cloudflare-dns.com", 184),
			demoEnc("1.1.1.1", "cloudflare", demoFI, "doh", "cloudflare-dns.com", 182),
		}
		r.Warnings = []Warning{
			{ID: WarnPlainOnProvider, Severity: SeverityCritical, Facts: []string{"1.1.1.1", "411"}},
			{ID: WarnProfileNotServed, Severity: SeverityInfo},
		}
		r.Options = []Option{
			{ID: OptChainIntoTunnels, Recommended: true, Gives: LevelTunnelPlain, Action: Action{Kind: "chain", Rows: tunnelRows}},
			{ID: OptEncryptedUpstream, Gives: LevelTunnelEncrypted, Action: Action{Kind: "section", Target: "dns-fast"}},
		}
	}
	return r
}
