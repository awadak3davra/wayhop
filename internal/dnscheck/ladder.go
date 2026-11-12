package dnscheck

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// AdviseInput is everything the ladder reads.
type AdviseInput struct {
	Path         PathReport
	Interception []Interception
	Resolvers    []ResolverResult
	Encrypted    []EncryptedResult
	// What the page's controls say, which only the server knows.
	InterceptOn      bool     // LAN :53 is forced to the router
	BypassGaps       []string // interfaces where it is not
	EncryptedEscape  bool     // clients can reach DoT or public DoH
	IPv6Gaps         []string
	ProfileEncrypted bool     // the DNS page has encrypted resolvers
	ProfileServes    bool     // and they answer clients
	EncryptedDetour  string   // the outbound they leave by: "direct" means the provider's line
	TunnelVia        []string // outbound ids usable for chain rows, in preference order
	// ViaByIface turns an existing kernel binding back into the outbound id the chain editor accepts.
	ViaByIface map[string]string
	// ChainLocked: this platform has no chain editor to open.
	ChainLocked bool
}

// SettleMeasured withdraws "measured" when the table shows nothing for a plain first row. The test lookup
// must have left by some row, so silence means this table does not track the router's own traffic, and a
// page saying "measured, 0 lookups" would be stating what never happened.
func SettleMeasured(p PathReport) PathReport {
	if !p.Measured || len(p.Upstreams) == 0 || p.Upstreams[0].Kind != "plain" {
		return p
	}
	for _, f := range p.Flows {
		if f.FromCanary {
			return p
		}
	}
	p.Measured, p.SampleSec = false, 0
	return p
}

// LevelOf places a measured path on the ladder.
func LevelOf(in AdviseInput) Level {
	if in.Path.Measured {
		// A flow beats configuration: in particular, a dead local first row falls through to a plain
		// row, and only the test lookup can show which one actually answered.
		if level, ok := canaryLevel(in.Path); ok {
			return level
		}
	}
	if len(in.Path.Upstreams) == 0 {
		return LevelUnknown
	}
	first := in.Path.Upstreams[0]
	switch first.Kind {
	case "local", "doh", "dot":
		if first.Kind != "local" && first.LeavesBy != "" {
			// Seen on a test router: https-dns-proxy to 1.1.1.1 routed through a tunnel, called the provider's
			// line because the page read sing-box's detour, which this proxy has nothing to do with. The
			// same box sent 8.8.8.8 by the provider: dnsmasq picks among these rows, so the worst one counts.
			for _, u := range in.Path.Upstreams {
				if (u.Kind == "doh" || u.Kind == "dot") && u.LeavesBy != "" && !u.ViaTunnel {
					return LevelProviderEncrypted
				}
			}
			return LevelTunnelEncrypted
		}
		if in.EncryptedDetour != "" && in.EncryptedDetour != "direct" {
			return LevelTunnelEncrypted
		}
		return LevelProviderEncrypted
	}
	if first.ViaTunnel {
		return LevelTunnelPlain
	}
	if first.Kind == "plain" {
		host := upstreamHost(first)
		if ip := net.ParseIP(host); ip != nil {
			if ip.IsLoopback() {
				return LevelUnknown
			}
			if ip.IsPrivate() && first.Iface == "" {
				for _, u := range in.Path.Upstreams {
					if strings.HasPrefix(u.Iface, "br") {
						return LevelUnknown
					}
				}
				return LevelProviderPlain
			}
		}
		if first.Iface != "" && strings.HasPrefix(first.Iface, "br") {
			return LevelUnknown
		}
		return LevelProviderPlain
	}
	return LevelUnknown
}

// canaryLevel reads the test lookup's flow. Its window also catches whatever else the router sent, such
// as its own lookups, which stay on the provider's line on purpose. Taken alone, one of those would say
// the provider reads everything. So a flow counts only when it fits a chain row, and the earliest row
// that took one wins: a later row only answers what an earlier one failed.
func canaryLevel(p PathReport) (Level, bool) {
	levelOf := func(f Flow) (Level, bool) {
		switch f.Kind {
		case PathTunnel:
			return LevelTunnelPlain, true
		case PathWAN:
			return LevelProviderPlain, true
		}
		return "", false
	}
	// Seen in the lab: a chain of 127.0.0.1#5353 then 1.1.1.1 read as the provider's line, because the
	// router's own lookups also go to 1.1.1.1. When the first row answers, it is the one taking them.
	firstAnswered := p.FirstRowAnswered && len(p.Upstreams) > 0 && encryptedFirstRow(p.Upstreams[0])
	if !firstAnswered {
		for _, u := range p.Upstreams {
			for _, f := range p.Flows {
				if f.FromCanary && flowOnUpstream(f, u) {
					if level, ok := levelOf(f); ok {
						return level, true
					}
				}
			}
		}
	}
	if len(p.Upstreams) > 0 {
		if encryptedFirstRow(p.Upstreams[0]) {
			for _, kind := range []PathKind{PathWAN, PathTunnel} {
				for _, f := range p.Flows {
					if f.FromCanary && f.Port == 53 && f.Kind == kind {
						if inOwnResolvConf(f.Server, p.OwnResolvConf) || onAnyRow(f, p.Upstreams) {
							continue
						}
						return levelOf(f)
					}
				}
			}
		}
		return "", false
	}
	// The chain could not be read, so the flow's own path is all there is. The provider's line first:
	// that is the worse reading.
	for _, kind := range []PathKind{PathWAN, PathTunnel} {
		for _, f := range p.Flows {
			if f.FromCanary && f.Port == 53 && f.Kind == kind {
				return levelOf(f)
			}
		}
	}
	return "", false
}

func encryptedFirstRow(u Upstream) bool {
	return u.Kind == "local" || u.Kind == "doh" || u.Kind == "dot"
}

func onAnyRow(f Flow, rows []Upstream) bool {
	for _, u := range rows {
		if flowOnUpstream(f, u) {
			return true
		}
	}
	return false
}

func inOwnResolvConf(server string, own []string) bool {
	for _, s := range own {
		if sameResolver(server, s) {
			return true
		}
	}
	return false
}

func flowOnUpstream(f Flow, u Upstream) bool {
	port := u.Port
	if port == 0 {
		port = 53
	}
	if f.Port != port || !sameResolver(f.Server, upstreamHost(u)) {
		return false
	}
	return u.Iface == "" || f.Iface == u.Iface
}

// Advise turns the measurements into warnings and options, worst and cheapest first.
func Advise(in AdviseInput) ([]Warning, []Option) {
	level := LevelOf(in)
	var warnings []Warning
	addWarning := func(id string, severity Severity, facts ...string) {
		warnings = append(warnings, Warning{ID: id, Severity: severity, Facts: facts})
	}

	for _, i := range in.Interception {
		if i.Intercepted {
			addWarning(WarnPathIntercepted, SeverityCritical, i.Path.Iface)
		}
	}
	for i := range in.Path.Upstreams {
		u := &in.Path.Upstreams[i]
		if r, ok := forgedOnUpstream(in, i); ok {
			iface := r.Path.Iface
			if iface == "" {
				iface = u.Iface
			}
			addWarning(WarnResolverForged, SeverityCritical, r.Address, iface)
		}
	}
	if level == LevelProviderPlain {
		server, count := "", 0
		for _, f := range in.Path.Flows {
			if f.Kind != PathWAN || f.Port != 53 {
				continue
			}
			count += f.Flows
			if server == "" || f.FromCanary {
				server = f.Server
			}
		}
		if server == "" && len(in.Path.Upstreams) > 0 {
			server = upstreamHost(in.Path.Upstreams[0])
		}
		if count > 0 {
			addWarning(WarnPlainOnProvider, SeverityCritical, server, strconv.Itoa(count))
		} else {
			addWarning(WarnPlainOnProvider, SeverityCritical, server)
		}
	}
	var lastResort []string
	lastResortFlows := 0
	for _, u := range in.Path.Upstreams {
		if !u.LastResort {
			continue
		}
		port := u.Port
		if port == 0 {
			port = 53
		}
		lastResort = append(lastResort, upstreamHost(u))
		for _, f := range in.Path.Flows {
			if f.Kind == PathWAN && sameResolver(f.Server, upstreamHost(u)) && f.Port == port {
				lastResortFlows += f.Flows
			}
		}
	}
	if len(lastResort) > 0 {
		addWarning(WarnPlainLastResort, SeverityWarn, strings.Join(lastResort, ", "), strconv.Itoa(lastResortFlows))
	}
	if !in.InterceptOn || len(in.BypassGaps) > 0 {
		addWarning(WarnClientsBypass, SeverityWarn, in.BypassGaps...)
	}
	if in.EncryptedEscape && level != LevelUnknown && level != LevelProviderPlain {
		addWarning(WarnEncryptedEscape, SeverityWarn)
	}
	if len(in.IPv6Gaps) > 0 {
		addWarning(WarnIPv6Gap, SeverityWarn, in.IPv6Gaps...)
	}
	single, singleIface := singleUsablePath(in)
	if single {
		addWarning(WarnSinglePath, SeverityWarn, singleIface)
	}
	encryptedDirect := in.EncryptedDetour == "direct" && in.ProfileEncrypted && in.ProfileServes
	if encryptedDirect {
		addWarning(WarnEncryptedDirect, SeverityWarn)
	}
	if in.ProfileEncrypted && !in.ProfileServes && (level == LevelProviderPlain || level == LevelTunnelPlain) {
		addWarning(WarnProfileNotServed, SeverityInfo)
	}
	if len(in.Path.OwnResolvConf) > 0 {
		addWarning(WarnOwnLookupsPlain, SeverityInfo, in.Path.OwnResolvConf...)
	}
	if level == LevelUnknown {
		addWarning(WarnNotMeasured, SeverityInfo)
	}

	hasWarning := func(id string) bool {
		for _, w := range warnings {
			if w.ID == id {
				return true
			}
		}
		return false
	}
	var options []Option
	addOption := func(id string, gives Level, action Action) {
		options = append(options, Option{
			ID: id, Recommended: len(options) == 0, Gives: gives, Action: action,
		})
	}
	chainAction := func(rows []ChainHint) Action { return Action{Kind: "chain", Rows: rows} }
	sectionAction := func(target string) Action { return Action{Kind: "section", Target: target} }

	if hasWarning(WarnResolverForged) && !in.ChainLocked {
		if rows, ok := replacementRows(in); ok {
			addOption(OptReplaceResolver, "", chainAction(rows))
		}
	}
	if level == LevelProviderPlain && len(in.TunnelVia) > 0 && !in.ChainLocked {
		if rows := tunnelChainRows(in); len(rows) > 0 {
			addOption(OptChainIntoTunnels, LevelTunnelPlain, chainAction(rows))
		}
	}
	if single && len(in.TunnelVia) > 0 && !in.ChainLocked {
		if rows, ok := secondTunnelRows(in); ok {
			addOption(OptAddSecondTunnel, "", chainAction(rows))
		}
	}
	if hasWarning(WarnClientsBypass) {
		addOption(OptInterceptOn, "", sectionAction("dns-toggles"))
	}
	encryptedOnTunnel := false
	for _, e := range in.Encrypted {
		if e.Path.Kind == PathTunnel && e.Status == StatusPass && (e.Proto == "doh" || e.Proto == "dot") {
			encryptedOnTunnel = true
			break
		}
	}
	if (level == LevelTunnelPlain || level == LevelProviderPlain) && encryptedOnTunnel && len(in.TunnelVia) > 0 {
		addOption(OptEncryptedUpstream, LevelTunnelEncrypted, sectionAction("dns-fast"))
	}
	if encryptedDirect && len(in.TunnelVia) > 0 {
		addOption(OptEncryptedInTunnel, LevelTunnelEncrypted, sectionAction("dns-fast"))
	}
	if hasWarning(WarnEncryptedEscape) {
		addOption(OptBlockEncrypted, "", sectionAction("dns-toggles"))
	}
	if hasWarning(WarnPlainLastResort) && !in.ChainLocked {
		if rows := existingRows(in, false); len(rows) > 0 {
			addOption(OptRemoveLastResort, "", chainAction(rows))
		}
	}
	return warnings, options
}

func chainHintAddress(u Upstream) string {
	if (u.Kind == "doh" || u.Kind == "dot") && u.Port > 0 {
		return "127.0.0.1"
	}
	return upstreamHost(u)
}

func upstreamHost(u Upstream) string {
	addr := strings.TrimSpace(u.Address)
	if strings.Contains(addr, "://") {
		if parsed, err := url.Parse(addr); err == nil && parsed.Hostname() != "" {
			return parsed.Hostname()
		}
	}
	if i := strings.IndexByte(addr, '#'); i >= 0 {
		addr = addr[:i]
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	return strings.Trim(addr, "[]")
}

func sameResolver(a, b string) bool {
	a, b = strings.Trim(a, "[]"), strings.Trim(b, "[]")
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	if ia != nil && ib != nil {
		return ia.Equal(ib)
	}
	return strings.EqualFold(a, b)
}

func resultOnUpstream(r ResolverResult, u Upstream) bool {
	if u.Port != 0 && u.Port != 53 {
		return false
	}
	return sameResolver(r.Address, upstreamHost(u)) && resultPathOnUpstream(r, u)
}

func resultPathOnUpstream(r ResolverResult, u Upstream) bool {
	if u.Kind == "local" {
		return false
	}
	if u.Iface != "" {
		return r.Path.Iface == u.Iface
	}
	return r.Path.Kind == PathWAN
}

func verdictOnUpstream(in AdviseInput, index int) Verdict {
	u := in.Path.Upstreams[index]
	verdict := Verdict("")
	for _, r := range in.Resolvers {
		if !resultOnUpstream(r, u) {
			continue
		}
		switch r.Verdict {
		case VerdictForged:
			return VerdictForged
		case VerdictUnreachable:
			verdict = VerdictUnreachable
		}
	}
	return verdict
}

func forgedOnUpstream(in AdviseInput, index int) (ResolverResult, bool) {
	u := in.Path.Upstreams[index]
	for _, r := range in.Resolvers {
		if r.Verdict == VerdictForged && resultOnUpstream(r, u) {
			return r, true
		}
	}
	return ResolverResult{}, false
}

func singleUsablePath(in AdviseInput) (bool, string) {
	seenIfaces := map[string]bool{}
	emptyCount := 0
	lastIface := ""
	for i, u := range in.Path.Upstreams {
		if verdictOnUpstream(in, i) == VerdictForged || verdictOnUpstream(in, i) == VerdictUnreachable {
			continue
		}
		if u.Iface == "" {
			emptyCount++
		} else {
			seenIfaces[u.Iface] = true
			lastIface = u.Iface
		}
	}
	total := len(seenIfaces) + emptyCount
	if total == 1 {
		if len(seenIfaces) == 1 {
			return true, lastIface
		}
		return true, ""
	}
	return false, ""
}

func viaForUpstream(in AdviseInput, u Upstream) string {
	if u.Iface == "" {
		return ""
	}
	if via := in.ViaByIface[u.Iface]; via != "" {
		return via
	}
	for _, via := range in.TunnelVia {
		if via == u.Iface {
			return via
		}
	}
	return ""
}

// existingRows renders only resolvers that were not measured bad. keepLast is false for the
// remove-last-resort action; the other actions retain every usable configured row.
func existingRows(in AdviseInput, keepLast bool) []ChainHint {
	var rows []ChainHint
	for i, u := range in.Path.Upstreams {
		via := viaForUpstream(in, u)
		iface := ""
		if via == "" {
			iface = u.Iface
		}
		if !keepLast && u.LastResort {
			continue
		}
		verdict := verdictOnUpstream(in, i)
		if verdict == VerdictForged || verdict == VerdictUnreachable {
			continue
		}
		rows = append(rows, ChainHint{Address: chainHintAddress(u), Port: u.Port, Via: via, Iface: iface})
	}
	return rows
}

func replacementRows(in AdviseInput) ([]ChainHint, bool) {
	var rows []ChainHint
	for i, u := range in.Path.Upstreams {
		via := viaForUpstream(in, u)
		iface := ""
		if via == "" {
			iface = u.Iface
		}
		verdict := verdictOnUpstream(in, i)
		if verdict == VerdictUnreachable {
			continue
		}
		row := ChainHint{Address: chainHintAddress(u), Port: u.Port, Via: via, Iface: iface}
		if verdict == VerdictForged {
			found := false
			for _, candidate := range in.Resolvers {
				if candidate.Verdict != VerdictGenuine || sameResolver(candidate.Address, row.Address) ||
					!resultPathOnUpstream(candidate, u) {
					continue
				}
				row.Address, row.Port, found = candidate.Address, 0, true
				break
			}
			if !found {
				return nil, false
			}
		}
		rows = append(rows, row)
	}
	return rows, len(rows) > 0
}

func pathForVia(in AdviseInput, via string) Path {
	for iface, id := range in.ViaByIface {
		if id == via {
			return Path{Iface: iface, Kind: PathTunnel}
		}
	}
	for _, r := range in.Resolvers {
		if r.Path.Kind == PathTunnel && (r.Path.Iface == via || r.Path.Label == via) {
			return r.Path
		}
	}
	for _, e := range in.Encrypted {
		if e.Path.Kind == PathTunnel && (e.Path.Iface == via || e.Path.Label == via) {
			return e.Path
		}
	}
	return Path{Iface: via, Kind: PathTunnel}
}

func samePath(a, b Path) bool {
	return a.Kind == b.Kind && a.Iface == b.Iface
}

func resolverUsable(in AdviseInput, address string, path Path) bool {
	for _, r := range in.Resolvers {
		if sameResolver(r.Address, address) && samePath(r.Path, path) &&
			(r.Verdict == VerdictUnreachable || r.Verdict == VerdictForged) {
			return false
		}
	}
	return true
}

func resolverCandidates(in AdviseInput) []string {
	out := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	for _, r := range in.Resolvers {
		// The router's own listener was offered as a row bound to a tunnel when every public resolver
		// failed. A row there would ask itself, or nothing.
		if ip := net.ParseIP(r.Address); r.Path.Kind == PathRouter || ip == nil || ip.IsLoopback() || ip.IsPrivate() {
			continue
		}
		duplicate := false
		for _, address := range out {
			if sameResolver(address, r.Address) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			out = append(out, r.Address)
		}
	}
	return out
}

func pickResolver(in AdviseInput, path Path, offset int) (string, bool) {
	candidates := resolverCandidates(in)
	for i := range candidates {
		address := candidates[(i+offset)%len(candidates)]
		if resolverUsable(in, address, path) {
			return address, true
		}
	}
	return "", false
}

func tunnelChainRows(in AdviseInput) []ChainHint {
	var rows []ChainHint
	usedIfaces := map[string]bool{}
	for i, via := range in.TunnelVia {
		if len(rows) == 2 {
			break
		}
		path := pathForVia(in, via)
		if usedIfaces[path.Iface] {
			continue
		}
		address, ok := pickResolver(in, path, i)
		if !ok {
			continue
		}
		usedIfaces[path.Iface] = true
		rows = append(rows, ChainHint{Address: address, Via: via})
	}
	return rows
}

func secondTunnelRows(in AdviseInput) ([]ChainHint, bool) {
	existing := existingRows(in, true)
	if len(existing) != 1 {
		return nil, false
	}
	currentVia := existing[0].Via
	currentIface := ""
	for i, u := range in.Path.Upstreams {
		if verdictOnUpstream(in, i) != VerdictForged && verdictOnUpstream(in, i) != VerdictUnreachable {
			currentIface = u.Iface
		}
	}
	for i, via := range in.TunnelVia {
		path := pathForVia(in, via)
		if via == currentVia || (currentIface != "" && path.Iface == currentIface) {
			continue
		}
		address, ok := pickResolver(in, path, i+1)
		if !ok {
			continue
		}
		return append(existing, ChainHint{Address: address, Via: via}), true
	}
	return nil, false
}
