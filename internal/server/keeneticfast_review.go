package server

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"time"

	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/nativedns"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// keeneticFastFacts is what Review reads from the router for the Keenetic fast plane.
type keeneticFastFacts struct {
	// resolver is why Entware's dnsmasq is not the LAN resolver ("" = it is).
	resolver string
	// lanIfaces is the installed plane's LAN interfaces (enforcement redirects there), nil if unknown.
	lanIfaces []string
	// profileNames says an enabled inline list or rule carries a domain name, whatever the plan kept.
	profileNames bool
}

// isNDMPolicy reports an outbound that is a KeeneticOS access policy (kept by the plane, though Review
// compiles without the policies an Apply captures).
func isNDMPolicy(outbound string) bool {
	_, ok := model.NDMPolicyName(outbound)
	return ok
}

// profileHasDomainNames reports an enabled inline list or rule with a domain name (not an address).
func profileHasDomainNames(prof *model.Profile) bool {
	isName := func(e string) bool {
		e = strings.TrimSpace(e)
		if e == "" || strings.HasPrefix(e, "#") {
			return false
		}
		if _, err := netip.ParsePrefix(e); err == nil {
			return false
		}
		_, err := netip.ParseAddr(e)
		return err != nil
	}
	for _, rl := range prof.RoutingLists {
		if !rl.Enabled || rl.Source != "" {
			continue
		}
		for _, e := range append(append([]string(nil), rl.Manual...), rl.DomainCache...) {
			if isName(e) {
				return true
			}
		}
	}
	for _, r := range prof.Rules {
		if !r.Disabled && !r.Default && len(r.Domain)+len(r.DomainSuffix) > 0 {
			return true
		}
	}
	return false
}

// keeneticResolverProbe reads whether Entware's dnsmasq is usable and holds :53. A variable for tests.
var keeneticResolverProbe = func(s *Server) string {
	if p := keeneticFastResolverProblem(keeneticChainUsable(), nativedns.RunEffectivePath(s.dnsRunner()).Answering()); p != "" {
		return p
	}
	conf, err := os.ReadFile(keeneticMainConf)
	if err != nil {
		return "Entware dnsmasq's configuration could not be read: " + err.Error()
	}
	return keeneticPolicyIncluded(string(conf))
}

// keeneticPolicyIncluded says why Entware dnsmasq's main configuration does not read the policy file
// ("" = it does), HUNT-K #11: a conf-dir= of its directory whose filters take a .conf file, or a
// conf-file= of the file itself. dnsmasq --test on the main configuration says nothing about a file
// it never reads.
func keeneticPolicyIncluded(conf string) string {
	dir := strings.TrimSuffix(keeneticPBRDnsmasqConfPath[:strings.LastIndex(keeneticPBRDnsmasqConfPath, "/")], "/")
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "conf-file="); ok && strings.TrimSpace(v) == keeneticPBRDnsmasqConfPath {
			return ""
		}
		v, ok := strings.CutPrefix(line, "conf-dir=")
		if !ok {
			continue
		}
		parts := strings.Split(v, ",")
		if strings.TrimSuffix(strings.TrimSpace(parts[0]), "/") != dir {
			continue
		}
		included, filtered := false, false
		excluded := false
		for _, f := range parts[1:] {
			f = strings.TrimSpace(f)
			switch {
			case strings.HasPrefix(f, "*"):
				filtered = true
				included = included || f == "*.conf"
			case f == ".conf":
				excluded = true
			}
		}
		if !excluded && (!filtered || included) {
			return ""
		}
	}
	return "Entware dnsmasq's configuration (" + keeneticMainConf + ") does not read " + dir + ", where WayHop writes its routing policy"
}

// keeneticFastReview is Review's part for the Keenetic fast plane: the resolver prerequisite of DNS
// enforcement, what the plane carries, and what it does not carry yet. Nothing off KeeneticOS fast
// mode, in the demo, or without the kernel plane.
func (s *Server) keeneticFastReview(cfg config.Config, prof *model.Profile) []PlanFinding {
	if s == nil || prof == nil || cfg.Demo || !s.keeneticFastOn(cfg) || !keeneticKernelPlaneCarriesLists("fast") {
		return nil
	}
	plan, _, err := pbr.Compile(prof, s.pbrCompileOptions(cfg))
	if err != nil || plan == nil {
		return nil
	}
	// Names are judged from the profile too (HUNT-K #3): Review compiles without the access policies an
	// Apply captures, so a list sent to one is not in this plan, but Apply enforces DNS for its names.
	facts := keeneticFastFacts{profileNames: profileHasDomainNames(prof)}
	if keeneticPlanHasDomainNames(plan) || facts.profileNames {
		facts.resolver = keeneticResolverProbe(s)
	}
	if k := s.kernelBaseline(); k != nil {
		facts.lanIfaces = k.Ipset.LANIfaces
	}
	return keeneticFastFindings(cfg, prof, plan, facts)
}

// keeneticFastFindings is keeneticFastReview given the router's facts.
func keeneticFastFindings(cfg config.Config, prof *model.Profile, plan *pbr.Plan, facts keeneticFastFacts) []PlanFinding {
	var out []PlanFinding
	note := func(id, item, detail, remedy string) {
		out = append(out, PlanFinding{ID: id, Setting: "routing mode fast", Item: item,
			Severity: platform.SeverityDegraded, Reason: platform.ReasonOperatorChoice, Blocks: platform.BlocksNothing,
			Detail: detail, Remedy: remedy})
	}
	names := map[string]bool{}
	sets := 0
	for _, z := range plan.Zones {
		if len(z.Domains) == 0 {
			continue
		}
		sets += 2
		for _, d := range z.Domains {
			names[d] = true
		}
	}
	hasNames := len(names) > 0 || facts.profileNames
	enforce := cfg.FastDNSEnforceOn() && hasNames
	if hasNames {
		switch {
		case facts.resolver != "" && enforce:
			out = append(out, PlanFinding{ID: "fast_path.keenetic_resolver", Setting: "routing mode fast", Item: "DNS enforcement",
				Requested: "LAN DNS answered by the router", Effective: "not the router's dnsmasq",
				Severity: platform.SeverityBlocked, Reason: platform.ReasonFeatureWouldBeDropped, Blocks: platform.BlocksApply,
				Detail: "Fast mode redirects the LAN's DNS to the router's resolver so the lists' names fill their sets, which needs " +
					"Entware's dnsmasq answering on port 53: " + facts.resolver + ".",
				Remedy: "Set up the router's DNS on the DNS page (Entware dnsmasq on port 53), or set fast_dns_enforce to false in config.json."})
		case facts.resolver != "":
			note("fast_path.keenetic_resolver", "names in fast mode",
				"The lists' names fill their sets only through Entware's dnsmasq answering the LAN on port 53: "+facts.resolver+".",
				"Set up the router's DNS on the DNS page, or use hybrid mode.")
		}
		on := "off (fast_dns_enforce is false): a device that asks its own DNS server bypasses the lists' names"
		if enforce {
			ifaces := "the LAN interfaces the plane captures"
			if len(facts.lanIfaces) > 0 {
				ifaces = strings.Join(facts.lanIfaces, ", ")
			}
			on = "on: plain DNS from " + ifaces + " is answered by the router's dnsmasq and DNS over TLS is refused " +
				"(DNS over HTTPS cannot be told apart from other HTTPS)"
		}
		note("fast_path.keenetic_names", "names in fast mode",
			fmt.Sprintf("%d name(s) go through the router's dnsmasq into %d resolver-fed sets (wd_*), whose addresses live six hours "+
				"and are kept alive by new connections to them. DNS enforcement is %s.", len(names), sets, on),
			"Nothing to do.")
	}
	for _, r := range prof.Rules {
		if !r.Disabled && !r.Default && len(r.GeoSite) == 0 && len(r.Domain) > 0 {
			note("fast_path.domain_widened."+r.ID, r.ID,
				fmt.Sprintf("The rule %q matches exact names (%s). dnsmasq matches a name and every name under it, so in fast mode "+
					"the rule also takes their subdomains.", r.ID, strings.Join(r.Domain, ", ")),
				"Nothing to do if the subdomains may go the same way; otherwise use hybrid mode for this rule.")
		}
	}
	// Not carried by the Keenetic fast plane yet: remote lists and lists only the proxy core can send.
	// They keep the compatibility routing they have today.
	fromList := map[string]bool{}
	for _, z := range plan.Zones {
		if o, ok := plan.ZoneOrigin(z.Name); ok && o.Kind == pbr.ZoneFromList {
			fromList[o.ID] = true
		}
	}
	var remote, core []string
	for i := range prof.RoutingLists {
		rl := &prof.RoutingLists[i]
		switch {
		case !rl.Enabled:
		case rl.Source != "":
			remote = append(remote, listName(rl))
		case !fromList[rl.ID] && rl.Outbound != model.OutboundDirect && rl.Outbound != model.OutboundBlock && !isNDMPolicy(rl.Outbound):
			core = append(core, listName(rl))
		}
	}
	sort.Strings(remote)
	sort.Strings(core)
	if len(remote)+len(core) > 0 {
		var parts []string
		if len(remote) > 0 {
			parts = append(parts, "remote lists ("+strings.Join(shortList(remote, 5), ", ")+")")
		}
		if len(core) > 0 {
			parts = append(parts, "lists sent to a proxy ("+strings.Join(shortList(core, 5), ", ")+")")
		}
		note("fast_path.keenetic_not_carried", "lists in fast mode",
			"Fast mode on KeeneticOS does not carry "+strings.Join(parts, " or ")+" yet: they stay with the proxy core's "+
				"compatibility routing, as before.",
			"Nothing to do; to have them in the kernel plane, give their entries to an inline list sent to a WireGuard/AmneziaWG connection.")
	}
	return out
}

// keeneticFastCheck is the Diagnostics row of the Keenetic fast plane: the wd_ sets and their members,
// DNS enforcement, the last fresh-address reset, the warm-up and dnsmasq's health.
func (s *Server) keeneticFastCheck(ctx context.Context, row healthRow) healthRow {
	return s.keeneticFastCheckOf(ctx, row, s.kernelBaseline())
}

// keeneticFastCheckOf is keeneticFastCheck for the installed plane k (nil: none).
func (s *Server) keeneticFastCheckOf(ctx context.Context, row healthRow, k *executionKernelArtifactV1) healthRow {
	if k == nil || !k.Ipset.DynamicDomainSets || !keeneticPlanHasDomainNames(k.Plan) {
		row.Status, row.Summary = "na", "no list or rule matches names in fast mode"
		return row
	}
	names, _ := k.Plan.DynamicSets(keeneticKillSwitchOptions(*k.Ipset))
	elements := 0
	var readErr error
	if read := keeneticSetMembers(*k.Ipset); read != nil {
		for _, name := range names {
			members, err := read(ctx, name)
			if err != nil {
				readErr = fmt.Errorf("%s: %v", name, err)
				continue
			}
			elements += len(members)
		}
	}
	s.fastDNS.mu.Lock()
	st, kst := &s.fastDNS, s.fastDNS.keenetic
	ferr, restarted, dnsFails, dnsErr, backedOut := st.err, st.restarted, st.dnsFails, st.dnsErr, st.backedOut
	restartGaveUp := st.restartOwed && st.restartTries >= fastDNSMaxOwedRestarts
	s.fastDNS.mu.Unlock()
	enforce := "off"
	suspended := k.Ipset.FastDNSEnforce && keeneticDNSSuspended()
	switch {
	case suspended:
		enforce = "suspended"
	case k.Ipset.FastDNSEnforce:
		enforce = "on"
	}
	row.Summary = fmt.Sprintf("%d wd_ sets, %d addresses resolved · DNS enforcement %s · last fresh-address reset %d", len(names), elements, enforce, kst.freshLast)
	var detail []string
	if !kst.freshAt.IsZero() {
		detail = append(detail, fmt.Sprintf("%d connection(s) reset since the start, last look %s", kst.freshTotal, kst.freshAt.Format(time.RFC3339)))
	}
	if kst.warm != "" {
		detail = append(detail, "warm-up "+kst.warm+" ("+kst.warmAt.Format(time.RFC3339)+")")
	}
	if !restarted.IsZero() {
		detail = append(detail, "dnsmasq last restarted for the policy "+restarted.Format(time.RFC3339))
	}
	row.Detail = strings.Join(detail, "; ")
	switch {
	case suspended:
		row.Status = "fail"
		row.Detail = "the router's dnsmasq stopped answering, so DNS enforcement is suspended: the LAN's devices use their own " +
			"resolvers and the lists' names do not fill their sets until dnsmasq answers again (then it comes back by itself)"
		row.Fix = "Restart dnsmasq (" + keeneticDnsmasqInitScript + " restart) or reboot the router, and check its log."
	case kst.failOpenHeld != "":
		row.Status = "fail"
		row.Detail = kst.failOpenHeld
		row.Fix = "Restart dnsmasq (" + keeneticDnsmasqInitScript + " restart) or reboot the router, and check its log."
	case restartGaveUp:
		row.Status = "fail"
		row.Detail = fmt.Sprintf("dnsmasq did not answer after %d restarts following a back-out; WayHop stopped restarting it", fastDNSMaxOwedRestarts)
		row.Fix = "Restart dnsmasq by hand (" + keeneticDnsmasqInitScript + " restart) or reboot the router, and check its log."
	case backedOut:
		row.Status = "fail"
		row.Detail = ferr
		row.Fix = "Switch routing mode to hybrid, or Apply again once the resolver is healthy."
	case kst.guardErr != "":
		row.Status = "warn"
		row.Detail = "the last Apply's dnsmasq restart was refused and rolled back: " + kst.guardErr
		row.Fix = "Check dnsmasq's log and " + keeneticMainConf + ", then Apply again."
	case ferr != "":
		row.Status = "warn"
		row.Detail = ferr
	case readErr != nil:
		row.Status = "warn"
		row.Detail = "the sets could not be read: " + readErr.Error()
		row.Fix = "Apply again: the plane recreates its sets."
	case dnsFails > 0:
		row.Status = "warn"
		row.Detail = fmt.Sprintf("the router's resolver missed the last %d check(s) through its upstreams: %s", dnsFails, dnsErr)
		row.Fix = "Check dnsmasq's CPU (top) and its upstreams; switch routing mode to hybrid if it does not recover."
	default:
		row.Status = "pass"
	}
	return row
}
