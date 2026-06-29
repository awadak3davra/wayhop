package keenetic

import (
	"fmt"
	"net/netip"
	"strings"

	"velinx/internal/model"
	"velinx/internal/pbr"
)

// kpbr_build.go orchestrates the FULL Keenetic kernel-PBR cutover that replaces keen-pbr's LIST
// routing (kernel ipset + dnsmasq ipset= + iptables MARK + ip rule/route + a failover cron),
// while KEEPING S86 (RU-routing) and S89 (default 3-tier failover) and NOT touching sing-box.
// It produces pure artifact strings (offline, testable); the device-writing is the cutover.sh
// the EmitCutover* funcs render. The list domains are kept as TEXT (NOT remapped to .srs — that
// was the abandoned fakeip path) so dnsmasq can populate the kernel ipsets at resolve-time.

// KernelInputs are the pre-flight reads the cutover supplies (all gathered read-only).
type KernelInputs struct {
	KeenPBRConfig   []byte
	LocalListFiles  map[string][]string
	RunningConfig   string
	WanGateway      string                             // discovered default nexthop (e.g. 172.20.0.1)
	WanIface        string                             // default eth3
	MgmtIface       string                             // mgmt interface excluded from the bypass (default Wireguard2)
	RemapKeentestTo string                             // "" → netherlands
	ExtraBypassIPs  []string                           // resolved peer-endpoint IPs (hostnames)
	Fetch           func(url string) ([]string, error) // fetch+parse a list feed (domains or CIDRs)
	S86Mark         uint32                             // RU-routing skip-guard mark (default 0x250)
}

func (in *KernelInputs) defaults() {
	if in.WanIface == "" {
		in.WanIface = "eth3"
	}
	if in.MgmtIface == "" {
		in.MgmtIface = "Wireguard2"
	}
	if in.RemapKeentestTo == "" {
		in.RemapKeentestTo = EpNetherlands
	}
	if in.S86Mark == 0 {
		in.S86Mark = 0x250
	}
}

// KernelArtifacts are the rendered, device-applyable pieces of the kernel-PBR cutover.
type KernelArtifacts struct {
	Plan           *pbr.Plan
	Profile        *model.Profile
	IpsetRestore   string // `ipset restore -!` stream
	DnsmasqConfig  string // /opt/etc/dnsmasq.d/30-velinx.conf
	IptablesScript string // mangle MARK chain + nat MASQUERADE (idempotent shell)
	IPScript       string // ip rule/route (idempotent shell)
	FailoverCron   string // /opt/etc/cron.1min/wr-failover
	NetfilterHook  string // /opt/etc/ndm/netfilter.d/40-velinx.sh
	Teardown       string // rollback: remove the whole plane
	Warnings       []string
}

func (in KernelInputs) ipsetOpts() pbr.IpsetOptions {
	return pbr.IpsetOptions{WanIface: in.WanIface, S86Mark: in.S86Mark}
}

// BuildKernelPlan assembles the profile (no .srs remap; domains as text), compiles the kernel
// plan, derives the anti-loop bypass from the live peer IPs + resolved hostnames, and renders
// every artifact. Pure: no device writes.
func BuildKernelPlan(in KernelInputs) (*KernelArtifacts, error) {
	in.defaults()
	live := parseWireguardEndpoints(in.RunningConfig)
	if len(live) == 0 {
		return nil, fmt.Errorf("pre-flight: no WireGuard interfaces in running-config")
	}

	p := LiveProfile()
	lists, err := ImportKeenPBR(in.KeenPBRConfig, in.LocalListFiles, keenPBROutboundMap())
	if err != nil {
		return nil, err
	}
	active := lists[:0]
	for _, l := range lists {
		if l.Outbound != "" {
			active = append(active, l)
		}
	}
	p.RoutingLists = active // NO applyCatalogSRS — dnsmasq needs domain text, not .srs

	_, missing := ReconcileAdopt(live, LiveAdoptInterfaces())
	warns := remapMissing(p, missing, in.RemapKeentestTo)

	if in.Fetch != nil {
		if err := InlineCIDRSources(p, in.Fetch); err != nil {
			return nil, err
		}
		if err := InlineDomainSources(p, in.Fetch); err != nil {
			return nil, err
		}
	}
	// Drop lists that ended up empty (e.g. a feed that failed to fetch) so one dead upstream
	// can't invalidate the whole cutover — it just omits that list (logged as a warning).
	kept := p.RoutingLists[:0]
	for _, l := range p.RoutingLists {
		if l.Source != "" || l.CIDRSource != "" || len(l.Manual) > 0 {
			kept = append(kept, l)
		} else {
			warns = append(warns, "dropped empty routing list "+l.ID+" (feed returned no entries)")
		}
	}
	p.RoutingLists = kept
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("assembled profile invalid: %w", err)
	}

	plan, cw, err := pbr.Compile(p, pbr.Options{CollectDomainZones: true})
	if err != nil {
		return nil, err
	}
	for _, w := range cw {
		warns = append(warns, w.Scope+": "+w.Msg)
	}

	// Anti-loop bypass: resolved hostnames + the live peer IPs (skip the mgmt interface).
	bypass := append([]string{}, in.ExtraBypassIPs...)
	seen := map[string]bool{}
	for _, h := range bypass {
		seen[h] = true
	}
	for _, h := range BypassHosts(live, in.MgmtIface) {
		if _, err := netip.ParseAddr(h); err != nil {
			warns = append(warns, fmt.Sprintf("peer endpoint %q is a hostname — supply its resolved IP via ExtraBypassIPs", h))
			continue
		}
		if !seen[h] {
			bypass = append(bypass, h)
			seen[h] = true
		}
	}
	plan.BypassV4, plan.BypassV6 = splitIPs(bypass)

	io := in.ipsetOpts()
	opt := pbr.Options{CollectDomainZones: true}
	art := &KernelArtifacts{
		Plan:           plan,
		Profile:        p,
		IpsetRestore:   plan.RenderIpsetRestore(io),
		DnsmasqConfig:  plan.DnsmasqIpsetConfig(io, 1024),
		IptablesScript: plan.RenderIptablesScript(io),
		IPScript:       plan.RenderIPScript(opt),
		FailoverCron:   FailoverCronScript(plan, p, in.WanGateway, in.WanIface),
		Teardown:       plan.RenderTeardownScript(opt, io),
		Warnings:       warns,
	}
	// Tunnel NAT (the fix for the forwarded-traffic black-hole): forwarded LAN traffic egressing a
	// WR tunnel keeps its private LAN source unless we MASQUERADE it to the tunnel's own IP — without
	// this the VPN server has no route back to the LAN subnet and the flow dies ("ends at the
	// router"). RenderIptablesScript's SNAT is `-o <WAN>` only (the no-kill-switch fallback), never
	// the tunnel egress. We MASQUERADE on EVERY failover-member tunnel iface (not just the
	// compile-time primary) so a re-election can't re-break it; mgmt is excluded (never a list
	// member). The router's own egress already carries the tunnel src, so MASQUERADE is a no-op for
	// it and only rewrites the forwarded LAN flows.
	tunSeen := map[string]bool{}
	var tunMasq, tunMasqDown strings.Builder
	for _, e := range plan.Egresses {
		if e.Kind == pbr.EgressWAN {
			continue
		}
		for _, m := range ResolveEgressMembers(p, e.Tag) {
			if m == "WAN" || m == "BLOCK" || tunSeen[m] {
				continue
			}
			tunSeen[m] = true
			fmt.Fprintf(&tunMasq, "iptables -t nat -C POSTROUTING -o %s -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o %s -j MASQUERADE\n", m, m)
			fmt.Fprintf(&tunMasqDown, "iptables -t nat -D POSTROUTING -o %s -j MASQUERADE 2>/dev/null || true\n", m)
		}
	}
	art.IptablesScript += tunMasq.String()
	art.Teardown += tunMasqDown.String()

	art.NetfilterHook = kernelNetfilterHook(art, io)
	return art, nil
}

// splitIPs partitions bare IP addresses into v4/v6 (the bypass set is IPs, not CIDRs).
func splitIPs(in []string) (v4, v6 []string) {
	for _, s := range in {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		if a.Is6() {
			v6 = append(v6, a.String()+"/128")
		} else {
			v4 = append(v4, a.String()+"/32")
		}
	}
	return v4, v6
}

// kernelNetfilterHook re-asserts the whole kernel plane after an NDM netfilter rebuild (which
// wipes /opt iptables + ipset state): recreate the sets if the sentinel set is gone, then
// re-apply the idempotent mangle/nat + ip rules. Runs on every netfilter.d event (cheap +
// idempotent). Mirrors why S86/keen-pbr ship their own hook.
func kernelNetfilterHook(art *KernelArtifacts, io pbr.IpsetOptions) string {
	names := art.Plan.IpsetNames(io)
	var b strings.Builder
	b.WriteString("#!/opt/bin/sh\n")
	b.WriteString("# Velinx kernel-PBR — re-assert ipset/iptables/ip after NDM netfilter rebuild.\n")
	b.WriteString("# Auto-generated; do not edit. Removed on Velinx teardown.\n")
	// HW-NAT fastnat OFF + rp_filter loose, re-asserted every event (NDM/boot may re-enable
	// fastnat, which bypasses the mangle marking the whole plane depends on).
	b.WriteString("echo 0 > /proc/sys/net/netfilter/nf_conntrack_fastnat 2>/dev/null\n")
	b.WriteString("for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 2 > \"$f\" 2>/dev/null; done\n")
	if len(names) > 0 {
		fmt.Fprintf(&b, "if ! ipset list -n %s >/dev/null 2>&1; then\n", names[0])
		b.WriteString("ipset restore -! <<'WRIPSET'\n")
		b.WriteString(art.IpsetRestore)
		b.WriteString("WRIPSET\nfi\n")
	}
	b.WriteString(art.IptablesScript)
	b.WriteString(art.IPScript)
	b.WriteString("exit 0\n")
	return b.String()
}
