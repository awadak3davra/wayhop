package keenetic

import (
	"fmt"
	"net/netip"

	"wayhop/internal/model"
)

// prepare.go ties the whole cutover pipeline together: pre-flight device reads → a ready
// CutoverOptions. It does NO device writes — Cutover (returned ready) is user-gated.

// PrepareInputs are the pre-flight reads the daemon supplies (all read-only on the device).
type PrepareInputs struct {
	KeenPBRConfig     []byte                             // /opt/etc/keen-pbr/config.json
	LocalListFiles    map[string][]string                // file-list contents (e.g. local.lst lines)
	RunningConfig     string                             // `show running-config`
	LiveSingboxConfig []byte                             // /opt/etc/sing-box/config.json (for real Hy2/VLESS params)
	WanGateway        string                             // discovered default gateway on eth3
	Fetch             func(url string) ([]string, error) // fetch+parse a list feed THROUGH a tunnel (IP-feeds + domain feeds)
	RemapKeentestTo   string                             // "" → netherlands
	LocalDirect       []string                           // CIDRs forced WAN-direct ("" → [109.254.0.0/16])
	MgmtReverse       []string                           // mgmt-reverse subnets ("" → [10.0.0.0/24])
	ExtraBypassIPs    []string                           // resolved peer-endpoint IPs (hostnames the daemon resolved) → WAN bypass

	// Apply-side paths threaded into CutoverOptions (defaults apply on the real device; tests
	// point these at temp dirs so no real /opt path is touched).
	Stage     SingboxStageOptions
	Netfilter NetfilterHookOptions
}

// PrepareCutover builds the CutoverOptions from the pre-flight reads: parse the live
// interfaces, BuildProfile (reconciled), inline the CIDR feeds, assemble the sing-box config,
// substitute the real Hy2/VLESS params, derive the anti-loop bypass IPs, and wire the kernel
// plane apply/teardown closures (capturing run). Returns the options + warnings. ⚠️ The
// returned Cutover is DEVICE-WRITING; the caller runs it only on a user-gated, failsafe-
// wrapped deploy.
func PrepareCutover(run Runner, in PrepareInputs) (CutoverOptions, []string, error) {
	var warns []string
	live := parseWireguardEndpoints(in.RunningConfig)
	if len(live) == 0 {
		return CutoverOptions{}, nil, fmt.Errorf("pre-flight: no WireGuard interfaces in running-config")
	}

	p, _, bw, err := BuildProfile(in.KeenPBRConfig, in.LocalListFiles, live, in.RemapKeentestTo)
	if err != nil {
		return CutoverOptions{}, nil, err
	}
	warns = append(warns, bw...)

	if in.Fetch != nil {
		// Inline both IP-feed (CIDRSource) and domain (Source) lists — keen-pbr's .lst/v2fly
		// feeds can't be sing-box remote rule_sets, so everything becomes an inline rule_set.
		if err := InlineCIDRSources(p, in.Fetch); err != nil {
			return CutoverOptions{}, nil, err
		}
		if err := InlineDomainSources(p, in.Fetch); err != nil {
			return CutoverOptions{}, nil, err
		}
	}

	cfg, err := AssembleSingboxConfig(p, dohDetourFor(p, in.RemapKeentestTo))
	if err != nil {
		return CutoverOptions{}, nil, err
	}
	if len(in.LiveSingboxConfig) > 0 {
		missing, err := SubstituteRealOutbounds(cfg, in.LiveSingboxConfig,
			map[string]string{"hy2-main": EpHy2, "vless-main": EpVless})
		if err != nil {
			return CutoverOptions{}, nil, err
		}
		for _, m := range missing {
			warns = append(warns, fmt.Sprintf("live sing-box outbound %q not found — tunnel keeps placeholder params", m))
		}
	}

	// Anti-loop bypass: the live peer endpoint IPs (skip the mgmt interface). A hostname
	// endpoint can't be a kernel route — skip it with a warning (resolve at the daemon).
	bypass := append([]string{}, in.ExtraBypassIPs...) // resolved hostnames the daemon supplied
	seen := map[string]bool{}
	for _, h := range bypass {
		seen[h] = true
	}
	for _, h := range BypassHosts(live, "Wireguard2") {
		if _, err := netip.ParseAddr(h); err != nil {
			warns = append(warns, fmt.Sprintf("peer endpoint %q is a hostname — supply its resolved IP via ExtraBypassIPs", h))
			continue
		}
		if !seen[h] {
			bypass = append(bypass, h)
			seen[h] = true
		}
	}

	localDirect := in.LocalDirect
	if localDirect == nil {
		localDirect = []string{"109.254.0.0/16"}
	}
	mgmtReverse := in.MgmtReverse
	if mgmtReverse == nil {
		mgmtReverse = []string{"10.0.0.0/24"}
	}
	kOpt := KernelPlaneOptions{
		WanGateway: in.WanGateway, BypassIPs: bypass,
		LocalDirect: localDirect, MgmtReverse: mgmtReverse,
	}

	cOpt := CutoverOptions{
		SingboxConfig:  cfg,
		Stage:          in.Stage,
		Netfilter:      in.Netfilter,
		ApplyKernel:    func() error { return ApplyKernelPlane(run, kOpt) },
		TeardownKernel: func() error { return TeardownKernelPlane(run, kOpt) },
	}
	return cOpt, warns, nil
}

// dohDetourFor picks the DoH detour outbound: a tunnel that SURVIVES reconciliation, so the DNS
// plane never references a dropped endpoint. Prefer netherlands (the default censored-DoH path);
// else the keentest remap target (guaranteed live); else any surviving native tunnel; else any
// surviving endpoint. Previously hardcoded to EpNetherlands — in the netherlands-down recovery
// path (operator remaps keentest to a live tunnel) that left a dangling dns.detour="netherlands".
func dohDetourFor(p *model.Profile, remapTo string) string {
	if p.EndpointByID(EpNetherlands) != nil {
		return EpNetherlands
	}
	if remapTo != "" && p.EndpointByID(remapTo) != nil {
		return remapTo
	}
	for _, e := range p.Endpoints {
		if e.Engine == model.EngineExternal {
			return e.ID
		}
	}
	if len(p.Endpoints) > 0 {
		return p.Endpoints[0].ID
	}
	return ""
}
