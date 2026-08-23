package server

import (
	"bytes"
	"fmt"
	"os/exec"
	"slices"
	"strings"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// applykeeneticpbr.go builds the KeeneticOS kernel policy artifact from an already-compiled pbr.Plan.
//
// KeeneticOS has no nftables, so the nft plane in applykernel.go cannot run here; what the platform
// does carry is ipset + iptables mangle marks + ip rule/route, which internal/pbr/render_ipset.go has
// rendered all along without anything wired to execute it. This file is that wiring's input half: it
// turns the plan into the exact bytes the executor will run, so the ledger authenticates the program
// itself rather than a recipe the executor re-derives later.
//
// Everything here is pure: no host probing, no command execution.

const (
	executionToolIpset     = "ipset"
	executionToolIptables  = "iptables"
	executionToolIp6tables = "ip6tables"
	executionToolDnsmasq   = "dnsmasq"
	executionToolShell     = "sh"
)

// keeneticPBRToolPins are the bare command names render_ipset.go emits, in the order the preamble
// defines them. Order is fixed so the rendered preamble is byte-stable for a given tool set: the
// artifact is content-addressed, and a map iteration would rehash it on every capture.
var keeneticPBRToolPins = []string{
	executionToolIpset, executionToolIptables, executionToolIp6tables, executionToolIP,
}

// keeneticPBRPreamble pins every bare tool name the rendered script uses to the absolute path of the
// binary whose identity was probed and recorded in the artifact.
//
// The nft plane executes discrete argv vectors, so its runner can check the identity of each binary
// it is about to exec. This plane is shell, because NDM re-invokes the same program from a
// netfilter.d hook after every firewall rebuild. A shell function shadows PATH lookup for the bare
// name, so `iptables -t mangle …` in the body reaches exactly /opt/sbin/iptables and nothing else —
// which restores the guarantee that would otherwise be lost the moment the program became text.
//
// Deliberately no `set -e`: the rendered body is idempotent by way of `… 2>/dev/null || true` and
// exit codes that are expected to be non-zero on a re-run, and aborting on the first of those would
// leave the plane half-installed.
func keeneticPBRPreamble(artifact executionKernelIpsetArtifactV1) (string, error) {
	paths := map[string]string{
		executionToolIpset:     artifact.IpsetTool.ResolvedPath,
		executionToolIptables:  artifact.IptablesTool.ResolvedPath,
		executionToolIp6tables: artifact.IP6Tool.ResolvedPath,
		executionToolIP:        artifact.IPTool.ResolvedPath,
	}
	var b strings.Builder
	b.WriteString("# WayHop Keenetic policy plane. Generated — do not edit.\n")
	b.WriteString("# Every tool below is pinned to the exact binary whose identity the Apply ledger\n")
	b.WriteString("# authenticated; the bare names in the body resolve to these and nothing else.\n")
	for _, tool := range keeneticPBRToolPins {
		resolved := paths[tool]
		if !validExecutionRouterPath(resolved) {
			return "", fmt.Errorf("%w: %s has no authenticated path", errExactKernelArtifact, tool)
		}
		// A multicall host dispatches on argv[0], so pinning to its resolved path alone would run
		// the host with no applet: BusyBox for ip, and xtables-multi for the whole iptables family
		// on Entware, which answers "ERROR: No valid subcommand given". The rule lives in
		// executionMulticallApplet so the probe, the argv runner and this preamble cannot disagree.
		if applet := executionMulticallApplet(resolved, tool); applet != "" {
			fmt.Fprintf(&b, "%s() { %s %s \"$@\"; }\n", tool, resolved, applet)
			continue
		}
		fmt.Fprintf(&b, "%s() { %s \"$@\"; }\n", tool, resolved)
	}
	return b.String(), nil
}

// keeneticKernelPBRPresent reports whether this router carries the tools the Keenetic plane needs.
//
// It answers the capability question — may Fast/Hybrid be offered here — and deliberately stops at
// presence. iptables has no whole-ruleset --check, so the only way to dry-run the plane would be to
// install it, and mutating a live router to answer "what could you do" is not a trade worth making.
// Nothing is executed on the strength of this: the artifact records each binary's digest and the
// executor re-verifies it before and after running anything.
func keeneticKernelPBRPresent() bool {
	for _, tool := range []string{executionToolIpset, executionToolIptables} {
		if _, err := exec.LookPath(tool); err != nil {
			return false
		}
	}
	return true
}

// keeneticDomainsViaDNSMasq reports whether a domain can reach the kernel plane on this router.
//
// It needs both halves: the plane itself, and a resolver that can put an answer into an ipset. With
// only one of them a domain list is unroutable here and must still pull in the proxy core — routing
// nothing while reporting success is the failure this guards against.
func keeneticDomainsViaDNSMasq() bool {
	if !keeneticKernelPBRPresent() {
		return false
	}
	_, err := exec.LookPath(executionToolDnsmasq)
	return err == nil
}

// keeneticKernelCarriesDomains reports whether a LISTED NAME reaches transparently-routed LAN
// traffic without sing-box in the path.
//
// On KeeneticOS with the resolver wired it does: dnsmasq is handed `ipset=/name/…/set` for every
// listed name, so each answer becomes a set member at query time, and the mangle rule marks packets
// to that member. A LAN device is policy-routed on its first connection after the lookup, TUN or no
// TUN. Measured on a live router: three lookups took wr_list_rl_teamviewer_4 from 15 to 22
// members and that set's MARK rule counted packets, in routing mode "fast".
//
// It reads the CAPTURE rather than probing again, so the answer describes the apply being performed
// rather than the router a moment later. capture.DomainsViaDNSMasq already implies the kernel plane
// (keeneticDomainsViaDNSMasq requires keeneticKernelPBRPresent), which is why the plane is not
// re-tested here.
//
// Deliberately NOT consulted: whether the plan materializes a proxy core. It usually does on this
// router — the DNS plane alone is enough to make keenetic.PlanRequiresCore true — and an earlier cut
// of this fix keyed on that, which left the false warning firing on the very router that disproved
// it. A core existing for DNS says nothing about who matches routing-list names; dnsmasq still fills
// the sets and the kernel still marks the packets.
func keeneticKernelCarriesDomains(capture *executionNativeCaptureV1) bool {
	return capture != nil && capture.DomainsViaDNSMasq
}

// keeneticPBROptions is the plan-independent shape of the Keenetic plane. WanIface comes from the
// host facts rather than render_ipset.go's default, which is a live router.
func keeneticPBROptions(wanIface string) pbr.IpsetOptions {
	return pbr.IpsetOptions{WanIface: wanIface}
}

// keeneticLANIface is where clients arrive on KeeneticOS: the bridge every LAN segment joins. DNS
// interception must be bound to it — the same redirect on the WAN side would capture the router's own
// upstream queries and answer them with itself.
const keeneticLANIface = "br0"

// keeneticPBROptionsFor is keeneticPBROptions plus the parts that depend on the PROFILE rather than
// the host: today, whether clients' DNS is intercepted.
func keeneticPBROptionsFor(wanIface string, p *model.Profile) pbr.IpsetOptions {
	o := keeneticPBROptions(wanIface)
	if p != nil && p.DNS != nil && p.DNS.Enabled && p.DNS.Intercept {
		o.DNSIntercept = true
		o.DNSInterceptLAN = keeneticLANIface
		o.DNSRejectEncrypted = p.DNS.InterceptRejectEncrypted
	}
	return o
}

// buildKeeneticKernelIpsetArtifact renders the plan into the bytes the executor will run. The two
// scripts carry the preamble so the artifact is self-contained: the netfilter.d hook installs the
// same bytes and therefore re-asserts exactly what was reviewed, not a re-render that could have
// drifted with the profile.
func buildKeeneticKernelIpsetArtifact(
	plan *pbr.Plan,
	opt pbr.Options,
	io pbr.IpsetOptions,
	tools executionKernelIpsetArtifactV1,
) (*executionKernelIpsetArtifactV1, error) {
	if plan == nil {
		return nil, errExecutionInvalidCapture
	}
	artifact := tools
	artifact.WANIface = io.WanIface
	preamble, err := keeneticPBRPreamble(artifact)
	if err != nil {
		return nil, err
	}
	artifact.Restore = []byte(plan.RenderIpsetRestore(io))
	artifact.Script = []byte(preamble + plan.RenderIptablesScript(io) + plan.RenderIPScript(opt))
	artifact.Teardown = []byte(preamble + plan.RenderTeardownScript(opt, io))
	artifact.SetNames = append([]string(nil), plan.IpsetNames(io)...)
	if artifact.SetNames == nil {
		artifact.SetNames = []string{}
	}
	// DnsmasqIpsetConfig is empty for a plan with no domain zone; keep it empty rather than nil so
	// the artifact encodes identically whether or not the plan ever had domains.
	artifact.DnsmasqConf = []byte(plan.DnsmasqIpsetConfig(io, keeneticPBRDnsmasqMaxLine))
	if artifact.DnsmasqConf == nil {
		artifact.DnsmasqConf = []byte{}
	}
	if !validExecutionKernelIpsetArtifact(artifact) {
		return nil, errExecutionInvalidCapture
	}
	return &artifact, nil
}

// keeneticPBRDnsmasqMaxLine bounds one generated `ipset=` line. dnsmasq accepts long lines, but a
// single unbounded one is unreadable in a config an operator may have to inspect on a router with
// only vi, so the renderer splits by domain count instead.
const keeneticPBRDnsmasqMaxLine = 1024

// validExactKernelPresentIpsetArtifact is the ipset plane's answer to
// validExactKernelPresentArtifact, and keeps that function's real guarantee: the stored artifact
// must be byte-identical to what the stored plan renders. Re-deriving it here is what stops a
// tampered or stale blob from being executed as if it had been reviewed — the tool identities the
// preamble is built from live in the artifact, so the render is reproducible.
//
// It also requires the nft fields to be empty. A single artifact carrying both planes would leave
// the executor free to pick, and only one of them can be the reviewed program.
func validExactKernelPresentIpsetArtifact(artifact executionKernelArtifactV1) bool {
	if artifact.Plan == nil || artifact.Ipset == nil ||
		len(artifact.Nft) != 0 || len(artifact.IP) != 0 || len(artifact.Offload) != 0 ||
		len(artifact.Teardown) != 0 ||
		artifact.NFTTool != (ExecutionToolIdentityV1{}) || artifact.IPTool != (ExecutionToolIdentityV1{}) {
		return false
	}
	stored := *artifact.Ipset
	if !validExecutionKernelIpsetArtifact(stored) {
		return false
	}
	rendered, err := buildKeeneticKernelIpsetArtifact(
		artifact.Plan, exactKernelOptions(), keeneticPBROptions(stored.WANIface), stored)
	if err != nil {
		return false
	}
	return bytes.Equal(stored.Restore, rendered.Restore) &&
		bytes.Equal(stored.Script, rendered.Script) &&
		bytes.Equal(stored.Teardown, rendered.Teardown) &&
		bytes.Equal(stored.DnsmasqConf, rendered.DnsmasqConf) &&
		slices.Equal(stored.SetNames, rendered.SetNames)
}

func validExecutionKernelIpsetArtifact(artifact executionKernelIpsetArtifactV1) bool {
	if !validExecutionToolIdentity(artifact.IpsetTool, executionToolIpset) ||
		!validExecutionToolIdentity(artifact.IptablesTool, executionToolIptables) ||
		!validExecutionToolIdentity(artifact.IP6Tool, executionToolIp6tables) ||
		!validExecutionToolIdentity(artifact.IPTool, executionToolIP) ||
		!validExecutionToolIdentity(artifact.ShellTool, executionToolShell) {
		return false
	}
	// A plane that marks nothing is not a plane. An empty Script would install no chain at all while
	// the ledger recorded an ensure-present kernel action, and postcheck would then confirm an empty
	// program as healthy.
	if len(artifact.Script) == 0 || len(artifact.Teardown) == 0 {
		return false
	}
	// Domain sets are the only reason dnsmasq participates. Requiring its identity only when the
	// config is non-empty keeps a pure IP-CIDR plan installable on a router with no dnsmasq.
	if len(artifact.DnsmasqConf) != 0 && !validExecutionToolIdentity(artifact.DnsmasqTool, executionToolDnsmasq) {
		return false
	}
	for _, name := range artifact.SetNames {
		if !validExecutionIdentityText(name, executionMaxToolVersionBytes) {
			return false
		}
	}
	return true
}
