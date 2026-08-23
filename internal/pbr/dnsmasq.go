package pbr

// Domain-based routing via dnsmasq nft-set / ipset population.
//
// Many router setups route by DOMAIN (not just by CIDR) by having dnsmasq add the
// resolved IPs of matched domains into a kernel set (nftables set or legacy ipset),
// which this plan's PBR chain then marks + routes via the same per-zone fwmark used for
// IP-CIDR zones. This is the cheap, "lazy" alternative to pre-resolving an 80k-domain
// list: only the IPs the user actually visits ever enter the set, so standing RAM is ~0.
//
// This file is PURE STRING RENDERING ONLY. It turns the plan's domain-bearing zones into
// the text of a dnsmasq config snippet. It does NOT write files, run dnsmasq, or wire
// into Apply/render.go/pbr.go — that integration is a deliberate follow-up.
//
// Intended deployment path of the rendered snippet (one of, depending on platform):
//   - OpenWrt / generic Linux : /etc/dnsmasq.d/wayhop-pbr.conf
//   - Entware / Keenetic /opt : /opt/etc/dnsmasq.d/wayhop-pbr.conf
//   - Keenetic stock dnsmasq  : included via the /opt overlay's dnsmasq conf-dir
// After writing, dnsmasq must be reloaded (SIGHUP) so the directives take effect. The
// kernel set named here must already exist (Compile/RenderNft declares the same
// "<zone>_4"/"<zone>_6" sets in `table inet <Plan.Table>`); dnsmasq only POPULATES it.

import (
	"fmt"
	"sort"
	"strings"
)

// DomainSet is one dnsmasq → kernel-set mapping: a kernel set fed by the resolved IPs of
// the given domains. It is a standalone input so callers that do not have a full *Plan
// (e.g. a unit harness or a future external caller) can still render a snippet; the
// Plan-based helpers below build these for you.
type DomainSet struct {
	// SetBase is the zone's base set name (e.g. "list_ru_block"). The v4 / v6 kernel sets
	// are derived as SetBase+"_4" / SetBase+"_6" to match RenderNft's declarations exactly.
	SetBase string
	// Domains are the (already-domain) entries that should auto-populate the set on
	// resolution. Rendering normalizes + de-dupes them; an empty result yields no line.
	Domains []string
}

// DnsmasqOptions tune the rendered directive form. The zero value renders the modern
// nftables form against the plan's own table for both IPv4 and IPv6 — the right default
// for the native-first kernel-PBR plane this package compiles.
type DnsmasqOptions struct {
	// Table is the nftables table the kernel sets live in (matches Plan.Table, e.g.
	// "wayhop_pbr"). Required for the nftset form; ignored by the legacy ipset form.
	Table string

	// Legacy, when true, emits the older `ipset=/dom/.../set4,set6` form instead of the
	// modern `nftset=/dom/.../inet#table#set` form. Use for dnsmasq builds compiled with
	// --enable-ipset but WITHOUT nftset support (older Entware / older OpenWrt). Default
	// false → the nftset form (dnsmasq 2.81+, what current OpenWrt/Entware ship).
	Legacy bool

	// NoV6, when true, suppresses the IPv6 (..._6) set from each directive — for a v4-only
	// fail-closed posture mirroring the rest of the plan. Default false → both families.
	NoV6 bool
}

// nftFamily is the address family dnsmasq's nftset directive targets. We declare the
// kernel sets in `table inet` (dual-stack), so dnsmasq must reference them as `inet`.
const nftFamily = "inet"

// dnsmasqHeader marks the generated snippet so an operator (and any future apply layer)
// can recognize + safely overwrite it.
const dnsmasqHeader = "# WayHop dnsmasq domain-routing snippet (generated; do not edit by hand)"

// PlanDomainSets returns the DomainSets this plan needs: one per zone that carries
// domains (zones only carry Domains when Compile ran with Options.CollectDomainZones).
// The result is sorted by SetBase for stable, diff-friendly output. Zones without any
// domains are skipped.
func (pl *Plan) PlanDomainSets() []DomainSet {
	var out []DomainSet
	for _, z := range pl.Zones {
		if len(z.Domains) == 0 {
			continue
		}
		out = append(out, DomainSet{SetBase: z.Name, Domains: z.Domains})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SetBase < out[j].SetBase })
	return out
}

// RenderDnsmasq renders the full dnsmasq.d snippet for this plan's domain zones, ready to
// write to the intended conf-dir path documented at the top of this file. Returns the
// empty string when the plan has no domain zones (so the caller can skip writing a file).
func (pl *Plan) RenderDnsmasq(opt DnsmasqOptions) string {
	return RenderDnsmasqSets(pl.PlanDomainSets(), opt)
}

// RenderDnsmasqSets renders a dnsmasq.d snippet for an arbitrary list of DomainSets.
// Each set yields at most one directive line (domains are joined into the single
// dnsmasq form). Sets are emitted in input order EXCEPT that the slice is first sorted
// by SetBase for deterministic output; a set whose domains normalize to empty is
// skipped. The whole snippet is empty (no header) when nothing remains.
func RenderDnsmasqSets(sets []DomainSet, opt DnsmasqOptions) string {
	if opt.Table == "" {
		opt.Table = "wayhop_pbr"
	}

	// Stable order, independent of caller order.
	ordered := append([]DomainSet(nil), sets...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].SetBase < ordered[j].SetBase })

	var lines []string
	for _, ds := range ordered {
		line := renderDirective(ds, opt)
		if line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return dnsmasqHeader + "\n" + strings.Join(lines, "\n") + "\n"
}

// renderDirective renders a single dnsmasq directive line for one DomainSet, or "" when
// the set has no usable domains. normalizeDomains (shared with the nft path in pbr.go)
// lowercases, trims wildcards/comments, and de-dupes so the emitted domain list matches
// exactly what populates the kernel set.
func renderDirective(ds DomainSet, opt DnsmasqOptions) string {
	doms := normalizeDomains(ds.Domains)
	if len(doms) == 0 || ds.SetBase == "" {
		return ""
	}
	// dnsmasq form: KEY=/dom1/dom2/.../<target>. The leading empty segment before the
	// first "/" plus a trailing "/" around the domain group is dnsmasq's required syntax.
	domPart := "/" + strings.Join(doms, "/") + "/"

	set4 := ds.SetBase + "_4"
	set6 := ds.SetBase + "_6"

	if opt.Legacy {
		// ipset=/dom/.../set4[,set6] — dnsmasq adds the resolved A (and AAAA) records to
		// the named ipset(s). The ipset names must match the kernel ipset names exactly.
		targets := set4
		if !opt.NoV6 {
			targets = set4 + "," + set6
		}
		return "ipset=" + domPart + targets
	}

	// nftset=/dom/.../FAMILY#TABLE#SET[,FAMILY#TABLE#SET] — dnsmasq adds resolved A
	// records to the v4 set and AAAA records to the v6 set within `table inet <table>`.
	v4 := fmt.Sprintf("%s#%s#%s", nftFamily, opt.Table, set4)
	if opt.NoV6 {
		return "nftset=" + domPart + v4
	}
	v6 := fmt.Sprintf("%s#%s#%s", nftFamily, opt.Table, set6)
	return "nftset=" + domPart + v4 + "," + v6
}

// DnsmasqSetNames returns, for a plan, the kernel set names dnsmasq will populate — the
// "<zone>_4" / "<zone>_6" pair per domain zone. Useful for a future apply layer to verify
// the sets exist (RenderNft declares them) before reloading dnsmasq, and for diagnostics.
// Honors NoV6 (omits the _6 names). Sorted, de-duped.
func (pl *Plan) DnsmasqSetNames(opt DnsmasqOptions) []string {
	return dnsmasqSetNames(pl.PlanDomainSets(), opt)
}

func dnsmasqSetNames(sets []DomainSet, opt DnsmasqOptions) []string {
	seen := map[string]bool{}
	var out []string
	add := func(n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, ds := range sets {
		if len(normalizeDomains(ds.Domains)) == 0 || ds.SetBase == "" {
			continue
		}
		add(ds.SetBase + "_4")
		if !opt.NoV6 {
			add(ds.SetBase + "_6")
		}
	}
	sort.Strings(out)
	return out
}
