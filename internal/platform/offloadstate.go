package platform

import (
	"strconv"
	"strings"
)

// OffloadState is the EFFECTIVE runtime flow-offload state — deliberately distinct from Accel
// (a CAPABILITY: "this SoC has a PPE / this kernel has an nft flowtable"). A router can advertise
// hardware offload while every packet still takes the slow path, which is exactly what happens when a
// policy-routing plane disables the fast path or forces per-packet classification. Reporting the
// capability as if it were the outcome is the "claimed enabled because configured" failure the spec
// forbids, so this reports what the datapath is ACTUALLY doing plus WHY it was downgraded.
//
// Three modes are kept apart because they answer different questions and routinely disagree:
// Requested is what WayHop's own config asks for, Configured is what the device is set to, and
// Effective is what was observed happening. Every consumer reads this one struct, so a row in
// Diagnostics cannot contradict the capabilities endpoint about the same router.
type OffloadState struct {
	Requested  string `json:"requested,omitempty"` // WayHop's configured mode: off | sw | hw (empty = unset)
	Configured string `json:"configured"`          // the device's own intent: off | sw | hw | unknown
	Effective  string `json:"effective"`           // observed: off | sw | hw | unknown

	// Evidence availability, one flag per independent signal. Without these, "off" and "nothing could
	// be measured" collapse into the same answer — which is the confusion this type exists to end.
	UCIKnown   bool `json:"uci_known"`   // /etc/config/firewall was readable
	NftKnown   bool `json:"nft_known"`   // the nft flowtable list was readable
	KnobsKnown bool `json:"knobs_known"` // this platform exposes fast-path sysctls (Keenetic/MediaTek)
	FlowsKnown bool `json:"flows_known"` // conntrack could be sampled

	Flowtable   bool `json:"flowtable"`          // a flowtable is installed in the ruleset
	FlowtableHW bool `json:"flowtable_hw"`       // that flowtable carries `flags offload` (hardware)
	PPEEnabled  bool `json:"ppe_enabled"`        // the hardware PPE knob
	FastNATOn   bool `json:"fastnat_on"`         // the software fast-path knob
	MarkedPlane bool `json:"marked_plane"`       // WayHop's own mark-based PBR table is installed
	FlowsTotal  int  `json:"flows_total"`        // conntrack entries sampled
	FlowsOffl   int  `json:"flows_offloaded"`    // entries carrying any offload mark
	FlowsHW     int  `json:"flows_hw_offloaded"` // entries explicitly marked [HW_OFFLOAD]

	Reasons        []string `json:"reasons,omitempty"`        // why the modes differ, or why nothing is known
	Recommendation string   `json:"recommendation,omitempty"` // what to do about it, if anything
}

// OffloadInputs is the captured device text a verdict is derived from. Every field is optional: an
// absent one contributes no evidence, which is what keeps `unknown` reachable instead of assumed.
type OffloadInputs struct {
	Requested   string // the mode WayHop's config asks for: off | sw | hw
	FirewallUCI string // /etc/config/firewall — fw4's configured intent
	Flowtables  string // `nft list flowtables` output
	// FlowtablesKnown says the command RAN. `nft list flowtables` prints nothing when no flowtable
	// exists, which is the same empty string a missing nft produces — and those are the difference
	// between "conclusively off" and "nothing could be measured".
	FlowtablesKnown bool
	PPEEnabled      string // /proc/sys/net/hwnat/ppe_enabled
	FastNAT         string // /proc/sys/net/netfilter/nf_conntrack_fastnat
	Conntrack       string // a sample of /proc/net/nf_conntrack
	// ConntrackKnown distinguishes a readable empty table from an unreadable one. Non-empty text also
	// implies known for compatibility with recorded fixtures and other pure callers.
	ConntrackKnown bool
	// MarkedPlane says WayHop's PBR table was seen in the kernel. A false here only softens the
	// recommendation's wording; the carve-out warning is stated either way, so failing to observe the
	// plane can never turn the advice into something unsafe.
	MarkedPlane bool
}

// DetectOffload derives the effective offload state from captured device text. Pure (no I/O) so it is
// unit-tested against real captures, and the single place any consumer's verdict comes from.
//
// Precedence: observed flows beat every knob and every config line. A router whose connections carry
// an offload mark IS offloading, whatever /etc/config/firewall says, and saying "the hardware fast
// path is unused" in that state is a claim contradicted by the evidence sitting next to it.
func DetectOffload(in OffloadInputs) OffloadState {
	st := OffloadState{
		Requested:   in.Requested,
		Configured:  "unknown",
		Effective:   "unknown",
		MarkedPlane: in.MarkedPlane,
	}

	// The device's own intent, from fw4's config rather than from what WayHop asked for.
	if strings.TrimSpace(in.FirewallUCI) != "" {
		st.UCIKnown = true
		sw, hw := parseOffloadConfig(in.FirewallUCI)
		switch {
		case sw && hw:
			st.Configured = "hw"
		case sw:
			st.Configured = "sw"
		case hw:
			st.Configured = "off"
			st.Reasons = append(st.Reasons,
				"flow_offloading_hw is set but flow_offloading is not, so fw4 installs no flowtable at all")
		default:
			st.Configured = "off"
		}
	}

	// What is actually installed. `flags offload` is the hardware form.
	if in.FlowtablesKnown {
		st.NftKnown = true
		st.Flowtable = strings.Contains(in.Flowtables, "flowtable")
		st.FlowtableHW = st.Flowtable && strings.Contains(in.Flowtables, "flags offload")
	}

	ppe, ppeOK := parseSysctlBool(in.PPEEnabled)
	fn, fnOK := parseSysctlBool(in.FastNAT)
	st.PPEEnabled, st.FastNATOn, st.KnobsKnown = ppe, fn, ppeOK || fnOK

	st.FlowsKnown = in.ConntrackKnown
	st.countFlows(in.Conntrack)
	st.decide()
	st.explain()
	st.recommend()
	return st
}

// countFlows samples conntrack for offload marks.
//
// The kernel prints "[OFFLOAD] " when IPS_OFFLOAD is set and "[HW_OFFLOAD] " otherwise, so the two
// tags are not a clean software/hardware split: a hardware-offloaded flow can print the plain tag.
// [HW_OFFLOAD] therefore PROVES hardware, while [OFFLOAD] proves only that the flow left the slow
// path — which is why the tier for a plain tag is settled by the flowtable's flags, not guessed here.
func (st *OffloadState) countFlows(conntrack string) {
	st.FlowsKnown = st.FlowsKnown || strings.TrimSpace(conntrack) != ""
	for _, ln := range strings.Split(conntrack, "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		st.FlowsTotal++
		switch {
		case strings.Contains(ln, "[HW_OFFLOAD]"):
			st.FlowsOffl++
			st.FlowsHW++
		case strings.Contains(ln, "[OFFLOAD]"):
			st.FlowsOffl++
		}
	}
}

// decide sets Effective from the strongest evidence available, and leaves it "unknown" when there is
// none. Each branch is decidable from what it reads; nothing infers the datapath from configuration.
func (st *OffloadState) decide() {
	switch {
	case st.FlowsHW > 0:
		st.Effective = "hw"
	case st.FlowsOffl > 0 && st.FlowtableHW:
		st.Effective = "hw"
	case st.FlowsOffl > 0:
		st.Effective = "sw"
	case st.NftKnown && !st.Flowtable:
		// No flowtable exists, so nothing can be offloaded regardless of any knob.
		st.Effective = "off"
	case st.Flowtable && st.FlowsKnown && st.FlowsTotal > 0:
		// A flowtable is installed and not one sampled connection uses it.
		st.Effective = "off"
	case st.KnobsKnown && st.PPEEnabled && !st.FastNATOn:
		// The exact defeated state: hardware capability ON, software fast path forced OFF, so nothing
		// is actually offloaded. This is what a mark-based policy-routing plane does to a MediaTek box.
		st.Effective = "off"
	case st.KnobsKnown && !st.PPEEnabled:
		st.Effective = "off"
	case st.KnobsKnown && st.PPEEnabled && st.FastNATOn && st.FlowsKnown && st.FlowsTotal > 0:
		// Knobs look right but nothing is actually offloaded — report honestly rather than optimistically.
		st.Effective = "off"
		// Enabled knobs with no active observed flow are intent, not proof of an effective fast path.
		// Keep unknown until a flow carries an offload mark or a non-empty sample proves that none do.
	}
}

// explain records why the verdict is what it is, and why it differs from what was asked for. The
// mismatch lines are the point: a bare "off" next to a configured "hw" is what sends an operator
// looking for a fault that is not there.
func (st *OffloadState) explain() {
	switch {
	case st.Effective == "hw" && st.FlowsHW > 0:
		st.Reasons = append(st.Reasons, quantify(st.FlowsHW, st.FlowsTotal, "hardware-offloaded"))
	case st.Effective == "sw":
		st.Reasons = append(st.Reasons, quantify(st.FlowsOffl, st.FlowsTotal, "offloaded")+
			"; none is marked as hardware-offloaded and the flowtable does not carry `flags offload`")
	case st.Effective == "off" && st.NftKnown && !st.Flowtable:
		st.Reasons = append(st.Reasons, "no flowtable is installed, so no connection can leave the slow path")
	case st.Effective == "off" && st.Flowtable && st.FlowsTotal > 0:
		st.Reasons = append(st.Reasons, "a flowtable is installed but "+
			quantify(st.FlowsOffl, st.FlowsTotal, "offloaded"))
	case st.Effective == "off" && st.KnobsKnown && st.PPEEnabled && !st.FastNATOn:
		st.Reasons = append(st.Reasons, "hardware PPE is enabled but the conntrack fast path "+
			"(nf_conntrack_fastnat) is disabled, so flows are not offloaded — a per-packet "+
			"policy-routing plane typically forces this")
		if st.FlowsKnown && st.FlowsTotal > 0 {
			st.Reasons = append(st.Reasons, quantify(st.FlowsOffl, st.FlowsTotal, "offloaded"))
		}
	case st.Effective == "off" && st.KnobsKnown && !st.PPEEnabled:
		st.Reasons = append(st.Reasons, "hardware PPE is disabled")
	case st.Effective == "off" && st.KnobsKnown:
		st.Reasons = append(st.Reasons, "the fast-path knobs are enabled, but "+
			quantify(st.FlowsOffl, st.FlowsTotal, "offloaded"))
	case st.Effective == "unknown" && st.FlowsKnown && st.FlowsTotal == 0:
		st.Reasons = append(st.Reasons,
			"conntrack was readable but contained no active connections, so no effective offload tier could be observed")
	case st.Effective == "unknown":
		st.Reasons = append(st.Reasons, "no runtime evidence was available"+missing(st)+
			", so the effective state cannot be stated")
	}

	if st.Effective == "unknown" {
		return // a mismatch against an unmeasured state is not a finding.
	}
	if st.Requested != "" && st.Requested != st.Effective {
		st.Reasons = append(st.Reasons,
			"requested offload mode is "+st.Requested+" but the effective state is "+st.Effective)
	}
	if st.UCIKnown && st.Configured != st.Effective {
		st.Reasons = append(st.Reasons,
			"the router is configured for "+st.Configured+" but the effective state is "+st.Effective)
	}
}

// recommend states what to do, and never advises a blind flow_offloading_hw flip: WayHop steers
// tunnel carve-outs by firewall mark, so a flowtable that does not exclude marked connections would
// offload a carve-out straight past the tunnel — a leak, delivered as a performance tip.
func (st *OffloadState) recommend() {
	const carveOut = " WayHop routes tunnel carve-outs by firewall mark, so the flowtable must EXCLUDE " +
		"marked connections; enabling flow_offloading_hw without that exclusion can offload a carve-out " +
		"straight past the tunnel."
	const carveOutLive = " WayHop's mark-based policy-routing plane is installed on this router right " +
		"now, so a flowtable that does not EXCLUDE marked connections would offload a carve-out straight " +
		"past the tunnel. Do not enable flow_offloading_hw without that exclusion."

	warning := carveOut
	if st.MarkedPlane {
		warning = carveOutLive
	}
	switch st.Effective {
	case "unknown":
		st.Recommendation = "Nothing about the datapath could be measured here, so no offload setting " +
			"should be changed on the strength of this row."
	case "off":
		st.Recommendation = "Enabling flow offload can raise routed throughput and lower CPU." + warning
	case "sw":
		st.Recommendation = "Software offload is working. Hardware offload would raise throughput " +
			"further on a capable NIC." + warning
	}
}

func quantify(n, total int, what string) string {
	return strconv.Itoa(n) + " of " + strconv.Itoa(total) + " sampled connections are " + what
}

// missing names the signals that were unreadable, so "unknown" points somewhere.
func missing(st *OffloadState) string {
	var absent []string
	if !st.NftKnown {
		absent = append(absent, "no flowtable list")
	}
	if !st.KnobsKnown {
		absent = append(absent, "no fast-path knobs")
	}
	if !st.FlowsKnown {
		absent = append(absent, "no conntrack sample")
	}
	if len(absent) == 0 {
		return ""
	}
	return " (" + strings.Join(absent, ", ") + ")"
}

// parseOffloadConfig reads the fw4 (uci) firewall text and reports whether software and hardware flow
// offloading are enabled in the defaults section. Accepts the common uci truthy spellings ('1'/true/
// on/yes, quoted or not).
func parseOffloadConfig(cfg string) (sw, hw bool) {
	for _, ln := range strings.Split(cfg, "\n") {
		f := strings.Fields(ln)
		if len(f) < 3 || f[0] != "option" {
			continue
		}
		on := false
		switch strings.Trim(f[2], "'\"") {
		case "1", "true", "on", "yes":
			on = true
		}
		switch f[1] {
		case "flow_offloading":
			sw = on
		case "flow_offloading_hw":
			hw = on
		}
	}
	return sw, hw
}

// parseSysctlBool reads a /proc/sys style boolean ("0"/"1"). ok is false when the file was absent or
// unparseable, so callers can distinguish "off" from "this platform has no such knob".
func parseSysctlBool(s string) (val, ok bool) {
	t := strings.TrimSpace(s)
	if t == "" {
		return false, false
	}
	n, err := strconv.Atoi(strings.Fields(t)[0])
	if err != nil {
		return false, false
	}
	return n != 0, true
}
