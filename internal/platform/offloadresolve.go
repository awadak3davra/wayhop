package platform

// ResolveOffload implements the "Auto" offload mode: pick the safest option this router actually
// supports, rather than making the operator work out whether their SoC has a flowtable.
//
// The spec requires four modes (Off / Software / Hardware / Auto) and requires the UI to explain why
// a mode is unavailable or was downgraded. Auto is the mode that needs the explanation most: it
// resolves to something different per router, so without a stated reason the user cannot tell an
// intentional "off, because this hardware cannot do it" from a silent failure.
//
// The ordering is deliberately conservative. Hardware offload is chosen ONLY when a flowtable exists
// AND a hardware path is reported; anything less falls to software, and anything less than that
// falls to Off. Falling back is always safe — offload is an optimisation — whereas guessing upward
// risks a flowtable that will not load, or one that quietly bypasses the policy routing that
// carve-outs depend on.
//
// It is a pure function of the capability probe so the decision is identical in preview, apply and
// reconcile. A resolver that disagreed with itself between those three would produce exactly the
// class of drift this project spent its effort eliminating.
func ResolveOffload(requested string, caps Capabilities) (effective, reason string) {
	switch requested {
	case "", "off":
		return "off", ""
	case "sw", "hw":
		// An explicit choice is honoured here and judged by Preflight, which reports a request this
		// router cannot satisfy. Resolution and judgement are kept separate so neither has to guess
		// at the other's intent.
		return requested, ""
	case "auto":
		// fall through to the decision below
	default:
		// Unknown values fail closed. Config validation rejects them long before this, so reaching
		// here means something bypassed validation — in which case Off is the only safe answer.
		return "off", "unrecognised offload mode; using Off"
	}

	switch {
	case caps.Accel.Kind == "nft-flowtable" && caps.Accel.HW:
		return "hw", "hardware flow-offload is supported by this kernel and NIC"
	case caps.Accel.Kind == "nft-flowtable":
		return "sw", "this kernel supports a software flowtable but reports no hardware offload path"
	case caps.Accel.Kind == "ppe":
		return "off", "acceleration here is the firmware's own hardware NAT (PPE), which WayHop does not drive"
	default:
		return "off", "no forwarding accelerator was detected on this router"
	}
}

// OffloadModes are the modes the UI offers, in the order it should present them. "auto" is first
// because it is the right default for anyone who does not already know their router's capabilities.
var OffloadModes = []string{"auto", "off", "sw", "hw"}
