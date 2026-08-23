package server

import (
	"net/http"

	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// handlePBRStatus reports whether the kernel PBR plan is currently installed and whether
// it matches the current profile. Uses zone count as a lightweight staleness proxy (not a
// full diff): if installed zones != compiled zones the plan is considered stale. A nil
// installed plan is always stale (plan should be applied).
func (s *Server) handlePBRStatus(w http.ResponseWriter, r *http.Request) {
	installedPlan := s.installedKernelPlan()
	installed := installedPlan != nil
	installedZones := 0
	var masqIfaces []string
	if installedPlan != nil {
		installedZones = len(installedPlan.Zones)
		masqIfaces = installedPlan.MasqIfaces
	}
	plane := "kernel"
	if s.detectedPlatform() == platform.Keenetic {
		plane = "native"
	}

	p := s.store.Profile()
	compiledZones := 0
	if fresh, _, err := pbr.Compile(&p, pbr.Options{}); err == nil {
		compiledZones = len(fresh.Zones)
	}
	if masqIfaces == nil {
		masqIfaces = []string{}
	}
	// The plane is "installed" as far as the record knows; the reconcile loop's last observation
	// says whether the kernel still carries it.
	verified := installed && s.kernelPlaneObserved() != kernelPlaneMissing

	writeJSON(w, http.StatusOK, map[string]any{
		"mode":           s.config().RoutingMode,
		"plane":          plane,
		"installed":      installed,
		"verified":       verified,
		"zones":          installedZones,
		"masq_ifaces":    masqIfaces,
		"compiled_zones": compiledZones,
		"stale":          !installed || !verified || installedZones != compiledZones,
	})
}

// handlePBRPreview compiles the current profile into a kernel policy-based-routing plan
// and returns it READ-ONLY — the rendered nftables ruleset, the ip rule/route commands,
// and warnings about model content the IP-based compiler does not kernel-route (domains,
// geoip rule-sets, group failover, proxy-engine targets). Diagnostics for the native-
// first "hybrid" routing mode (docs/ARCHITECTURE_NATIVE_FIRST.md (development repository)). It does NOT touch the
// router — no nft/ip is executed.
func (s *Server) handlePBRPreview(w http.ResponseWriter, r *http.Request) {
	c := s.config()
	p := s.store.Profile()
	// Compile with the SAME options the apply path uses (flow-offload flowtable et al.),
	// so the preview reflects what Apply would actually install — a bare Options{} omits it.
	plan, warns, err := pbr.Compile(&p, s.pbrCompileOptions(c))
	if err != nil || plan == nil {
		msg := "no routing plan compiled (add routing lists with IP/CIDR sources)"
		if err != nil {
			msg = err.Error()
		}
		writeErr(w, http.StatusUnprocessableEntity, msg)
		return
	}
	if warns == nil {
		warns = []pbr.Warning{}
	}
	// Flow-offload loads in a SEPARATE best-effort transaction (see pbr.Plan.RenderOffload/Apply);
	// append it to the preview so the diagnostics still show the full plane Apply would install.
	nft := plan.RenderNft()
	if off := plan.RenderOffload(); off != "" {
		nft += "\n# --- flow-offload (loaded separately, best-effort — failure degrades offload only) ---\n" + off
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":     c.RoutingMode,
		"plan":     plan,
		"nft":      nft,
		"ip":       plan.RenderIP(pbr.Options{}),
		"teardown": plan.RenderTeardown(pbr.Options{}),
		"warnings": warns,
	})
}
