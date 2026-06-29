package server

import (
	"net/http"

	"wakeroute/internal/pbr"
)

// handlePBRStatus reports whether the kernel PBR plan is currently installed and whether
// it matches the current profile. Uses zone count as a lightweight staleness proxy (not a
// full diff): if installed zones != compiled zones the plan is considered stale. A nil
// installed plan is always stale (plan should be applied).
func (s *Server) handlePBRStatus(w http.ResponseWriter, r *http.Request) {
	s.pbrMu.Lock()
	installed := s.pbrPlan != nil
	installedZones := 0
	var masqIfaces []string
	if s.pbrPlan != nil {
		installedZones = len(s.pbrPlan.Zones)
		masqIfaces = s.pbrPlan.MasqIfaces
	}
	s.pbrMu.Unlock()

	p := s.store.Profile()
	compiledZones := 0
	if fresh, _, err := pbr.Compile(&p, pbr.Options{}); err == nil {
		compiledZones = len(fresh.Zones)
	}
	if masqIfaces == nil {
		masqIfaces = []string{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"mode":           s.config().RoutingMode,
		"installed":      installed,
		"zones":          installedZones,
		"masq_ifaces":    masqIfaces,
		"compiled_zones": compiledZones,
		"stale":          !installed || installedZones != compiledZones,
	})
}

// handlePBRPreview compiles the current profile into a kernel policy-based-routing plan
// and returns it READ-ONLY — the rendered nftables ruleset, the ip rule/route commands,
// and warnings about model content the IP-based compiler does not kernel-route (domains,
// geoip rule-sets, group failover, proxy-engine targets). Diagnostics for the native-
// first "hybrid" routing mode (docs/ARCHITECTURE_NATIVE_FIRST.md). It does NOT touch the
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
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":     c.RoutingMode,
		"plan":     plan,
		"nft":      plan.RenderNft(),
		"ip":       plan.RenderIP(pbr.Options{}),
		"teardown": plan.RenderTeardown(pbr.Options{}),
		"warnings": warns,
	})
}

// handlePBRApply compiles the current profile into a kernel PBR plan and applies it
// (nftables + ip rules/routes) without touching the sing-box config. Use when only
// routing lists changed, or after fw4 reload flushed the nft table.
func (s *Server) handlePBRApply(w http.ResponseWriter, r *http.Request) {
	c := s.config()
	p := s.store.Profile()
	mode := s.routingMode(c)
	if c.Demo {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "zones": 0, "warnings": []pbr.Warning{}, "demo": true})
		return
	}
	// #1: mode-gate exactly like handleApply (genOptionsWithPlan). The kernel plane exists ONLY in
	// hybrid/fast; in tun/mixed the capture-all sing-box TUN owns all traffic, so installing a kernel
	// plane here would desync the two datapaths (the TUN config never route_excluded these CIDRs).
	// Tear any stale plane down instead of installing one.
	if mode != "hybrid" && mode != "fast" {
		if err := s.applyPBR(nil); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "zones": 0, "warnings": []pbr.Warning{}, "mode": mode})
		return
	}
	// #2/#8: compile with pbrCompileOptions (NOT bare Options{}) so the plan carries the flow-offload
	// flowtable in fast mode — otherwise this endpoint silently replaced the offload-bearing plan
	// installed by handleApply with an offload-less one (DeepEqual differs → teardown+reapply).
	plan, warns, err := pbr.Compile(&p, s.pbrCompileOptions(c))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.applyPBR(plan); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if warns == nil {
		warns = []pbr.Warning{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"zones":    len(plan.Zones),
		"warnings": warns,
	})
}

// handlePBRTeardown removes the kernel PBR plane (nft table + ip rules/routes).
// The plan tears down best-effort (errors ignored per Teardown contract).
func (s *Server) handlePBRTeardown(w http.ResponseWriter, r *http.Request) {
	s.pbrMu.Lock()
	plan := s.pbrPlan
	s.pbrPlan = nil
	s.pbrMu.Unlock()
	if plan != nil {
		_ = plan.Teardown(s.pbrRunner, pbr.Options{})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
