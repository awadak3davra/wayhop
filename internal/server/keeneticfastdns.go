package server

import (
	"fmt"
	"strings"

	"wayhop/internal/config"
	"wayhop/internal/nativedns"
	"wayhop/internal/pbr"
)

func keeneticPlanHasDomainNames(plan *pbr.Plan) bool {
	if plan == nil {
		return false
	}
	for _, z := range plan.Zones {
		if len(z.Domains) > 0 {
			return true
		}
	}
	return false
}

func keeneticFastDNSEnabled(cfg config.Config, plan *pbr.Plan) bool {
	return cfg.FastDNSEnforceOn() && keeneticPlanHasDomainNames(plan)
}

// keeneticFastEnforceRefusal refuses a fast-mode Apply that must enforce DNS but knows no LAN interface
// to enforce it on (HUNT-K #2): the program would carry no redirect, its postcheck would expect none,
// and the LAN's devices would keep their own resolvers while Review said enforcement was on.
func keeneticFastEnforceRefusal(io pbr.IpsetOptions) error {
	if !io.FastDNSEnforce || len(io.EnforcedLANs()) > 0 {
		return nil
	}
	return newMaterializeError("kernel",
		"fast mode redirects the LAN's DNS to the router, but the router's LAN interfaces could not be read, so it cannot be enforced",
		"Review and Apply again; if it persists, set fast_dns_enforce to false in config.json.")
}

func keeneticFastResolverProblem(usable error, answering nativedns.Answering) string {
	if usable != nil {
		return "Entware dnsmasq is not usable: " + usable.Error()
	}
	if strings.HasPrefix(answering.Process, "dnsmasq") {
		return ""
	}
	if answering.Process == "" {
		return "the LAN DNS listener could not be identified as Entware dnsmasq"
	}
	return fmt.Sprintf("%s owns LAN DNS, not Entware dnsmasq", answering.Process)
}
