package server

import (
	"context"
	"fmt"
	"net/http"

	"wayhop/internal/config"
	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// ndmpolicy.go is the host-aware half of routing a list into one of KeeneticOS's access policies
// (competitor gap 6: HydraRoute Neo routes its lists through the router's own policies, so NDM's
// failover, fail-back and blackhole apply to them). The profile stores only the policy's name; the
// mark NDM routes it by is read from the router - by the review here, and by the Apply capture
// (captureExecutionNative) for the plan it compiles.

// demoNDMPolicies is the demo's router: two policies in the shape a live Keenetic reports, so the
// panel and the review can be exercised without NDM. Marks and tables are the measured ones.
var demoNDMPolicies = []keenetic.Policy{
	{Name: "Policy0", Description: "Bypass", Mark: 0x0ffffaaa, Table: 4096},
	{Name: "Policy1", Description: "Tunnel", Mark: 0x0ffffaab, Table: 4098},
}

// ndmPolicyFacts is what the review knows about the router's access policies.
type ndmPolicyFacts struct {
	inUse    []string          // the policies the enabled lists point at; nil = none, nothing was read
	keenetic bool              // the router runs KeeneticOS (or is the demo's)
	marks    map[string]uint32 // name → mark, as read
	readErr  error             // the read failed: nothing can be said about which policies exist
}

// reviewNDMPolicies reads the router's access policies for the review, and only when a list points at
// one: every other profile reads nothing and cannot fail here. The review is built on every panel
// visit; the read is one ndmc call, and on a live Keenetic two consecutive ones finished within the
// same wall-clock second.
func (s *Server) reviewNDMPolicies(ctx context.Context, cfg config.Config, p *model.Profile) ndmPolicyFacts {
	facts := ndmPolicyFacts{inUse: model.NDMPoliciesInUse(p)}
	if len(facts.inUse) == 0 {
		return facts
	}
	if cfg.Demo {
		facts.keenetic, facts.marks = true, keenetic.PolicyMarks(demoNDMPolicies)
		return facts
	}
	if s.detectedPlatform() != platform.Keenetic {
		return facts
	}
	facts.keenetic = true
	policies, err := s.keeneticPolicies(ctx)
	if err != nil {
		facts.readErr = err
		return facts
	}
	facts.marks = keenetic.PolicyMarks(policies)
	return facts
}

// ndmPolicyFindings refuses Apply for every enabled list sent to an access policy this router cannot
// route it by: off KeeneticOS there are none, an unreadable listing proves nothing, and a policy NDM no
// longer has - deleted or renamed in the router's settings - would leave the list marked for a rule
// that does not exist.
func ndmPolicyFindings(p *model.Profile, facts ndmPolicyFacts) []PlanFinding {
	if p == nil || len(facts.inUse) == 0 {
		return nil
	}
	var out []PlanFinding
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		name, ok := model.NDMPolicyName(rl.Outbound)
		if !rl.Enabled || !ok {
			continue
		}
		f := PlanFinding{
			Setting: "routing list", Item: listName(rl),
			Severity: platform.SeverityBlocked, Reason: platform.ReasonSavedValueIncompat, Blocks: platform.BlocksApply,
		}
		switch {
		case !facts.keenetic:
			f.ID = "list.ndm_policy_unsupported"
			f.Detail = fmt.Sprintf("This list is sent to access policy %q. Access policies belong to KeeneticOS, and this router is not running it.", name)
			f.Remedy = "Point the list at a connection or a group."
		case facts.readErr != nil:
			f.ID = "list.ndm_policy_unread"
			f.Detail = fmt.Sprintf("This list is sent to access policy %q, and the router's access policies could not be read, so whether it exists is unknown.", name)
			f.Remedy = "Review again in a moment. If it keeps failing, NDM is not answering `show ip policy` on this router."
		default:
			if _, present := facts.marks[name]; present {
				continue
			}
			f.ID = "list.ndm_policy_missing"
			f.Detail = fmt.Sprintf("This list is sent to access policy %q, which this router does not have: it was deleted or renamed in the router's settings.", name)
			f.Remedy = "Send the list to one of the router's access policies, or point it at a connection."
		}
		out = append(out, f)
	}
	return out
}

// ndmPolicyAnswer is one access policy as GET /api/keenetic/policies reports it.
type ndmPolicyAnswer struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Mark        uint32 `json:"mark"`
}

// handleKeeneticPolicies answers GET /api/keenetic/policies: the router's access policies a routing
// list can be sent to, as NDM reports them right now. Read-only; the panel offers them as
// "ndm-policy:<name>" outbounds.
func (s *Server) handleKeeneticPolicies(w http.ResponseWriter, r *http.Request) {
	// Demo mode must not run host commands, and the picker has to be buildable without a router.
	if s.demoMode() {
		writeJSONNoStore(w, http.StatusOK, ndmPolicyAnswers(demoNDMPolicies))
		return
	}
	if s.detectedPlatform() != platform.Keenetic {
		writeErr(w, http.StatusUnprocessableEntity, "access policies are read from KeeneticOS, and this router is not running KeeneticOS")
		return
	}
	policies, err := s.keeneticPolicies(r.Context())
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "cannot read the router's access policies")
		return
	}
	writeJSONNoStore(w, http.StatusOK, ndmPolicyAnswers(policies))
}

func ndmPolicyAnswers(policies []keenetic.Policy) []ndmPolicyAnswer {
	out := make([]ndmPolicyAnswer, 0, len(policies))
	for _, p := range policies {
		out = append(out, ndmPolicyAnswer{Name: p.Name, Description: p.Description, Mark: p.Mark})
	}
	return out
}
