package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"wayhop/internal/changeset"
	"wayhop/internal/config"
	"wayhop/internal/core"
	"wayhop/internal/dnsaudit"
	"wayhop/internal/generator"
	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
)

// The plan is what the Review & Apply panel shows and the only thing POST /api/apply is pinned to
// (through its rev). It is cheap on purpose: the cached capability probe, a pure kernel compile, the
// change-set differ. `sing-box check`, the NDM running-config read and the interface probes happen
// inside Apply, once.

// Plan verdicts.
const (
	VerdictReady   = "ready"   // nothing in the way
	VerdictWarning = "warning" // findings the user may knowingly accept
	VerdictBlocked = "blocked" // at least one hard blocker; apply is refused
)

// PlanFinding is one object-scoped problem as a finding source reports it. It carries the requested
// and effective values so the UI never has to imply that a discarded setting is active. Findings are
// folded into the API's Finding shape by foldFindings.
type PlanFinding struct {
	ID           string              `json:"id"`
	CapabilityID string              `json:"capability_id,omitempty"`
	Setting      string              `json:"setting"`
	Requested    string              `json:"requested"`
	Effective    string              `json:"effective"`
	Severity     string              `json:"severity"` // platform.SeverityBlocked | SeverityDegraded | SeverityPrivacy
	Reason       platform.ReasonCode `json:"reason_code,omitempty"`
	Detail       string              `json:"detail"`
	Remedy       string              `json:"remedy,omitempty"`
	Blocks       string              `json:"blocks"`
	// Item names the affected object (a rule, list or endpoint) for the folded entry's items[].
	Item string `json:"item,omitempty"`
	// Fix is a machine-readable way out, for the classes where prose is not enough because the panel
	// has no page for the object. Only set where an action genuinely exists; nil means "read the
	// remedy", which is every other finding.
	Fix *FindingFix `json:"fix,omitempty"`
}

// FindingFix is the one action that resolves a finding, named so the panel can offer a button
// instead of an instruction. Deliberately a closed vocabulary rather than a URL: the panel decides
// how to present it, and a finding cannot talk the panel into calling an arbitrary endpoint.
type FindingFix struct {
	Action string `json:"action"` // "delete_rule"
	ID     string `json:"id"`
	// Label is what the object is, for a button that has to read as an action on a specific thing.
	Label string `json:"label,omitempty"`
}

// Finding is the folded, API-facing shape. ID is stable and doubles as the acknowledgement key.
type Finding struct {
	ID          string   `json:"id"`
	Code        string   `json:"code"`
	Severity    string   `json:"severity"`
	Blocks      string   `json:"blocks"`
	AckRequired bool     `json:"ack_required"`
	Acked       bool     `json:"acked"`
	Title       string   `json:"title"`
	Detail      string   `json:"detail"`
	Remedy      string   `json:"remedy,omitempty"`
	Count       int      `json:"count"`
	Items       []string `json:"items"`
	// Fix survives the fold from the FIRST finding in the group, which is the one whose Detail and
	// Remedy are shown. Offering an action for a different member than the one described would be a
	// button that does something other than what the text above it says.
	Fix *FindingFix `json:"fix,omitempty"`
}

// hard reports whether the finding refuses Apply outright.
func (f Finding) hard() bool { return f.Blocks == platform.BlocksApply }

// planFindingItems bounds items[]; count says how many there really were.
const planFindingItems = 50

// planChanges is the change set vs the applied baseline.
type planChanges struct {
	BaselineAvailable bool                                       `json:"baseline_available"`
	BaselineRev       string                                     `json:"baseline_rev,omitempty"`
	Pending           bool                                       `json:"pending"`
	Count             int                                        `json:"count"`
	MayInterrupt      bool                                       `json:"may_interrupt"`
	RequiresApply     bool                                       `json:"requires_apply"`
	BySubsystem       map[changeset.Subsystem][]changeset.Change `json:"by_subsystem"`
	Changes           []changeset.Change                         `json:"changes"`
	Reason            string                                     `json:"reason,omitempty"`
}

type planWindow struct {
	Open        bool   `json:"open"`
	Phase       string `json:"phase"`
	SecondsLeft int    `json:"seconds_left"`
}

type planProbe struct {
	At    time.Time `json:"at"`
	AgeS  int64     `json:"age_s"`
	Stale bool      `json:"stale"`
	Error string    `json:"error,omitempty"`
}

type planPlatform struct {
	Name          string `json:"name"`
	CoreAvailable bool   `json:"core_available"`
	CoreRunning   bool   `json:"core_running"`
	KernelPlane   bool   `json:"kernel_plane"`
	NativeVPN     bool   `json:"native_vpn"`
}

// Plan is what a client reviews. Rev is the only value POST /api/apply is pinned to.
type Plan struct {
	Rev               string       `json:"rev"`
	Pending           bool         `json:"pending"`
	NothingConfigured bool         `json:"nothing_configured"`
	AppliedRev        string       `json:"applied_rev"`
	AppliedAt         int64        `json:"applied_at"`
	Verdict           string       `json:"verdict"`
	Findings          []Finding    `json:"findings"`
	Changes           planChanges  `json:"changes"`
	Window            planWindow   `json:"window"`
	Probe             planProbe    `json:"probe"`
	Platform          planPlatform `json:"platform"`
}

// blockers lists the hard blockers.
func (p Plan) blockers() []Finding {
	var out []Finding
	for _, f := range p.Findings {
		if f.hard() {
			out = append(out, f)
		}
	}
	return out
}

// unacked lists the findings that need an acknowledgement and do not have one.
func (p Plan) unacked() []Finding {
	var out []Finding
	for _, f := range p.Findings {
		if f.AckRequired && !f.Acked {
			out = append(out, f)
		}
	}
	return out
}

// capStaleAfter is how long a capability observation stays trustworthy. Longer than a page's
// lifetime but far shorter than a session: a probe from an hour ago says nothing useful about a
// router whose USB stick was pulled ten minutes ago.
const capStaleAfter = 5 * time.Minute

// capCache holds the last capability evaluation so an ordinary page load does not re-probe the
// host. Refresh is explicit (?refresh=1) or automatic once stale.
type capCache struct {
	mu  sync.Mutex
	set platform.CapabilitySet
}

// capabilitySet returns the current capability evaluation, probing the host when the cached copy is
// missing, stale, or a refresh was demanded.
func (s *Server) capabilitySet(ctx context.Context, refresh bool) platform.CapabilitySet {
	s.caps.mu.Lock()
	defer s.caps.mu.Unlock()

	if !refresh && !s.caps.set.ProbedAt.IsZero() && time.Since(s.caps.set.ProbedAt) < capStaleAfter {
		return s.caps.set
	}
	if s.config().Demo {
		// Demo is an explicitly synthetic router. Keep it deterministic and independent of the
		// developer host, but still pass through the same capability evaluator and endpoint gates as
		// production. Tests may seed the cache above with unsupported/unknown states to exercise those
		// refusal paths; there is no blanket demo bypass.
		rt := platform.RuntimeFacts{
			KernelPBRWired:   true,
			SingboxRunnable:  true,
			SingboxVersion:   "demo",
			NativeOperations: cloneHostBoolMap(s.nativeOperations),
			ProbedAt:         time.Now(),
		}
		s.caps.set = platform.Evaluate(platform.DemoCapabilities(), rt)
		return s.caps.set
	}
	s.caps.set = platform.Evaluate(platform.DetectCapabilities(), s.runtimeFacts(ctx))
	return s.caps.set
}

// runtimeFacts gathers the observations the pure evaluator cannot make for itself.
func (s *Server) runtimeFacts(ctx context.Context) platform.RuntimeFacts {
	c := s.config()
	rt := platform.RuntimeFacts{
		KernelPBRWired:   s.kernelPBRAvailable(),
		NativeOperations: cloneHostBoolMap(s.nativeOperations),
		ProbedAt:         time.Now(),
	}

	// A binary somewhere on PATH is not proof the CONFIGURED core can run. Check the configured
	// path, that it is executable, and that it actually answers a version query.
	if bin := strings.TrimSpace(c.SingBox.Bin); bin != "" {
		if st, err := os.Stat(bin); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			vctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			if v, err := core.New(bin, c.SingBox.Config).Version(vctx); err == nil {
				rt.SingboxRunnable, rt.SingboxVersion = true, strings.TrimSpace(v)
			}
			cancel()
		}
	}

	// Native DNS: reading is implemented for both supported platforms; write-back is NOT, and
	// conflating them would put a control on screen that edits the router's own DNS with nothing
	// behind it. Kept explicit so enabling write-back later is a deliberate edit here.
	switch platform.Detect() {
	case platform.OpenWrt, platform.Keenetic:
		rt.NativeDNSRead = true
	}
	rt.NativeDNSWrite = false

	rt.IPv6Routable = hasRoutableIPv6()
	return rt
}

// detectedPlatform is the router platform, honoring the test injection point.
func (s *Server) detectedPlatform() platform.Platform {
	if s.platformOf != nil {
		return s.platformOf()
	}
	return platform.Detect()
}

// planCapabilities are the raw platform facts preflight judges the configuration against, with the
// same accelerator override the apply path uses so both read one source of truth.
func (s *Server) planCapabilities() platform.Capabilities {
	caps := platform.DetectCapabilities()
	if s.config().Demo {
		caps = platform.DemoCapabilities()
	}
	caps.Accel = platform.Accel{Kind: s.accelKind(), HW: s.accelHW()}
	return caps
}

// buildPlan assembles the reviewable plan. It reads state and changes nothing on the router.
func (s *Server) buildPlan(ctx context.Context, refresh bool) (Plan, error) {
	desired, err := s.captureDesiredSnapshot()
	if err != nil {
		return Plan{}, fmt.Errorf("capture desired state: %w", err)
	}
	capset := s.capabilitySet(ctx, refresh)
	view := s.pendingView(desired)
	base := s.appliedBaseline()

	plan := Plan{
		Rev:               desired.DesiredRev,
		Pending:           view.Pending,
		NothingConfigured: view.NothingConfigured,
		AppliedRev:        view.AppliedRev,
		AppliedAt:         view.AppliedAt,
		Probe:             planProbe{At: capset.ProbedAt, Error: capset.ProbeError},
	}
	if !capset.ProbedAt.IsZero() {
		age := time.Since(capset.ProbedAt)
		plan.Probe.AgeS = int64(age / time.Second)
		plan.Probe.Stale = age > capStaleAfter
	}

	raw := s.rawFindings(ctx, desired, capset)
	plan.Findings = foldFindings(raw, s.isAcked)
	plan.Verdict = planVerdict(plan.Findings)
	plan.Changes = s.planChanges(desired, base)
	plan.Window = s.planWindow()
	plan.Platform = s.planPlatform()
	return plan, nil
}

// invalidProfileRemedy picks the way out that fits the FAILURE, not the average of all failures.
//
// Pure so both branches can be pinned: the generic sentence for a draft that is merely unfinished,
// and the specific one for a live reference to something switched OFF.
func invalidProfileRemedy(err error) string {
	var disabledRef *model.DisabledRefError
	if errors.As(err, &disabledRef) {
		return "Something switched off is still being pointed at. Either switch it back on, or " +
			"remove the reference: take the member out of the group, or point the rule or routing " +
			"list at another exit. Then review again."
	}
	// A reference to something that is GONE has a different way out again — and for one object kind
	// the generic sentence names an action that does not exist. Rules are read in five places in the
	// panel and rendered as an editable row in none, so "correct or disable the affected object" sends
	// the operator hunting a control no page has. Measured on the demo profile: rule "st-rule-6" (and
	// "st-rule-12") point at "st-grp-0", which is not in the profile; Apply is blocked for the whole
	// configuration and neither rule appears anywhere in the DOM.
	var missing *model.UnresolvedRefError
	if errors.As(err, &missing) {
		if missing.Kind == "rule" {
			// No REST route in the sentence any more: the finding now carries the action structurally
			// (see invalidProfileFix) and the review renders it as a button, so naming a curl here
			// would describe handwork the operator no longer has to do.
			return fmt.Sprintf("This rule has no row on any page, so no screen can correct it. "+
				"Either bring back %q so the reference resolves, or remove the rule.", missing.Target)
		}
		return fmt.Sprintf("%s %q points at %q, which is not in the profile. Point it at an exit that "+
			"exists, or remove the reference. Then review again.", capitalizeFirst(missing.Kind), missing.ID, missing.Target)
	}
	return "Correct or disable the affected object, then review again."
}

// invalidProfileItem names the ONE object that has to change, for the finding's items[]. Without it
// the entry reads "Items: profile" — the whole configuration — when exactly one object is at fault.
func invalidProfileItem(err error) string {
	var missing *model.UnresolvedRefError
	if errors.As(err, &missing) {
		return missing.Kind + " " + strconv.Quote(missing.ID)
	}
	// The switched-off class names its object too. It did not until DisabledRefError gained the same
	// structure, and the effect was visible the moment several problems were listed together: twelve
	// entries read "routing list \"st-rl-6\"" and the first read "profile" — the whole configuration —
	// purely because that one happened to be the other class.
	var off *model.DisabledRefError
	if errors.As(err, &off) {
		return off.Kind + " " + strconv.Quote(off.ID)
	}
	return ""
}

// invalidProfileFix offers the action for the one class the panel cannot otherwise reach. A rule has
// no row on any page, so the remedy could only hand over a REST route — true, and not something an
// operator should have to run by hand to unblock their own router. Every other kind (group, routing
// list, endpoint) has a page, and sending those to a button here would take the operator away from
// the screen where the object actually lives.
func invalidProfileFix(err error) *FindingFix {
	var missing *model.UnresolvedRefError
	if errors.As(err, &missing) && missing.Kind == "rule" {
		return &FindingFix{Action: "delete_rule", ID: missing.ID, Label: missing.ID}
	}
	return nil
}

func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// rawFindings runs every finding source against one desired snapshot.
func (s *Server) rawFindings(ctx context.Context, desired DesiredSnapshot, capset platform.CapabilitySet) []PlanFinding {
	cfg := desired.Config
	prof := desired.Profile
	var raw []PlanFinding
	// A profile that does not validate cannot be generated: say so here instead of at Apply time.
	if err := prof.Validate(); err != nil {
		// The way out depends on the CLASS of failure, and one generic sentence cannot serve both.
		//
		// "Correct or disable the affected object" fits a draft that is merely unfinished. It is
		// actively wrong for the class that blocks a working router: a live reference to something
		// switched OFF. There the object is ALREADY disabled, so the one action the sentence names has
		// no effect, and the two that do - switch it back on, or drop the reference - go unsaid.
		// Measured on the demo profile: "group "seed-grp-eu": member "seed-trojan-fi" is disabled",
		// Apply blocked for the whole configuration, remedy "Correct or disable the affected object".
		//
		// This class is worth the extra sentence precisely because it blocks EVERY apply from now on,
		// including ones that have nothing to do with the reference, and because the store refuses to
		// create it - so a profile that holds one arrived by restore or import, where the operator was
		// not the one who switched anything off and has no reason to guess what did.
		// One finding per broken REFERENCE, not one per profile.
		//
		// Validate stops at the first failure, so the review named one object, the operator fixed it,
		// re-reviewed, and met the next — with nothing anywhere saying how many were left. Measured on
		// the demo profile: st-rule-6, st-rule-7 and st-rule-12 were three round trips.
		//
		// These fold into a single entry by ID (see foldFindings): the first one keeps its Detail,
		// Remedy and Fix, and every one contributes its Item, so the entry reads "3 items" and lists
		// them. Emitting them separately rather than teaching the fold about counts keeps the counting
		// in the one place that already does it.
		problems := model.CollectRefProblems(prof)
		if len(problems) == 0 {
			// Not a reference fault (a rule with no matcher, a bad CIDR): there is one error and it is
			// this one.
			problems = nil
		}
		emitted := 0
		for _, rp := range problems {
			refErr := model.RefProblemError(rp)
			raw = append(raw, PlanFinding{
				ID: "profile.invalid", Setting: "profile", Severity: platform.SeverityBlocked,
				Reason: platform.ReasonSavedValueIncompat, Blocks: platform.BlocksApply,
				Detail: rp.Message,
				Remedy: invalidProfileRemedy(refErr),
				Item:   invalidProfileItem(refErr),
				Fix:    invalidProfileFix(refErr),
			})
			emitted++
		}
		if emitted == 0 {
			raw = append(raw, PlanFinding{
				ID: "profile.invalid", Setting: "profile", Severity: platform.SeverityBlocked,
				Reason: platform.ReasonSavedValueIncompat, Blocks: platform.BlocksApply,
				Detail: err.Error(),
				Remedy: invalidProfileRemedy(err),
				Item:   invalidProfileItem(err),
				Fix:    invalidProfileFix(err),
			})
		}
	}
	// Preflight (routing mode / offload / protocols / DNS-path coherence) against the same host
	// facts the apply path uses.
	raw = append(raw, evaluatePlanFindings(capset, s.preflightFor(cfg, prof, s.planCapabilities(), s.offloadObservation(ctx).State))...)
	// The core is required by this datapath but cannot run: nothing else in the plan matters then.
	if s.datapathRequiresCore(cfg, prof) && !capset.Usable(platform.CapEngineSingbox) {
		c := capset.Get(platform.CapEngineSingbox)
		raw = append(raw, PlanFinding{
			ID: "core.unavailable", CapabilityID: platform.CapEngineSingbox, Setting: "core",
			Severity: platform.SeverityBlocked, Reason: c.Reason, Blocks: platform.BlocksApply,
			Detail: c.Detail, Remedy: c.Remedy,
		})
	}
	raw = append(raw, s.endpointFindings(prof, capset)...)
	raw = append(raw, unfetchedFeedFindings(&prof)...)
	// Dead rules are a property of the CONFIGURATION, not of the router's capabilities, but the
	// review panel is the right moment to surface them: they are about to be applied, and a rule
	// that can never fire reads exactly like one that works.
	raw = append(raw, shadowedRuleFindings(&prof)...)
	// What the KERNEL plane will not carry. pbr.Compile already works this out and the preview shows
	// it — but only to somebody who opens the preview. The review panel is where Apply is decided.
	raw = append(raw, s.kernelPlaneFindings(&cfg, &prof)...)
	return raw
}

// datapathRequiresCore answers, per platform, whether this datapath materializes a sing-box core.
// The two platforms express "native" differently: generator.DatapathNativeOnly is the OpenWrt/kernel
// PBR shape (routing mode "fast" with every endpoint kernel-native), while KeeneticOS runs a purely
// native profile through NDM whatever the mode.
//
// On KeeneticOS a domain list needs the core only when the resolver cannot fill the kernel plane's
// sets for it: with dnsmasq wired, a name becomes an ipset member at query time and the kernel
// routes it, so asking for the core there would install one nothing uses.
// datapathCoreReasons names what pulls the core in, for the platform that can answer. The generic
// predicate has no reason walk, so elsewhere the battery keeps its old sentence rather than invent one.
func (s *Server) datapathCoreReasons(cfg config.Config, prof model.Profile) []string {
	if s.detectedPlatform() == platform.Keenetic && !cfg.Demo {
		return keenetic.CoreReasons(&prof, keeneticDomainsViaDNSMasq())
	}
	return nil
}

// authFieldMissing names the credential this protocol authenticates with when it is empty, or "" .
//
// Deliberately the protocols model.missingProtoParam leaves alone: those it DOES cover already fail
// Apply with a precise error, and reporting them twice would put a degraded note beside a blocker
// about the same field. This covers the ones sing-box loads happily and the server then rejects.
func authFieldMissing(e model.Endpoint) string {
	get := func(k string) string { v, _ := e.Params[k].(string); return strings.TrimSpace(v) }
	switch e.Protocol {
	case model.ProtoVLESS, model.ProtoVMess:
		if get("uuid") == "" {
			return "uuid"
		}
	case model.ProtoTrojan, model.ProtoHysteria2:
		if get("password") == "" {
			return "password"
		}
	}
	return ""
}

func (s *Server) datapathRequiresCore(cfg config.Config, prof model.Profile) bool {
	if s.detectedPlatform() == platform.Keenetic && !cfg.Demo {
		return keenetic.PlanRequiresCore(&prof, keeneticDomainsViaDNSMasq())
	}
	return !generator.DatapathNativeOnly(&prof, desiredRoutingMode(cfg))
}

// unfetchedFeedFindings names a routing list whose feed has never been fetched. Such a list holds
// nothing, so the native compiler refuses it ("CIDR source has no reviewed CIDR cache") — correctly,
// but at Apply, in the compiler's words, one screen after the one that caused it. The same fact
// belongs in the review, where it is one click from the button that fixes it.
func unfetchedFeedFindings(p *model.Profile) []PlanFinding {
	var out []PlanFinding
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if !rl.Enabled {
			continue
		}
		if rl.CIDRSource != "" && len(rl.CIDRCache) == 0 {
			out = append(out, PlanFinding{
				ID: "list.cidr_unfetched", Setting: "routing list", Item: listName(rl),
				Severity: platform.SeverityBlocked, Reason: platform.ReasonSavedValueIncompat,
				Blocks: platform.BlocksApply,
				Detail: "This list routes by an IP feed that has not been downloaded yet, so it currently matches nothing.",
				Remedy: "Click «↻ Refresh sources» on the Routing page, then review again.",
			})
		}
		if rl.DomainSource != "" && len(rl.DomainCache) == 0 {
			out = append(out, PlanFinding{
				ID: "list.domain_unfetched", Setting: "routing list", Item: listName(rl),
				Severity: platform.SeverityBlocked, Reason: platform.ReasonSavedValueIncompat,
				Blocks: platform.BlocksApply,
				Detail: "This list routes by a domain feed that has not been downloaded yet, so it currently matches nothing.",
				Remedy: "Click «↻ Refresh sources» on the Routing page, then review again.",
			})
		}
	}
	return out
}

func listName(rl *model.RoutingList) string {
	if rl.Name != "" {
		return rl.Name
	}
	return rl.ID
}

// pluginBinaryPresent mirrors plugin.Manager's binary lookup (the engine directory next to the
// configured core, then PATH) so the plan can say whether an engine plugin could start.
func (s *Server) pluginBinaryPresent(name string) bool {
	if s.binaryPresentOf != nil {
		return s.binaryPresentOf(name)
	}
	if s.config().Demo {
		return true
	}
	if bin := s.config().SingBox.Bin; bin != "" {
		if fi, err := os.Stat(filepath.Join(filepath.Dir(bin), name)); err == nil && !fi.IsDir() {
			return true
		}
	}
	_, err := exec.LookPath(name)
	return err == nil
}

// endpointFindings judges every enabled endpoint's engine/protocol against what this router and this
// build can run. A missing engine binary is a feature-level finding (the endpoint will not come up;
// Apply still proceeds and reports the plugin as a problem); an engine this build has no executor
// for, or an external Keenetic tunnel whose NDM identity is unknown, is a hard blocker because the
// materialization cannot express it at all.
func (s *Server) endpointFindings(prof model.Profile, capset platform.CapabilitySet) []PlanFinding {
	var out []PlanFinding
	keeneticHost := s.detectedPlatform() == platform.Keenetic
	name := func(e model.Endpoint) string {
		if e.Name != "" {
			return e.Name
		}
		return e.ID
	}
	for _, e := range prof.Endpoints {
		if !e.Enabled {
			continue
		}
		// A credential sing-box TOLERATES is not a credential the SERVER tolerates. model.Validate
		// deliberately blocks only the fields whose absence hard-rejects the config (see
		// missingProtoParam): an empty vless uuid or trojan password loads fine and simply never
		// authenticates. Right call for a gate — and it left the operator with nothing at all.
		//
		// Measured on the demo: Add connection → Manual → trojan, server and port filled, password
		// left empty. The panel answered "Added Manual probe" in the success style, stored it enabled,
		// and the review said "ready". Nothing on any screen said the connection cannot authenticate.
		//
		// Reported as DEGRADED, not blocked, because that is what it is: nothing else breaks, this one
		// exit will not come up. Blocking Apply over it would take a working router down for a
		// half-filled draft.
		if field := authFieldMissing(e); field != "" {
			out = append(out, PlanFinding{
				ID: "endpoint.credential", Setting: "credential", Item: name(e),
				Severity: platform.SeverityDegraded, Reason: platform.ReasonSavedValueIncompat,
				Blocks: platform.BlocksFeature,
				Detail: "This connection has no " + field + ", so the server will refuse it. Everything else keeps working; this exit will not come up.",
				Remedy: "Open the connection and fill in the " + field + ", or switch it off until you have one.",
			})
		}
		switch e.Engine {
		case model.EngineExternal:
			iface, _ := e.Params["interface"].(string)
			if strings.TrimSpace(iface) == "" {
				out = append(out, PlanFinding{
					ID: "endpoint.external.interface", Setting: "external interface", Item: name(e),
					Severity: platform.SeverityBlocked, Reason: platform.ReasonInterfaceMissing,
					Blocks: platform.BlocksApply,
					Detail: "The connection routes through an existing interface but does not name one.",
					Remedy: "Set the interface the connection should use, or disable it.",
				})
				continue
			}
			if keeneticHost {
				if _, ndmKnown := keenetic.ResolveNDMName(e); !e.IsExternal() || !ndmKnown {
					out = append(out, PlanFinding{
						ID: "endpoint.external.keenetic_identity", Setting: "native tunnel", Item: name(e),
						Severity: platform.SeverityBlocked, Reason: platform.ReasonSavedValueIncompat,
						Blocks: platform.BlocksApply,
					})
				}
			}
		case model.EngineSingBox:
			// The core itself is judged once by core.unavailable; here only a protocol the (usable)
			// core cannot carry is worth a separate entry.
			if !capset.Usable(platform.CapEngineSingbox) {
				continue
			}
			protocol := strings.ToLower(string(e.Protocol))
			if c := capset.Get(platform.CapProtocolPrefix + protocol); !c.State.Usable() {
				out = append(out, PlanFinding{
					ID: "endpoint.protocol." + protocol, CapabilityID: c.ID, Setting: "protocol",
					Item: name(e), Requested: protocol, Effective: "not carried",
					Severity: platform.SeverityBlocked, Reason: c.Reason, Blocks: platform.BlocksApply,
					Detail: c.Detail, Remedy: c.Remedy,
				})
			}
		case model.EngineAmneziaWG:
			if capset.Usable(platform.CapEngineAmneziaWG) || s.pluginBinaryPresent("awg") || s.pluginBinaryPresent("awg-quick") {
				continue
			}
			out = append(out, PlanFinding{
				ID: "endpoint.engine.amneziawg", CapabilityID: platform.CapEngineAmneziaWG,
				Setting: "engine", Item: name(e), Requested: "amneziawg", Effective: "not started",
				Severity: platform.SeverityBlocked, Reason: platform.ReasonMissingBinary,
				Blocks: platform.BlocksFeature,
				Detail: "Neither the AmneziaWG kernel module nor the awg tools are installed, so this connection cannot come up.",
				Remedy: "Install AmneziaWG (the awg tools or the platform package), or disable the connection.",
			})
		case model.EngineOlcRTC:
			if s.pluginBinaryPresent("olcrtc") {
				continue
			}
			out = append(out, PlanFinding{
				ID: "endpoint.engine.olcrtc", CapabilityID: platform.CapEngineOlcRTC,
				Setting: "engine", Item: name(e), Requested: "olcrtc", Effective: "not started",
				Severity: platform.SeverityBlocked, Reason: platform.ReasonMissingBinary,
				Blocks: platform.BlocksFeature,
				Detail: "The olcrtc binary is not installed, so this connection cannot come up.",
				Remedy: "Install olcRTC through the Updater, or disable the connection.",
			})
		case model.EngineNfqws:
			if s.pluginBinaryPresent("nfqws2") {
				continue
			}
			out = append(out, PlanFinding{
				ID: "endpoint.engine.nfqws", Setting: "engine", Item: name(e), Requested: "nfqws",
				Effective: "not started", Severity: platform.SeverityBlocked,
				Reason: platform.ReasonMissingBinary, Blocks: platform.BlocksFeature,
				Detail: "The nfqws2 binary is not installed, so this desync profile cannot start.",
				Remedy: "Install nfqws2, or disable the connection.",
			})
		default:
			out = append(out, PlanFinding{
				ID: "endpoint.engine." + string(e.Engine), Setting: "engine", Item: name(e),
				Requested: string(e.Engine), Effective: "not applied",
				Severity: platform.SeverityBlocked, Reason: platform.ReasonBackendNotWired,
				Blocks: platform.BlocksApply,
				Detail: "This WayHop build has no executor for the " + string(e.Engine) + " engine.",
				Remedy: "Use sing-box, AmneziaWG or olcRTC for this connection, or disable it.",
			})
		}
	}
	return out
}

// planVerdict folds the findings into one answer.
func planVerdict(findings []Finding) string {
	verdict := VerdictReady
	for _, f := range findings {
		if f.hard() {
			return VerdictBlocked
		}
		verdict = VerdictWarning
	}
	return verdict
}

// planChanges diffs the saved state against the applied baseline.
func (s *Server) planChanges(desired DesiredSnapshot, base *appliedRevision) planChanges {
	if base == nil || base.Desired == nil {
		out := planChanges{
			BaselineAvailable: false, Pending: s.pendingView(desired).Pending,
			BySubsystem: map[changeset.Subsystem][]changeset.Change{}, Changes: []changeset.Change{},
			Reason: "no applied baseline yet — a full change review becomes available after the next Apply",
		}
		if base != nil {
			out.BaselineRev = base.Rev
		}
		return out
	}
	cs := changeset.Diff(base.Rev, desired.DesiredRev, base.Desired.Profile, desired.Profile, base.Desired.Config, desired.Config)
	changes := cs.Changes
	if changes == nil {
		changes = []changeset.Change{}
	}
	return planChanges{
		BaselineAvailable: true, BaselineRev: base.Rev,
		Pending: cs.Count() > 0 || base.Rev != desired.DesiredRev,
		Count:   cs.Count(), MayInterrupt: cs.MayInterrupt(), RequiresApply: cs.RequiresApply(),
		BySubsystem: cs.BySubsystem(), Changes: changes,
	}
}

func (s *Server) planWindow() planWindow {
	out := planWindow{Open: s.liveRevision() != nil}
	if s.failsafe != nil {
		st := s.failsafe.Status()
		out.Phase, out.SecondsLeft = st.Phase, st.SecondsLeft
		if st.Pending {
			out.Open = true
		}
	}
	return out
}

func (s *Server) planPlatform() planPlatform {
	out := planPlatform{Name: string(s.detectedPlatform()), KernelPlane: s.kernelPBRAvailable()}
	if s.config().Demo {
		out.Name = "demo"
	}
	if s.singbox != nil {
		out.CoreAvailable, out.CoreRunning = s.singbox.Available(), s.singbox.Running()
	}
	// The demo poses as a router that HAS the core (platform.DemoCapabilities sets SingboxPresent),
	// and the verdict in this same response is computed from that pose. Reading the real machine here
	// put both in one payload: "verdict": "ready" beside "core_available": false, for a profile whose
	// default route needs the core. Measured after pointing the default route at a proxy-carried
	// group on the demo — zero findings, and the platform block flatly contradicting them.
	//
	// The health battery is deliberately NOT changed to match: it answers "what is on this machine",
	// which is what makes the core-absent branches reachable in the demo at all. This block answers
	// "what would Apply find", and that is the pose.
	if s.config().Demo {
		out.CoreAvailable, out.CoreRunning = true, true
	}
	switch s.detectedPlatform() {
	case platform.OpenWrt, platform.Keenetic:
		out.NativeVPN = !s.config().Demo
	}
	return out
}

// foldFindings groups the raw findings by (id, severity, blocks) — the id already names the code and
// setting — names the affected objects in items[] and applies the acknowledgement policy: a hard
// blocker is never acknowledgeable, a feature-level or privacy finding needs one, everything else is
// informational. Blockers come first, then acknowledgements, then notes.
func foldFindings(raw []PlanFinding, acked func(id string) bool) []Finding {
	type key struct{ id, severity, blocks string }
	order := make([]key, 0, len(raw))
	groups := make(map[key]*Finding, len(raw))
	for _, f := range raw {
		severity := normalizeSeverity(f.Severity)
		blocks := normalizeBlocks(f.Blocks)
		// A privacy finding is INFORMATION: the configuration works exactly as asked and discloses
		// something while doing it. It used to be promoted to "blocks a feature" and then demanded a
		// signature per finding before Apply would light up — five checkboxes for a disclosure the
		// operator never asked to change. Telling them is the job; making them countersign it is not.
		_ = severity
		k := key{f.ID, severity, blocks}
		item := f.Item
		if item == "" && f.Setting != "" && f.Setting != f.ID {
			item = f.Setting
		}
		if g := groups[k]; g != nil {
			g.Count++
			if item != "" && len(g.Items) < planFindingItems && !containsString(g.Items, item) {
				g.Items = append(g.Items, item)
			}
			continue
		}
		code, title, detail, remedy := findingTemplate(f)
		if f.Detail != "" {
			detail = f.Detail
		}
		if f.Requested != "" && f.Effective != "" && f.Requested != f.Effective {
			detail = strings.TrimSpace(detail + " Requested: " + f.Requested + "; effective: " + f.Effective + ".")
		}
		if f.Remedy != "" {
			remedy = f.Remedy
		}
		hard := blocks == platform.BlocksApply
		g := &Finding{
			ID: f.ID, Code: code, Severity: severity, Blocks: blocks,
			// Acknowledgement is for a configuration that will NOT do what it says — a feature the
			// router silently drops. A privacy note is not that: it is reported, counted and left in
			// plain sight, and Apply stays available.
			AckRequired: !hard && blocks == platform.BlocksFeature && severity != platform.SeverityPrivacy,
			Title:       title, Detail: detail, Remedy: remedy, Count: 1, Items: []string{},
			Fix: f.Fix,
		}
		if item != "" {
			g.Items = append(g.Items, item)
		}
		g.Acked = g.AckRequired && acked != nil && acked(g.ID)
		groups[k] = g
		order = append(order, k)
	}
	out := make([]Finding, 0, len(order))
	for _, k := range order {
		out = append(out, *groups[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := findingRank(out[i]), findingRank(out[j])
		if ri != rj {
			return ri < rj
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func findingRank(f Finding) int {
	switch {
	case f.hard():
		return 0
	case f.AckRequired:
		return 1
	default:
		return 2
	}
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func normalizeSeverity(severity string) string {
	switch severity {
	case platform.SeverityBlocked, platform.SeverityDegraded, platform.SeverityPrivacy:
		return severity
	default:
		return platform.SeverityDegraded
	}
}

func normalizeBlocks(blocks string) string {
	switch blocks {
	case platform.BlocksNothing, platform.BlocksOptimisation, platform.BlocksFeature,
		platform.BlocksApply, platform.BlocksEdit:
		return blocks
	default:
		return platform.BlocksApply
	}
}

// findingTemplate names a raw finding for humans: a closed code plus a title/detail/remedy the UI can
// show even when the source supplied no prose.
func findingTemplate(f PlanFinding) (code, title, detail, remedy string) {
	switch {
	case f.ID == "profile.invalid":
		return "PROFILE_INVALID", "The configuration is invalid",
			"At least one enabled configuration object is incomplete or inconsistent.",
			"Correct or disable the affected object, then review again."
	case f.ID == "endpoint.credential":
		return "Connection has no credential", "Connection cannot authenticate",
			"An enabled connection is missing the secret its protocol authenticates with.",
			"Open the connection and fill it in, or switch it off until you have one."
	case f.ID == "core.unavailable":
		return "CORE_UNAVAILABLE", "The proxy core is unavailable",
			"This datapath needs the configured sing-box core, but it cannot be run.",
			"Install or repair the configured sing-box core, or choose a native-only datapath."
	case f.ID == "endpoint.external.keenetic_identity":
		return "NATIVE_ADOPTION_INCOMPLETE", "Native Keenetic tunnel needs re-adoption",
			"An enabled native exit predates the captured KeeneticOS ownership and NDM identity required for safe Apply.",
			"Open Diagnostics and use Repair adoption for the affected native tunnel, then review again."
	case f.ID == "endpoint.external.interface":
		return "EXTERNAL_INTERFACE_MISSING", "External connection has no interface",
			"The connection routes through an existing interface but does not name one.",
			"Set the interface the connection should use, or disable it."
	case strings.HasPrefix(f.ID, "endpoint.engine."):
		return "ENGINE_UNAVAILABLE", "Connection engine is unavailable",
			"An enabled connection needs an engine this router cannot run.",
			"Install or repair the required engine, or disable the connection."
	case strings.HasPrefix(f.ID, "endpoint.protocol."):
		return "PROTOCOL_UNAVAILABLE", "Connection protocol is unavailable",
			"An enabled connection uses a protocol the configured core cannot carry.",
			"Install or repair the configured core, or disable the connection."
	case strings.HasPrefix(f.ID, "shadowed.route."):
		return "SHADOWED_ROUTING_RULE", "Routing rule can never match",
			"An earlier enabled routing rule already matches the same traffic.",
			"Review or remove the shadowed routing rule."
	case strings.HasPrefix(f.ID, "shadowed.dns."):
		return "SHADOWED_DNS_RULE", "DNS rule can never match",
			"An earlier enabled DNS rule already matches the same queries.",
			"Review or remove the shadowed DNS rule."
	case strings.HasPrefix(f.ID, "kernel_plane.dead."):
		return "KERNEL_RULE_DROPPED", "Rule is not carried in fast mode",
			"The kernel plane cannot carry this rule and fast mode has no TUN fallback.",
			"Use kernel-compatible matchers or choose a mode with a TUN fallback."
	case f.ID == "kernel_plane.fallback":
		return "KERNEL_RULE_FALLBACK", "Rules use the userspace fallback",
			"The kernel plane cannot carry these rules, so the TUN handles them instead.",
			"No action is needed if the slower fallback is expected."
	case strings.HasPrefix(f.Setting, "dns_path:encrypted:") || strings.HasPrefix(f.ID, "dns_path:encrypted:"):
		return "DNS_EXIT_MISMATCH_ENCRYPTED", "Encrypted DNS uses a different exit",
			"DNS queries stay encrypted, but the resolver sees them from the WAN address while the matching traffic exits through a tunnel.",
			"Accept this if it is intentional, or route DNS for the affected lists through the same tunnel."
	case strings.HasPrefix(f.Setting, "dns_path:plaintext:") || strings.HasPrefix(f.ID, "dns_path:plaintext:"):
		return "DNS_PATH_EXPOSED", "DNS would bypass the tunnel unencrypted",
			"DNS queries for the affected routing lists would leave directly before their traffic enters the tunnel.",
			"Use encrypted DNS or route DNS for the affected lists through the same tunnel."
	case strings.HasPrefix(f.Setting, "dns_path:") || strings.HasPrefix(f.ID, "dns_path:"):
		return "DNS_PATH_MISMATCH", "DNS and traffic use different exits",
			"At least one routing list resolves names through a different exit from its traffic.",
			"Align the DNS and traffic detours for the affected routing lists."
	case f.Setting == "routing_mode" || strings.HasPrefix(f.ID, "routing_mode="):
		return "ROUTING_MODE_UNAVAILABLE", "Routing mode cannot work as requested",
			"The selected routing mode is not fully supported by this router.",
			"Choose a routing mode supported by this router."
	case f.Setting == "offload_devices" || strings.HasPrefix(f.ID, "offload_devices="):
		return "OFFLOAD_DEVICES_UNAVAILABLE", "Offload devices are unavailable",
			"No complete device set is available for the requested flow offload.",
			"Select valid WAN and bridge devices or turn off flow offload."
	case f.Setting == "offload" || strings.HasPrefix(f.ID, "offload="):
		return "OFFLOAD_UNAVAILABLE", "Flow offload cannot work as requested",
			"This router cannot provide the requested offload behavior.",
			"Use a supported offload mode or leave offload disabled."
	case strings.HasPrefix(f.Setting, "protocol:") || strings.HasPrefix(f.ID, "protocol:"):
		return "PROTOCOL_UNAVAILABLE", "Connection protocol needs attention",
			"One or more enabled connections use a protocol this router does not fully support.",
			"Install the required engine or disable the affected connections."
	default:
		return "CONFIGURATION_COMPATIBILITY", "Configuration needs review",
			"The configuration contains a compatibility issue.",
			"Review the affected configuration before applying it."
	}
}

// preflight judges the CURRENT saved configuration against this host. Always returns a non-nil
// slice so clients can test length without a null check.
func (s *Server) preflight(caps platform.Capabilities, observed platform.OffloadState) []platform.Unsupported {
	return s.preflightFor(s.config(), s.store.Profile(), caps, observed)
}

// preflightFor is preflight over an explicit configuration snapshot.
func (s *Server) preflightFor(c config.Config, prof model.Profile, caps platform.Capabilities, observed platform.OffloadState) []platform.Unsupported {
	in := platform.PreflightInput{
		RoutingMode:    s.routingMode(c), // the EFFECTIVE mode, not the raw field
		Offload:        c.Offload,
		OffloadDevices: c.OffloadDevices,
		PBRAvailable:   s.kernelPBRAvailable(),
		Observed:       observed,
	}
	for _, r := range prof.Rules {
		// A disabled rule is not part of what will be applied, so it must not raise a warning.
		if r.Disabled {
			continue
		}
		if len(r.Domain) > 0 || len(r.DomainSuffix) > 0 || len(r.GeoSite) > 0 {
			in.HasDomainRules = true
			break
		}
	}
	for _, e := range prof.Endpoints {
		in.Protocols = append(in.Protocols, strings.ToLower(string(e.Protocol)))
	}

	out := platform.Preflight(in, caps)

	// DNS/traffic coherence rides in the same list because it answers the same pre-Apply question —
	// "will this configuration do what it says?" — and the user should not have to look in two
	// places. Encrypted direct DNS is an acknowledgeable exit-policy choice; plaintext direct DNS is
	// a hard privacy failure.
	for _, a := range dnsaudit.DetectAsymmetric(prof) {
		out = append(out, dnsPathUnsupported(a))
	}

	if out != nil {
		return out
	}
	return []platform.Unsupported{}
}

// evaluatePlanFindings turns preflight output into findings, attaching the capability id and reason
// code so a client can act on a stable key instead of matching prose.
func evaluatePlanFindings(capset platform.CapabilitySet, pf []platform.Unsupported) []PlanFinding {
	out := make([]PlanFinding, 0, len(pf))
	for _, u := range pf {
		id := capabilityIDForSetting(u.Setting, u.Value)
		c := capset.Get(id)
		f := PlanFinding{
			ID:        u.Setting + "=" + u.Value,
			Setting:   u.Setting,
			Requested: u.Value,
			Effective: effectiveFor(u),
			Severity:  u.Severity,
			Detail:    u.Reason,
			Remedy:    u.Remedy,
			Blocks:    platform.BlocksApply,
		}
		if strings.HasPrefix(u.Setting, "dns_path:") {
			// The setting carries the routing list id, and the list belongs in Item — not in the fold
			// key. Keying by it gave every list its own card of identical prose: five lists produced
			// five paragraphs, a "how to fix" box each, and half a screen of review for ONE fact with
			// five names. Folding on the KIND collapses that to one entry listing the lists, which is
			// what Items exists for and how every other repeated finding already reads.
			f.Item = strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(u.Setting, "dns_path:"), "encrypted:"), "plaintext:")
			f.ID = strings.TrimSuffix(u.Setting, ":"+f.Item)
		}
		if _, known := capset.Items[id]; known {
			f.CapabilityID = id
			f.Reason = c.Reason
			f.Blocks = c.Blocks
		}
		// An optimisation that cannot load must never block an Apply, whatever preflight called it.
		if f.Blocks == platform.BlocksOptimisation {
			f.Severity = platform.SeverityDegraded
		}
		// A direct encrypted resolver changes the privacy boundary but does not expose query contents
		// to the WAN path; it is an explicit, acknowledgeable policy choice. Plaintext direct DNS
		// remains a hard refusal regardless of the otherwise-usable DNS proxy capability.
		if f.Severity == platform.SeverityPrivacy && strings.HasPrefix(f.Setting, "dns_path:encrypted:") {
			f.Blocks = platform.BlocksNothing
		}
		if f.Severity == platform.SeverityPrivacy && strings.HasPrefix(f.Setting, "dns_path:plaintext:") {
			f.Blocks = platform.BlocksApply
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// effectiveFor states what the router will actually do, so requested and effective are never
// conflated in the response.
func effectiveFor(u platform.Unsupported) string {
	if u.Severity == platform.SeverityBlocked {
		return "not applied"
	}
	return "degraded"
}

// capabilityIDForSetting maps a preflight setting onto its capability id. Unmapped settings return
// an id the set will not know, which Get() answers as unknown — failing closed rather than
// silently treating an unmapped setting as supported.
func capabilityIDForSetting(setting, value string) string {
	switch {
	case setting == "routing_mode":
		return "routing.mode." + value
	case setting == "offload":
		if value == "hw" {
			return platform.CapOffloadHW
		}
		return platform.CapOffloadSW
	case setting == "offload_devices":
		return platform.CapOffloadSW
	case strings.HasPrefix(setting, "protocol:"):
		return platform.CapProtocolPrefix + strings.TrimPrefix(setting, "protocol:")
	case strings.HasPrefix(setting, "dns_path:"):
		return platform.CapDNSProxyPlane
	}
	return "unmapped." + setting
}

// hasRoutableIPv6 reports whether a usable global IPv6 route exists. Only a POSITIVE finding is
// meaningful: a router whose provider hands out a non-routable prefix (observed in the field) has
// v6 addresses and default routes that reach nothing, so address presence alone proves nothing.
func hasRoutableIPv6() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() != nil || !ipn.IP.IsGlobalUnicast() {
				continue
			}
			// 2000::/3 is the only range IANA has allocated for global unicast. Providers handing
			// out addresses outside it (6000::/3 has been seen) produce a v6 stack that looks
			// configured and reaches nothing.
			if ipn.IP[0]&0xE0 == 0x20 {
				return true
			}
		}
	}
	return false
}

// tally collapses repeats, keeping first-seen order and saying how many there were.
//
// One finding is produced per affected object and the log lines that name them repeat the same id
// once per routing list that hits it. On the operator's own router that produced a refusal naming
// `kernel_plane.list-cascade` about ninety times in a row. The count is kept rather than dropped,
// because "this affects 90 of your lists" and "this affects one" are different situations.
func tally(ids []string) []string {
	seen := make(map[string]int, len(ids))
	order := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; !ok {
			order = append(order, id)
		}
		seen[id]++
	}
	out := make([]string, 0, len(order))
	for _, id := range order {
		if n := seen[id]; n > 1 {
			out = append(out, id+" (×"+strconv.Itoa(n)+")")
		} else {
			out = append(out, id)
		}
	}
	return out
}

// shadowedRuleFindings reports rules that can never match because an earlier enabled rule already
// matches everything they do. Rule order is semantic — sing-box takes the first match and the
// generator emits rules in array order — so a shadowed rule is dead configuration that looks live.
//
// Severity is a warning and Blocks is "nothing": the configuration applies exactly as written and
// the router does what it was told. What is wrong is the operator's belief about it, so this
// informs rather than refuses. Detection is exact-duplicate only, so a finding here is never a
// guess (see model.ShadowedRules).
func shadowedRuleFindings(prof *model.Profile) []PlanFinding {
	var out []PlanFinding
	add := func(kind, plural string, s model.Shadowed) {
		id := s.ID
		if id == "" {
			id = "#" + strconv.Itoa(s.Index+1)
		}
		by := s.ByID
		if by == "" {
			by = "#" + strconv.Itoa(s.ShadowedBy+1)
		}
		out = append(out, PlanFinding{
			ID:        "shadowed." + kind + "." + id,
			Setting:   plural + " " + id,
			Item:      id,
			Requested: s.Match,
			Effective: "never matches",
			Severity:  platform.SeverityDegraded,
			Reason:    platform.ReasonFeatureWouldBeDropped,
			Detail: "This rule matches exactly what " + plural + " " + by + " above it matches, and " +
				"rules are evaluated in order, so it can never take effect.",
			Remedy: "Delete it, or narrow it so it matches something the earlier rule does not.",
			Blocks: platform.BlocksNothing,
		})
	}
	for _, s := range model.ShadowedRules(prof.Rules) {
		add("route", "routing rule", s)
	}
	if prof.DNS != nil {
		for _, s := range model.ShadowedDNSRules(prof.DNS.Rules) {
			add("dns", "DNS rule", s)
		}
	}
	return out
}

// kernelPlaneFindings reports model content the kernel (PBR) compiler will not route.
//
// pbr.Compile returns these warnings and the preview endpoint renders them, but the review panel —
// the one place Apply is actually decided — never saw them. In hybrid the configuration applies
// exactly as written and sing-box still carries the traffic, so that is informational: severity
// degraded, Blocks nothing. In fast mode there is no TUN underneath, so the rule is simply dead: a
// whole feature silently does not work, which the user must acknowledge (Blocks feature).
//
// Compile errors are swallowed deliberately: a plan that cannot be compiled is surfaced by Apply
// itself, and a second, differently-worded failure here would be noise rather than information.
func (s *Server) kernelPlaneFindings(cfg *config.Config, prof *model.Profile) []PlanFinding {
	if cfg == nil || prof == nil {
		return nil
	}
	// What the kernel compiler declines to route only MEANS something in the modes that ask the
	// kernel to route. This ran for every mode and phrased every warning the same way, so a Keenetic
	// in `mixed` — which has no kernel plane at all — answered a plan with 219 findings reporting
	// that traffic the user never asked the kernel to carry is carried by sing-box instead.
	mode := s.routingMode(*cfg)
	switch mode {
	case "tun", "mixed":
		// No kernel PBR in either: `tun` puts everything through the sing-box TUN and `mixed` runs a
		// proxy inbound only. Nothing was requested of the kernel, so nothing about it is a finding.
		return nil
	}

	_, warns, err := pbr.Compile(prof, s.pbrCompileOptions(*cfg))
	if err != nil || len(warns) == 0 {
		return nil
	}

	if mode == "fast" {
		// `fast` is hybrid WITHOUT the capture-all TUN, so there is no userspace path underneath:
		// what the kernel will not route is not carried by anything.
		out := make([]PlanFinding, 0, len(warns))
		for _, w := range warns {
			scope := w.Scope
			if scope == "" {
				scope = "routing"
			}
			out = append(out, PlanFinding{
				ID:        "kernel_plane.dead." + scope,
				Setting:   scope,
				Item:      scope,
				Requested: "routed by the kernel plane",
				Effective: "not routed at all",
				Severity:  platform.SeverityDegraded,
				Reason:    platform.ReasonFeatureWouldBeDropped,
				Detail:    w.Msg,
				Remedy:    "In fast mode there is no capture-all TUN to fall back to, so this rule has no effect. Give it an IP or CIDR matcher the kernel can route, or switch to hybrid, where sing-box carries what the kernel cannot.",
				Blocks:    platform.BlocksFeature,
			})
		}
		return out
	}

	// hybrid: the kernel routes what it can and the capture-all TUN carries the rest, so this IS
	// informational — but as one finding carrying the list, not one finding per rule. The count is
	// the part an operator acts on; the individual messages are the detail behind it.
	detail := make([]string, 0, len(warns))
	items := make([]string, 0, len(warns))
	for _, w := range warns {
		detail = append(detail, w.Msg)
		if w.Scope != "" {
			items = append(items, w.Scope)
		}
	}
	out := []PlanFinding{{
		ID:        "kernel_plane.fallback",
		Setting:   "routing",
		Requested: "routed by the kernel plane",
		Effective: fmt.Sprintf("%d rule(s) routed by sing-box instead", len(warns)),
		Severity:  platform.SeverityDegraded,
		Reason:    platform.ReasonFeatureWouldBeDropped,
		Detail:    strings.Join(detail, "\n"),
		Remedy:    "No action needed if that is what you expect — sing-box still carries this traffic, but it does not take the kernel fast path.",
		Blocks:    platform.BlocksNothing,
	}}
	// One raw finding per affected rule would fold into the same entry; carry the names directly.
	for i, item := range items {
		if i == 0 {
			out[0].Item = item
			continue
		}
		out = append(out, PlanFinding{ID: "kernel_plane.fallback", Setting: "routing", Item: item,
			Severity: platform.SeverityDegraded, Reason: platform.ReasonFeatureWouldBeDropped, Blocks: platform.BlocksNothing})
	}
	return out
}

// --- handlers -----------------------------------------------------------------------------------

// handleApplyPlan (GET /api/apply/plan[?refresh=1]) returns the reviewable plan. It takes no lock:
// it reads the store, the record and the cached capability probe.
func (s *Server) handleApplyPlan(w http.ResponseWriter, r *http.Request) {
	refresh := r.URL.Query().Get("refresh") == "1" || r.URL.Query().Get("refresh") == "true"
	plan, err := s.buildPlan(r.Context(), refresh)
	if err != nil {
		writeErrNoStore(w, http.StatusServiceUnavailable, "the plan could not be built: "+err.Error())
		return
	}
	writeJSONNoStore(w, http.StatusOK, plan)
}

// handleApplyAck (POST /api/apply/ack {ids, acked}) toggles persisted acknowledgements.
func (s *Server) handleApplyAck(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs   []string `json:"ids"`
		Acked *bool    `json:"acked"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErrNoStore(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	acked := body.Acked == nil || *body.Acked
	s.setAcks(body.IDs, acked)
	writeJSONNoStore(w, http.StatusOK, map[string]any{"ok": true, "acked": s.ackedIDs()})
}

func writeJSONNoStore(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, v)
}

func writeErrNoStore(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Cache-Control", "no-store")
	writeErr(w, status, msg)
}
