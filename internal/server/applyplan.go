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

	"wayhop/internal/awg"
	"wayhop/internal/binstore"
	"wayhop/internal/changeset"
	"wayhop/internal/config"
	"wayhop/internal/core"
	"wayhop/internal/dnsaudit"
	"wayhop/internal/generator"
	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
	"wayhop/internal/plugin"
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
			SingboxVersion:   "1.14.4 (demo)",
			NativeOperations: cloneHostBoolMap(s.nativeOperations),
			ProbedAt:         time.Now(),
		}
		s.caps.set = platform.Evaluate(platform.DemoCapabilities(), rt)
		return s.caps.set
	}
	caps := platform.DetectCapabilities()
	// The same observation answers the accelerator for everything else that decides with it
	// (QA-129): the offload resolver and the preflight must not keep an older one.
	s.noteAccel(caps.Accel)
	s.caps.set = platform.Evaluate(caps, s.runtimeFacts(ctx))
	return s.caps.set
}

// runtimeFacts gathers the observations the pure evaluator cannot make for itself. It is asked when
// the capability set is probed, so it probes the kernel-PBR plane afresh and keeps the answer for
// every other reader (QA-129).
func (s *Server) runtimeFacts(ctx context.Context) platform.RuntimeFacts {
	c := s.config()
	rt := platform.RuntimeFacts{
		KernelPBRWired:   s.refreshKernelPBR(),
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
	caps.Accel = s.noteAccel(caps.Accel)
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
	coreRuns := s.datapathRequiresCore(cfg, prof)
	if coreRuns && !capset.Usable(platform.CapEngineSingbox) {
		c := capset.Get(platform.CapEngineSingbox)
		raw = append(raw, PlanFinding{
			ID: "core.unavailable", CapabilityID: platform.CapEngineSingbox, Setting: "core",
			Severity: platform.SeverityBlocked, Reason: c.Reason, Blocks: platform.BlocksApply,
			Detail: c.Detail, Remedy: c.Remedy,
		})
	}
	raw = append(raw, s.endpointFindings(prof, capset)...)
	raw = append(raw, unfetchedFeedFindings(&prof)...)
	raw = append(raw, tlsFragmentFindings(&prof, desiredRoutingMode(cfg))...)
	raw = append(raw, coreInlineSizeFindings(&prof, desiredRoutingMode(cfg))...)
	raw = append(raw, coreOverrideFindings(cfg.CoreOverride, coreRuns, generator.DaemonUse{
		ClashAddr: desired.Inputs.ClashAddr, ClashSecret: cfg.Clash.Secret, Probe: cfg.Ports.Probe() > 0,
	})...)
	// Dead rules are a property of the CONFIGURATION, not of the router's capabilities, but the
	// review panel is the right moment to surface them: they are about to be applied, and a rule
	// that can never fire reads exactly like one that works.
	raw = append(raw, shadowedRuleFindings(&prof)...)
	// A list sent to one of KeeneticOS's access policies is routed by NDM's mark for it, which only the
	// router can say it has. Read once here, for the refusal and for the kernel compile below alike.
	policies := s.reviewNDMPolicies(ctx, cfg, &prof)
	raw = append(raw, ndmPolicyFindings(&prof, policies)...)
	// What the KERNEL plane will not carry. pbr.Compile already works this out and the preview shows
	// it — but only to somebody who opens the preview. The review panel is where Apply is decided.
	raw = append(raw, s.kernelPlaneFindings(&cfg, &prof, policies.marks)...)
	// Not part of what Apply changes, but part of whether the router does what it was asked: an
	// enabled Telegram bridge that cannot run, or that listens where it should not (tgbridge.go).
	raw = append(raw, s.tgBridgeFindings()...)
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
		return keenetic.CoreReasons(&prof, s.keeneticRoutePlanes(prof))
	}
	return nil
}

// keeneticRoutePlanes is the keenetic.RoutePlanes the native plan compiles with, from the same
// probes the Apply capture reads (keeneticDomainsViaDNSMasq, keeneticKernelPBRPresent) and the same
// userspace decision the native planner makes (nativeplan.KeeneticUserspace), judged against the
// review's capability set.
func (s *Server) keeneticRoutePlanes(prof model.Profile) keenetic.RoutePlanes {
	mode := desiredRoutingMode(s.config())
	return keenetic.RoutePlanes{
		DomainsViaDNSMasq: keeneticKernelPlaneCarriesLists(mode) && keeneticDomainsViaDNSMasq(),
		ListsViaIpset:     keeneticKernelPlaneCarriesLists(mode),
		Userspace: nativeplan.UserspaceDevices(
			nativeplan.KeeneticUserspace(&prof, s.capabilitySet(context.Background(), false))),
		Foreign: keeneticForeignDevices(prof),
	}
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
	case model.ProtoOpenVPN:
		// Only a profile that signs in with them (auth-user-pass); a certificate profile has none.
		if signsIn, _ := e.Params["auth_user_pass"].(bool); signsIn {
			if get("username") == "" {
				return "user name"
			}
			if get("password") == "" {
				return "password"
			}
		}
	}
	return ""
}

func (s *Server) datapathRequiresCore(cfg config.Config, prof model.Profile) bool {
	if s.detectedPlatform() == platform.Keenetic && !cfg.Demo {
		return keenetic.PlanRequiresCore(&prof, s.keeneticRoutePlanes(prof))
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

// tlsFragmentFindings says where a list's TLS fragmentation will not happen, so the setting does not
// read as working when it cannot. sing-box applies it to connections it makes itself: a tunnelled list
// carries the ClientHello inside the tunnel, and in mixed or fast mode the LAN's traffic for a direct
// list never reaches the core. Advisory only: the list itself still routes as before.
func tlsFragmentFindings(p *model.Profile, mode string) []PlanFinding {
	var out []PlanFinding
	for i := range p.RoutingLists {
		rl := &p.RoutingLists[i]
		if !rl.Enabled || rl.TLSFragment == "" {
			continue
		}
		detail := ""
		switch {
		case rl.Outbound != model.OutboundDirect:
			detail = "TLS fragmentation is set, but this list goes through a tunnel, where the TLS handshake travels inside the tunnel; it applies only to a list routed direct."
		case mode == "mixed" || mode == "fast":
			detail = "TLS fragmentation is set, but in " + mode + " mode the LAN's traffic for this list does not pass through the proxy core, which is what fragments it."
		default:
			continue
		}
		out = append(out, PlanFinding{
			ID: "list.tls_fragment_unused", Setting: "routing list", Item: listName(rl),
			Severity: platform.SeverityDegraded, Reason: platform.ReasonModeConflict, Blocks: platform.BlocksNothing,
			Detail: detail,
			Remedy: "Route the list direct in tun or hybrid mode, or turn fragmentation off for it.",
		})
	}
	return out
}

// coreInlineWarnEntries is where the lists the core holds inline start to cost a router something it
// may not have. Measured on the live Keenetic (sing-box 1.13.19, 149 MB available): 100,000 names took
// `sing-box check` to 9.3 s of Apply's 15 s limit and the core to 147 MB RSS against a 34 MB baseline;
// adding 45,612 prefixes took the check to 12.8 s. On flash each entry costs roughly 150 bytes at the
// peak of an Apply (the config, its staged check copy and the Apply record), and the test router's overlay
// had 6.1 MB free. Fetched feeds reach the core since QA-066, so a refilter-sized list sent to a proxy
// lands here.
const coreInlineWarnEntries = 20000

func coreInlineSizeFindings(p *model.Profile, mode string) []PlanFinding {
	if generator.DatapathNativeOnly(p, mode) {
		return nil
	}
	n := generator.CoreInlineEntries(p, mode == "hybrid" || mode == "fast")
	if n <= coreInlineWarnEntries {
		return nil
	}
	return []PlanFinding{{
		ID: "core.inline_size", Setting: "routing lists",
		Severity: platform.SeverityDegraded, Reason: platform.ReasonOperatorChoice, Blocks: platform.BlocksNothing,
		Detail: fmt.Sprintf("The proxy core will hold %d names and address ranges from routing lists. "+
			"On a router that costs memory, flash space and time: measured, 100,000 took the core's config check to 9 s of its 15 s limit and over 100 MB of memory.", n),
		Remedy: "Send large IP lists to a WireGuard or AmneziaWG connection in hybrid or fast mode, where the kernel routes them without the core, or choose a smaller list.",
	}}
}

// coreOverrideFindings says that the operator's core override is in force and which top-level keys of
// the core config it reaches, and names every listener it opens beyond loopback. None of it blocks:
// the override is deliberate, Apply refuses one the core cannot read (`sing-box check`) or whose own
// rules name a missing outbound (generator.ApplyCoreOverride), and the fail-safe window covers the
// rest.
//
// The open listener is a privacy finding and not a blocker. Serving the LAN is a legitimate reason to
// write an override - a SOCKS port for a device that cannot sit behind the TUN - and whether the port
// is open on the WAN is the router's firewall's call, which the config cannot show. So it is said,
// in plain sight with what it exposes, and Apply stays available.
//
// The keys, never the text: a prepended outbound carries a server's credentials.
//
// An override that takes from WayHop what it runs the core through (generator.DaemonLosses: the Clash
// API, the probe inbound, the generated inbounds or route rules) is a warning of its own, naming what
// stops working: the core runs and `sing-box check` passes, so nothing else would say it, and the
// features go quiet rather than fail. It does not block either: the operator may mean it.
func coreOverrideFindings(text string, coreRuns bool, use generator.DaemonUse) []PlanFinding {
	o, err := generator.ParseCoreOverride(text)
	if err != nil {
		// Validate refuses this at save, so only a hand-edited config.json reaches here; Generate
		// would refuse it at Apply too, one screen later and in its own words.
		return []PlanFinding{{
			ID: "core.override_invalid", Setting: "core_override", Severity: platform.SeverityBlocked,
			Reason: platform.ReasonSavedValueIncompat, Blocks: platform.BlocksApply, Detail: err.Error(),
		}}
	}
	if o == nil {
		return nil
	}
	detail := "The sing-box config WayHop generates is changed by the core override saved in Settings, " +
		"after everything else is generated. Apply checks the result with sing-box check before it is written."
	if !coreRuns {
		detail = "A core override is saved, but this configuration runs no proxy core, so the override changes nothing until one does."
	}
	var out []PlanFinding
	for _, key := range o.Keys() {
		out = append(out, PlanFinding{
			ID: "core.override", Setting: "core_override", Item: key,
			Severity: platform.SeverityDegraded, Reason: platform.ReasonOperatorChoice, Blocks: platform.BlocksNothing,
			Detail: detail,
		})
	}
	if !coreRuns {
		return out
	}
	for _, l := range o.OpenListeners() {
		out = append(out, PlanFinding{
			ID: "core.override_open_listener", Setting: "core_override", Item: l,
			Severity: platform.SeverityPrivacy, Reason: platform.ReasonOperatorChoice, Blocks: platform.BlocksNothing,
		})
	}
	losses := o.DaemonLosses(use)
	if len(losses) == 0 {
		return out
	}
	// One detail for the folded finding: every PlanFinding of an ID shares the first one's.
	var stops []string
	for _, kind := range []generator.DaemonLossKind{generator.LossClashAPI, generator.LossProbe, generator.LossInbounds, generator.LossRouteRules} {
		for _, l := range losses {
			if l.Kind == kind {
				stops = append(stops, daemonLossStops[kind])
				break
			}
		}
	}
	lossDetail := "The core runs and sing-box check passes, but the override removes or changes what WayHop uses the core through, " +
		"so nothing else will say this: " + strings.Join(stops, "; ") + "."
	for _, l := range losses {
		out = append(out, PlanFinding{
			ID: "core.override_daemon_loss", Setting: "core_override", Item: l.Item,
			Severity: platform.SeverityDegraded, Reason: platform.ReasonFeatureWouldBeDropped, Blocks: platform.BlocksNothing,
			Detail: lossDetail,
		})
	}
	return out
}

// daemonLossStops says, per generator.DaemonLossKind, what stops working.
var daemonLossStops = map[generator.DaemonLossKind]string{
	generator.LossClashAPI: "health checks, failover, the Connections page, the speed test, per-list traffic and the Telegram bot " +
		"lose the Clash API they read and steer the core through",
	generator.LossProbe: "the per-exit service check loses the probe inbound it asks each exit through",
	generator.LossInbounds: "the inbounds WayHop generates stop following the profile and Settings, " +
		"and the core has only those the override lists",
	generator.LossRouteRules: "WayHop's guard rules go with the generated route rules - the probe rules (the service check then " +
		"measures the routing, not the exit), the TUN's sniff, and the bypass that keeps each tunnel's own server traffic out " +
		"of the tunnels - and the profile's rules and routing lists stop applying",
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

// openWrtUserspaceMoves is the review's view of nativeplan.MoveError on OpenWrt, from the applied
// plan: an endpoint the router's own AmneziaWG ran that the userspace lane would now take, or one the
// lane ran that the native writer would now take back. Both run it on one device name, which is why
// the planner refuses the move within one Apply. Keyed by endpoint, valued by where it would go.
func (s *Server) openWrtUserspaceMoves(prof model.Profile, capset platform.CapabilitySet,
	userspace map[string]nativeplan.UserspaceEndpoint) map[string]string {
	moves := map[string]string{}
	base := s.appliedBaseline()
	if base == nil {
		return moves
	}
	previous := nativeBaselineFromMaterialization(&base.Materialization)
	if previous == nil {
		// A generic previous (no native plan) is not read here, although its AmneziaWG ran on
		// WayHop's engine: the review cannot tell whether this Apply's native plan will compile at
		// all, and a profile that stays generic moves nothing, so a blocker here could stop every
		// Apply. The planner refuses the real move (genericPluginDevices), naming the same remedy.
		return moves
	}
	was := make(map[string]nativeplan.Path, len(previous.Decisions))
	for _, decision := range previous.Decisions {
		was[decision.EndpointID] = decision.Path
	}
	for _, e := range prof.Endpoints {
		if !e.Enabled || e.Engine != model.EngineAmneziaWG || !e.OwnsResource() {
			continue
		}
		_, lane := userspace[e.ID]
		switch path := was[e.ID]; {
		case lane && (path == nativeplan.PathNativeCreate || path == nativeplan.PathNativeManage || path == nativeplan.PathNativeUpdate):
			moves[e.ID] = "WayHop's userspace AmneziaWG"
		case !lane && path == nativeplan.PathEnginePlugin && nativeAWGCreatable(e, capset):
			moves[e.ID] = "OpenWrt's own AmneziaWG"
		}
	}
	return moves
}

// nativeAWGCreatable reports whether the router's own AmneziaWG can create and remove e's interface.
func nativeAWGCreatable(e model.Endpoint, capset platform.CapabilitySet) bool {
	protocol := string(e.Protocol)
	return capset.Usable(platform.NativeOperationCapabilityID(protocol, platform.NativeCreate)) &&
		capset.Usable(platform.NativeOperationCapabilityID(protocol, platform.NativeRemove))
}

// endpointFindings judges every enabled endpoint's engine/protocol against what this router and this
// build can run. A missing engine binary is a feature-level finding (the endpoint will not come up;
// Apply still proceeds and reports the plugin as a problem); an engine this build has no executor
// for, or an external Keenetic tunnel whose NDM identity is unknown, is a hard blocker because the
// materialization cannot express it at all.
// awgUserspaceInstalled reports whether amneziawg-go can be started: the plugin manager's own lookup,
// or the gzip the updater keeps on a flash too small for the binary, which the plugin unpacks into
// RAM at every start (binstore).
func (s *Server) awgUserspaceInstalled() bool {
	if s.pluginBinaryPresent("amneziawg-go") {
		return true
	}
	if s.binaryPresentOf != nil {
		return false // a test that owns the lookup owns the answer
	}
	if bin := s.config().SingBox.Bin; bin != "" {
		_, stored := binstore.Read(filepath.Dir(bin), "amneziawg-go")
		return stored
	}
	return false
}

func (s *Server) endpointFindings(prof model.Profile, capset platform.CapabilitySet) []PlanFinding {
	var out []PlanFinding
	keeneticHost := s.detectedPlatform() == platform.Keenetic
	var userspace map[string]nativeplan.UserspaceEndpoint
	moves := map[string]string{}
	// The kernel module generation the Apply's capture would compile with (awgkernel.go): asked with
	// anything else, the review and the planner disagree about where a connection runs.
	kernel := awg.GenNone
	if !s.config().Demo {
		kernel = s.awgKernelGeneration()
		userspace = nativeplan.UserspaceFor(&prof, s.detectedPlatform(), capset, kernel)
		if s.detectedPlatform() == platform.OpenWrt {
			moves = s.openWrtUserspaceMoves(prof, capset, userspace)
		}
	}
	name := func(e model.Endpoint) string {
		if e.Name != "" {
			return e.Name
		}
		return e.ID
	}
	coreVer := s.coreVersion(s.config())
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
		out = append(out, pinFindings(&e, name(e), coreVer)...)
		if generator.GeckoNeedsNewerCore(&e, coreVer) {
			out = append(out, PlanFinding{
				ID: "endpoint.hysteria2.gecko", Setting: "obfs", Item: name(e),
				Severity: platform.SeverityDegraded, Reason: platform.ReasonBinaryTooOld,
				Blocks: platform.BlocksFeature,
				Detail: "This connection uses gecko obfuscation, which sing-box carries from 1.14; this router's core is older, so it is applied without it and will not reach its server. Everything else keeps working.",
				Remedy: "Update sing-box to 1.14 or newer on the Components page, or switch this connection off.",
			})
		}
		// QUIC tuning an older core refuses at decode is left out of the shared config: the connection
		// comes up as it did before the setting, on the path that needed it.
		if generator.QUICTuningNeedsNewerCore(&e, coreVer) {
			out = append(out, PlanFinding{
				ID: "endpoint.quic.tuning", Setting: "QUIC packet size", Item: name(e),
				Severity: platform.SeverityDegraded, Reason: platform.ReasonBinaryTooOld,
				Blocks: platform.BlocksNothing,
				Detail: "This connection sets its QUIC packet size or turns off path MTU discovery, which sing-box carries from 1.14; this router's core is older, so it is applied without them and may still stall on a link that drops large packets. Everything else keeps working.",
				Remedy: "Update sing-box to 1.14 or newer on the Components page, or clear these settings.",
			})
		}
		// A Hysteria2 size the Chrome handshake replaces is written and does nothing; the panel says so
		// beside the field, and this says it for a size that came from the API or an import.
		if generator.QUICSizeReplacedByChrome(&e, coreVer) {
			out = append(out, PlanFinding{
				ID: "endpoint.hysteria2.quic_size_parrot", Setting: "QUIC packet size", Item: name(e),
				Severity: platform.SeverityDegraded, Reason: platform.ReasonFeatureWouldBeDropped,
				Blocks: platform.BlocksNothing,
			})
		}
		// An SSH exit with no pinned host key: sing-box then takes whatever key answers, so anyone who
		// can intercept the way to the server can pose as it. The exit works all the same, which is
		// why nothing else would say so; it is a choice the operator may keep, so nothing is blocked.
		if e.Protocol == model.ProtoSSH {
			if keys, err := model.SSHHostKeys(&e); err == nil && len(keys) == 0 {
				out = append(out, PlanFinding{
					ID: "endpoint.ssh.host_key", Setting: "host key", Item: name(e),
					Severity: platform.SeverityPrivacy, Reason: platform.ReasonOperatorChoice,
					Blocks: platform.BlocksNothing,
				})
			}
			// The exit carries TCP only, and what is routed to it sends UDP too: QUIC falls back to
			// TCP, but calls, games and DNS over UDP fail, with nothing else to say why. A note, not a
			// block: TCP through it works, which may be all the operator wants from it.
			if generator.SSHExitGetsUDP(&prof, e.ID) {
				out = append(out, PlanFinding{
					ID: "endpoint.ssh.tcp_only", Setting: "UDP", Item: name(e),
					Severity: platform.SeverityDegraded, Reason: platform.ReasonFeatureWouldBeDropped,
					Blocks: platform.BlocksNothing,
				})
			}
		}
		if generator.SSHAlgorithmsNeedNewerCore(&e, coreVer) {
			out = append(out, PlanFinding{
				ID: "endpoint.ssh.algorithms", Setting: "algorithms", Item: name(e),
				Severity: platform.SeverityDegraded, Reason: platform.ReasonBinaryTooOld,
				Blocks: platform.BlocksNothing,
			})
		}
		// Encrypted Client Hello (generator/ech.go). What the core leaves out is said here; what model
		// .Validate refuses (a malformed config, ECH switched on with Reality) never gets this far.
		switch {
		case generator.ECHDroppedByCore(&e, coreVer):
			out = append(out, PlanFinding{
				ID: "endpoint.tls.ech.core", Setting: "ECH", Item: name(e),
				Severity: platform.SeverityDegraded, Reason: platform.ReasonBinaryLacksFeature,
				Blocks: platform.BlocksFeature,
			})
		case generator.ECHQueryNameNeedsNewerCore(&e, coreVer):
			out = append(out, PlanFinding{
				ID: "endpoint.tls.ech.qsn", Setting: "ECH", Item: name(e),
				Severity: platform.SeverityDegraded, Reason: platform.ReasonBinaryTooOld,
				Blocks: platform.BlocksFeature,
			})
		}
		if generator.ECHFingerprintReplaced(&e, coreVer) != "" {
			out = append(out, PlanFinding{
				ID: "endpoint.tls.ech.fingerprint", Setting: "ECH", Item: name(e),
				Severity: platform.SeverityDegraded, Reason: platform.ReasonFeatureWouldBeDropped,
				Blocks: platform.BlocksNothing,
			})
		}
		// The DNS lookup goes where the DNS rules send it (generator.ECHLookupFor). Through the
		// connection it is for, it never answers while the connection is down: said, and to be
		// acknowledged, rather than fixed by sending the name elsewhere, which would put it on a
		// server the operator did not choose (the direct resolver: the WAN, often in the clear).
		// To plain DNS it is answered, and the name ECH hides goes out in the clear.
		if l := generator.ECHLookupFor(&prof, &e, coreVer); l != nil {
			if l.Through != "" {
				out = append(out, PlanFinding{
					ID: "endpoint.tls.ech.dns_loop", Setting: "ECH", Item: name(e),
					Severity: platform.SeverityDegraded, Reason: platform.ReasonSavedValueIncompat,
					Blocks: platform.BlocksFeature,
				})
			}
			switch {
			case l.Clear:
				out = append(out, PlanFinding{
					ID: "endpoint.tls.ech.dns_clear", Setting: "ECH", Item: name(e),
					Severity: platform.SeverityPrivacy, Reason: platform.ReasonOperatorChoice,
					Blocks: platform.BlocksNothing,
				})
			case l.Through == "":
				out = append(out, PlanFinding{
					ID: "endpoint.tls.ech.dns", Setting: "ECH", Item: name(e),
					Severity: platform.SeverityDegraded, Reason: platform.ReasonOperatorChoice,
					Blocks: platform.BlocksNothing,
				})
			}
		}
		out = append(out, multiplexFindings(e, name(e))...)
		out = append(out, finalMaskFindings(e, name(e))...)
		if generator.RealmNeedsNewerCore(&e, coreVer) {
			out = append(out, PlanFinding{
				ID: "endpoint.hysteria2.realm", Setting: "realm", Item: name(e),
				Severity: platform.SeverityDegraded, Reason: platform.ReasonBinaryTooOld,
				Blocks: platform.BlocksFeature,
				Detail: "This connection reaches its server through a Hysteria realm, which sing-box carries from 1.14; this router's core is older, so it is applied without a server and will not come up. Everything else keeps working.",
				Remedy: "Update sing-box to 1.14 or newer on the Components page, or switch this connection off.",
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
				// A tunnel run outside KeeneticOS has no NDM identity to capture; the Apply capture
				// proves instead that no NDM interface owns its link (validKeeneticAdoptEvidence).
				_, foreign := foreignKeeneticDevice(e)
				if _, ndmKnown := keenetic.ResolveNDMName(e); !foreign && (!e.IsExternal() || !ndmKnown) {
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
			if move, ok := moves[e.ID]; ok {
				// The Apply would be refused by the planner (nativeplan.MoveError); say it here, where it
				// is one click from the fix - and, when the operator changed nothing, what did.
				detail := "This connection would move to " + move + " in one Apply, and on OpenWrt both run it on the " +
					"same device name, so the old tunnel's teardown would take the new one down with it."
				if why := nativeplan.OpenWrtMoveReason(e, kernel); why != "" {
					detail += " It moves because " + why + "."
				}
				out = append(out, PlanFinding{
					ID: "endpoint.amneziawg.move", Setting: "AmneziaWG engine", Item: name(e),
					Requested: move, Effective: "not moved",
					Severity: platform.SeverityBlocked, Reason: platform.ReasonModeConflict,
					Blocks: platform.BlocksApply,
					Detail: detail,
					Remedy: "Switch the connection off and apply, then switch it on and apply again.",
				})
				continue
			}
			// The router hands it to WayHop's userspace engine: what matters then is amneziawg-go, not the
			// router's module or the awg tools, and the operator should know it is not native.
			if u, ok := userspace[e.ID]; ok {
				if !s.awgUserspaceInstalled() {
					out = append(out, PlanFinding{
						ID: "endpoint.engine.amneziawg_go", Setting: "engine", Item: name(e),
						Requested: "amneziawg-go", Effective: "not started",
						Severity: platform.SeverityBlocked, Reason: platform.ReasonMissingBinary,
						Blocks: platform.BlocksFeature,
						Detail: "This connection runs on WayHop's userspace AmneziaWG because " + u.Reason +
							", and amneziawg-go is not installed, so it cannot come up.",
						Remedy: "Install AmneziaWG 3 (amneziawg-go) through the Updater, or disable the connection.",
					})
					continue
				}
				out = append(out, PlanFinding{
					ID: "endpoint.amneziawg.userspace", Setting: "engine", Item: name(e),
					Requested: "native AmneziaWG", Effective: "amneziawg-go",
					Severity: platform.SeverityDegraded, Reason: u.Code, Blocks: platform.BlocksNothing,
					Detail: "This connection runs on WayHop's userspace AmneziaWG (amneziawg-go) because " + u.Reason +
						". It works, with less throughput than a native tunnel.",
					Remedy: u.Remedy,
				})
				continue
			}
			// Set to run on amneziawg-go where no native lane carries it - the generic path, the demo:
			// the plugin needs the binary exactly as a lane endpoint does, and the kernel tools are moot.
			if e.AWGUserspace {
				if !s.awgUserspaceInstalled() {
					out = append(out, PlanFinding{
						ID: "endpoint.engine.amneziawg_go", Setting: "engine", Item: name(e),
						Requested: "amneziawg-go", Effective: "not started",
						Severity: platform.SeverityBlocked, Reason: platform.ReasonMissingBinary,
						Blocks: platform.BlocksFeature,
						Detail: "This connection is set to run on amneziawg-go, which is not installed, so it cannot come up.",
						Remedy: "Install AmneziaWG 3 (amneziawg-go) through the Updater, or set the connection's engine back to Automatic.",
					})
				}
				continue
			}
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
			// Retired: a profile saved by an older build can still hold one, and must load.
			out = append(out, PlanFinding{
				ID: "endpoint.engine.olcrtc", Setting: "engine", Item: name(e),
				Requested: "olcrtc", Effective: "not applied",
				Severity: platform.SeverityBlocked, Reason: platform.ReasonBackendNotWired,
				Blocks: platform.BlocksApply,
				Detail: "WayHop no longer runs olcRTC: the project ended (its repository was archived on 2026-09-30) and it was removed.",
				Remedy: "Delete this connection, or disable it, and move what used it to another connection.",
			})
		case model.EngineByeDPI:
			if s.byedpiUnavailable() {
				// One stored enabled before the save gate refused it, or restored from another router's
				// backup. The planner would fail the Apply on it; said here, the review names the
				// connection and the way out before anything is attempted.
				out = append(out, PlanFinding{
					ID: "endpoint.engine.byedpi.keenetic", Setting: "engine", Item: name(e), Requested: "byedpi",
					Effective: "not applied", Severity: platform.SeverityBlocked,
					Reason: platform.ReasonPlatformUnsupported, Blocks: platform.BlocksApply,
					Detail: nativeplan.ByeDPIOnKeenetic + ", so this connection cannot run on this router.",
					Remedy: "Disable the connection, after pointing any routing list or rule that uses it at another connection.",
				})
				continue
			}
			if s.pluginBinaryPresent("ciadpi") {
				continue
			}
			out = append(out, PlanFinding{
				ID: "endpoint.engine.byedpi", Setting: "engine", Item: name(e), Requested: "byedpi",
				Effective: "not started", Severity: platform.SeverityBlocked,
				Reason: platform.ReasonMissingBinary, Blocks: platform.BlocksFeature,
				Detail: "The ciadpi binary (ByeDPI) is not installed, so this connection cannot start.",
				Remedy: "Install ByeDPI's ciadpi, or disable the connection.",
			})
		default:
			// nfqws included (QA-055): its finding used to say "install nfqws2" and nothing when the
			// binary was there, but the executor refuses the engine either way (it modifies packets and
			// has no exit; classifyExecutionEndpoint), so the install it promised fixed nothing.
			out = append(out, PlanFinding{
				ID: "endpoint.engine." + string(e.Engine), Setting: "engine", Item: name(e),
				Requested: string(e.Engine), Effective: "not applied",
				Severity: platform.SeverityBlocked, Reason: platform.ReasonBackendNotWired,
				Blocks: platform.BlocksApply,
				Detail: "This WayHop build has no executor for the " + string(e.Engine) + " engine.",
				Remedy: "Use sing-box or AmneziaWG for this connection, or disable it.",
			})
		}
	}
	if !s.config().Demo {
		out = append(out, s.awgTransitionFindings(prof, capset, userspace, moves)...)
	}
	return out
}

// awgTransitionFindings are the review's account of an AmneziaWG change on the router that the
// connections have not caught up with yet: connections still on amneziawg-go that the kernel module now
// carries (they switch at their next start - an Apply that leaves them unchanged does not restart them,
// and nothing restarts a working tunnel to move it), and a netifd that has not read the AmneziaWG handler
// an install added or changed, while this Apply would write OpenWrt's own AmneziaWG interfaces.
func (s *Server) awgTransitionFindings(prof model.Profile, capset platform.CapabilitySet,
	userspace map[string]nativeplan.UserspaceEndpoint, moves map[string]string) []PlanFinding {
	var out []PlanFinding
	p := s.detectedPlatform()
	nativePlan := p == platform.OpenWrt || p == platform.Keenetic
	running := s.awgRunningOnUserspace()
	var probe awg.Probe
	if len(running) > 0 {
		probe = s.awgHostProbe()
	}
	writesNative := false
	for _, e := range prof.Endpoints {
		if !e.Enabled || e.Engine != model.EngineAmneziaWG || !e.OwnsResource() {
			continue
		}
		_, inLane := userspace[e.ID]
		_, moving := moves[e.ID]
		native := nativePlan && !inLane && nativeAWGCreatable(e, capset)
		writesNative = writesNative || (native && p == platform.OpenWrt)
		if !running[e.ID] || moving || native {
			continue // not on the engine, or a move the blocker above already explains
		}
		next := plugin.AWGDecision(probe, p == platform.Keenetic, e)
		if !awgSwitchesToKernel(probe, next, true) {
			continue
		}
		name := e.Name
		if name == "" {
			name = e.ID
		}
		out = append(out, PlanFinding{
			ID: "endpoint.amneziawg.kernel_switch", Setting: "AmneziaWG engine", Item: name,
			Requested: "AmneziaWG kernel module", Effective: "amneziawg-go until its next start",
			Severity: platform.SeverityDegraded, Reason: platform.ReasonNone, Blocks: platform.BlocksNothing,
			Detail: "This connection runs on amneziawg-go, and the AmneziaWG kernel module installed since it started carries it (" +
				next.Reason + "). It keeps running as it is and switches to the kernel module the next time it starts: " +
				"after a WayHop restart or a reboot, or when an Apply changes it. An Apply that leaves it unchanged does not restart it.",
			Remedy: "Nothing is required. Restart WayHop or the router when a short interruption suits you to switch it now.",
		})
	}
	if writesNative && s.awgNetifdRestartPending() {
		out = append(out, PlanFinding{
			ID: "endpoint.amneziawg.netifd_restart", Setting: "AmneziaWG handler",
			Severity: platform.SeverityDegraded, Reason: platform.ReasonMissingService, Blocks: platform.BlocksFeature,
			Detail: "AmneziaWG's netifd handler was installed or changed after the network service started, and netifd reads " +
				"handlers only when it starts. Until it restarts, OpenWrt's own AmneziaWG interfaces this Apply writes may not " +
				"come up, or may come up without their AmneziaWG 3.x settings.",
			Remedy: "Restart the network service from the AmneziaWG row on the Components page (every link drops for a few seconds), " +
				"or reboot the router, then apply.",
		})
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
// blocker is never acknowledgeable, a feature-level finding needs one, and everything else —
// privacy findings included — is informational. Blockers come first, then acknowledgements, then
// notes. (This said "a feature-level OR PRIVACY finding needs one" long after the code stopped
// asking for a privacy signature; the reasoning for that is spelled out at the branch below.)
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
		g := &Finding{
			ID: f.ID, Code: code, Severity: severity, Blocks: blocks,
			// Acknowledgement is for a configuration that will NOT do what it says — a feature the
			// router silently drops. A privacy note is not that: it is reported, counted and left in
			// plain sight, and Apply stays available.
			// BlocksFeature and BlocksApply are distinct values, so this test already excludes a hard
			// blocker; the "!hard &&" that used to lead it restated that and needed a variable to do it.
			AckRequired: blocks == platform.BlocksFeature && severity != platform.SeverityPrivacy,
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

// pinFindings says what the core does with an enabled connection's certificate pins
// (generator/pin.go) where that is not what the pin's own format does: a pin an older core (or an
// unknown version) leaves out, named apart when the connection then accepts any certificate; a pin
// that is not a SHA-256 hash, ignored by every core; a Hysteria pin checked instead of the chain where
// Hysteria checks both; a pin from a format that also accepts a CA's hash, which sing-box never
// matches; pins beside Reality, which uses none; and a link's verify name (vcn) where sing-box checks
// the SNI instead. None stops the core from loading, so none holds Apply.
func pinFindings(e *model.Endpoint, item, coreVer string) []PlanFinding {
	var out []PlanFinding
	note := func(id string, reason platform.ReasonCode) PlanFinding {
		return PlanFinding{ID: id, Setting: "certificate pin", Item: item, Severity: platform.SeverityDegraded,
			Reason: reason, Blocks: platform.BlocksNothing}
	}
	coreName := strings.TrimSpace(strings.SplitN(coreVer, "\n", 2)[0])
	if coreName == "" {
		coreName = "a sing-box of unknown version"
	}
	if cov, left := generator.PinsLeftOut(e, coreVer); left {
		f := note("endpoint.tls.pin.core", platform.ReasonBinaryTooOld)
		f.Requested, f.Effective = "certificate pin", "not checked by "+coreName
		if need := generator.PinCoreNeeded(e, coreVer); need != "" {
			f.Requested = "certificate pin (sing-box " + need + " or newer)"
		}
		if cov.Insecure {
			f.ID = "endpoint.tls.pin.unenforced"
		}
		out = append(out, f)
	}
	if generator.PinMalformed(e) {
		out = append(out, note("endpoint.tls.pin.invalid", platform.ReasonSavedValueIncompat))
	}
	if generator.PinReplacesChainCheck(e, coreVer) {
		out = append(out, note("endpoint.tls.pin.replaces_chain", platform.ReasonOperatorChoice))
	}
	if generator.PinsMayNameCA(e, coreVer) {
		out = append(out, note("endpoint.tls.pin.leaf", platform.ReasonSavedValueIncompat))
	}
	if generator.PinsUnusedByReality(e) {
		out = append(out, note("endpoint.tls.pin.reality", platform.ReasonFeatureWouldBeDropped))
	}
	if names := generator.CertNameUnchecked(e, coreVer); len(names) > 0 {
		sni := e.Server
		if e.TLS != nil && e.TLS.SNI != "" {
			sni = e.TLS.SNI
		}
		out = append(out, PlanFinding{ID: "endpoint.tls.vcn", Setting: "certificate name", Item: item,
			Severity: platform.SeverityDegraded, Reason: platform.ReasonSavedValueIncompat, Blocks: platform.BlocksNothing,
			Requested: "certificate checked against " + strings.Join(names, ", "), Effective: "checked against the SNI " + sni})
	}
	return out
}

// multiplexFindings says what an enabled connection's multiplex will not do. The save refuses the
// first two (model.EndpointParamProblem), so they reach here only from a profile that came another way
// (a restored backup, a hand-edited file); the generator then leaves the setting out rather than fail
// the shared config, and this says so. The third the save allows: Shadowsocks with UDP over TCP, where
// sing-box never builds the multiplex client.
func multiplexFindings(e model.Endpoint, item string) []PlanFinding {
	m := e.Multiplex
	if m == nil || !m.Enabled {
		return nil
	}
	mk := func(id string, reason platform.ReasonCode, requested, effective string) []PlanFinding {
		return []PlanFinding{{ID: id, Setting: "multiplex", Item: item, Severity: platform.SeverityDegraded,
			Reason: reason, Blocks: platform.BlocksFeature, Requested: requested, Effective: effective}}
	}
	proto := m.Protocol
	if proto == "" {
		proto = "h2mux"
	}
	switch {
	case !model.MultiplexCapable(e.Protocol) || !model.MuxProtocols[proto]:
		return mk("endpoint.multiplex.unsupported", platform.ReasonSavedValueIncompat, "multiplex ("+proto+") on "+string(e.Protocol), "off")
	case model.MuxUoTIgnored(&e):
		return mk("endpoint.multiplex.uot_ignored", platform.ReasonFeatureWouldBeDropped, "multiplex with UDP over TCP", "multiplex off")
	case m.Brutal != nil && m.Brutal.Enabled && (!model.BrutalRateOK(m.Brutal.UpMbps) || !model.BrutalRateOK(m.Brutal.DownMbps)):
		return mk("endpoint.multiplex.brutal_speed", platform.ReasonSavedValueIncompat,
			fmt.Sprintf("TCP Brutal %d/%d Mbps", m.Brutal.UpMbps, m.Brutal.DownMbps), "TCP Brutal off")
	}
	return nil
}

// finalMaskFindings says what sing-box does with a connection's Xray finalmask (a link's fm=,
// model.ParseFinalMask): nothing. The masks that change only what the client sends are named, since the
// connection works without them but without that evasion. The importers refuse a mask the server
// undoes, and fm that is not a finalmask; one that arrives another way (the API, a restored backup)
// is named as failing every connection. None stops the core from loading, so none holds Apply.
func finalMaskFindings(e model.Endpoint, item string) []PlanFinding {
	raw, _ := e.Params[model.ParamFinalMask].(string)
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	f := PlanFinding{Setting: "finalmask", Item: item, Severity: platform.SeverityDegraded, Effective: "not applied"}
	fm, err := model.ParseFinalMask(raw)
	switch {
	case err != nil:
		f.ID, f.Reason, f.Blocks, f.Requested = "endpoint.finalmask.peer", platform.ReasonSavedValueIncompat,
			platform.BlocksFeature, "Xray finalmask ("+err.Error()+")"
	case len(fm.Peer) > 0:
		f.ID, f.Reason, f.Blocks, f.Requested = "endpoint.finalmask.peer", platform.ReasonSavedValueIncompat,
			platform.BlocksFeature, "Xray finalmask: "+strings.Join(fm.Peer, ", ")
	case len(fm.Sender) > 0:
		f.ID, f.Reason, f.Blocks, f.Requested = "endpoint.finalmask.sender", platform.ReasonFeatureWouldBeDropped,
			platform.BlocksNothing, "Xray finalmask: "+strings.Join(fm.Sender, ", ")
	default:
		return nil
	}
	return []PlanFinding{f}
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
	case f.ID == "endpoint.ssh.host_key":
		return "SSH_HOST_KEY_NOT_PINNED", "SSH exit accepts any server",
			"The connection has no host key, so the router accepts whatever key the server presents. Anyone who can " +
				"intercept the way to the server can pose as it: read or change every connection sent through this exit " +
				"that is not encrypted end to end, and take the password if the connection logs in with one (a private key " +
				"cannot be taken this way). The exit works; Apply is not held.",
			"Paste the server's host key lines into the connection's Host keys: run ssh-keyscan -p <port> <server> " +
				"where you trust the network, or read /etc/ssh/ssh_host_ed25519_key.pub on the server."
	case f.ID == "endpoint.ssh.tcp_only":
		return "SSH_EXIT_TCP_ONLY", "SSH exit carries TCP only",
			"An SSH server forwards TCP connections and nothing else, and rules, routing lists or a DNS server over UDP " +
				"send UDP to this exit too. That UDP is not carried: calls, games and DNS over UDP fail through it, and " +
				"browsers fall back from QUIC to TCP. In an automatic group, UDP goes to a member that carries it instead. " +
				"TCP works; Apply is not held.",
			"Send what needs UDP through another exit, and point a DNS server that uses this exit at DNS over TLS or HTTPS."
	case f.ID == "endpoint.ssh.algorithms":
		return "SSH_ALGORITHMS_NEED_NEWER_CORE", "SSH algorithm limits need sing-box 1.14",
			"This connection limits its ciphers, MACs or key exchanges, which sing-box carries from 1.14; this router's " +
				"core is older, so it is applied without the limits and negotiates from the defaults. A server that " +
				"accepts only the listed algorithms will refuse it.",
			"Update sing-box to 1.14 or newer on the Components page."
	case f.ID == "endpoint.tls.ech.core":
		return "ECH_NOT_IN_CORE", "This sing-box has no ECH",
			"This router's sing-box 1.12 was built with a Go older than 1.24, which has no Encrypted Client Hello, and it " +
				"refuses any config that asks for it. These connections are applied without ECH, so their server name is " +
				"sent in the clear, and a server that accepts only ECH refuses them.",
			"Update sing-box on the Components page: 1.13 or newer, or a 1.12 build made with Go 1.24 or newer."
	case f.ID == "endpoint.tls.ech.qsn":
		return "ECH_QUERY_NAME_NEEDS_NEWER_CORE", "ECH query server name needs sing-box 1.13",
			"This connection looks its ECH config up in DNS under a query server name, which sing-box carries from 1.13; " +
				"this router's core is older, so it looks up the connection's server name (SNI) instead, and the connection " +
				"fails unless that name publishes an ECH record.",
			"Update sing-box to 1.13 or newer on the Components page, or paste the server's ECH config into the connection."
	case f.ID == "endpoint.tls.pin.core":
		return "CERT_PIN_NEEDS_NEWER_CORE", "Certificate pin not checked by this sing-box",
			"These connections pin the server's certificate. sing-box checks a public-key pin from 1.13 and a " +
				"whole-certificate pin, the kind share links carry, from 1.15; this router's core is older, or its " +
				"version is not known yet, and an older core refuses the whole configuration over a pin, so the pins " +
				"it cannot check are left out. Where a connection also has a pin the core can check, only that one is " +
				"checked; otherwise the certificate's chain and name are checked as usual, and a server whose " +
				"certificate no public authority signed (a self-signed one) is refused. Apply is not held.",
			"Update sing-box to 1.15 or newer on the Components page."
	case f.ID == "endpoint.tls.pin.unenforced":
		return "CERT_PIN_NOT_ENFORCED", "Pinned connection accepts any certificate",
			"These connections pin the server's certificate and turn certificate checks off (\"insecure\"), as " +
				"their link asks, and the pin is left out: this router's sing-box is too old to check it (a " +
				"whole-certificate pin needs 1.15, a public-key pin 1.13) or its version is not known yet. They " +
				"accept any certificate, so anyone who can intercept the way to the server can pose as it. The " +
				"connections work; Apply is not held.",
			"Update sing-box to 1.15 or newer on the Components page."
	case f.ID == "endpoint.tls.pin.invalid":
		return "CERT_PIN_INVALID", "Certificate pin is not a valid SHA-256 hash",
			"These connections carry a certificate pin, kept from a link an older WayHop imported, that is not a " +
				"valid SHA-256 hash, so it is ignored: the connection checks the server as its other settings say, " +
				"and with certificate checks off (\"insecure\") and no other pin it accepts any certificate. Apply is " +
				"not held.",
			"Open the connection and re-enter the server's pin, or remove it."
	case f.ID == "endpoint.tls.pin.replaces_chain":
		return "CERT_PIN_REPLACES_CHAIN_CHECK", "The pin is checked instead of the certificate chain",
			"These connections pin the server's certificate with Hysteria's pinSHA256 and keep certificate checks " +
				"on. Hysteria's own client then checks the certificate's chain, name and expiry as well as the pin; " +
				"sing-box checks the pin instead, so a certificate that matches the pin is accepted even after it has " +
				"expired. The pin names that one certificate exactly. Apply is not held.",
			"Nothing is required. Replace the pin when the server's certificate is renewed."
	case f.ID == "endpoint.tls.pin.leaf":
		return "CERT_PIN_SERVER_CERT_ONLY", "A certificate pin must be the server's own certificate",
			"These connections' whole-certificate pins, or some of them, came from a link or config whose format also " +
				"accepts the hash of a CA certificate in the server's chain (Xray's pcs=, mihomo's fingerprint). sing-box " +
				"compares a pin with the server's own certificate only, so a pin that is a CA's hash matches nothing, and " +
				"unless another pin is the server's own certificate, every handshake of the connection fails. Apply is " +
				"not held.",
			"If the connection does not come up, pin the server's own certificate instead: on the server, " +
				"openssl x509 -in <certificate> -noout -fingerprint -sha256 prints it."
	case f.ID == "endpoint.tls.pin.reality":
		return "CERT_PIN_UNUSED_WITH_REALITY", "Certificate pins are not used with Reality",
			"These Reality connections carry certificate pins (a link's pcs=, or set through the API). Reality " +
				"authenticates the server by its own key and replaces any certificate check, so the pins are not " +
				"used; they are kept only to be shared again. Apply is not held.",
			"Nothing is required. Remove the pins through the API, or switch the connection to plain TLS to use them."
	case f.ID == "endpoint.finalmask.sender":
		return "FINALMASK_SENDER_NOT_APPLIED", "Xray finalmask is not applied",
			"These connections' links carry Xray masks (fm=) that change only what the client sends: fragment " +
				"splits what it writes first (the TLS ClientHello), noise sends datagrams of its own ahead of the " +
				"connection's, udphop hops between the server's ports. sing-box has no masks, so they are left out. " +
				"The server reads the connection the same either way, so it works, without that evasion. Apply is " +
				"not held.",
			"Nothing is required. Where the network blocks the connection without them, try the connection's TLS " +
				"fragment settings or another transport."
	case f.ID == "endpoint.finalmask.peer":
		return "FINALMASK_PEER_UNSUPPORTED", "The server expects an Xray mask sing-box lacks",
			"These connections carry an Xray finalmask (fm=) that the server applies too, or one Xray itself would " +
				"refuse. It reached the profile through the API or a restored backup: an import refuses such a " +
				"link. sing-box has no masks, so every connection to that server fails. Apply is not held.",
			"Switch the connection off, or connect to the server through an inbound without the mask."
	case f.ID == "endpoint.tls.vcn":
		return "CERT_NAME_NOT_CHECKED", "Certificate is checked against the SNI, not the link's name",
			"These connections' links ask to check the server's certificate against another name (vcn), so that " +
				"the real name can stay out of the SNI. sing-box has no such option: it checks the certificate " +
				"against the SNI, so the connection fails unless the certificate also covers the SNI. Apply is not held.",
			"Pin the server's certificate, which replaces the name check (sing-box 1.15 or newer for the pins " +
				"share links carry), or set the SNI to a name the certificate covers."
	case f.ID == "endpoint.hysteria2.quic_size_parrot":
		return "QUIC_SIZE_REPLACED_BY_CHROME", "QUIC packet size is replaced by Chrome's",
			"These Hysteria2 connections set an initial QUIC packet size, but they parrot Chrome's QUIC handshake, " +
				"which starts at Chrome's own size (1250 bytes, 1230 over IPv6) instead, so the setting does nothing. " +
				"Turning off path MTU discovery still applies. Apply is not held.",
			"Turn on \"No Chrome QUIC fingerprint\" on the connection for the size to apply, or clear the size."
	case f.ID == "endpoint.tls.ech.fingerprint":
		return "ECH_FINGERPRINT_REPLACED", "ECH is sent with the chrome fingerprint",
			"These connections ask for a uTLS fingerprint (safari, ios, edge, android, 360, qq, random or randomized) " +
				"whose ClientHello cannot carry Encrypted Client Hello: with it every handshake fails. They are applied " +
				"with the chrome fingerprint instead, so that ECH works. Apply is not held.",
			"Nothing is required. Set the connection's fingerprint to chrome or firefox, or clear it, and this goes away; " +
				"switch ECH off to keep the fingerprint."
	case f.ID == "endpoint.tls.ech.dns":
		return "ECH_FROM_ROUTER_DNS", "ECH config is looked up through the router's DNS",
			"These connections look their ECH config up (an HTTPS record, kept for its TTL) through the router's DNS " +
				"rules, not through the connection. A name answered by FakeIP, refused by a DNS rule or blocked by the " +
				"network fails the lookup, and then the connection fails: it does not fall back to an unencrypted " +
				"handshake. Apply is not held.",
			"Make sure the DNS server that answers the name reaches it, or paste the server's ECH config into the " +
				"connection, which needs no lookup."
	case f.ID == "endpoint.tls.ech.dns_loop":
		return "ECH_LOOKUP_THROUGH_ITSELF", "ECH lookup goes through the connection it is for",
			"These connections look their ECH config up in DNS, and the DNS server the router's DNS rules give that " +
				"lookup to is reached through the connection itself, or through a group that holds it (the secure DNS " +
				"default rides the main exit). The lookup needs the connection it is for: the connection does not come " +
				"up, or, in a group that can leave it, comes up only while DNS goes another way and drops again when the " +
				"record expires.",
			"Paste the server's ECH config into the connection, which needs no lookup, or add a DNS rule that sends the " +
				"name it looks up (its query server name, else its SNI) to a server that does not go through it."
	case f.ID == "endpoint.tls.ech.dns_clear":
		return "ECH_NAME_IN_CLEAR_DNS", "ECH lookup sends the hidden name over plain DNS",
			"These connections look their ECH config up in DNS, and the DNS server the router's DNS rules give that " +
				"lookup to is plain DNS (udp or tcp) or the router's own resolver, which forwards it as the router is set " +
				"up to. The name ECH hides (the query server name, else the SNI) then goes out in the DNS question, " +
				"readable by the firewall ECH is meant to blind. The connection works; Apply is not held.",
			"Paste the server's ECH config into the connection, which needs no lookup, or send the name to an encrypted " +
				"DNS server (DoH, DoT, DoQ) with a DNS rule or as the final server on the DNS page."
	case f.ID == "endpoint.multiplex.unsupported":
		return "MULTIPLEX_NOT_APPLIED", "Multiplex is left out",
			"These connections ask for multiplex where sing-box has none: on a protocol other than VLESS, VMess, Trojan " +
				"or Shadowsocks, or with a multiplex protocol other than h2mux, smux or yamux (an Xray server's mux.cool " +
				"is not one). Saving refuses this; it came with a restored or edited profile. The core would refuse the " +
				"whole configuration over it, so these connections are applied without multiplex.",
			"On Hysteria2, TUIC and the other protocols without multiplex, open the connection and save it: " +
				"the form has no Multiplex section there, so saving drops the setting. On VLESS, VMess, Trojan or " +
				"Shadowsocks, pick h2mux, smux or yamux in its Multiplex section, or switch multiplex off."
	case f.ID == "endpoint.multiplex.brutal_speed":
		return "MULTIPLEX_BRUTAL_RATE", "TCP Brutal is left out",
			"These connections turn TCP Brutal on with an upload or download rate that is missing, zero, negative or " +
				"past 100000 Mbps. The core refuses a missing or zero rate and misreads a negative one, so they are " +
				"applied with multiplex and without TCP Brutal.",
			"Open the connection and set both TCP Brutal rates in Mbps, or switch TCP Brutal off."
	case f.ID == "endpoint.multiplex.uot_ignored":
		return "MULTIPLEX_UOT_IGNORED", "Multiplex does nothing with UDP over TCP",
			"These Shadowsocks connections send UDP over TCP, and sing-box then never starts multiplex: every " +
				"connection opens its own. They work; only the multiplex is not used.",
			"Switch multiplex off on the connection, or turn UDP over TCP off if the server does not need it."
	case f.ID == "core.unavailable":
		return "CORE_UNAVAILABLE", "The proxy core is unavailable",
			"This datapath needs the configured sing-box core, but it cannot be run.",
			"Install or repair the configured sing-box core, or choose a native-only datapath."
	case f.ID == "endpoint.external.keenetic_identity":
		return "NATIVE_ADOPTION_INCOMPLETE", "Native Keenetic tunnel needs re-adoption",
			"An enabled native exit predates the captured KeeneticOS ownership and NDM identity required for safe Apply.",
			"Open Diagnostics and use Repair adoption for the affected native tunnel, then review again."
	case f.ID == "endpoint.amneziawg.kernel_switch":
		return "AWG_KERNEL_SWITCH_PENDING", "Connections switch to the AmneziaWG kernel module at their next start",
			"These connections run on amneziawg-go, and the kernel module now carries them.",
			"Nothing is required; they switch the next time they start."
	case f.ID == "endpoint.amneziawg.netifd_restart":
		return "AWG_NETIFD_RESTART_PENDING", "The network service must restart for AmneziaWG",
			"netifd has not read the AmneziaWG handler that was installed or changed.",
			"Restart the network service from the Components page, or reboot the router."
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
	case f.ID == "list.ndm_policy_missing":
		return "NDM_POLICY_MISSING", "Routing list is sent to an access policy the router does not have",
			"An enabled routing list names a KeeneticOS access policy that NDM no longer reports.",
			"Send the list to an existing access policy, or point it at a connection."
	case f.ID == "list.ndm_policy_unsupported":
		return "NDM_POLICY_UNSUPPORTED", "Access policies exist only on KeeneticOS",
			"An enabled routing list is sent to a KeeneticOS access policy on a router that is not running KeeneticOS.",
			"Point the list at a connection or a group."
	case f.ID == "list.ndm_policy_unread":
		return "NDM_POLICY_UNREAD", "The router's access policies could not be read",
			"An enabled routing list is sent to a KeeneticOS access policy, and NDM did not report its policies.",
			"Review again; if it keeps failing, check that NDM answers on this router."
	case f.ID == "core.override":
		return "CORE_OVERRIDE_ACTIVE", "A core override changes the generated config",
			"The core override saved in Settings changes the sing-box config WayHop generates.",
			"Nothing is required. Clear the override in Settings to run the generated config as it is."
	case f.ID == "core.override_open_listener":
		return "CORE_OVERRIDE_OPEN_LISTENER", "The core override listens beyond loopback",
			"The core override makes the core listen on an address other than loopback. Anyone who can reach it can use it: " +
				"an open proxy, or a remote control for the core, on the LAN, and on the WAN wherever the firewall lets it through.",
			"Listen on 127.0.0.1 unless the LAN is meant to use it; then require users on the inbound (or a secret on the Clash API) " +
				"and keep the port closed on the WAN."
	case f.ID == "core.override_daemon_loss":
		return "CORE_OVERRIDE_DAEMON_LOSS", "The core override takes what WayHop runs the core through",
			"The core override removes or changes part of the core that WayHop's own features use.",
			"Add route rules with prepend instead of replacing route.rules, leave experimental.clash_api as WayHop writes it, " +
				"and when the override restates inbounds, restate WayHop's own (probe-in among them) with the new ones."
	case f.ID == "core.override_invalid":
		return "CORE_OVERRIDE_INVALID", "The core override cannot be applied",
			"The core override in config.json is not one WayHop can apply.",
			"Correct the core override in Settings, or clear it."
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
	// a hard privacy failure. The audit reads the DNS plane as the core will be generated for this
	// mode and platform (dnsPlaneTUN): without TUN the generator drops fakeip servers.
	plane := dnsaudit.Plane{TUN: dnsPlaneTUN(in.RoutingMode, platform.Platform(caps.Platform))}
	for _, a := range dnsaudit.DetectAsymmetric(prof, plane) {
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
		// A list on a KeeneticOS access policy: where its traffic leaves is NDM's to know, not WayHop's,
		// so its DNS finding is advice (dnsPathUnsupported), never a refusal (QA-063).
		if _, policy := model.NDMPolicyName(f.Requested); policy && strings.HasPrefix(f.Setting, "dns_path:") {
			f.Blocks = platform.BlocksNothing
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
//
// ndmPolicies are the router's access policies as the review read them (nil when no list uses one), so
// a list sent to a policy that exists is not reported as one the kernel will not carry.
func (s *Server) kernelPlaneFindings(cfg *config.Config, prof *model.Profile, ndmPolicies map[string]uint32) []PlanFinding {
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

	opts := s.pbrCompileOptions(*cfg)
	opts.NDMPolicies = ndmPolicies
	plan, warns, err := pbr.Compile(prof, opts)
	if err != nil {
		return nil
	}
	var shadowed []PlanFinding
	if mode == "hybrid" && !opts.CollectDomainZones {
		shadowed = blockNamesShadowedFindings(prof, plan)
	}
	if len(warns) == 0 {
		return shadowed
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
	return append(out, shadowed...)
}

// blockNamesShadowedFindings names each block list that blocks by NAME while the kernel plane routes
// address ranges in hybrid. Names are matched only in the proxy core, and the kernel takes its lists'
// addresses before the core sees the connection - the TUN excludes them - so a blocked name whose
// address sits in one of those ranges is routed, not blocked, whatever the lists' order. Seen live:
// a messenger listed to block, every one of its addresses inside another list's /20, and its traffic
// left by the tunnel (QA-065). A block the kernel carries is emitted last and wins any overlap, hence the remedy.
func blockNamesShadowedFindings(prof *model.Profile, plan *pbr.Plan) []PlanFinding {
	if plan == nil {
		return nil
	}
	blackhole := map[string]bool{}
	for _, e := range plan.Egresses {
		if e.Kind == pbr.EgressBlackhole {
			blackhole[e.Tag] = true
		}
	}
	kernelRanges := false
	for _, z := range plan.Zones {
		if !blackhole[z.EgressTag] && !z.SrcScoped && len(z.V4)+len(z.V6) > 0 {
			kernelRanges = true
			break
		}
	}
	if !kernelRanges {
		return nil
	}
	var out []PlanFinding
	for i := range prof.RoutingLists {
		rl := &prof.RoutingLists[i]
		if !rl.Enabled || rl.Outbound != model.OutboundBlock {
			continue
		}
		names := rl.DomainSource != "" || len(rl.DomainCache) > 0
		for _, m := range rl.Manual {
			if names = names || entryIsDomain(m); names {
				break
			}
		}
		if !names {
			continue
		}
		out = append(out, PlanFinding{
			ID: "kernel_plane.block_names_shadowed", Setting: "routing list", Item: listName(rl),
			Severity: platform.SeverityDegraded, Reason: platform.ReasonModeConflict, Blocks: platform.BlocksNothing,
			Detail: "This list blocks by name, which only the proxy core can match. In hybrid mode the kernel routes the address ranges of your IP lists before the core sees the connection, so a blocked name whose address falls in one of them is routed, not blocked. The order of the lists does not change this.",
			Remedy: "Add the service's IP ranges to this list as well: a block the kernel carries wins over any route.",
		})
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
