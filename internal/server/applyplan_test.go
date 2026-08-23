package server

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// The plan is what the panel reviews and the only thing Apply is pinned to. These cover what it
// says (verdict, findings, changes) and what it must NOT do (touch the router).

func TestPlanVerdict(t *testing.T) {
	cases := []struct {
		name string
		in   []Finding
		want string
	}{
		{"nothing to say", nil, VerdictReady},
		{"a note", []Finding{{Blocks: platform.BlocksNothing}}, VerdictWarning},
		{"an optimisation", []Finding{{Blocks: platform.BlocksOptimisation}}, VerdictWarning},
		{"a feature that will not work", []Finding{{Blocks: platform.BlocksFeature, AckRequired: true}}, VerdictWarning},
		{"a hard blocker", []Finding{{Blocks: platform.BlocksApply}}, VerdictBlocked},
		{"a blocker among notes", []Finding{{Blocks: platform.BlocksNothing}, {Blocks: platform.BlocksApply}}, VerdictBlocked},
	}
	for _, tc := range cases {
		if got := planVerdict(tc.in); got != tc.want {
			t.Errorf("%s: verdict = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The acknowledgement policy decides what the panel asks the operator to confirm. Getting it wrong
// in either direction is a bug: a tickbox over an impossible Apply, or a whole feature silently not
// working with nothing to notice.
func TestFoldFindings_AckPolicy(t *testing.T) {
	cases := []struct {
		name        string
		in          PlanFinding
		wantAck     bool
		wantBlocks  string
		wantBlocker bool
	}{
		{name: "a hard blocker is never acknowledgeable",
			in:         PlanFinding{ID: "core.unavailable", Severity: platform.SeverityBlocked, Blocks: platform.BlocksApply},
			wantBlocks: platform.BlocksApply, wantBlocker: true},
		{name: "a feature that will not work must be acknowledged",
			in:      PlanFinding{ID: "endpoint.engine.olcrtc", Severity: platform.SeverityBlocked, Blocks: platform.BlocksFeature},
			wantAck: true, wantBlocks: platform.BlocksFeature},
		// A privacy finding is reported, not countersigned. The configuration does exactly what was
		// asked; what it discloses is worth saying and worth seeing, and gating Apply on a checkbox
		// per disclosure asks the operator to sign for something they never requested to change.
		{name: "a privacy trade-off is reported, not acknowledged",
			in:         PlanFinding{ID: "dns_path:encrypted:l1", Setting: "dns_path:encrypted:l1", Severity: platform.SeverityPrivacy, Blocks: platform.BlocksNothing},
			wantBlocks: platform.BlocksNothing},
		{name: "a note is informational",
			in:         PlanFinding{ID: "kernel_plane.fallback", Severity: platform.SeverityDegraded, Blocks: platform.BlocksNothing},
			wantBlocks: platform.BlocksNothing},
		{name: "an optimisation is informational",
			in:         PlanFinding{ID: "offload=hw", Setting: "offload", Severity: platform.SeverityDegraded, Blocks: platform.BlocksOptimisation},
			wantBlocks: platform.BlocksOptimisation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := foldFindings([]PlanFinding{tc.in}, nil)
			if len(got) != 1 {
				t.Fatalf("folded = %+v, want one entry", got)
			}
			f := got[0]
			if f.AckRequired != tc.wantAck {
				t.Errorf("ack_required = %v, want %v (%+v)", f.AckRequired, tc.wantAck, f)
			}
			if f.Blocks != tc.wantBlocks {
				t.Errorf("blocks = %q, want %q", f.Blocks, tc.wantBlocks)
			}
			if f.hard() != tc.wantBlocker {
				t.Errorf("hard() = %v, want %v", f.hard(), tc.wantBlocker)
			}
			if f.Code == "" || f.Title == "" || f.Detail == "" {
				t.Errorf("every finding needs a code, a title and a detail: %+v", f)
			}
		})
	}
}

// One finding per affected object would be a wall of the same sentence. Folding keeps the count an
// operator acts on and names the objects behind it, bounded.
func TestFoldFindings_CollapsesRepeatsAndNamesTheObjects(t *testing.T) {
	var raw []PlanFinding
	for i := 0; i < 60; i++ {
		raw = append(raw, PlanFinding{
			ID: "kernel_plane.dead.routing", Setting: "routing", Item: "list-" + strconv.Itoa(i),
			Severity: platform.SeverityDegraded, Blocks: platform.BlocksFeature,
			Detail: "the kernel plane cannot carry this rule",
		})
	}
	// A repeat of the SAME object must not inflate the items list.
	raw = append(raw, raw[0])
	got := foldFindings(raw, nil)
	if len(got) != 1 {
		t.Fatalf("folded = %d entries, want one", len(got))
	}
	if got[0].Count != 61 {
		t.Errorf("count = %d, want 61 (every occurrence)", got[0].Count)
	}
	if len(got[0].Items) != planFindingItems {
		t.Errorf("items = %d, want them bounded at %d", len(got[0].Items), planFindingItems)
	}
	if got[0].Items[0] != "list-0" {
		t.Errorf("items must name the affected objects, got %v", got[0].Items[:1])
	}
}

// The requested/effective pair is the difference between "this is on" and "this was discarded", so
// it has to reach the operator.
func TestFoldFindings_DetailCarriesRequestedAndEffective(t *testing.T) {
	got := foldFindings([]PlanFinding{{
		ID: "offload=hw", Setting: "offload", Requested: "hw", Effective: "degraded",
		Severity: platform.SeverityDegraded, Blocks: platform.BlocksOptimisation,
	}}, nil)
	if len(got) != 1 || !strings.Contains(got[0].Detail, "Requested: hw; effective: degraded") {
		t.Fatalf("detail = %q, want the requested/effective pair", got[0].Detail)
	}
}

// Blockers first, then what needs acknowledging, then the notes: the panel renders in this order and
// the operator reads the top first.
func TestFoldFindings_Order(t *testing.T) {
	got := foldFindings([]PlanFinding{
		{ID: "kernel_plane.fallback", Severity: platform.SeverityDegraded, Blocks: platform.BlocksNothing},
		{ID: "endpoint.engine.olcrtc", Severity: platform.SeverityBlocked, Blocks: platform.BlocksFeature},
		{ID: "core.unavailable", Severity: platform.SeverityBlocked, Blocks: platform.BlocksApply},
	}, nil)
	var ids []string
	for _, f := range got {
		ids = append(ids, f.ID)
	}
	want := []string{"core.unavailable", "endpoint.engine.olcrtc", "kernel_plane.fallback"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v, want %v", ids, want)
	}
}

func TestFoldFindings_AckedReflectsThePersistedRecord(t *testing.T) {
	s := applystate_server(t)
	raw := []PlanFinding{{ID: "endpoint.engine.olcrtc", Severity: platform.SeverityBlocked, Blocks: platform.BlocksFeature}}
	if got := foldFindings(raw, s.isAcked); got[0].Acked {
		t.Error("nothing has been acknowledged yet")
	}
	s.setAcks([]string{"endpoint.engine.olcrtc"}, true)
	if got := foldFindings(raw, s.isAcked); !got[0].Acked {
		t.Error("a persisted acknowledgement must show in the plan")
	}
	// Undo: the panel can un-tick it.
	s.setAcks([]string{"endpoint.engine.olcrtc"}, false)
	if got := foldFindings(raw, s.isAcked); got[0].Acked {
		t.Error("an acknowledgement must be revocable")
	}
	// A hard blocker is never reported as acknowledged, whatever the record says.
	s.setAcks([]string{"core.unavailable"}, true)
	blocker := []PlanFinding{{ID: "core.unavailable", Severity: platform.SeverityBlocked, Blocks: platform.BlocksApply}}
	if got := foldFindings(blocker, s.isAcked); got[0].Acked || got[0].AckRequired {
		t.Errorf("a hard blocker must never read as acknowledged: %+v", got[0])
	}
}

func TestBuildPlan_PendingAndNothingConfigured(t *testing.T) {
	s, _ := applytest_server(t)

	// An empty install asks for no datapath: not pending, and the panel says so rather than
	// greeting a fresh router with "unapplied changes".
	plan, err := s.buildPlan(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Pending || !plan.NothingConfigured {
		t.Errorf("empty install: pending=%v nothing_configured=%v", plan.Pending, plan.NothingConfigured)
	}
	if plan.Verdict != VerdictReady || plan.Rev == "" {
		t.Errorf("empty install: verdict=%q rev=%q", plan.Verdict, plan.Rev)
	}
	if plan.Changes.BaselineAvailable || plan.Changes.Reason == "" {
		t.Errorf("with nothing applied the change set must say there is no baseline: %+v", plan.Changes)
	}
	if plan.Changes.Changes == nil {
		t.Error("changes must be an array, never null")
	}

	// Configure something: pending, still nothing applied.
	apply_seedVLESS(t, s)
	plan, err = s.buildPlan(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Pending || plan.NothingConfigured || plan.AppliedRev != "" {
		t.Errorf("configured but unapplied: %+v", plan)
	}

	// Apply, then edit: the change set diffs against what was applied.
	if _, aerr := s.runApply(context.Background(), applyRequest{Save: true}); aerr != nil {
		t.Fatalf("apply: %v", aerr.body())
	}
	applied := s.committedRevision()
	if err := s.store.UpsertEndpoint(profilehandlers_endpoint("v2", "DE")); err != nil {
		t.Fatal(err)
	}
	plan, err = s.buildPlan(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Pending || plan.AppliedRev != applied.Rev || plan.AppliedAt == 0 {
		t.Errorf("after an edit: pending=%v applied_rev=%q", plan.Pending, plan.AppliedRev)
	}
	if !plan.Changes.BaselineAvailable || plan.Changes.Count == 0 || plan.Changes.BaselineRev != applied.Rev {
		t.Fatalf("changes = %+v, want a real diff against the applied baseline", plan.Changes)
	}
	if len(plan.Changes.BySubsystem) == 0 {
		t.Error("the panel groups changes by subsystem")
	}
}

func TestBuildPlan_BlockedAndWarningVerdicts(t *testing.T) {
	s, _ := applytest_server(t)
	apply_seedVLESS(t, s)

	// A router that cannot carry the protocol blocks the Apply.
	s.caps.set = applytest_caps([]string{platform.CapProtocolPrefix + "vless"})
	plan, err := s.buildPlan(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Verdict != VerdictBlocked {
		t.Fatalf("verdict = %q, want blocked (%+v)", plan.Verdict, plan.Findings)
	}
	blockers := plan.blockers()
	if len(blockers) != 1 || blockers[0].ID != "endpoint.protocol.vless" {
		t.Fatalf("blockers = %+v", blockers)
	}
	if len(blockers[0].Items) != 1 || blockers[0].Items[0] != "NL" {
		t.Errorf("a blocker must name the affected connection, got items %v", blockers[0].Items)
	}
	if blockers[0].Remedy == "" {
		t.Error("a blocker must carry a remedy")
	}

	// A shadowed rule is a note: the configuration applies exactly as written.
	s.caps.set = applytest_caps(nil)
	dup := model.Rule{ID: "r1", Domain: []string{"example.com"}, Outbound: "v1"}
	if err := s.store.UpsertRule(dup); err != nil {
		t.Fatal(err)
	}
	dup.ID = "r2"
	if err := s.store.UpsertRule(dup); err != nil {
		t.Fatal(err)
	}
	plan, err = s.buildPlan(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Verdict != VerdictWarning {
		t.Fatalf("verdict = %q, want warning (%+v)", plan.Verdict, plan.Findings)
	}
	var shadowed *Finding
	for i := range plan.Findings {
		if strings.HasPrefix(plan.Findings[i].ID, "shadowed.route.") {
			shadowed = &plan.Findings[i]
		}
	}
	if shadowed == nil {
		t.Fatalf("the dead rule must be reported: %+v", plan.Findings)
	}
	if shadowed.hard() || shadowed.AckRequired {
		t.Errorf("a dead rule informs, it does not refuse: %+v", shadowed)
	}
	if len(plan.blockers()) != 0 || len(plan.unacked()) != 0 {
		t.Error("a warning verdict must not refuse an Apply")
	}
}

// The plan is opened on every panel visit, so it must stay cheap: no `sing-box check`, no binary
// hashing, no NDM running-config read.
func TestBuildPlan_TouchesNothingExpensive(t *testing.T) {
	s, fake := applytest_server(t)
	apply_seedVLESS(t, s)
	hostProbes, ndmReads := 0, 0
	s.hostProbeOf = func(_ context.Context, desired DesiredSnapshot) (hostProbeV1, error) {
		hostProbes++
		return applytest_hostProbe(desired, platform.Unknown), nil
	}
	s.keeneticConfigReader = func(context.Context) (string, error) {
		ndmReads++
		return exactKeeneticBaselineConfig, nil
	}

	for i := 0; i < 3; i++ {
		if _, err := s.buildPlan(context.Background(), false); err != nil {
			t.Fatal(err)
		}
	}
	if got := fake.snapshot(); len(got) != 0 {
		t.Errorf("the plan called router adapters: %v", got)
	}
	if hostProbes != 0 {
		t.Errorf("the plan ran the host probe %d time(s) — it hashes the core binary", hostProbes)
	}
	if ndmReads != 0 {
		t.Errorf("the plan read the NDM running config %d time(s)", ndmReads)
	}

	// An Apply, by contrast, captures the host exactly once.
	if _, aerr := s.runApply(context.Background(), applyRequest{Save: true}); aerr != nil {
		t.Fatalf("apply: %v", aerr.body())
	}
	if hostProbes != 1 {
		t.Errorf("an Apply must capture the host exactly once, got %d", hostProbes)
	}
}

// The window and platform blocks are what the panel writes its copy from.
func TestBuildPlan_WindowAndPlatform(t *testing.T) {
	s, _ := applytest_server(t)
	apply_seedVLESS(t, s)
	plan, err := s.buildPlan(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Window.Open {
		t.Error("no window is open before any Apply")
	}
	if plan.Platform.Name == "" {
		t.Error("the platform must be named")
	}
	if plan.Probe.At.IsZero() {
		t.Error("the capability probe telemetry must be reported")
	}
	if _, aerr := s.runApply(context.Background(), applyRequest{}); aerr != nil {
		t.Fatalf("apply: %v", aerr.body())
	}
	plan, err = s.buildPlan(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Window.Open || plan.Window.Phase != "armed" || plan.Window.SecondsLeft <= 0 {
		t.Errorf("window = %+v, want the armed Test window with a countdown", plan.Window)
	}
}
