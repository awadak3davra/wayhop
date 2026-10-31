package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"wayhop/internal/keenetic"
	"wayhop/internal/model"
	"wayhop/internal/nativeplan"
)

// QA-108. A second Apply of a profile whose native KeeneticOS connection did not change must leave
// that connection on the NDM interface the first Apply created. The capture reads every `interface
// WireguardN` block of the running config as occupied, WayHop's own included, and Compile used to
// allocate past all of them: the unchanged endpoint moved from Wireguard10 to Wireguard11 and the
// reconcile removed the live Wireguard10, so every Apply re-created every native tunnel (handshake,
// dropped flows, and whatever the operator had attached to the interface in KeeneticOS went with
// the `no interface`).
func TestKeeneticReapplyKeepsTheNativeSlot(t *testing.T) {
	desired, host, capture := keeneticUserspaceTuple(t)
	first, _, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host}, native: &capture})
	if err != nil {
		t.Fatalf("first materialize: %v", err)
	}
	t1 := first.Native.Delta.Reconcile.Target
	slot1 := t1.Keenetic.IfaceFor["native"]
	if !strings.HasPrefix(slot1, "Wireguard") {
		t.Fatalf("the first Apply did not create a native interface for the endpoint: %q", slot1)
	}
	// The running config NDM prints after the first Apply: its block, and the WAN.
	var rc strings.Builder
	for _, block := range t1.Keenetic.Interfaces {
		rc.WriteString(block[0] + "\n")
		for _, line := range block[1:] {
			rc.WriteString("    " + line + "\n")
		}
		rc.WriteString("!\n")
	}
	rc.WriteString("interface ISP\n    ip global 1000\n!\n")
	second, err := captureExecutionNativeFrom(context.Background(), desired, ExecutionHostFactsV1{Host: host}, nil,
		func(context.Context) (string, error) { return rc.String(), nil })
	if err != nil {
		t.Fatalf("second capture: %v", err)
	}
	if !second.OccupiedInterfaces[slot1] {
		t.Fatalf("the capture no longer sees the live %s as occupied; this test lost its trigger", slot1)
	}
	m2, _, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host}, native: &second, previous: &first})
	if err != nil {
		t.Fatalf("second materialize: %v", err)
	}
	rec := m2.Native.Delta.Reconcile
	slot2 := rec.Target.Keenetic.IfaceFor["native"]
	if slot1 != slot2 {
		t.Errorf("unchanged endpoint moved from %s to %s", slot1, slot2)
	}
	for _, c := range rec.KeeneticTeardown {
		if c == "no interface "+slot1 {
			t.Errorf("second Apply of an unchanged profile tears down the live %s", slot1)
		}
	}
	// The kept block is the one already running, so prepare has nothing to send for it, and the
	// plan says it is kept, which is what spares it on a failed Apply.
	if kept := rec.Target.Keenetic.KeptInterfaces; len(kept) != 1 || kept[0] != slot1 {
		t.Errorf("kept interfaces = %v, want [%s]", kept, slot1)
	}
	for _, block := range rec.Target.Keenetic.Interfaces {
		if !verifyExactKeeneticInterfaceBlock(block, rc.String(), true) {
			t.Errorf("the kept interface block differs from the live one:\n%v", block)
		}
	}
}

// keeneticslot_applied runs a complete first Apply of the tuple through the stand-in NDM.
func keeneticslot_applied(t *testing.T, desired DesiredSnapshot, host HostSnapshotV1, capture executionNativeCaptureV1) (executionMaterializationV1, *fakeNDM) {
	t.Helper()
	first, _, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host}, native: &capture})
	if err != nil {
		t.Fatalf("first materialize: %v", err)
	}
	ndm := newFakeNDM()
	adapter := ndm.adapter()
	reconcile := first.Native.Delta.Reconcile
	if err := adapter.prepare(context.Background(), *reconcile.Target); err != nil {
		t.Fatalf("first prepare: %v", err)
	}
	if err := adapter.commit(context.Background(), reconcile); err != nil {
		t.Fatalf("first commit: %v", err)
	}
	if err := adapter.persist(context.Background(), reconcile); err != nil {
		t.Fatalf("first persist: %v", err)
	}
	return first, ndm
}

// keeneticslot_next materializes the next Apply against what the stand-in NDM prints now.
func keeneticslot_next(t *testing.T, desired DesiredSnapshot, host HostSnapshotV1, first executionMaterializationV1, ndm *fakeNDM) nativeplan.Reconciliation {
	t.Helper()
	capture, err := captureExecutionNativeFrom(context.Background(), desired, ExecutionHostFactsV1{Host: host}, nil,
		func(context.Context) (string, error) { return ndm.render(), nil })
	if err != nil {
		t.Fatalf("capture: %v", err)
	}
	next, _, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host}, native: &capture, previous: &first})
	if err != nil {
		t.Fatalf("next materialize: %v", err)
	}
	reconcile := next.Native.Delta.Reconcile
	slot := first.Native.Delta.Reconcile.Target.Keenetic.IfaceFor["native"]
	if kept := reconcile.Target.Keenetic.KeptInterfaces; len(kept) != 1 || kept[0] != slot {
		t.Fatalf("the next Apply does not keep %s: kept %v", slot, kept)
	}
	return reconcile
}

func keeneticslot_insertBefore(anchor, line string) func([]string) []string {
	return func(lines []string) []string {
		for i, existing := range lines {
			if existing == anchor {
				return append(lines[:i], append([]string{line}, lines[i:]...)...)
			}
		}
		return append(lines, line)
	}
}

// The reviewer's case. The live interface differs from its block only by a line the operator added
// in KeeneticOS (an access group, printed between `ip global` and `ip tcp`). prepare used to find no
// exact run of the block's lines, re-send the block, file it under `attempted`, fail the verification
// (NDM keeps the added line where it is) and answer with `no interface`: the tunnel the previous
// Apply created was deleted by an Apply that changed nothing about it.
func TestKeeneticKeptSlotWithAnOperatorLineSurvivesPrepare(t *testing.T) {
	desired, host, capture := keeneticUserspaceTuple(t)
	first, ndm := keeneticslot_applied(t, desired, host, capture)
	slot := first.Native.Delta.Reconcile.Target.Keenetic.IfaceFor["native"]
	accessGroup := "ip access-group _WEBADMIN_" + slot + " in"
	ndm.edit(slot, keeneticslot_insertBefore("ip tcp adjust-mss pmtu", accessGroup))
	reconcile := keeneticslot_next(t, desired, host, first, ndm)

	before := len(ndm.calls)
	if err := ndm.adapter().prepare(context.Background(), *reconcile.Target); err != nil {
		t.Errorf("prepare failed: %v", err)
	}
	if !ndm.has(slot) {
		t.Fatalf("prepare deleted the live %s the previous Apply created", slot)
	}
	if sent := ndm.calls[before:]; len(sent) != 0 {
		t.Errorf("prepare sent %d command(s) for an interface that was already live", len(sent))
	}
	if !strings.Contains(ndm.render(), accessGroup) {
		t.Error("the operator's access group is gone")
	}
}

// Re-sending a kept block also re-sent its `ip global`, the priority the interface was created with,
// over the higher one the ladder had given it: the default route left the tunnel for the WAN until
// commit raised it again, or for good if anything failed in between. A kept block is not re-sent at
// all, and commit only moves the ladder.
func TestKeeneticKeptSlotIsNotResentAndKeepsTheDefaultRoute(t *testing.T) {
	desired, host, capture := keeneticCreateTuple(t, []model.Rule{{ID: "default", Default: true, Outbound: "native"}})
	first, ndm := keeneticslot_applied(t, desired, host, capture)
	slot := first.Native.Delta.Reconcile.Target.Keenetic.IfaceFor["native"]
	raised := keenetic.GlobalPriorities(ndm.render())[slot]
	if raised <= 1000 {
		t.Fatalf("%s reads ip global %d after the first Apply; this test lost its trigger", slot, raised)
	}
	reconcile := keeneticslot_next(t, desired, host, first, ndm)
	block := reconcile.Target.Keenetic.Interfaces[0]

	adapter := ndm.adapter()
	before := len(ndm.calls)
	if err := adapter.prepare(context.Background(), *reconcile.Target); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if sent := ndm.calls[before:]; len(sent) != 0 {
		t.Fatalf("prepare re-sent the kept block: %d command(s)", len(sent))
	}
	if got := keenetic.GlobalPriorities(ndm.render())[slot]; got != raised {
		t.Fatalf("%s reads ip global %d after prepare, want the ladder's %d", slot, got, raised)
	}
	if err := adapter.commit(context.Background(), reconcile); err != nil {
		t.Fatalf("commit: %v", err)
	}
	for _, call := range ndm.calls[before:] {
		for _, line := range block[1:] {
			if !strings.HasPrefix(line, "ip global ") && call == block[0]+" "+line {
				t.Errorf("commit re-sent the kept block's %q", strings.Fields(line)[0])
			}
		}
	}
	if err := adapter.postcheck(context.Background(), *reconcile.Target, reconcile.KeeneticTeardown, reconcile.KeeneticPriorityRestore); err != nil {
		t.Fatalf("postcheck: %v", err)
	}
	if got, want := keenetic.GlobalPriorities(ndm.render())[slot], reconcile.Target.Keenetic.GlobalPriority[slot]; got != want {
		t.Errorf("%s reads ip global %d after commit, want %d", slot, got, want)
	}
}

// Commit, abort and persist each answer a failure by removing the target. A kept interface is not
// the target's to remove: the Apply did not create it and the baseline it falls back to has it.
func TestKeeneticFailedApplyDoesNotRemoveTheKeptSlot(t *testing.T) {
	desired, host, capture := keeneticCreateTuple(t, nil)
	first, ndm := keeneticslot_applied(t, desired, host, capture)
	slot := first.Native.Delta.Reconcile.Target.Keenetic.IfaceFor["native"]
	reconcile := keeneticslot_next(t, desired, host, first, ndm)
	target := *reconcile.Target
	adapter := ndm.adapter()
	removed := func(from int) bool {
		for _, call := range ndm.calls[from:] {
			if call == "no interface "+slot {
				return true
			}
		}
		return !ndm.has(slot)
	}

	if err := adapter.prepare(context.Background(), target); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	before := len(ndm.calls)
	ndm.refuse = func(line string) bool { return strings.HasPrefix(line, "ip route ") }
	if err := adapter.commit(context.Background(), reconcile); err == nil {
		t.Fatal("commit succeeded with every route refused")
	}
	if removed(before) {
		t.Errorf("a failed commit removed the kept %s", slot)
	}
	ndm.refuse = nil

	before = len(ndm.calls)
	if err := adapter.abort(context.Background(), target); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if removed(before) {
		t.Errorf("abort removed the kept %s", slot)
	}

	if err := adapter.commit(context.Background(), reconcile); err != nil {
		t.Fatalf("commit: %v", err)
	}
	ndm.routes = nil // something else took the routes away between postcheck and persist
	before = len(ndm.calls)
	if err := adapter.persist(context.Background(), reconcile); err == nil {
		t.Fatal("persist saved a configuration that no longer verifies")
	}
	if removed(before) {
		t.Errorf("persist's drift refusal removed the kept %s", slot)
	}
}

// keeneticslot_changes are the two ways an operator changes a WayHop-created interface in the
// KeeneticOS web UI: a setting the running config prints, and a regenerated private key, which it
// does not print and which only the public key in `show interface` gives away.
var keeneticslot_changes = map[string]func(lines []string) []string{
	"a setting": func(lines []string) []string {
		for i, line := range lines {
			if strings.HasPrefix(line, "description ") {
				lines[i] = "description renamed-in-keeneticos"
			}
		}
		return lines
	},
	"the key": func(lines []string) []string {
		for i, line := range lines {
			if strings.HasPrefix(line, "wireguard private-key ") {
				lines[i] = "wireguard private-key " + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
			}
		}
		return lines
	},
}

// A kept interface someone changed outside WayHop is never rewritten (that is an in-place update the
// adapter has no authority for) nor deleted. In an Apply prepare stops, names it, and touches nothing
// - not even the new tunnel the same Apply adds - and says that nothing was touched, so the Apply is
// not answered with a rollback that would refuse the same way. At boot or in a rollback nobody reads
// that refusal and the whole datapath would stay down, so the interface is left as it is, reported,
// and everything else goes ahead.
func TestKeeneticChangedKeptSlotIsNeverRewritten(t *testing.T) {
	for change, edit := range keeneticslot_changes {
		for _, strict := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s, apply=%v", change, strict), func(t *testing.T) {
				desired, host, capture := keeneticCreateTuple(t, nil)
				first, ndm := keeneticslot_applied(t, desired, host, capture)
				slot := first.Native.Delta.Reconcile.Target.Keenetic.IfaceFor["native"]
				ndm.edit(slot, edit)
				edited := slices.Clone(ndm.ifaces[slot].lines)
				second := executionAWGEndpoint("second")
				second.Server = "198.51.100.21"
				desired2, host2, _ := keeneticCreateTuple(t, nil, second)
				reconcile := keeneticslot_next(t, desired2, host2, first, ndm)
				added := reconcile.Target.Keenetic.IfaceFor["second"]
				if added == "" || added == slot || len(reconcile.Target.Keenetic.Interfaces) != 2 {
					t.Fatalf("the second Apply does not add a tunnel of its own: %v", reconcile.Target.Keenetic.IfaceFor)
				}
				adapter := ndm.adapter()
				var reported [][]string
				adapter.reportLeft = func(ifaces []string) { reported = append(reported, ifaces) }
				ctx := context.Background()
				if strict {
					ctx = withStrictNativePrepare(ctx)
				}
				before := len(ndm.calls)
				err := adapter.prepare(ctx, *reconcile.Target)
				if len(reported) != 1 || !slices.Equal(reported[0], []string{slot}) {
					t.Errorf("reported %v, want [[%s]]", reported, slot)
				}
				if strict {
					var untouched *applyStepUntouchedError
					if !errors.Is(err, errExactKeeneticApply) || !errors.As(err, &untouched) || !strings.Contains(err.Error(), slot) {
						t.Fatalf("prepare error = %v, want an untouched refusal naming %s", err, slot)
					}
					if sent := ndm.calls[before:]; len(sent) != 0 || ndm.has(added) {
						t.Fatalf("a refusing prepare sent %d command(s); %s created %v", len(sent), added, ndm.has(added))
					}
				} else {
					if err != nil {
						t.Fatalf("prepare at boot/rollback = %v, want the rest brought up", err)
					}
					if !ndm.has(added) {
						t.Fatalf("%s was not created next to the changed %s", added, slot)
					}
					if err := adapter.commit(ctx, reconcile); err != nil {
						t.Fatalf("commit: %v", err)
					}
					if err := adapter.postcheck(ctx, *reconcile.Target, reconcile.KeeneticTeardown, reconcile.KeeneticPriorityRestore); err != nil {
						t.Fatalf("postcheck: %v", err)
					}
				}
				for _, call := range ndm.calls[before:] {
					if strings.HasPrefix(call, "interface "+slot+" ") || call == "no interface "+slot {
						t.Errorf("the changed %s was written to: %q", slot, strings.Fields(call)[:3])
					}
				}
				if !ndm.has(slot) || !slices.Equal(ndm.ifaces[slot].lines, edited) {
					t.Errorf("the changed %s is not as the operator left it", slot)
				}
			})
		}
	}
}

// The running config never prints a private key, so a key NDM accepted and ignored would leave an
// interface that matches its block line for line. Its public key gives it away, and the interface
// prepare just created is removed again.
func TestKeeneticCreatedTunnelIsHeldToItsKey(t *testing.T) {
	desired, host, capture := keeneticCreateTuple(t, nil)
	m, _, err := materialize(materializeInput{desired: desired, host: ExecutionHostFactsV1{Host: host}, native: &capture})
	if err != nil {
		t.Fatal(err)
	}
	target := *m.Native.Delta.Reconcile.Target
	slot := target.Keenetic.IfaceFor["native"]
	ndm := newFakeNDM()
	ndm.ignore = func(line string) bool { return strings.Contains(line, " wireguard private-key ") }
	if err := ndm.adapter().prepare(context.Background(), target); !errors.Is(err, errExactKeeneticApply) {
		t.Fatalf("prepare = %v, want a failure: the key never landed", err)
	}
	if ndm.has(slot) {
		t.Errorf("the half-created %s was left behind", slot)
	}
}

// A refusal that changed nothing is not a mutation, so the Apply is not rolled back: the rollback
// would re-run the previous plan into the same changed interface, refuse the same way, and report
// "could NOT be fully restored" for a router nothing had touched. Any other prepare failure still is.
func TestRunApply_UntouchedNativeRefusalIsNotRolledBack(t *testing.T) {
	for name, prepareErr := range map[string]error{
		"nothing touched":  &applyStepUntouchedError{err: errExactKeeneticApply},
		"after a mutation": errExactKeeneticApply,
	} {
		t.Run(name, func(t *testing.T) {
			s, fake := applytest_server(t)
			applytest_keenetic(s)
			if err := s.store.UpsertEndpoint(applytest_wireguardEndpoint("wg1")); err != nil {
				t.Fatal(err)
			}
			if _, aerr := s.runApply(context.Background(), applyRequest{Save: true}); aerr != nil {
				t.Fatalf("first apply: %v", aerr.body())
			}
			fake.reset()
			fake.prepareNativeErr = prepareErr // the rollback's prepare meets it again, as on the router
			_, aerr := s.runApply(context.Background(), applyRequest{Save: true})
			if aerr == nil || aerr.Stage != stepNativePrepare {
				t.Fatalf("got %+v, want a native_prepare failure", aerr)
			}
			untouched := name == "nothing touched"
			prepares := strings.Count(strings.Join(fake.snapshot(), ","), "prepareNative")
			if untouched {
				if prepares != 1 || strings.Contains(aerr.Message, "restored") {
					t.Errorf("ops = %v, message %q: want no rollback and no restore claimed", fake.snapshot(), aerr.Message)
				}
				return
			}
			// The reviewer's case before the mark existed: rolled back into the same refusal.
			if prepares != 2 || !strings.Contains(aerr.Message, "could NOT be fully restored") {
				t.Errorf("ops = %v, message %q: want the rollback, refused again", fake.snapshot(), aerr.Message)
			}
		})
	}
}

// Boot and a rollback re-run a plan whose interfaces may already be on the router (NDM re-creates
// saved ones before Entware starts). prepare finds them live and does not create them, so none of
// that transaction's cleanups may remove them, kept slot or not.
func TestKeeneticReplayDoesNotRemoveInterfacesPrepareFoundLive(t *testing.T) {
	desired, host, capture := keeneticCreateTuple(t, nil)
	first, ndm := keeneticslot_applied(t, desired, host, capture)
	reconcile := first.Native.Delta.Reconcile
	target := *reconcile.Target
	slot := target.Keenetic.IfaceFor["native"]
	if len(target.Keenetic.KeptInterfaces) != 0 {
		t.Fatal("the first plan keeps a slot; this test lost its trigger")
	}
	adapter := ndm.adapter() // a new transaction over the same router, as at boot
	before := len(ndm.calls)
	if err := adapter.prepare(context.Background(), target); err != nil || len(ndm.calls) != before {
		t.Fatalf("replayed prepare = %v after %d command(s); want nothing sent", err, len(ndm.calls)-before)
	}
	ndm.refuse = func(line string) bool { return strings.HasPrefix(line, "ip route ") }
	if err := adapter.commit(context.Background(), reconcile); err == nil {
		t.Fatal("commit succeeded with every route refused")
	}
	ndm.refuse = nil
	if !ndm.has(slot) {
		t.Fatalf("a failed replayed commit removed %s, which it found live", slot)
	}
	if err := adapter.abort(context.Background(), target); err != nil || !ndm.has(slot) {
		t.Fatalf("abort = %v, %s still there %v", err, slot, ndm.has(slot))
	}
	// persist's drift refusal is the third one: the routes vanish between postcheck and the save.
	if err := adapter.commit(context.Background(), reconcile); err != nil {
		t.Fatalf("commit: %v", err)
	}
	ndm.routes = nil
	if err := adapter.persist(context.Background(), reconcile); err == nil || !ndm.has(slot) {
		t.Fatalf("persist = %v, %s still there %v; want a refused save that leaves it", err, slot, ndm.has(slot))
	}
	// Without that transaction's prepare nothing says the interface was found live, and abort removes
	// what the plan created, as it always has.
	if err := ndm.adapter().abort(context.Background(), target); err != nil || ndm.has(slot) {
		t.Fatalf("abort in a transaction that found nothing = %v, %s still there %v", err, slot, ndm.has(slot))
	}
}

func TestExactKeeneticRemovableSparesKeptAndFoundInterfaces(t *testing.T) {
	plan := &keenetic.Plan{
		Interfaces: [][]string{
			{"interface Wireguard10", "up"}, {"interface Wireguard11", "up"}, {"interface Wireguard12", "up"},
		},
		KeptInterfaces: []string{"Wireguard10"},
		Routes:         []string{"ip route 203.0.113.0 255.255.255.0 Wireguard10 auto"},
	}
	got := keenetic.TeardownCommands(exactKeeneticRemovable(plan, map[string]bool{"interface Wireguard12": true}))
	want := []string{"no ip route 203.0.113.0 255.255.255.0 Wireguard10", "no interface Wireguard11"}
	if !slices.Equal(got, want) {
		t.Fatalf("removable teardown = %q, want %q", got, want)
	}
	if len(plan.Interfaces) != 3 {
		t.Fatal("the plan itself was modified")
	}
}

// A cleanup puts back the ladder only on interfaces it leaves standing. One it removes would get a
// write first, and for an interface the Apply created that write is `ip global 0`.
func TestExactKeeneticCleanupRestoresOnlyInterfacesItKeeps(t *testing.T) {
	runner := &exactKeeneticRecordRunner{}
	adapter, _ := newExactKeeneticNativeAdapter(runner)
	plan := &keenetic.Plan{
		Interfaces:        [][]string{{"interface Wireguard11", "up"}},
		GlobalPriorityWas: map[string]int{"Wireguard11": 0, "Wireguard3": 5461},
	}
	if err := adapter.cleanup(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"interface Wireguard3", "ip global 5461"}, {"no interface Wireguard11"}}
	if !slices.EqualFunc(runner.batches, want, slices.Equal[[]string]) {
		t.Fatalf("cleanup batches = %q, want %q", runner.batches, want)
	}
}

// Every cleanup spares a kept interface, so the list may only name the plan's own blocks, once.
func TestValidExactKeeneticTargetBoundsKeptInterfaces(t *testing.T) {
	for name, kept := range map[string][]string{
		"own block":       {"Wireguard10"},
		"not a block":     {"Wireguard3"},
		"named twice":     {"Wireguard10", "Wireguard10"},
		"the WAN instead": {"ISP"},
	} {
		target := exactKeeneticTestTarget()
		target.Keenetic.KeptInterfaces = kept
		if got, want := validExactKeeneticTarget(target), name == "own block"; got != want {
			t.Errorf("%s: valid = %v, want %v", name, got, want)
		}
	}
}

// keeneticslot_server is a Server whose native plane is the real Keenetic adapter over the stand-in
// router (the other planes are the recording fakes), with one WayHop-created tunnel Applied and
// saved. It returns that tunnel's interface.
func keeneticslot_server(t *testing.T) (*Server, *applytest_ops, *fakeNDM, string) {
	t.Helper()
	s, fake := applytest_server(t)
	applytest_keenetic(s)
	ndm := newFakeNDM()
	// The capture before an Apply reads the router directly; only the adapter's own reads fail on demand.
	s.keeneticConfigReader = func(context.Context) (string, error) { return ndm.render(), nil }
	s.keeneticInterfacesReader = ndm.readInterfaces
	adapter := ndm.adapter()
	adapter.reportLeft = s.noteKeeneticLeftAsIs
	native, _ := newExactNativePlatformAdapter(nil, adapter)
	ops := fake.ops()
	ops.prepareNative, ops.commitNative, ops.abortNative = native.prepare, native.commit, native.abort
	ops.persistNative, ops.postcheckNative = native.persist, native.postcheck
	s.execOps = &ops
	if err := s.store.UpsertEndpoint(applytest_wireguardEndpoint("wg1")); err != nil {
		t.Fatal(err)
	}
	if _, aerr := s.runApply(context.Background(), applyRequest{Save: true}); aerr != nil {
		t.Fatalf("apply: %v", aerr.body())
	}
	committed := s.committedRevision()
	slot := committed.Materialization.nativeTarget().Keenetic.IfaceFor["wg1"]
	if !ndm.has(slot) {
		t.Fatalf("the Apply did not create the tunnel: %v", committed.Materialization.nativeTarget().Keenetic.IfaceFor)
	}
	fake.reset()
	return s, fake, ndm, slot
}

// Boot re-runs the committed configuration and stopped at its first step on such an interface:
// sing-box never started (the scheduled restart only restarts a running core) and the only trace
// was a log line. It now converges around it. The Diagnostics row looks at the router when it runs:
// it named the change before boot found it and stops naming it once the operator undoes it.
func TestKeeneticBootConvergesAroundAChangedTunnelAndReportsIt(t *testing.T) {
	s, fake, ndm, slot := keeneticslot_server(t)
	if row := s.keeneticLeftAsIsCheck(context.Background()); row.Status != "pass" {
		t.Fatalf("after a clean Apply the row reads %s: %s", row.Status, row.Summary)
	}
	original := slices.Clone(ndm.ifaces[slot].lines)
	ndm.edit(slot, keeneticslot_changes["a setting"])
	if row := s.keeneticLeftAsIsCheck(context.Background()); row.Status != "warn" || !strings.Contains(row.Summary, slot) || row.Fix == "" {
		t.Errorf("Diagnostics row = %+v, want a warning naming %s", row, slot)
	}

	if err := s.converge(context.Background(), s.committedRevision()); err != nil {
		t.Fatalf("boot converge stopped on the changed tunnel: %v", err)
	}
	if got := fake.snapshot(); len(got) == 0 {
		t.Error("nothing after the native step ran")
	}
	if !ndm.has(slot) {
		t.Fatalf("boot removed the changed %s", slot)
	}
	ndm.ifaces[slot].lines = original
	if row := s.keeneticLeftAsIsCheck(context.Background()); row.Status != "pass" {
		t.Errorf("the change was undone and the row still reads %s: %s", row.Status, row.Summary)
	}
}

// The forward run of an Apply is where a changed tunnel stops everything (withStrictNativePrepare):
// nothing is sent, nothing after the native step runs, nothing is rolled back.
func TestRunApply_RefusesAChangedTunnelBeforeChangingAnything(t *testing.T) {
	s, fake, ndm, slot := keeneticslot_server(t)
	ndm.edit(slot, keeneticslot_changes["the key"])
	edited := slices.Clone(ndm.ifaces[slot].lines)
	before := len(ndm.calls)
	_, aerr := s.runApply(context.Background(), applyRequest{Save: true})
	if aerr == nil || aerr.Stage != stepNativePrepare || !strings.Contains(aerr.Detail, slot) {
		t.Fatalf("got %+v, want a native_prepare refusal naming %s", aerr, slot)
	}
	if strings.Contains(aerr.Message, "restored") {
		t.Errorf("message %q claims a restore for a router nothing touched", aerr.Message)
	}
	if sent := ndm.calls[before:]; len(sent) != 0 || len(fake.snapshot()) != 0 || !slices.Equal(ndm.ifaces[slot].lines, edited) {
		t.Errorf("the refused Apply ran %d router command(s) and steps %v", len(sent), fake.snapshot())
	}
}

// A router that cannot be read cannot be vouched for, and nothing has been sent yet: an Apply stops
// without a rollback (which would meet the same router and report a restore that failed). Outside an
// Apply an unreadable interface list leaves a key unverified, not the datapath down.
func TestKeeneticUnreadableRouterIsNotAChange(t *testing.T) {
	for name, fail := range map[string]func(*fakeNDM){
		"running config": func(ndm *fakeNDM) { ndm.unreadableConfig = true },
		"interface list": func(ndm *fakeNDM) { ndm.unreadableListing = true },
	} {
		t.Run(name, func(t *testing.T) {
			s, fake, ndm, _ := keeneticslot_server(t)
			fail(ndm)
			before := len(ndm.calls)
			_, aerr := s.runApply(context.Background(), applyRequest{Save: true})
			if aerr == nil || aerr.Stage != stepNativePrepare {
				t.Fatalf("got %+v, want a native_prepare failure", aerr)
			}
			if strings.Contains(aerr.Message, "restored") || (aerr.RolledBack != nil && *aerr.RolledBack) {
				t.Errorf("message %q: an Apply that sent nothing was rolled back", aerr.Message)
			}
			if len(ndm.calls) != before || len(fake.snapshot()) != 0 {
				t.Errorf("the refused Apply ran %d router command(s) and steps %v", len(ndm.calls)-before, fake.snapshot())
			}
		})
	}

	s, fake, ndm, slot := keeneticslot_server(t)
	ndm.unreadableListing = true
	if err := s.converge(context.Background(), s.committedRevision()); err != nil {
		t.Fatalf("boot converge stopped on an unreadable interface list: %v", err)
	}
	if len(fake.snapshot()) == 0 {
		t.Error("nothing after the native step ran")
	}
	if row := s.keeneticLeftAsIsCheck(context.Background()); row.Status != "warn" || !strings.Contains(row.Summary, slot) {
		t.Errorf("Diagnostics row = %+v, want the unchecked key of %s named", row, slot)
	}
}
