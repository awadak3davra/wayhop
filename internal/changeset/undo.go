package changeset

import (
	"fmt"
	"strings"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// UndoScope selects how much of the pending change set to revert.
type UndoScope string

const (
	// ScopeField reverts ONE field of one object back to its baseline value, leaving that object's
	// other edits intact — the smallest safe semantic unit.
	ScopeField UndoScope = "field"
	// ScopeObject reverts one object wholesale: restore a deleted one, drop a newly added one, or
	// reset a modified one to its baseline.
	ScopeObject UndoScope = "object"
	// ScopeSubsystem reverts every change in one subsystem (all routing edits, all DNS edits, …).
	ScopeSubsystem UndoScope = "subsystem"
	// ScopeAll discards the entire pending change set, restoring the complete baseline.
	ScopeAll UndoScope = "all"
)

// UndoRequest describes what to revert. ID/Field are required only for the narrower scopes.
type UndoRequest struct {
	Scope UndoScope `json:"scope"`
	ID    string    `json:"id,omitempty"` // object id (field/object scope)
	// ObjectType is the row's object_type (field/object scope). Ids are unique within one profile,
	// but the differ's synthetic ids are not reserved: a routing list named "DNS" gets the slug id
	// "dns", the DNS plane's id, and an id can also move between kinds across baseline and desired.
	// Without the type, Undo on the DNS row reverted that list instead. Optional: when it is empty
	// (a client that predates it) every kind is tried in a fixed order.
	ObjectType string    `json:"object_type,omitempty"`
	Field      string    `json:"field,omitempty"`     // field label as reported in the diff (field scope)
	Subsystem  Subsystem `json:"subsystem,omitempty"` // subsystem scope
}

// Object types as the differ labels its rows (Change.ObjectType).
const (
	objEndpoint    = "endpoint"
	objGroup       = "group"
	objRoutingList = "routing_list"
	objRule        = "rule"
	objDeviceGroup = "device_group"
	objDNS         = "dns"
	objSetting     = "setting"
)

// wants reports whether a request naming objType may resolve to kind; an empty objType may resolve
// to any kind.
func wants(objType, kind string) bool { return objType == "" || objType == kind }

// Undo computes the state that results from reverting the requested part of the diff. It returns NEW
// profile/config values — the caller persists them, so the underlying data really changes rather than
// the UI merely hiding a row (§1.5).
//
// It is deliberately pure and total: an unknown id/field is an error rather than a silent no-op, so a
// stale review pane can never make the user believe something was undone when it was not.
func Undo(base, desired model.Profile, baseCfg, desiredCfg config.Config, req UndoRequest) (model.Profile, config.Config, error) {
	switch req.Scope {
	case ScopeAll:
		return undoAll(base, desired, baseCfg, desiredCfg)

	case ScopeSubsystem:
		return undoSubsystem(base, desired, baseCfg, desiredCfg, req.Subsystem)

	case ScopeObject:
		if req.ID == "" {
			return desired, desiredCfg, fmt.Errorf("object undo requires an id")
		}
		p, c, ok := undoObject(base, desired, baseCfg, desiredCfg, req.ObjectType, req.ID, rankSlot)
		if !ok {
			return desired, desiredCfg, fmt.Errorf("no pending change for object %q", req.ID)
		}
		return p, c, nil

	case ScopeField:
		if req.ID == "" || req.Field == "" {
			return desired, desiredCfg, fmt.Errorf("field undo requires an id and a field")
		}
		p, c, ok := undoField(base, desired, baseCfg, desiredCfg, req.ObjectType, req.ID, req.Field)
		if !ok {
			return desired, desiredCfg, fmt.Errorf("no pending change for field %q of %q", req.Field, req.ID)
		}
		return p, c, nil
	}
	return desired, desiredCfg, fmt.Errorf("unknown undo scope %q", req.Scope)
}

// undoAll reverts every change the differ REPORTED — and nothing else. Returning (base, baseCfg)
// verbatim would also wipe state the review never listed: every config field outside the reviewable
// settings (ports, paths, allowed hosts, secrets). "Discard all pending changes" must mean the rows
// the user was shown, so this replays the same per-object machinery the narrower scopes use — which
// is why every object type Diff reports needs a case in undoObject: a type without one answered
// "undone" here while its rows stayed pending and shipped on the next Apply.
func undoAll(base, desired model.Profile, baseCfg, desiredCfg config.Config) (model.Profile, config.Config, error) {
	outP, outC, touched := undoReported(base, desired, baseCfg, desiredCfg, func(Change) bool { return true })
	if !touched {
		return desired, desiredCfg, fmt.Errorf("no pending changes to discard")
	}
	return outP, outC, nil
}

// undoSubsystem reverts every change the differ attributes to one subsystem.
func undoSubsystem(base, desired model.Profile, baseCfg, desiredCfg config.Config, sub Subsystem) (model.Profile, config.Config, error) {
	if sub == "" {
		return desired, desiredCfg, fmt.Errorf("subsystem undo requires a subsystem")
	}
	outP, outC, touched := undoReported(base, desired, baseCfg, desiredCfg,
		func(ch Change) bool { return ch.Subsystem == sub })
	if !touched {
		return desired, desiredCfg, fmt.Errorf("no pending changes in subsystem %q", sub)
	}
	return outP, outC, nil
}

// undoReported reverts the changes matching keep. Settings are reverted FIELD-BY-FIELD rather than as
// one object: all config changes share the synthetic id "settings" but land in DIFFERENT subsystems
// (routing mode → firewall_pbr, offload → offload, rule-set route → routing), so undoing one
// subsystem as an "object" would silently revert the other two settings as well.
//
// One pass can leave a move pending. Each list goes to the slot that is best among the lists as they
// stand at its turn, and a list placed later can leave an earlier one out of order: over 4000 random
// reorders one "Discard all" still left l2 and l3 swapped, two "Position" rows after it answered
// "undone" (over 197k reorders of up to 10 lists, 2560 needed a second pass and none a third). So
// the pass repeats on what is still pending until nothing is or a pass changes nothing. Only
// routing-list order can survive a pass, and every routing-list row is in the routing group, so a
// repeat never reaches past the group the user asked to undo.
func undoReported(base, desired model.Profile, baseCfg, desiredCfg config.Config, keep func(Change) bool) (model.Profile, config.Config, bool) {
	outP, outC := desired, desiredCfg
	var touched bool
	for pass := 0; pass < maxUndoPasses; pass++ {
		p, c, did := undoReportedOnce(base, outP, baseCfg, outC, keep)
		if !did {
			break
		}
		outP, outC, touched = p, c, true
	}
	return outP, outC, touched
}

// maxUndoPasses bounds undoReported's repeats, with room over the two the fuzz ever needed.
const maxUndoPasses = 4

func undoReportedOnce(base, desired model.Profile, baseCfg, desiredCfg config.Config, keep func(Change) bool) (model.Profile, config.Config, bool) {
	cs := Diff("", "", base, desired, baseCfg, desiredCfg)
	outP, outC := desired, desiredCfg
	var touched bool
	seenObj := map[string]bool{}
	for _, ch := range cs.Changes {
		if !keep(ch) {
			continue
		}
		if ch.ObjectType == objSetting {
			if _, c, ok := undoField(base, outP, baseCfg, outC, objSetting, ch.ID, ch.Field); ok {
				outC, touched = c, true
			}
			continue
		}
		// Keyed by type as well: the DNS plane's synthetic id can equal a real object's id.
		key := ch.ObjectType + "\x00" + ch.ID
		if seenObj[key] {
			continue
		}
		seenObj[key] = true
		// restoreIndex, not rankSlot: here every list of the batch goes back, one after another, and
		// what counts is the baseline order once the last of them is placed. Placing each by rankSlot
		// left rows behind after 223 of 4000 random reorders; restoreIndex, which keeps the fewest
		// lists out of baseline order, after 1 (which the repeat above clears).
		if p, c, ok := undoObject(base, outP, baseCfg, outC, ch.ObjectType, ch.ID, restoreIndex); ok {
			outP, outC, touched = p, c, true
		}
	}
	return outP, outC, touched
}

// undoObject restores one object to its baseline shape. "settings" is the synthetic id the differ
// uses for config-level changes, so undoing it restores the whole baseline config; "dns" is the DNS
// plane's, which is one object in the profile. listSlot places a routing list (see undoRoutingObject).
func undoObject(base, desired model.Profile, baseCfg, desiredCfg config.Config, objType, id string, listSlot slotFunc) (model.Profile, config.Config, bool) {
	if wants(objType, objSetting) && id == "settings" && !settingsEqual(baseCfg, desiredCfg) {
		return desired, restoreSettings(baseCfg, desiredCfg), true
	}
	type kind struct {
		name string
		undo func(base, desired model.Profile, id string) (model.Profile, bool)
	}
	undoList := func(base, desired model.Profile, id string) (model.Profile, bool) {
		return undoRoutingObject(base, desired, id, listSlot)
	}
	for _, k := range []kind{
		{objEndpoint, undoEndpointObject},
		{objGroup, undoGroupObject},
		{objRoutingList, undoList},
		{objRule, undoRuleObject},
		{objDeviceGroup, undoDeviceGroupObject},
		{objDNS, undoDNSObject},
	} {
		if !wants(objType, k.name) {
			continue
		}
		if p, ok := k.undo(base, desired, id); ok {
			return p, desiredCfg, true
		}
	}
	return desired, desiredCfg, false
}

// settingsEqual compares just the settings the differ reports. config.Config as a whole is not
// comparable (it holds slices), and only these fields are reviewable, so equality is scoped to them.
func settingsEqual(a, b config.Config) bool {
	return a.RoutingMode == b.RoutingMode && a.Offload == b.Offload && a.RuleSetDetour == b.RuleSetDetour &&
		a.CoreOverride == b.CoreOverride
}

// restoreSettings copies ONLY the settings the differ reports back to baseline, leaving every other
// config field (ports, paths, secrets the review never showed) exactly as-is.
func restoreSettings(baseCfg, desiredCfg config.Config) config.Config {
	out := desiredCfg
	out.RoutingMode = baseCfg.RoutingMode
	out.Offload = baseCfg.Offload
	out.RuleSetDetour = baseCfg.RuleSetDetour
	out.CoreOverride = baseCfg.CoreOverride
	return out
}

func undoEndpointObject(base, desired model.Profile, id string) (model.Profile, bool) {
	s, ok := undoOrdered(base.Endpoints, desired.Endpoints, id, endpointID, endpointsEqual, nil)
	if ok {
		desired = cloneProfile(desired)
		desired.Endpoints = s
	}
	return desired, ok
}

func undoGroupObject(base, desired model.Profile, id string) (model.Profile, bool) {
	s, ok := undoOrdered(base.Groups, desired.Groups, id, groupID, groupsEqual, nil)
	if ok {
		desired = cloneProfile(desired)
		desired.Groups = s
	}
	return desired, ok
}

// undoRoutingObject also restores ORDER: a reordered rule goes back to its baseline position, since
// routing lists are evaluated in order and a "position" change is a real, reviewable change. slot
// picks that position: rankSlot for one list's own Undo, restoreIndex for a batch.
//
// A modified list keeps the feed timestamps it has now (see keepRefreshClock).
func undoRoutingObject(base, desired model.Profile, id string, slot slotFunc) (model.Profile, bool) {
	baseLists := base.RoutingLists
	if bi, di := indexOfRouting(base.RoutingLists, id), indexOfRouting(desired.RoutingLists, id); bi >= 0 && di >= 0 {
		baseLists = append([]model.RoutingList(nil), baseLists...)
		baseLists[bi] = keepRefreshClock(baseLists[bi], desired.RoutingLists[di])
	}
	s, ok := undoOrdered(baseLists, desired.RoutingLists, id, routingID, routingEqual, slot)
	if ok {
		desired = cloneProfile(desired)
		desired.RoutingLists = s
	}
	return desired, ok
}

// undoRuleObject resets a rule in place rather than moving it: the differ reports no "Position" row
// for rules, so restoring order here would make a move nobody was shown.
func undoRuleObject(base, desired model.Profile, id string) (model.Profile, bool) {
	s, ok := undoOrdered(base.Rules, desired.Rules, id, ruleID, rulesEqual, nil)
	if ok {
		desired = cloneProfile(desired)
		desired.Rules = s
	}
	return desired, ok
}

func undoDeviceGroupObject(base, desired model.Profile, id string) (model.Profile, bool) {
	s, ok := undoOrdered(base.DeviceGroups, desired.DeviceGroups, id, deviceGroupID, deviceGroupsEqual, nil)
	if ok {
		desired = cloneProfile(desired)
		desired.DeviceGroups = s
	}
	return desired, ok
}

// undoDNSObject puts the whole DNS plane back as the baseline had it: enabled, off, or absent.
func undoDNSObject(base, desired model.Profile, id string) (model.Profile, bool) {
	if id != "dns" || len(diffDNSPlane(base.DNS, desired.DNS)) == 0 {
		return desired, false
	}
	desired.DNS = cloneDNS(base.DNS)
	return desired, true
}

// slotFunc returns where id goes in desired once id itself is taken out of it.
type slotFunc func(baseIDs, desiredIDs []string, id string) int

// undoOrdered reverts one object of an ordered collection: a modified one is reset to its baseline
// value, a removed one restored, an added one dropped. With a slot, a modified one also goes back to
// its baseline-relative position (routing lists, whose order the review reports); without one it
// stays where it is and a restored one goes to restoreIndex.
//
// A restored object is re-inserted RELATIVE to the objects present in both states, never at its
// absolute baseline index: after other objects were added or removed that index points somewhere
// else. Undoing one of two removed lists in [a b c d] put c at index 2 of [b d] — after d, so d
// started winning traffic c used to route and the review grew "Reordered" rows nobody made.
func undoOrdered[T any](base, desired []T, id string, idOf func(T) string, equal func(a, b T) bool, slot slotFunc) ([]T, bool) {
	bi, di := indexByID(base, id, idOf), indexByID(desired, id, idOf)
	if bi < 0 && di < 0 {
		return desired, false
	}
	if bi < 0 { // added -> drop
		out := append([]T(nil), desired[:di]...)
		return append(out, desired[di+1:]...), true
	}
	target := di
	switch {
	case slot != nil:
		target = slot(idsOf(base, idOf), idsOf(desired, idOf), id)
	case di < 0:
		target = restoreIndex(idsOf(base, idOf), idsOf(desired, idOf), id)
	}
	if di >= 0 && target == di && equal(base[bi], desired[di]) {
		return desired, false
	}
	out := make([]T, 0, len(desired)+1)
	for i := range desired {
		if i != di {
			out = append(out, desired[i])
		}
	}
	return insertAt(out, base[bi], target), true
}

// restoreIndex returns where id belongs in desired once id itself is taken out of it: the slot that
// puts the fewest objects present in both states on the other side of id than the baseline had them.
// Counting id's surviving baseline predecessors (the old rule for a move) is not enough: a list the
// user ADDED in front shifts that count by one, and undoing c's move in [n c a b] gave [n a c b].
// Objects absent from the baseline carry no order to keep, so they never count. Ties keep id where
// it already is (an undo of a content edit must not move it past a list added beside it);
// otherwise the earliest slot wins.
func restoreIndex(baseIDs, desiredIDs []string, id string) int {
	rank := make(map[string]int, len(baseIDs))
	for i, x := range baseIDs {
		rank[x] = i
	}
	own, inBase := rank[id]
	rest, cur := make([]string, 0, len(desiredIDs)), -1
	for _, x := range desiredIDs {
		if x == id {
			cur = len(rest)
			continue
		}
		rest = append(rest, x)
	}
	if !inBase {
		if cur >= 0 {
			return cur
		}
		return len(rest)
	}
	// misplaced = shared objects left of the slot that the baseline put after id, plus shared objects
	// right of it that the baseline put before id. Start at slot 0 and slide right.
	misplaced := 0
	for _, x := range rest {
		if r, ok := rank[x]; ok && r < own {
			misplaced++
		}
	}
	best, bestAt, atCur := misplaced, 0, -1
	if cur == 0 {
		atCur = misplaced
	}
	for k, x := range rest {
		if r, ok := rank[x]; ok {
			if r < own {
				misplaced--
			} else {
				misplaced++
			}
		}
		if misplaced < best {
			best, bestAt = misplaced, k+1
		}
		if cur == k+1 {
			atCur = misplaced
		}
	}
	if cur >= 0 && atCur == best {
		return cur
	}
	return bestAt
}

// rankSlot returns where id goes in desired, once id itself is taken out, so that exactly as many
// objects present in both states sit in front of it as did in the baseline. That count is the test
// the differ uses to report a "Position" row (relativeOrder), so a list placed here never shows one;
// restoreIndex's fewest-out-of-order slot can disagree with it. It did: base [a b c], desired
// [b c a] listed b "#2 -> #1" and Undo on that row answered 400 "no pending change" because b
// already held the best slot; [a b c d e] -> [c d e b a] moved b but its row stayed. Over 20k
// random reorders 2304 Position undos were refused.
//
// The slots that satisfy it run from just after the k-th shared object to just before the next one,
// with only objects absent from the baseline between them. Those carry no baseline order, so id
// keeps its slot when it is already in that range (an undo of a renamed list that was never moved
// must not move it) and otherwise takes the nearest end, which keeps it on the same side of an
// object the user added next to it. A restored object takes the first slot. An id the baseline lacks
// keeps its slot.
func rankSlot(baseIDs, desiredIDs []string, id string) int {
	inDesired := make(map[string]bool, len(desiredIDs))
	for _, x := range desiredIDs {
		inDesired[x] = true
	}
	inBase := make(map[string]bool, len(baseIDs))
	k, found := 0, false
	for _, x := range baseIDs {
		inBase[x] = true
		if x == id {
			found = true
		} else if !found && inDesired[x] {
			k++
		}
	}
	rest, cur := make([]string, 0, len(desiredIDs)), -1
	for _, x := range desiredIDs {
		if x == id {
			cur = len(rest)
			continue
		}
		rest = append(rest, x)
	}
	if !found {
		if cur >= 0 {
			return cur
		}
		return len(rest)
	}
	lo, hi, shared := 0, len(rest), 0
	for i, x := range rest {
		if !inBase[x] {
			continue
		}
		if shared == k {
			hi = i
			break
		}
		shared++
		if shared == k {
			lo = i + 1
		}
	}
	switch {
	case cur < 0 || cur < lo:
		return lo
	case cur > hi:
		return hi
	}
	return cur
}

// keepRefreshClock is the baseline list b as it goes back, with the feed timestamps of cur, the
// list as it is now. A stamp says when a feed was last fetched, which did happen; it only seeds the
// refresh clock and is no part of the review. The baseline's can be older or zero, and zero marks a
// feed as never loaded, so the refresher fetched it at once and re-staged the very feed the
// operator had just declined. A zero stamp now (the store zeroes it when that feed's source
// changes) leaves the baseline's, which belongs to the baseline source going back.
func keepRefreshClock(b, cur model.RoutingList) model.RoutingList {
	if cur.CIDRRefreshed != 0 {
		b.CIDRRefreshed = cur.CIDRRefreshed
	}
	if cur.DomainRefreshed != 0 {
		b.DomainRefreshed = cur.DomainRefreshed
	}
	return b
}

// undoField reverts a single field, preserving the object's other pending edits (§1.5's "undo one
// field while preserving other changes"). The field label is the one the differ emitted, so every
// label a differ emits needs a case below: the review gives each row an Undo button, and a label
// without one answered 400 "no pending change for field …", which was false.
func undoField(base, desired model.Profile, baseCfg, desiredCfg config.Config, objType, id, field string) (model.Profile, config.Config, bool) {
	if wants(objType, objSetting) && id == "settings" {
		out := desiredCfg
		switch field {
		case "Routing mode":
			out.RoutingMode = baseCfg.RoutingMode
		case "Flow offload":
			out.Offload = baseCfg.Offload
		case "Rule-set download route":
			out.RuleSetDetour = baseCfg.RuleSetDetour
		case "Core override":
			out.CoreOverride = baseCfg.CoreOverride
		}
		if !settingsEqual(out, desiredCfg) {
			return desired, out, true
		}
	}

	// Without an object type the kinds are tried in turn, so a kind that does not know the field
	// falls through to the next one instead of ending the search.
	if bi, di := indexOfEndpoint(base.Endpoints, id), indexOfEndpoint(desired.Endpoints, id); wants(objType, objEndpoint) && bi >= 0 && di >= 0 {
		e := desired.Endpoints[di]
		if revertEndpointField(&e, base.Endpoints[bi], field) {
			out := cloneProfile(desired)
			out.Endpoints[di] = e
			return out, desiredCfg, true
		}
	}
	if bi, di := indexOfGroup(base.Groups, id), indexOfGroup(desired.Groups, id); wants(objType, objGroup) && bi >= 0 && di >= 0 {
		g := desired.Groups[di]
		if revertGroupField(&g, base.Groups[bi], field) {
			out := cloneProfile(desired)
			out.Groups[di] = g
			return out, desiredCfg, true
		}
	}
	if bi, di := indexOfRouting(base.RoutingLists, id), indexOfRouting(desired.RoutingLists, id); wants(objType, objRoutingList) && bi >= 0 && di >= 0 {
		// "Position" is emitted as a FIELD on a reordered list, so field-scope undo must handle it —
		// otherwise the one row the review shows for a move cannot be undone individually.
		if field == "Position" {
			if p, ok := undoRoutingPosition(base, desired, id); ok {
				return p, desiredCfg, true
			}
		}
		r := desired.RoutingLists[di]
		if revertRoutingField(&r, base.RoutingLists[bi], field) {
			out := cloneProfile(desired)
			out.RoutingLists[di] = r
			return out, desiredCfg, true
		}
	}
	// A rule and a device group each get ONE row, which covers every difference in the object (the
	// rule's matchers and target; the group's name and members), so undoing that row resets the
	// whole object — reverting less would leave the row pending.
	if field == "Rule definition" && wants(objType, objRule) && indexByID(base.Rules, id, ruleID) >= 0 && indexByID(desired.Rules, id, ruleID) >= 0 {
		if p, ok := undoRuleObject(base, desired, id); ok {
			return p, desiredCfg, true
		}
	}
	if field == "Members" && wants(objType, objDeviceGroup) && indexByID(base.DeviceGroups, id, deviceGroupID) >= 0 &&
		indexByID(desired.DeviceGroups, id, deviceGroupID) >= 0 {
		if p, ok := undoDeviceGroupObject(base, desired, id); ok {
			return p, desiredCfg, true
		}
	}
	if wants(objType, objDNS) && id == "dns" && base.DNS != nil && desired.DNS != nil {
		d := *desired.DNS // a copy: the caller's profile may be the store's published one
		if revertDNSField(&d, *base.DNS, field) {
			out := desired
			out.DNS = &d
			return out, desiredCfg, true
		}
	}
	return desired, desiredCfg, false
}

// undoRoutingPosition moves a list back to its baseline-relative position WITHOUT touching its
// content (the content edits stay pending, per §1.5's smallest-safe-unit rule). The slot is the
// differ's own test for the row (rankSlot), so the row this undo was made on always clears.
func undoRoutingPosition(base, desired model.Profile, id string) (model.Profile, bool) {
	di := indexOfRouting(desired.RoutingLists, id)
	if di < 0 || indexOfRouting(base.RoutingLists, id) < 0 {
		return desired, false
	}
	target := rankSlot(idsOf(base.RoutingLists, routingID), idsOf(desired.RoutingLists, routingID), id)
	if target == di {
		return desired, false
	}
	cur := desired.RoutingLists[di]
	out := cloneProfile(desired)
	out.RoutingLists = append(out.RoutingLists[:di], out.RoutingLists[di+1:]...)
	out.RoutingLists = insertAt(out.RoutingLists, cur, target)
	return out, true
}

// revertGroupField sets one group field back to baseline.
func revertGroupField(g *model.Group, b model.Group, field string) bool {
	switch field {
	case "Name":
		g.Name = b.Name
	case "Type":
		g.Type = b.Type
	case "Members":
		g.Members = append([]string(nil), b.Members...)
	case "Health test":
		g.Test = b.Test
	case "Kill switch":
		g.KillSwitch = b.KillSwitch
	case "Interrupt on switch":
		g.InterruptOnSwitch = b.InterruptOnSwitch
	case "Managed by WayHop":
		g.Managed = b.Managed
	default:
		return false
	}
	return true
}

// revertDNSField sets one DNS-plane setting back to baseline, by the label diffDNSPlane gives it.
func revertDNSField(d *model.DNSSettings, b model.DNSSettings, field string) bool {
	switch field {
	case "DNS management":
		d.Enabled = b.Enabled
	case "Leak protection":
		d.LeakProof = b.LeakProof
	case "FakeIP":
		d.FakeIP = b.FakeIP
	case "Strategy":
		d.Strategy = b.Strategy
	case "Resolvers":
		d.Servers = b.Servers
	case "DNS rules":
		d.Rules = b.Rules
	case "Default resolver":
		d.Final = b.Final
	case "Intercept DNS":
		d.Intercept = b.Intercept
	case "Reject encrypted DNS":
		d.InterceptRejectEncrypted = b.InterceptRejectEncrypted
	case "DNS cache":
		d.DisableCache = b.DisableCache
	case "Independent cache":
		d.IndependentCache = b.IndependentCache
	case "Client subnet":
		d.ClientSubnet = b.ClientSubnet
	case "Reverse mapping":
		d.ReverseMapping = b.ReverseMapping
	default:
		return false
	}
	return true
}

// revertEndpointField sets one field of e back to b's value. Reports false for an unknown field so
// the caller can surface a real error instead of pretending the undo happened.
func revertEndpointField(e *model.Endpoint, b model.Endpoint, field string) bool {
	switch field {
	case "Name":
		e.Name = b.Name
	case "Server":
		e.Server = b.Server
	case "Port":
		e.Port = b.Port
	case "Protocol":
		e.Protocol = b.Protocol
	case "Engine":
		e.Engine = b.Engine
	case "Enabled":
		e.Enabled = b.Enabled
	case "MTU":
		e.MTU = b.MTU
	case fieldAWGEngine:
		e.AWGUserspace = b.AWGUserspace
	case "Owner":
		e.Owner = b.Owner
	case "Keepalive":
		e.PersistentKeepalive = b.PersistentKeepalive
	case "TLS settings":
		e.TLS = b.TLS
	case "Transport":
		e.Transport = b.Transport
	case "Multiplex":
		e.Multiplex = b.Multiplex
	case "Health test":
		e.Health = b.Health
	default:
		// Params are reported with humanised labels ("Peer public key" -> peer_public_key).
		key := paramKeyFromLabel(field)
		if key == "" {
			return false
		}
		bv, hadBase := b.Params[key]
		if _, hadDesired := e.Params[key]; !hadBase && !hadDesired {
			return false
		}
		e.Params = cloneParams(e.Params)
		if !hadBase {
			delete(e.Params, key)
		} else {
			e.Params[key] = bv
		}
	}
	return true
}

func revertRoutingField(r *model.RoutingList, b model.RoutingList, field string) bool {
	switch field {
	case "Name":
		r.Name = b.Name
	case "Outbound":
		r.Outbound = b.Outbound
	case "Enabled":
		r.Enabled = b.Enabled
	case "Source URL":
		r.Source = b.Source
	case "Entries":
		r.Manual = append([]string(nil), b.Manual...)
	case "Feed format":
		r.Format = b.Format
	case "IP feed":
		// Only the cache, not CIDRRefreshed: that stamp says when the last fetch ran, which did
		// happen, and it only seeds the refresh clock (it is kept out of the revision). Rewinding it
		// to the baseline's older value would make the list due at once, and the refresher would
		// re-stage the very feed the operator just declined. The slice is shared, not copied: a feed
		// runs to tens of thousands of prefixes and every writer replaces it whole.
		r.CIDRCache = b.CIDRCache
	case "Name feed":
		r.DomainCache = b.DomainCache // as "IP feed"
	case "IP feed source":
		r.CIDRSource = b.CIDRSource
	case "Name feed source":
		r.DomainSource = b.DomainSource
	case "Download via":
		r.DownloadVia = b.DownloadVia
	case "Auto-update":
		r.RefreshHours = b.RefreshHours
	case "Applies to":
		r.ScopeMode, r.ScopeGroups = b.ScopeMode, b.ScopeGroups
	case "TLS fragmentation":
		r.TLSFragment = b.TLSFragment
	default:
		return false
	}
	return true
}

// paramKeyFromLabel inverts fieldLabel ("Peer public key" -> "peer_public_key").
func paramKeyFromLabel(label string) string {
	s := strings.TrimSpace(label)
	if s == "" {
		return ""
	}
	return strings.ToLower(strings.ReplaceAll(s, " ", "_"))
}

// ---- small pure helpers ------------------------------------------------------------------------

func cloneProfile(p model.Profile) model.Profile {
	out := p
	out.Endpoints = append([]model.Endpoint(nil), p.Endpoints...)
	out.Groups = append([]model.Group(nil), p.Groups...)
	out.RoutingLists = append([]model.RoutingList(nil), p.RoutingLists...)
	out.Rules = append([]model.Rule(nil), p.Rules...)
	out.DeviceGroups = append([]model.DeviceGroup(nil), p.DeviceGroups...)
	return out
}

func cloneParams(m map[string]any) map[string]any {
	out := make(map[string]any, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

// insertAt puts v at index i, clamping i into range (a baseline position can exceed the current
// slice length after other removals).
func insertAt[T any](ss []T, v T, i int) []T {
	if i < 0 || i > len(ss) {
		i = len(ss)
	}
	ss = append(ss, v)
	copy(ss[i+1:], ss[i:])
	ss[i] = v
	return ss
}

func indexOfEndpoint(ss []model.Endpoint, id string) int {
	for i := range ss {
		if ss[i].ID == id {
			return i
		}
	}
	return -1
}

func indexOfGroup(ss []model.Group, id string) int {
	for i := range ss {
		if ss[i].ID == id {
			return i
		}
	}
	return -1
}

func indexOfRouting(ss []model.RoutingList, id string) int {
	for i := range ss {
		if ss[i].ID == id {
			return i
		}
	}
	return -1
}

func indexByID[T any](ss []T, id string, idOf func(T) string) int {
	for i := range ss {
		if idOf(ss[i]) == id {
			return i
		}
	}
	return -1
}

func idsOf[T any](ss []T, idOf func(T) string) []string {
	out := make([]string, len(ss))
	for i := range ss {
		out[i] = idOf(ss[i])
	}
	return out
}

func endpointID(e model.Endpoint) string       { return e.ID }
func groupID(g model.Group) string             { return g.ID }
func routingID(r model.RoutingList) string     { return r.ID }
func ruleID(r model.Rule) string               { return r.ID }
func deviceGroupID(g model.DeviceGroup) string { return g.ID }

// cloneDNS copies the plane's top-level struct so a restored plane never shares one pointer between
// the baseline record and the live profile.
func cloneDNS(d *model.DNSSettings) *model.DNSSettings {
	if d == nil {
		return nil
	}
	c := *d
	return &c
}

// Equality via the differ itself, so "changed" and "undone" can never disagree.
func rulesEqual(a, b model.Rule) bool {
	return len(diffRules([]model.Rule{a}, []model.Rule{b})) == 0
}

func deviceGroupsEqual(a, b model.DeviceGroup) bool {
	return len(diffDeviceGroups([]model.DeviceGroup{a}, []model.DeviceGroup{b})) == 0
}

func endpointsEqual(a, b model.Endpoint) bool {
	return len(diffEndpointFields(a, b)) == 0
}

func groupsEqual(a, b model.Group) bool {
	return len(diffGroups([]model.Group{a}, []model.Group{b})) == 0
}

func routingEqual(a, b model.RoutingList) bool {
	return len(diffRoutingLists([]model.RoutingList{a}, []model.RoutingList{b})) == 0
}
