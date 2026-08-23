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
	Scope     UndoScope `json:"scope"`
	ID        string    `json:"id,omitempty"`        // object id (field/object scope)
	Field     string    `json:"field,omitempty"`     // field label as reported in the diff (field scope)
	Subsystem Subsystem `json:"subsystem,omitempty"` // subsystem scope
}

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
		p, c, ok := undoObject(base, desired, baseCfg, desiredCfg, req.ID)
		if !ok {
			return desired, desiredCfg, fmt.Errorf("no pending change for object %q", req.ID)
		}
		return p, c, nil

	case ScopeField:
		if req.ID == "" || req.Field == "" {
			return desired, desiredCfg, fmt.Errorf("field undo requires an id and a field")
		}
		p, c, ok := undoField(base, desired, baseCfg, desiredCfg, req.ID, req.Field)
		if !ok {
			return desired, desiredCfg, fmt.Errorf("no pending change for field %q of %q", req.Field, req.ID)
		}
		return p, c, nil
	}
	return desired, desiredCfg, fmt.Errorf("unknown undo scope %q", req.Scope)
}

// undoAll reverts every change the differ REPORTED — and nothing else. Returning (base, baseCfg)
// verbatim would also wipe state the review never listed: Profile.Rules / DeviceGroups / DNS (which
// Diff does not cover) and every config field outside the three reviewable settings (ports, paths,
// allowed hosts, secrets). "Discard all pending changes" must mean the rows the user was shown, so
// this replays the same per-object machinery the narrower scopes use.
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
func undoReported(base, desired model.Profile, baseCfg, desiredCfg config.Config, keep func(Change) bool) (model.Profile, config.Config, bool) {
	cs := Diff("", "", base, desired, baseCfg, desiredCfg)
	outP, outC := desired, desiredCfg
	var touched bool
	seenObj := map[string]bool{}
	for _, ch := range cs.Changes {
		if !keep(ch) {
			continue
		}
		if ch.ID == "settings" {
			if _, c, ok := undoField(base, outP, baseCfg, outC, "settings", ch.Field); ok {
				outC, touched = c, true
			}
			continue
		}
		if seenObj[ch.ID] {
			continue
		}
		seenObj[ch.ID] = true
		if p, c, ok := undoObject(base, outP, baseCfg, outC, ch.ID); ok {
			outP, outC, touched = p, c, true
		}
	}
	return outP, outC, touched
}

// undoObject restores one object to its baseline shape. "settings" is the synthetic id the differ
// uses for config-level changes, so undoing it restores the whole baseline config.
func undoObject(base, desired model.Profile, baseCfg, desiredCfg config.Config, id string) (model.Profile, config.Config, bool) {
	if id == "settings" {
		if settingsEqual(baseCfg, desiredCfg) {
			return desired, desiredCfg, false
		}
		return desired, restoreSettings(baseCfg, desiredCfg), true
	}
	if p, ok := undoEndpointObject(base, desired, id); ok {
		return p, desiredCfg, true
	}
	if p, ok := undoGroupObject(base, desired, id); ok {
		return p, desiredCfg, true
	}
	if p, ok := undoRoutingObject(base, desired, id); ok {
		return p, desiredCfg, true
	}
	return desired, desiredCfg, false
}

// settingsEqual compares just the settings the differ reports. config.Config as a whole is not
// comparable (it holds slices), and only these fields are reviewable, so equality is scoped to them.
func settingsEqual(a, b config.Config) bool {
	return a.RoutingMode == b.RoutingMode && a.Offload == b.Offload && a.RuleSetDetour == b.RuleSetDetour
}

// restoreSettings copies ONLY the settings the differ reports back to baseline, leaving every other
// config field (ports, paths, secrets the review never showed) exactly as-is.
func restoreSettings(baseCfg, desiredCfg config.Config) config.Config {
	out := desiredCfg
	out.RoutingMode = baseCfg.RoutingMode
	out.Offload = baseCfg.Offload
	out.RuleSetDetour = baseCfg.RuleSetDetour
	return out
}

func undoEndpointObject(base, desired model.Profile, id string) (model.Profile, bool) {
	bi, di := indexOfEndpoint(base.Endpoints, id), indexOfEndpoint(desired.Endpoints, id)
	switch {
	case bi >= 0 && di >= 0: // modified -> reset to baseline
		if endpointsEqual(base.Endpoints[bi], desired.Endpoints[di]) {
			return desired, false
		}
		out := cloneProfile(desired)
		out.Endpoints[di] = base.Endpoints[bi]
		return out, true
	case bi >= 0 && di < 0: // removed -> restore, at its baseline position where possible
		out := cloneProfile(desired)
		out.Endpoints = insertAt(out.Endpoints, base.Endpoints[bi], bi)
		return out, true
	case bi < 0 && di >= 0: // added -> drop
		out := cloneProfile(desired)
		out.Endpoints = append(out.Endpoints[:di], out.Endpoints[di+1:]...)
		return out, true
	}
	return desired, false
}

func undoGroupObject(base, desired model.Profile, id string) (model.Profile, bool) {
	bi, di := indexOfGroup(base.Groups, id), indexOfGroup(desired.Groups, id)
	switch {
	case bi >= 0 && di >= 0:
		if groupsEqual(base.Groups[bi], desired.Groups[di]) {
			return desired, false
		}
		out := cloneProfile(desired)
		out.Groups[di] = base.Groups[bi]
		return out, true
	case bi >= 0 && di < 0:
		out := cloneProfile(desired)
		out.Groups = insertAt(out.Groups, base.Groups[bi], bi)
		return out, true
	case bi < 0 && di >= 0:
		out := cloneProfile(desired)
		out.Groups = append(out.Groups[:di], out.Groups[di+1:]...)
		return out, true
	}
	return desired, false
}

// undoRoutingObject also restores ORDER: a reordered rule goes back to its baseline position, since
// routing lists are evaluated in order and a "position" change is a real, reviewable change.
func undoRoutingObject(base, desired model.Profile, id string) (model.Profile, bool) {
	bi, di := indexOfRouting(base.RoutingLists, id), indexOfRouting(desired.RoutingLists, id)
	switch {
	case bi >= 0 && di >= 0:
		sameContent := routingEqual(base.RoutingLists[bi], desired.RoutingLists[di])
		target := baselineNeighbourIndex(base, desired, id)
		if sameContent && target == di {
			return desired, false
		}
		out := cloneProfile(desired)
		out.RoutingLists = append(out.RoutingLists[:di], out.RoutingLists[di+1:]...)
		// Re-insert RELATIVE to the surviving neighbours, not at the absolute baseline index: after
		// other lists were added or removed, the old index points somewhere else entirely and would
		// silently reshuffle rules the user never touched (routing is order-sensitive).
		if target > len(out.RoutingLists) {
			target = len(out.RoutingLists)
		}
		out.RoutingLists = insertAt(out.RoutingLists, base.RoutingLists[bi], target)
		return out, true
	case bi >= 0 && di < 0:
		out := cloneProfile(desired)
		out.RoutingLists = insertAt(out.RoutingLists, base.RoutingLists[bi], bi)
		return out, true
	case bi < 0 && di >= 0:
		out := cloneProfile(desired)
		out.RoutingLists = append(out.RoutingLists[:di], out.RoutingLists[di+1:]...)
		return out, true
	}
	return desired, false
}

// baselineNeighbourIndex computes where id belongs in the DESIRED slice so that its order relative to
// the lists present in BOTH states matches the baseline. It counts how many of id's baseline
// predecessors still exist in desired (excluding id itself) — that count is the insertion index.
func baselineNeighbourIndex(base, desired model.Profile, id string) int {
	inDesired := make(map[string]bool, len(desired.RoutingLists))
	for _, r := range desired.RoutingLists {
		if r.ID != id {
			inDesired[r.ID] = true
		}
	}
	idx := 0
	for _, r := range base.RoutingLists {
		if r.ID == id {
			break
		}
		if inDesired[r.ID] {
			idx++
		}
	}
	return idx
}

// undoField reverts a single field, preserving the object's other pending edits (§1.5's "undo one
// field while preserving other changes"). The field label is the one the differ emitted.
func undoField(base, desired model.Profile, baseCfg, desiredCfg config.Config, id, field string) (model.Profile, config.Config, bool) {
	if id == "settings" {
		out := desiredCfg
		switch field {
		case "Routing mode":
			out.RoutingMode = baseCfg.RoutingMode
		case "Flow offload":
			out.Offload = baseCfg.Offload
		case "Rule-set download route":
			out.RuleSetDetour = baseCfg.RuleSetDetour
		default:
			return desired, desiredCfg, false
		}
		if settingsEqual(out, desiredCfg) {
			return desired, desiredCfg, false
		}
		return desired, out, true
	}

	if bi, di := indexOfEndpoint(base.Endpoints, id), indexOfEndpoint(desired.Endpoints, id); bi >= 0 && di >= 0 {
		e := desired.Endpoints[di]
		if !revertEndpointField(&e, base.Endpoints[bi], field) {
			return desired, desiredCfg, false
		}
		out := cloneProfile(desired)
		out.Endpoints[di] = e
		return out, desiredCfg, true
	}
	if bi, di := indexOfGroup(base.Groups, id), indexOfGroup(desired.Groups, id); bi >= 0 && di >= 0 {
		g := desired.Groups[di]
		if !revertGroupField(&g, base.Groups[bi], field) {
			return desired, desiredCfg, false
		}
		out := cloneProfile(desired)
		out.Groups[di] = g
		return out, desiredCfg, true
	}
	if bi, di := indexOfRouting(base.RoutingLists, id), indexOfRouting(desired.RoutingLists, id); bi >= 0 && di >= 0 {
		// "Position" is emitted as a FIELD on a reordered list, so field-scope undo must handle it —
		// otherwise the one row the review shows for a move cannot be undone individually.
		if field == "Position" {
			p, ok := undoRoutingPosition(base, desired, id)
			return p, desiredCfg, ok
		}
		r := desired.RoutingLists[di]
		if !revertRoutingField(&r, base.RoutingLists[bi], field) {
			return desired, desiredCfg, false
		}
		out := cloneProfile(desired)
		out.RoutingLists[di] = r
		return out, desiredCfg, true
	}
	return desired, desiredCfg, false
}

// undoRoutingPosition moves a list back to its baseline-relative position WITHOUT touching its
// content (the content edits stay pending, per §1.5's smallest-safe-unit rule).
func undoRoutingPosition(base, desired model.Profile, id string) (model.Profile, bool) {
	di := indexOfRouting(desired.RoutingLists, id)
	if di < 0 || indexOfRouting(base.RoutingLists, id) < 0 {
		return desired, false
	}
	target := baselineNeighbourIndex(base, desired, id)
	if target == di {
		return desired, false
	}
	cur := desired.RoutingLists[di]
	out := cloneProfile(desired)
	out.RoutingLists = append(out.RoutingLists[:di], out.RoutingLists[di+1:]...)
	if target > len(out.RoutingLists) {
		target = len(out.RoutingLists)
	}
	out.RoutingLists = insertAt(out.RoutingLists, cur, target)
	return out, true
}

// revertGroupField sets one group field back to baseline (the differ emits Name/Type/Members).
func revertGroupField(g *model.Group, b model.Group, field string) bool {
	switch field {
	case "Name":
		g.Name = b.Name
	case "Type":
		g.Type = b.Type
	case "Members":
		g.Members = append([]string(nil), b.Members...)
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
	case "Owner":
		e.Owner = b.Owner
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

// Equality via the differ itself, so "changed" and "undone" can never disagree.
func endpointsEqual(a, b model.Endpoint) bool {
	return len(diffEndpointFields(a, b)) == 0
}

func groupsEqual(a, b model.Group) bool {
	return len(diffGroups([]model.Group{a}, []model.Group{b})) == 0
}

func routingEqual(a, b model.RoutingList) bool {
	return len(diffRoutingLists([]model.RoutingList{a}, []model.RoutingList{b})) == 0
}
