// Package changeset builds a CANONICAL, structured description of what an Apply would change on the
// router: the difference between a baseline revision and the desired state, expressed as semantic
// per-field entries ("DNS upstream: 1.1.1.1 → https://dns.example/dns-query") rather than a raw JSON
// or rendered-HTML diff.
//
// It exists so the user can answer, BEFORE anything touches the live router: what changed, what it
// was, what it becomes, which subsystem it hits, whether Apply/restart/reboot is needed, whether
// connectivity may drop, and whether it can be undone. Secrets are never carried: a changed key,
// password or token is reported only as "Not set → Set" / "Changed" / "Removed".
//
// Pure (no I/O, no clock) so it is exhaustively unit-testable and safe to call on every UI poll.
package changeset

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// Action is what happened to an object or field.
type Action string

const (
	ActionAdded     Action = "added"
	ActionModified  Action = "modified"
	ActionRemoved   Action = "removed"
	ActionReordered Action = "reordered"
	// ActionExternal marks a change made OUTSIDE WayHop (router drift) — it is reported, never
	// silently overwritten.
	ActionExternal Action = "externally_changed"
)

// Subsystem groups changes the way the review UI presents them.
type Subsystem string

const (
	SubConnections Subsystem = "connections"
	SubNativeVPN   Subsystem = "native_vpn"
	SubRouting     Subsystem = "routing"
	SubDeviceRules Subsystem = "device_rules"
	SubGroups      Subsystem = "groups"
	SubDNS         Subsystem = "dns"
	SubFirewallPBR Subsystem = "firewall_pbr"
	SubOffload     Subsystem = "offload"
	SubGeneral     Subsystem = "general"
	SubExternal    Subsystem = "external"
)

// Redaction placeholders. A secret's VALUE never appears in a change entry — only its transition.
const (
	SecretSet     = "Set"
	SecretNotSet  = "Not set"
	SecretChanged = "Changed"
	SecretRemoved = "Removed"
)

// Change is one reviewable difference. Every field the review UI needs is explicit so the panel can
// render, group, warn and undo without re-deriving anything.
type Change struct {
	ID         string    `json:"id"`          // stable object id (survives renames)
	ObjectType string    `json:"object_type"` // endpoint | group | routing_list | device_group | dns | setting
	ObjectName string    `json:"object_name"`
	Action     Action    `json:"action"`
	Field      string    `json:"field,omitempty"` // human field label; empty for whole-object add/remove
	Before     string    `json:"before,omitempty"`
	After      string    `json:"after,omitempty"`
	Source     string    `json:"source,omitempty"` // user | external | subscription
	Subsystem  Subsystem `json:"subsystem"`

	Impact                 string   `json:"impact,omitempty"` // expected runtime effect, in plain words
	RequiresApply          bool     `json:"requires_apply"`
	RequiresServiceRestart bool     `json:"requires_service_restart"`
	RequiresReboot         bool     `json:"requires_reboot"`
	MayInterrupt           bool     `json:"may_interrupt"`      // connectivity may drop while applying
	Rollbackable           bool     `json:"rollbackable"`       // covered by the fail-safe window
	Secret                 bool     `json:"secret,omitempty"`   // value redacted (never rendered)
	Warnings               []string `json:"warnings,omitempty"` // validation problems / conflicts
}

// ChangeSet is the full reviewable diff, pinned to the baseline it was computed against. Apply MUST
// verify BaselineRev is still current — applying a change set computed against a stale baseline is
// how concurrent edits get silently clobbered.
type ChangeSet struct {
	BaselineRev string   `json:"baseline_rev"`
	DesiredRev  string   `json:"desired_rev"`
	Changes     []Change `json:"changes"`
}

// Count is the number of pending changes (drives the review badge / banner).
func (cs ChangeSet) Count() int { return len(cs.Changes) }

// BySubsystem groups changes for the review panel, preserving within-group order.
func (cs ChangeSet) BySubsystem() map[Subsystem][]Change {
	out := map[Subsystem][]Change{}
	for _, c := range cs.Changes {
		out[c.Subsystem] = append(out[c.Subsystem], c)
	}
	return out
}

// RequiresApply reports whether anything in the set needs an Apply to take effect.
func (cs ChangeSet) RequiresApply() bool {
	for _, c := range cs.Changes {
		if c.RequiresApply {
			return true
		}
	}
	return false
}

// MayInterrupt reports whether applying this set may briefly drop connectivity — the warning the
// review panel must show before "Test changes" / "Apply permanently".
func (cs ChangeSet) MayInterrupt() bool {
	for _, c := range cs.Changes {
		if c.MayInterrupt {
			return true
		}
	}
	return false
}

// secretParamKeys are endpoint Params whose VALUE must never surface in a diff. Kept here as the
// single source of truth so a new protocol's secret can be added in exactly one place.
var secretParamKeys = map[string]bool{
	"private_key": true, "peer_public_key": false, // peer PUBLIC key is not secret
	"pre_shared_key": true, "password": true, "uuid": true, "token": true,
	"obfs_password": true, "auth": true, "auth_str": true, "secret": true,
	"short_id": true, "api_key": true, "subscription": true,
}

// IsSecretField reports whether a params key carries a secret (used by the diff and by callers that
// render field labels).
func IsSecretField(key string) bool { return secretParamKeys[strings.ToLower(strings.TrimSpace(key))] }

// isEmptyParam reports whether a params value is indistinguishable from "not set" (absent, nil, or
// the empty string). Used so an absent key and an explicitly-empty one never render as a change.
func isEmptyParam(v any) bool {
	if v == nil {
		return true
	}
	s, ok := v.(string)
	return ok && s == ""
}

// secretTransition renders a secret's change WITHOUT either value.
func secretTransition(before, after any) (string, string) {
	b, a := fmt.Sprint(before), fmt.Sprint(after)
	hadBefore, hasAfter := !isEmptyParam(before) && b != "<nil>", !isEmptyParam(after) && a != "<nil>"
	switch {
	case !hadBefore && hasAfter:
		return SecretNotSet, SecretSet
	case hadBefore && !hasAfter:
		return SecretSet, SecretRemoved
	default:
		return SecretSet, SecretChanged
	}
}

// Diff computes the canonical change set between a baseline and a desired state. baseRev/desiredRev
// are opaque revision identifiers (e.g. the canonical config hashes) used for stale-baseline checks.
func Diff(baseRev, desiredRev string, base, desired model.Profile, baseCfg, desiredCfg config.Config) ChangeSet {
	cs := ChangeSet{BaselineRev: baseRev, DesiredRev: desiredRev}
	cs.Changes = append(cs.Changes, diffEndpoints(base.Endpoints, desired.Endpoints)...)
	cs.Changes = append(cs.Changes, diffGroups(base.Groups, desired.Groups)...)
	cs.Changes = append(cs.Changes, diffRoutingLists(base.RoutingLists, desired.RoutingLists)...)
	cs.Changes = append(cs.Changes, diffRules(base.Rules, desired.Rules)...)
	cs.Changes = append(cs.Changes, diffDeviceGroups(base.DeviceGroups, desired.DeviceGroups)...)
	cs.Changes = append(cs.Changes, diffDNSPlane(base.DNS, desired.DNS)...)
	cs.Changes = append(cs.Changes, diffSettings(baseCfg, desiredCfg)...)
	return cs
}

// diffRules covers Profile.Rules (per-device / source routing). Without this the review could report
// "no changes" while an Apply genuinely rewrote the routing plane.
func diffRules(base, desired []model.Rule) []Change {
	var out []Change
	byID := map[string]model.Rule{}
	for _, r := range base {
		byID[r.ID] = r
	}
	seen := map[string]bool{}
	mk := func(id, name string, a Action) Change {
		return Change{
			ID: id, ObjectType: "rule", ObjectName: name, Action: a, Subsystem: SubDeviceRules,
			Source: "user", Impact: "changes which traffic this rule sends where",
			RequiresApply: true, RequiresServiceRestart: true, Rollbackable: true,
		}
	}
	for _, d := range desired {
		seen[d.ID] = true
		b, ok := byID[d.ID]
		if !ok {
			out = append(out, mk(d.ID, d.ID, ActionAdded))
			continue
		}
		if !sameJSON(b, d) {
			c := mk(d.ID, d.ID, ActionModified)
			c.Field = "Rule definition"
			c.Before, c.After = summariseRule(b), summariseRule(d)
			out = append(out, c)
		}
	}
	for _, b := range base {
		if !seen[b.ID] {
			c := mk(b.ID, b.ID, ActionRemoved)
			c.MayInterrupt = true
			out = append(out, c)
		}
	}
	return out
}

// summariseRule renders a rule's routing intent without dumping its raw JSON (and without values that
// could carry anything sensitive).
func summariseRule(r model.Rule) string {
	out := "→ " + nameOr(r.Outbound, "(no outbound)")
	if r.Disabled { // Disabled is the INVERTED toggle in the model (zero value = enabled)
		out += " (disabled)"
	}
	return out
}

// diffDeviceGroups covers Profile.DeviceGroups (named LAN device sets a rule can scope to).
func diffDeviceGroups(base, desired []model.DeviceGroup) []Change {
	var out []Change
	byID := map[string]model.DeviceGroup{}
	for _, g := range base {
		byID[g.ID] = g
	}
	seen := map[string]bool{}
	mk := func(id, name string, a Action) Change {
		return Change{
			ID: id, ObjectType: "device_group", ObjectName: name, Action: a, Subsystem: SubDeviceRules,
			Source: "user", Impact: "changes which devices the rules using this group apply to",
			RequiresApply: true, RequiresServiceRestart: true, Rollbackable: true,
		}
	}
	for _, d := range desired {
		seen[d.ID] = true
		b, ok := byID[d.ID]
		if !ok {
			out = append(out, mk(d.ID, nameOr(d.Name, d.ID), ActionAdded))
			continue
		}
		if !sameJSON(b, d) {
			c := mk(d.ID, nameOr(d.Name, d.ID), ActionModified)
			c.Field = "Members"
			c.Before, c.After = countWord(len(b.Members), "device", "devices"), countWord(len(d.Members), "device", "devices")
			out = append(out, c)
		}
	}
	for _, b := range base {
		if !seen[b.ID] {
			out = append(out, mk(b.ID, nameOr(b.Name, b.ID), ActionRemoved))
		}
	}
	return out
}

// diffDNSPlane covers Profile.DNS. Resolver ADDRESSES can embed account tokens (personal DoH URLs), so
// this deliberately reports only structural facts — never a resolver's address.
func diffDNSPlane(base, desired *model.DNSSettings) []Change {
	mk := func(field, before, after string) Change {
		return Change{
			ID: "dns", ObjectType: "dns", ObjectName: "DNS plane", Action: ActionModified,
			Field: field, Before: before, After: after, Subsystem: SubDNS, Source: "user",
			Impact:        "changes how names are resolved for routed traffic",
			RequiresApply: true, RequiresServiceRestart: true, Rollbackable: true,
		}
	}
	switch {
	case base == nil && desired == nil:
		return nil
	case base == nil:
		return []Change{{
			ID: "dns", ObjectType: "dns", ObjectName: "DNS plane", Action: ActionAdded, Subsystem: SubDNS,
			Source: "user", Impact: "WayHop starts managing DNS resolution",
			RequiresApply: true, RequiresServiceRestart: true, Rollbackable: true,
		}}
	case desired == nil:
		return []Change{{
			ID: "dns", ObjectType: "dns", ObjectName: "DNS plane", Action: ActionRemoved, Subsystem: SubDNS,
			Source: "user", Impact: "WayHop stops managing DNS; the core falls back to its default resolver",
			RequiresApply: true, RequiresServiceRestart: true, MayInterrupt: true, Rollbackable: true,
		}}
	}
	var out []Change
	if base.Enabled != desired.Enabled {
		c := mk("DNS management", boolWord(base.Enabled), boolWord(desired.Enabled))
		c.MayInterrupt = true
		out = append(out, c)
	}
	if base.LeakProof != desired.LeakProof {
		out = append(out, mk("Leak protection", boolWord(base.LeakProof), boolWord(desired.LeakProof)))
	}
	if base.FakeIP != desired.FakeIP {
		out = append(out, mk("FakeIP", boolWord(base.FakeIP), boolWord(desired.FakeIP)))
	}
	if base.Strategy != desired.Strategy {
		out = append(out, mk("Strategy", nameOr(base.Strategy, "default"), nameOr(desired.Strategy, "default")))
	}
	if len(base.Servers) != len(desired.Servers) {
		out = append(out, mk("Resolvers", countWord(len(base.Servers), "resolver", "resolvers"), countWord(len(desired.Servers), "resolver", "resolvers")))
	} else if !sameJSON(base.Servers, desired.Servers) {
		// Same count but different content: report the fact, never the addresses (tokens ride URLs).
		out = append(out, mk("Resolvers", SecretSet, SecretChanged))
	}
	if len(base.Rules) != len(desired.Rules) || !sameJSON(base.Rules, desired.Rules) {
		out = append(out, mk("DNS rules", countWord(len(base.Rules), "rule", "rules"), countWord(len(desired.Rules), "rule", "rules")))
	}
	if base.Final != desired.Final {
		out = append(out, mk("Default resolver", nameOr(base.Final, "none"), nameOr(desired.Final, "none")))
	}
	if base.Intercept != desired.Intercept {
		c := mk("Intercept DNS", boolWord(base.Intercept), boolWord(desired.Intercept))
		c.MayInterrupt = true
		out = append(out, c)
	}
	if base.InterceptRejectEncrypted != desired.InterceptRejectEncrypted {
		out = append(out, mk("Reject encrypted DNS", boolWord(base.InterceptRejectEncrypted), boolWord(desired.InterceptRejectEncrypted)))
	}
	if base.DisableCache != desired.DisableCache {
		// Rendered as the CACHE, not as the flag behind it: an operator reads "DNS cache: On -> Off",
		// where "Disable cache: Off -> On" makes them decode a double negative to learn the same thing.
		out = append(out, mk("DNS cache", boolWord(!base.DisableCache), boolWord(!desired.DisableCache)))
	}
	if base.IndependentCache != desired.IndependentCache {
		out = append(out, mk("Independent cache", boolWord(base.IndependentCache), boolWord(desired.IndependentCache)))
	}
	if base.ClientSubnet != desired.ClientSubnet {
		out = append(out, mk("Client subnet", nameOr(base.ClientSubnet, "none"), nameOr(desired.ClientSubnet, "none")))
	}
	if base.ReverseMapping != desired.ReverseMapping {
		out = append(out, mk("Reverse mapping", boolWord(base.ReverseMapping), boolWord(desired.ReverseMapping)))
	}
	return out
}

// describeHealth renders a probe the way it was configured: what is fetched, how often, and the
// latency that counts as unhealthy. A nil probe means the built-in default, which is a real
// difference from an explicit one and must not render as an empty string on either side.
func describeHealth(h *model.Health) string {
	if h == nil {
		return "default"
	}
	var parts []string
	if h.URL != "" {
		parts = append(parts, h.URL)
	}
	if h.Interval > 0 {
		parts = append(parts, "every "+strconv.Itoa(h.Interval)+"s")
	}
	if h.Tolerance > 0 {
		parts = append(parts, "tolerance "+strconv.Itoa(h.Tolerance)+"ms")
	}
	if len(parts) == 0 {
		return "default"
	}
	return strings.Join(parts, ", ")
}

// describeTLS renders TLS settings structurally. Reality's PublicKey/ShortID and any fingerprint are
// credential-ish, so only the SHAPE is reported — never the values.
func describeTLS(t *model.TLS) string {
	if t == nil || !t.Enabled {
		return "off"
	}
	parts := []string{nameOr(t.Type, "tls")}
	if t.SNI != "" {
		parts = append(parts, "SNI "+t.SNI)
	}
	if t.Insecure {
		parts = append(parts, "insecure")
	}
	if t.Fragment || t.RecordFragment {
		parts = append(parts, "fragmented")
	}
	return strings.Join(parts, ", ")
}

// describeTransport renders the stream transport structurally (type + host; a ws/grpc path can carry
// a token-like secret, so it is not rendered).
func describeTransport(tr *model.Transport) string {
	if tr == nil || tr.Type == "" {
		return "tcp"
	}
	if tr.Host != "" {
		return tr.Type + " (host " + tr.Host + ")"
	}
	return tr.Type
}

// sameJSON compares two values by their canonical JSON encoding — a dependable deep-equality for the
// model's plain data structs without hand-writing a comparison per type.
func sameJSON(a, b any) bool {
	ab, errA := json.Marshal(a)
	bb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(ab) == string(bb)
}

// ---- endpoints -------------------------------------------------------------------------------

func endpointSubsystem(e model.Endpoint) Subsystem {
	if e.Engine == model.EngineExternal {
		return SubNativeVPN
	}
	return SubConnections
}

func endpointName(e model.Endpoint) string {
	if strings.TrimSpace(e.Name) != "" {
		return e.Name
	}
	return e.ID
}

func diffEndpoints(base, desired []model.Endpoint) []Change {
	var out []Change
	baseByID := map[string]model.Endpoint{}
	for _, e := range base {
		baseByID[e.ID] = e
	}
	seen := map[string]bool{}

	for _, d := range desired {
		seen[d.ID] = true
		b, existed := baseByID[d.ID]
		if !existed {
			out = append(out, Change{
				ID: d.ID, ObjectType: "endpoint", ObjectName: endpointName(d), Action: ActionAdded,
				Subsystem: endpointSubsystem(d), Source: "user",
				Impact:        "a new egress becomes available to routing rules",
				RequiresApply: true, RequiresServiceRestart: true, Rollbackable: true,
			})
			continue
		}
		out = append(out, diffEndpointFields(b, d)...)
	}
	for _, b := range base {
		if seen[b.ID] {
			continue
		}
		c := Change{
			ID: b.ID, ObjectType: "endpoint", ObjectName: endpointName(b), Action: ActionRemoved,
			Subsystem: endpointSubsystem(b), Source: "user",
			Impact:        "traffic routed through this egress must move elsewhere",
			RequiresApply: true, RequiresServiceRestart: true, MayInterrupt: true, Rollbackable: true,
		}
		// Deleting a WayHop endpoint never destroys an EXTERNAL tunnel — say so, since that is the
		// single most alarming-looking removal in the review list.
		if b.Engine == model.EngineExternal {
			c.Impact = "WayHop stops routing through this native tunnel; the tunnel itself is left running (it is owned by the router, not WayHop)"
			c.MayInterrupt = true
		}
		out = append(out, c)
	}
	return out
}

// endpointScalarFields are the plain, non-secret fields worth reporting individually.
func endpointScalarFields(e model.Endpoint) map[string]string {
	m := map[string]string{
		"Name":      e.Name,
		"Server":    e.Server,
		"Port":      itoaOmitZero(e.Port),
		"Protocol":  string(e.Protocol),
		"Engine":    string(e.Engine),
		"Enabled":   boolWord(e.Enabled),
		"MTU":       itoaOmitZero(e.MTU),
		"Keepalive": itoaOmitZero(e.PersistentKeepalive),
	}
	if e.Owner != "" {
		m["Owner"] = string(e.Owner)
	}
	// Only where there is a choice to report: a WayHop AmneziaWG connection, or a stray flag on
	// anything else (which Validate refuses, and the review should not hide).
	if e.AWGUserspace {
		m[fieldAWGEngine] = "amneziawg-go"
	} else if e.Engine == model.EngineAmneziaWG {
		m[fieldAWGEngine] = "automatic"
	}
	return m
}

// fieldAWGEngine is the review row for Endpoint.AWGUserspace.
const fieldAWGEngine = "AmneziaWG engine"

func diffEndpointFields(b, d model.Endpoint) []Change {
	var out []Change
	sub := endpointSubsystem(d)
	mk := func(field, before, after string, secret bool) Change {
		c := Change{
			ID: d.ID, ObjectType: "endpoint", ObjectName: endpointName(d), Action: ActionModified,
			Field: field, Before: before, After: after, Subsystem: sub, Source: "user",
			RequiresApply: true, RequiresServiceRestart: true, Rollbackable: true, Secret: secret,
		}
		switch field {
		case "Enabled":
			c.MayInterrupt = true
			c.Impact = "turns this egress on/off; traffic using it will move"
		case fieldAWGEngine:
			c.MayInterrupt = true
			c.Impact = "moves this connection between the router's own AmneziaWG and amneziawg-go; its tunnel restarts"
		case "Server", "Port":
			c.MayInterrupt = true
			c.Impact = "reconnects this egress to a different address"
		default:
			c.Impact = "the egress is reconfigured and reconnects"
		}
		return c
	}

	bs, ds := endpointScalarFields(b), endpointScalarFields(d)
	keys := make([]string, 0, len(ds))
	for k := range ds {
		keys = append(keys, k)
	}
	for k := range bs {
		if _, ok := ds[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		if bs[k] != ds[k] {
			out = append(out, mk(k, bs[k], ds[k], false))
		}
	}

	// TLS / Transport are whole sub-structs. They carry security-relevant settings (Reality keys,
	// SNI, uTLS fingerprint, ws/grpc paths) and were previously invisible, so a change to them
	// produced an empty review while Apply genuinely rewrote the outbound. Reported structurally —
	// a Reality private/short id must never be rendered.
	if !sameJSON(b.TLS, d.TLS) {
		out = append(out, mk("TLS settings", describeTLS(b.TLS), describeTLS(d.TLS), false))
	}
	if !sameJSON(b.Transport, d.Transport) {
		out = append(out, mk("Transport", describeTransport(b.Transport), describeTransport(d.Transport), false))
	}
	// Health decides failover. A group can start electing a different member purely because the probe
	// URL, its interval or its latency tolerance moved, so this is a routing change in everything but
	// name. It moved the revision and rendered nothing, which is the banner-over-empty-review defect.
	if !sameJSON(b.Health, d.Health) {
		out = append(out, mk("Health test", describeHealth(b.Health), describeHealth(d.Health), false))
	}

	// Params: secrets report only a transition; non-secrets show real before/after.
	pkeys := map[string]bool{}
	for k := range b.Params {
		pkeys[k] = true
	}
	for k := range d.Params {
		pkeys[k] = true
	}
	sorted := make([]string, 0, len(pkeys))
	for k := range pkeys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		bv, dv := b.Params[k], d.Params[k]
		if fmt.Sprint(bv) == fmt.Sprint(dv) {
			continue
		}
		// An ABSENT key and an explicitly-empty one mean the same thing to every consumer, but they
		// differ as Go values — reporting that as a change produced phantom rows, and for a secret key
		// the flatly false "Set → Removed" (nothing was ever set). Treat both as "not present".
		if isEmptyParam(bv) && isEmptyParam(dv) {
			continue
		}
		if IsSecretField(k) {
			before, after := secretTransition(bv, dv)
			out = append(out, mk(fieldLabel(k), before, after, true))
			continue
		}
		out = append(out, mk(fieldLabel(k), valueWord(bv), valueWord(dv), false))
	}
	return out
}

// ---- groups ----------------------------------------------------------------------------------

func diffGroups(base, desired []model.Group) []Change {
	var out []Change
	byID := map[string]model.Group{}
	for _, g := range base {
		byID[g.ID] = g
	}
	seen := map[string]bool{}
	for _, d := range desired {
		seen[d.ID] = true
		b, ok := byID[d.ID]
		if !ok {
			out = append(out, Change{
				ID: d.ID, ObjectType: "group", ObjectName: nameOr(d.Name, d.ID), Action: ActionAdded,
				Subsystem: SubGroups, Source: "user", Impact: "a new failover/selection group becomes available",
				RequiresApply: true, RequiresServiceRestart: true, Rollbackable: true,
			})
			continue
		}
		mk := func(field, before, after string) Change {
			return Change{
				ID: d.ID, ObjectType: "group", ObjectName: nameOr(d.Name, d.ID), Action: ActionModified,
				Field: field, Before: before, After: after, Subsystem: SubGroups, Source: "user",
				Impact: "changes which egress this group selects", RequiresApply: true,
				RequiresServiceRestart: true, MayInterrupt: true, Rollbackable: true,
			}
		}
		if b.Name != d.Name {
			out = append(out, mk("Name", b.Name, d.Name))
		}
		if b.Type != d.Type {
			out = append(out, mk("Type", string(b.Type), string(d.Type)))
		}
		if strings.Join(b.Members, ", ") != strings.Join(d.Members, ", ") {
			out = append(out, mk("Members", strings.Join(b.Members, ", "), strings.Join(d.Members, ", ")))
		}
		if !sameJSON(b.Test, d.Test) {
			out = append(out, mk("Health test", describeHealth(b.Test), describeHealth(d.Test)))
		}
		if b.KillSwitch != d.KillSwitch {
			c := mk("Kill switch", boolWord(b.KillSwitch), boolWord(d.KillSwitch))
			c.Impact = "when every member is down, traffic is dropped instead of leaking to the provider"
			out = append(out, c)
		}
		if b.InterruptOnSwitch != d.InterruptOnSwitch {
			out = append(out, mk("Interrupt on switch", boolWord(b.InterruptOnSwitch), boolWord(d.InterruptOnSwitch)))
		}
		if b.Managed != d.Managed {
			out = append(out, mk("Managed by WayHop", boolWord(b.Managed), boolWord(d.Managed)))
		}
	}
	for _, b := range base {
		if !seen[b.ID] {
			out = append(out, Change{
				ID: b.ID, ObjectType: "group", ObjectName: nameOr(b.Name, b.ID), Action: ActionRemoved,
				Subsystem: SubGroups, Source: "user", Impact: "rules pointing at this group must be repointed",
				RequiresApply: true, RequiresServiceRestart: true, MayInterrupt: true, Rollbackable: true,
			})
		}
	}
	return out
}

// ---- routing lists (order-sensitive) ----------------------------------------------------------

func diffRoutingLists(base, desired []model.RoutingList) []Change {
	var out []Change
	basePos, baseByID := map[string]int{}, map[string]model.RoutingList{}
	for i, r := range base {
		basePos[r.ID] = i
		baseByID[r.ID] = r
	}
	// Relative order over the lists present in BOTH states — the only order change a user can
	// meaningfully review or undo. Absolute indices shift whenever anything is added/removed.
	relBase, relDesired := relativeOrder(base, desired), relativeOrder(desired, base)
	seen := map[string]bool{}
	for _, d := range desired {
		seen[d.ID] = true
		b, ok := baseByID[d.ID]
		if !ok {
			out = append(out, Change{
				ID: d.ID, ObjectType: "routing_list", ObjectName: nameOr(d.Name, d.ID), Action: ActionAdded,
				Subsystem: SubRouting, Source: "user", Impact: "new destinations start being routed by this rule",
				RequiresApply: true, RequiresServiceRestart: true, Rollbackable: true,
			})
			continue
		}
		mk := func(field, before, after string) Change {
			return Change{
				ID: d.ID, ObjectType: "routing_list", ObjectName: nameOr(d.Name, d.ID), Action: ActionModified,
				Field: field, Before: before, After: after, Subsystem: SubRouting, Source: "user",
				Impact: "changes where matching traffic is sent", RequiresApply: true,
				RequiresServiceRestart: true, Rollbackable: true,
			}
		}
		if b.Name != d.Name {
			out = append(out, mk("Name", b.Name, d.Name))
		}
		if b.Outbound != d.Outbound {
			c := mk("Outbound", b.Outbound, d.Outbound)
			c.MayInterrupt = true
			out = append(out, c)
		}
		if b.Enabled != d.Enabled {
			c := mk("Enabled", boolWord(b.Enabled), boolWord(d.Enabled))
			c.MayInterrupt = true
			out = append(out, c)
		}
		if b.Source != d.Source {
			out = append(out, mk("Source URL", b.Source, d.Source))
		}
		// How the downloaded rule-set is PARSED. Reading a binary .srs as text (or the reverse) yields
		// a list that matches nothing, so this decides whether the feed above works at all.
		if b.Format != d.Format {
			out = append(out, mk("Feed format", sourceOrNone(b.Format), sourceOrNone(d.Format)))
		}
		if len(b.Manual) != len(d.Manual) || strings.Join(b.Manual, ",") != strings.Join(d.Manual, ",") {
			out = append(out, mk("Entries", countWord(len(b.Manual), "entry", "entries"), countWord(len(d.Manual), "entry", "entries")))
		}
		// The downloaded feed. Nothing compared it, and it is the ONE thing the background refresher
		// stages: it fetches, writes the cache and logs "staged for strict reviewed Apply" — on purpose,
		// so remote prefixes never enter the datapath unreviewed. Without this row the operator was told
		// "you have unapplied changes, review them" and shown an empty review: measured on the router,
		// pending true with count 0, after cidr-antifilter went from 15751 to 15767 prefixes.
		//
		// Source is "external", not "user": nobody edited this. It is the feed moving underneath a list
		// the operator set up once, which is exactly why it deserves a review line of its own.
		if !sameStrings(b.CIDRCache, d.CIDRCache) {
			c := mk("IP feed", countWord(len(b.CIDRCache), "prefix", "prefixes"), countWord(len(d.CIDRCache), "prefix", "prefixes"))
			c.Source = "external"
			c.Impact = "the set of destinations this list matches changes"
			out = append(out, c)
		}
		// The downloaded NAME feed, the twin of the prefix feed above and staged the same way. Nothing
		// compared it either, so a names refresh that genuinely changed what the list matches arrived
		// as "you have unapplied changes" over an empty review — the same failure the row above was
		// added to fix, surviving in the other feed type because only one of the pair was covered.
		if !sameStrings(b.DomainCache, d.DomainCache) {
			c := mk("Name feed", countWord(len(b.DomainCache), "name", "names"), countWord(len(d.DomainCache), "name", "names"))
			c.Source = "external"
			c.Impact = "the set of destinations this list matches changes"
			out = append(out, c)
		}
		// Where each feed is fetched FROM is the operator's own edit, and it decides what the next
		// refresh will put in the caches above. Changing it silently is how a list quietly starts
		// matching a different internet.
		if b.CIDRSource != d.CIDRSource {
			out = append(out, mk("IP feed source", sourceOrNone(b.CIDRSource), sourceOrNone(d.CIDRSource)))
		}
		if b.DomainSource != d.DomainSource {
			out = append(out, mk("Name feed source", sourceOrNone(b.DomainSource), sourceOrNone(d.DomainSource)))
		}
		// Which connection DOWNLOADS the list. On a router whose ISP blocks the feed this is the
		// difference between a list that refreshes and one that silently stops, so it is a routing
		// decision in its own right rather than a preference.
		if b.DownloadVia != d.DownloadVia {
			out = append(out, mk("Download via", outboundOrDefault(b.DownloadVia), outboundOrDefault(d.DownloadVia)))
		}
		// How often the feed re-fetches. It does not change today's datapath, which is why it carries
		// no restart, but it changes how current the list stays — and an unreviewable edit is exactly
		// what leaves an operator staring at a banner with an empty review.
		if b.RefreshHours != d.RefreshHours {
			c := mk("Auto-update", refreshWord(b.RefreshHours), refreshWord(d.RefreshHours))
			c.Impact = "changes how often this list re-fetches"
			c.RequiresServiceRestart = false
			out = append(out, c)
		}
		// WHO the list applies to. Narrowing a list to one device group leaves every other device
		// routed differently than before, which is a routing change by any reading.
		if b.ScopeMode != d.ScopeMode || !sameStrings(b.ScopeGroups, d.ScopeGroups) {
			c := mk("Applies to", scopeWord(b.ScopeMode, b.ScopeGroups), scopeWord(d.ScopeMode, d.ScopeGroups))
			c.MayInterrupt = true
			out = append(out, c)
		}
		// Order matters for routing evaluation — report a move explicitly with both positions.
		// Compared on RELATIVE order (position among the lists present in BOTH states), not absolute
		// index: inserting or deleting any earlier list shifts every following absolute index, which
		// previously fabricated a "reordered" row for rules the user never touched.
		if op, ok := relBase[d.ID]; ok && op != relDesired[d.ID] {
			out = append(out, Change{
				ID: d.ID, ObjectType: "routing_list", ObjectName: nameOr(d.Name, d.ID), Action: ActionReordered,
				Field: "Position", Before: "#" + strconv.Itoa(op+1), After: "#" + strconv.Itoa(relDesired[d.ID]+1),
				Subsystem: SubRouting, Source: "user",
				Impact:        "rules are evaluated in order, so this changes which rule wins for overlapping destinations",
				RequiresApply: true, RequiresServiceRestart: true, Rollbackable: true,
			})
		}
	}
	for _, b := range base {
		if !seen[b.ID] {
			out = append(out, Change{
				ID: b.ID, ObjectType: "routing_list", ObjectName: nameOr(b.Name, b.ID), Action: ActionRemoved,
				Subsystem: SubRouting, Source: "user", Impact: "these destinations fall back to the default route",
				RequiresApply: true, RequiresServiceRestart: true, MayInterrupt: true, Rollbackable: true,
			})
		}
	}
	return out
}

// ---- settings --------------------------------------------------------------------------------

func diffSettings(b, d config.Config) []Change {
	var out []Change
	mk := func(field, before, after string, sub Subsystem, impact string, interrupt bool) Change {
		return Change{
			ID: "settings", ObjectType: "setting", ObjectName: field, Action: ActionModified,
			Field: field, Before: before, After: after, Subsystem: sub, Source: "user",
			Impact: impact, RequiresApply: true, RequiresServiceRestart: true,
			MayInterrupt: interrupt, Rollbackable: true,
		}
	}
	if b.RoutingMode != d.RoutingMode {
		c := mk("Routing mode", nameOr(b.RoutingMode, "default"), nameOr(d.RoutingMode, "default"), SubFirewallPBR,
			"changes how ALL traffic is captured and routed", true)
		c.Warnings = append(c.Warnings, "switching routing mode rebuilds the datapath; verify connectivity inside the fail-safe window")
		out = append(out, c)
	}
	if b.Offload != d.Offload {
		out = append(out, mk("Flow offload", nameOr(b.Offload, "off"), nameOr(d.Offload, "off"), SubOffload,
			"changes whether flows are accelerated in software/hardware", false))
	}
	if b.RuleSetDetour != d.RuleSetDetour {
		out = append(out, mk("Rule-set download route", nameOr(b.RuleSetDetour, "direct"), nameOr(d.RuleSetDetour, "direct"), SubRouting,
			"changes which path routing-list downloads use (direct downloads fail on a censored network)", false))
	}
	return out
}

// ---- small helpers ---------------------------------------------------------------------------

// relativeOrder ranks ss by position, counting ONLY the ids that also exist in other. Two states then
// compare on the same shared subset, so adding or deleting a list cannot fabricate a reorder for the
// untouched lists around it.
// sameStrings compares two feeds without building a joined copy of either: a routing list carries
// tens of thousands of prefixes, and this runs every time the review panel is opened.
// sourceOrNone names a feed URL for a review row. An empty source is "none" rather than a blank
// cell, so removing a feed reads as a decision instead of a rendering gap.
func sourceOrNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "none"
	}
	return s
}

// outboundOrDefault names the connection a download goes through. Empty means the ordinary path,
// which the panel calls Direct — printing "" would leave the operator guessing which it was.
func outboundOrDefault(s string) string {
	if strings.TrimSpace(s) == "" {
		return "direct"
	}
	return s
}

// refreshWord renders an auto-update interval in the units the panel offers it in. 0 is the daemon's
// default rather than "never", and saying "0 hours" would read as "constantly".
func refreshWord(h int) string {
	switch {
	case h <= 0:
		return "default"
	case h%24 == 0 && h > 24:
		return fmt.Sprintf("every %d days", h/24)
	case h == 24:
		return "daily"
	case h == 1:
		return "every hour"
	default:
		return fmt.Sprintf("every %d hours", h)
	}
}

// scopeWord renders which devices a list applies to. The group COUNT is carried because the mode
// alone ("only") does not say whether the last group was just removed, which would silently widen
// or narrow the list.
func scopeWord(mode string, groups []string) string {
	switch mode {
	case "only":
		return fmt.Sprintf("only %s", countWord(len(groups), "device group", "device groups"))
	case "except":
		return fmt.Sprintf("all except %s", countWord(len(groups), "device group", "device groups"))
	default:
		return "all devices"
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func relativeOrder(ss, other []model.RoutingList) map[string]int {
	inOther := make(map[string]bool, len(other))
	for _, r := range other {
		inOther[r.ID] = true
	}
	out, rank := make(map[string]int, len(ss)), 0
	for _, r := range ss {
		if !inOther[r.ID] {
			continue
		}
		out[r.ID] = rank
		rank++
	}
	return out
}

func nameOr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func boolWord(b bool) string {
	if b {
		return "On"
	}
	return "Off"
}

func itoaOmitZero(n int) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func countWord(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// valueWord renders a non-secret param value for display, keeping it short and never nil-ish.
//
// STRUCTURED values are never rendered. A param can nest secrets that a top-level key check cannot
// see — the WireGuard "peers" param is a list of peer objects each carrying pre_shared_key, and
// fmt.Sprint on it would dump those keys verbatim into the diff (and into the undo response). Any
// non-scalar therefore reports only that it changed. Scalars (string/number/bool) are safe and
// remain fully visible, which is what makes a diff useful.
func valueWord(v any) string {
	if v == nil {
		return ""
	}
	if !isScalar(v) {
		return structuredValue
	}
	s := fmt.Sprint(v)
	if s == "<nil>" {
		return ""
	}
	return s
}

// structuredValue is shown instead of a nested/complex param's contents (see valueWord).
const structuredValue = "(structured value)"

// isScalar reports whether v is a simple value safe to render verbatim in a diff.
func isScalar(v any) bool {
	switch v.(type) {
	case string, bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64, json.Number:
		return true
	}
	return false
}

// fieldLabel turns a params key into a human label ("peer_public_key" -> "Peer public key").
func fieldLabel(k string) string {
	s := strings.ReplaceAll(strings.TrimSpace(k), "_", " ")
	if s == "" {
		return k
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
