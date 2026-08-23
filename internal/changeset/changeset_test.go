package changeset

import (
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

func ep(id, name string, mutate ...func(*model.Endpoint)) model.Endpoint {
	e := model.Endpoint{
		ID: id, Name: name, Engine: model.EngineSingBox, Protocol: model.ProtoTrojan,
		Server: "203.0.113.9", Port: 443, Enabled: true,
		Params: map[string]any{"password": "SUPERSECRET"},
	}
	for _, m := range mutate {
		m(&e)
	}
	return e
}

func find(t *testing.T, cs ChangeSet, id, field string) Change {
	t.Helper()
	for _, c := range cs.Changes {
		if c.ID == id && c.Field == field {
			return c
		}
	}
	t.Fatalf("no change for id=%q field=%q in %+v", id, field, cs.Changes)
	return Change{}
}

// §1.7: adding an endpoint.
func TestDiff_AddEndpoint(t *testing.T) {
	base := model.Profile{}
	desired := model.Profile{Endpoints: []model.Endpoint{ep("a", "Alpha")}}
	cs := Diff("r1", "r2", base, desired, config.Config{}, config.Config{})

	if cs.Count() != 1 {
		t.Fatalf("want 1 change, got %d: %+v", cs.Count(), cs.Changes)
	}
	c := cs.Changes[0]
	if c.Action != ActionAdded || c.ObjectType != "endpoint" || c.ObjectName != "Alpha" {
		t.Errorf("unexpected change: %+v", c)
	}
	if c.Subsystem != SubConnections || !c.RequiresApply || !c.Rollbackable {
		t.Errorf("metadata wrong: %+v", c)
	}
}

// §1.7: modifying one endpoint field — and ONLY that field is reported.
func TestDiff_ModifyOneField(t *testing.T) {
	base := model.Profile{Endpoints: []model.Endpoint{ep("a", "Alpha")}}
	desired := model.Profile{Endpoints: []model.Endpoint{ep("a", "Alpha", func(e *model.Endpoint) { e.Port = 8443 })}}
	cs := Diff("r1", "r2", base, desired, config.Config{}, config.Config{})

	if cs.Count() != 1 {
		t.Fatalf("only the port changed; want 1 change, got %d: %+v", cs.Count(), cs.Changes)
	}
	c := find(t, cs, "a", "Port")
	if c.Before != "443" || c.After != "8443" {
		t.Errorf("want 443 → 8443, got %q → %q", c.Before, c.After)
	}
	if !c.MayInterrupt {
		t.Error("changing the server port reconnects the egress — MayInterrupt should be set")
	}
}

// §1.7 + §1.2: changing a secret must NEVER reveal either value.
func TestDiff_SecretNeverRevealed(t *testing.T) {
	base := model.Profile{Endpoints: []model.Endpoint{ep("a", "Alpha")}}
	desired := model.Profile{Endpoints: []model.Endpoint{ep("a", "Alpha", func(e *model.Endpoint) {
		e.Params = map[string]any{"password": "AN-EVEN-MORE-SECRET-VALUE"}
	})}}
	cs := Diff("r1", "r2", base, desired, config.Config{}, config.Config{})

	c := find(t, cs, "a", "Password")
	if !c.Secret {
		t.Error("password change must be flagged Secret")
	}
	if c.Before != SecretSet || c.After != SecretChanged {
		t.Errorf("want %q → %q, got %q → %q", SecretSet, SecretChanged, c.Before, c.After)
	}
	// The hard invariant: no secret value anywhere in the rendered set.
	for _, ch := range cs.Changes {
		blob := ch.Before + " " + ch.After + " " + ch.Impact + " " + strings.Join(ch.Warnings, " ")
		for _, leak := range []string{"SUPERSECRET", "AN-EVEN-MORE-SECRET-VALUE"} {
			if strings.Contains(blob, leak) {
				t.Fatalf("secret leaked into the change set: %q in %+v", leak, ch)
			}
		}
	}
}

// A newly-set secret reads "Not set → Set"; a cleared one reads "Set → Removed".
func TestDiff_SecretTransitions(t *testing.T) {
	none := ep("a", "Alpha", func(e *model.Endpoint) { e.Params = map[string]any{} })
	with := ep("a", "Alpha")

	add := Diff("1", "2", model.Profile{Endpoints: []model.Endpoint{none}}, model.Profile{Endpoints: []model.Endpoint{with}}, config.Config{}, config.Config{})
	if c := find(t, add, "a", "Password"); c.Before != SecretNotSet || c.After != SecretSet {
		t.Errorf("add: want %q → %q, got %q → %q", SecretNotSet, SecretSet, c.Before, c.After)
	}
	del := Diff("1", "2", model.Profile{Endpoints: []model.Endpoint{with}}, model.Profile{Endpoints: []model.Endpoint{none}}, config.Config{}, config.Config{})
	if c := find(t, del, "a", "Password"); c.Before != SecretSet || c.After != SecretRemoved {
		t.Errorf("remove: want %q → %q, got %q → %q", SecretSet, SecretRemoved, c.Before, c.After)
	}
}

// A peer PUBLIC key is not a secret — it must show real values (users identify peers by it).
func TestDiff_PublicKeyNotRedacted(t *testing.T) {
	b := ep("a", "A", func(e *model.Endpoint) { e.Params = map[string]any{"peer_public_key": "OLDPUB="} })
	d := ep("a", "A", func(e *model.Endpoint) { e.Params = map[string]any{"peer_public_key": "NEWPUB="} })
	cs := Diff("1", "2", model.Profile{Endpoints: []model.Endpoint{b}}, model.Profile{Endpoints: []model.Endpoint{d}}, config.Config{}, config.Config{})
	c := find(t, cs, "a", "Peer public key")
	if c.Secret || c.Before != "OLDPUB=" || c.After != "NEWPUB=" {
		t.Errorf("peer public key should be shown verbatim, got %+v", c)
	}
}

// §1.7: deleting an endpoint — and an EXTERNAL tunnel must say it is not destroyed.
func TestDiff_RemoveEndpoint_ExternalNotDestroyed(t *testing.T) {
	extern := ep("nwg1", "Native NL", func(e *model.Endpoint) {
		e.Engine = model.EngineExternal
		e.Owner = model.OwnerExternal
	})
	cs := Diff("1", "2", model.Profile{Endpoints: []model.Endpoint{extern}}, model.Profile{}, config.Config{}, config.Config{})
	if cs.Count() != 1 {
		t.Fatalf("want 1 change, got %+v", cs.Changes)
	}
	c := cs.Changes[0]
	if c.Action != ActionRemoved || c.Subsystem != SubNativeVPN {
		t.Errorf("external tunnel removal should land in the native-VPN group: %+v", c)
	}
	if !strings.Contains(c.Impact, "left running") {
		t.Errorf("impact must state the tunnel itself is NOT destroyed, got %q", c.Impact)
	}
}

// §1.7: reordering routing rules reports both positions.
func TestDiff_ReorderRoutingLists(t *testing.T) {
	a := model.RoutingList{ID: "a", Name: "A", Enabled: true, Outbound: "x"}
	b := model.RoutingList{ID: "b", Name: "B", Enabled: true, Outbound: "x"}
	cs := Diff("1", "2",
		model.Profile{RoutingLists: []model.RoutingList{a, b}},
		model.Profile{RoutingLists: []model.RoutingList{b, a}},
		config.Config{}, config.Config{})

	var moves int
	for _, c := range cs.Changes {
		if c.Action == ActionReordered {
			moves++
			if c.Before == "" || c.After == "" || c.Before == c.After {
				t.Errorf("reorder must carry distinct before/after positions: %+v", c)
			}
		}
	}
	if moves != 2 {
		t.Fatalf("swapping two rules should report 2 moves, got %d: %+v", moves, cs.Changes)
	}
	if !strings.Contains(cs.Changes[0].Impact, "evaluated in order") {
		t.Errorf("reorder impact should explain rule precedence, got %q", cs.Changes[0].Impact)
	}
}

// §1.7: changing offload + routing mode land in the right subsystems with the right risk flags.
func TestDiff_Settings(t *testing.T) {
	b := config.Config{RoutingMode: "hybrid", Offload: "off"}
	d := config.Config{RoutingMode: "tun", Offload: "hw"}
	cs := Diff("1", "2", model.Profile{}, model.Profile{}, b, d)

	rm := find(t, cs, "settings", "Routing mode")
	if rm.Subsystem != SubFirewallPBR || !rm.MayInterrupt || len(rm.Warnings) == 0 {
		t.Errorf("routing-mode change must be flagged interrupting + warned: %+v", rm)
	}
	off := find(t, cs, "settings", "Flow offload")
	if off.Subsystem != SubOffload || off.Before != "off" || off.After != "hw" {
		t.Errorf("offload change wrong: %+v", off)
	}
	if !cs.MayInterrupt() || !cs.RequiresApply() {
		t.Error("set-level flags should reflect the interrupting routing-mode change")
	}
}

// §1.4: grouping drives the review panel; unchanged input must produce an EMPTY set (no noise).
func TestDiff_GroupingAndNoNoise(t *testing.T) {
	p := model.Profile{
		Endpoints:    []model.Endpoint{ep("a", "Alpha")},
		RoutingLists: []model.RoutingList{{ID: "r", Name: "R", Enabled: true, Outbound: "a"}},
	}
	same := Diff("1", "1", p, p, config.Config{}, config.Config{})
	if same.Count() != 0 {
		t.Fatalf("identical states must produce no changes, got %+v", same.Changes)
	}
	if same.RequiresApply() || same.MayInterrupt() {
		t.Error("an empty set requires nothing")
	}

	mixed := Diff("1", "2", p, model.Profile{
		Endpoints:    []model.Endpoint{ep("a", "Alpha", func(e *model.Endpoint) { e.Enabled = false })},
		RoutingLists: []model.RoutingList{{ID: "r", Name: "R2", Enabled: true, Outbound: "a"}},
	}, config.Config{}, config.Config{})
	g := mixed.BySubsystem()
	if len(g[SubConnections]) != 1 || len(g[SubRouting]) != 1 {
		t.Errorf("expected one change in each subsystem, got %+v", g)
	}
}

// The change set is pinned to its baseline so Apply can reject a stale review (§1.6).
func TestDiff_CarriesRevisions(t *testing.T) {
	cs := Diff("base-rev", "desired-rev", model.Profile{}, model.Profile{}, config.Config{}, config.Config{})
	if cs.BaselineRev != "base-rev" || cs.DesiredRev != "desired-rev" {
		t.Errorf("revisions not carried: %+v", cs)
	}
}

// A background feed refresh is the ONE change the daemon stages on purpose: it fetches, writes the
// cache and logs "staged for strict reviewed Apply" so remote prefixes never enter the datapath
// unreviewed. Nothing compared CIDRCache, so the operator got "you have unapplied changes — review
// them" over an empty review. Measured on the router: pending true, changeset count 0, after
// cidr-antifilter moved from 15751 to 15767 prefixes.
func TestFeedRefreshIsReviewable(t *testing.T) {
	list := func(cidrs ...string) model.Profile {
		return model.Profile{RoutingLists: []model.RoutingList{{
			ID: "cidr-antifilter", Name: "Antifilter", Outbound: "grp", Enabled: true,
			Source: "https://example.invalid/feed.txt", CIDRCache: cidrs,
		}}}
	}
	base := list("10.0.0.0/8", "192.0.2.0/24")
	desired := list("10.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24")

	cs := Diff("base", "desired", base, desired, config.Config{}, config.Config{})
	var feed *Change
	for i := range cs.Changes {
		if cs.Changes[i].Field == "IP feed" {
			feed = &cs.Changes[i]
		}
	}
	if feed == nil {
		t.Fatalf("a refreshed feed produced no reviewable change: %+v", cs.Changes)
	}
	if feed.Before != "2 prefixes" || feed.After != "3 prefixes" {
		t.Errorf("row says %q -> %q, want the prefix counts", feed.Before, feed.After)
	}
	// Nobody edited this: the feed moved under a list the operator set up once.
	if feed.Source != "external" {
		t.Errorf("source=%q, want external", feed.Source)
	}
	if !feed.RequiresApply {
		t.Errorf("a staged feed must require an Apply — that is why it was staged")
	}

	// Identical feeds are not a change, however long they are.
	if same := Diff("base", "same", base, list("10.0.0.0/8", "192.0.2.0/24"), config.Config{}, config.Config{}); len(same.Changes) != 0 {
		t.Errorf("an unchanged feed produced %d change(s): %+v", len(same.Changes), same.Changes)
	}
	// Same length, different content: a feed that swapped a prefix must not read as unchanged.
	swapped := Diff("base", "swapped", base, list("10.0.0.0/8", "203.0.113.0/24"), config.Config{}, config.Config{})
	if len(swapped.Changes) == 0 {
		t.Errorf("a same-length feed with different prefixes was reported as unchanged")
	}
}
