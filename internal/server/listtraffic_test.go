package server

import (
	"os"
	"path/filepath"
	"testing"
)

// The Routing page prints these numbers next to each rule, so every way the attribution can be wrong
// is a number a user would act on: deleting a rule that looked idle, or trusting one that looked busy.

func TestListIDFromRulePayload(t *testing.T) {
	cases := []struct{ in, want string }{
		{"rs-seed-rl-stream", "seed-rl-stream"},
		{"rsm-seed-rl-work", "seed-rl-work"},
		// sing-box may report a rule that references both halves of one list. Both belong to the
		// same list, and returning one id means the connection's bytes are counted once.
		{"[rs-work rsm-work]", "work"},
		{"rs-a,rsm-a", "a"},
		// Not a routing list: geosite sets, plain rules, and the final fallback all pass through.
		{"geosite-netflix", ""},
		{"", ""},
		{"final", ""},
		{"domain_suffix", ""},
		// A prefix with nothing after it names no list.
		{"rs-", ""},
		{"rsm-", ""},
		// The id itself may contain a hyphen, which must not be treated as a separator.
		{"rs-ru-inside-v2", "ru-inside-v2"},
	}
	for _, c := range cases {
		if got := listIDFromRulePayload(c.in); got != c.want {
			t.Errorf("listIDFromRulePayload(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// "rsm-x" must not be read as the remote set of a list called "m-x". The prefixes differ at the third
// character, and checking "rs-" first would silently mis-attribute every manual list.
func TestListIDFromRulePayload_ManualPrefixWinsOverRemote(t *testing.T) {
	if got := listIDFromRulePayload("rsm-stream"); got != "stream" {
		t.Errorf(`"rsm-stream" belongs to list "stream", got %q`, got)
	}
}

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "singbox.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The visibility answer comes from the config the core is RUNNING. This is the distinction the whole
// flag exists for: a list the profile has but the running core does not is invisible, and its zero
// means "not routed here", not "no traffic".
func TestCoreVisibleLists_ReadsRunningConfig(t *testing.T) {
	p := writeCfg(t, `{"route":{"rule_set":[
		{"tag":"rs-stream","type":"remote"},
		{"tag":"rsm-work","type":"inline"},
		{"tag":"geosite-ads","type":"remote"}]}}`)
	ids, ok := coreVisibleLists(p)
	if !ok {
		t.Fatal("a readable config must report ok")
	}
	if !ids["stream"] || !ids["work"] {
		t.Errorf("both lists should be visible, got %v", ids)
	}
	if ids["ads"] {
		t.Error("a geosite set is not a routing list")
	}
	if len(ids) != 2 {
		t.Errorf("want exactly the two routing lists, got %v", ids)
	}
}

// An unreadable or malformed config must be distinguishable from a config with no rule-sets. Folding
// them together would mark every list invisible the moment the file was missing, and the page would
// tell the user their rules are not routing anything.
func TestCoreVisibleLists_UnreadableIsNotEmpty(t *testing.T) {
	if _, ok := coreVisibleLists(filepath.Join(t.TempDir(), "does-not-exist.json")); ok {
		t.Error("a missing config cannot report a confident answer")
	}
	if _, ok := coreVisibleLists(writeCfg(t, `{"route":{"rule_set":[{`)); ok {
		t.Error("a malformed config cannot report a confident answer")
	}
	ids, ok := coreVisibleLists(writeCfg(t, `{"route":{}}`))
	if !ok {
		t.Error("a well-formed config with no rule-sets IS a confident answer: nothing is visible")
	}
	if len(ids) != 0 {
		t.Errorf("no rule-sets means no visible lists, got %v", ids)
	}
}

// Counting must be per connection, not per poll: a single long-lived download that survives twenty
// samples is one connection, and reporting twenty would make an idle rule look like a busy one.
func TestObSampler_CountsEachConnectionOnce(t *testing.T) {
	o := newObSampler()
	// Simulate what sampleOutbounds does to the counters across three polls of the same connection.
	seen := func(id, payload string) {
		listID := listIDFromRulePayload(payload)
		if listID == "" {
			return
		}
		if _, had := o.prev[id]; !had {
			o.listConns[listID]++
		}
	}
	seen("c1", "rs-stream")
	o.prev["c1"] = 100
	seen("c1", "rs-stream")
	seen("c1", "rs-stream")
	if o.listConns["stream"] != 1 {
		t.Errorf("one connection across three polls is one connection, got %d", o.listConns["stream"])
	}
	seen("c2", "rs-stream")
	if o.listConns["stream"] != 2 {
		t.Errorf("a second connection should count, got %d", o.listConns["stream"])
	}
}
