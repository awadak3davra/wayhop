package health

import (
	"strings"
	"testing"

	"wayhop/internal/model"
)

// The advice the generic cause gives a down endpoint. Every transport it names except AmneziaWG
// runs INSIDE sing-box, so on a host without sing-box it is advice that cannot be followed.
const transportAdvice = "camouflaged transport"

// TestCoreMissingCause pins when the specific cause replaces the log-derived one. The rule is
// narrow on purpose: only a sing-box endpoint, only when core availability is KNOWN, and only when
// the answer is "absent". Asserting "no engine" from ignorance would be a worse lie than the
// generic timeout, so the unknown case must keep the old behaviour.
func TestCoreMissingCause(t *testing.T) {
	cases := []struct {
		name     string
		engine   model.Engine
		known    bool
		avail    bool
		specific bool
	}{
		{"singbox endpoint, core known absent", model.EngineSingBox, true, false, true},
		{"singbox endpoint, core present", model.EngineSingBox, true, true, false},
		{"singbox endpoint, availability unknown", model.EngineSingBox, false, false, false},
		{"kernel AmneziaWG needs no core", model.EngineAmneziaWG, true, false, false},
		{"adopted native tunnel needs no core", model.EngineExternal, true, false, false},
		{"a group carries no engine of its own", model.Engine(""), true, false, false},
	}
	for _, c := range cases {
		title, fix := coreMissingCause(c.engine, c.known, c.avail)
		if c.specific && title == "" {
			t.Errorf("%s: no specific cause, so the operator keeps the transport advice", c.name)
			continue
		}
		if !c.specific && title != "" {
			t.Errorf("%s: claimed %q when the log-derived cause should stand", c.name, title)
			continue
		}
		if !c.specific {
			continue
		}
		// The whole point is the remedy, not the label: it must send the operator to the install and
		// must not repeat the advice that cannot work.
		if strings.Contains(strings.ToLower(fix), transportAdvice) {
			t.Errorf("%s: the fix still offers a transport change: %q", c.name, fix)
		}
		if !strings.Contains(strings.ToLower(fix), "sing-box") {
			t.Errorf("%s: the fix does not name the engine to install: %q", c.name, fix)
		}
	}
}

// TestSnapshotUsesCoreMissingCause is the half the pure function cannot prove: that a down
// sing-box endpoint actually receives it through the snapshot the card reads, and that a kernel
// endpoint down beside it keeps the generic cause in the same snapshot.
func TestSnapshotUsesCoreMissingCause(t *testing.T) {
	p := model.Profile{Endpoints: []model.Endpoint{
		{ID: "e-vless", Name: "V", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
			Server: "203.0.113.9", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u"}},
		{ID: "e-awg", Name: "W", Engine: model.EngineAmneziaWG, Protocol: model.ProtoAmneziaWG,
			Server: "203.0.113.10", Port: 51820, Enabled: true,
			Params: map[string]any{"private_key": "aGVsbG8td29ybGQtaGVsbG8td29ybGQtaGVsbG8tMTI=", "peer_public_key": "aGVsbG8td29ybGQtaGVsbG8td29ybGQtaGVsbG8tMTI="}},
	}}
	m := NewMonitor(nil, health_newStore(t, p), nil, false)
	now := nowMS()
	for _, id := range []string{"e-vless", "e-awg"} {
		// flapThreshold=2: two consecutive Down observations flip Unknown->Down.
		m.record(id, id, "endpoint", Down, 0, now)
		m.record(id, id, "endpoint", Down, 0, now)
	}

	// Before the server reports availability, nothing about the core may be claimed.
	for _, v := range m.Snapshot() {
		if v.ID == "e-vless" && strings.Contains(v.Cause, "not installed") {
			t.Fatalf("claimed the engine is missing before anything reported it: %q", v.Cause)
		}
	}

	m.SetCoreAvailable(func() bool { return false })
	byID := map[string]View{}
	for _, v := range m.Snapshot() {
		byID[v.ID] = v
	}
	if got := byID["e-vless"]; !strings.Contains(got.CauseFix, "sing-box") ||
		strings.Contains(strings.ToLower(got.CauseFix), transportAdvice) {
		t.Errorf("the VLESS exit was not told its engine is missing: cause=%q fix=%q", got.Cause, got.CauseFix)
	}
	if got := byID["e-awg"]; strings.Contains(got.Cause, "not installed") {
		t.Errorf("the kernel exit was blamed on a missing engine it does not use: %q", got.Cause)
	}

	// The Test button reads a different path; the two must not disagree about one endpoint.
	single := m.viewWithCause("e-vless")
	if single.CauseFix != byID["e-vless"].CauseFix {
		t.Errorf("Test says %q but the card says %q", single.CauseFix, byID["e-vless"].CauseFix)
	}
}
