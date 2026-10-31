package store

import (
	"path/filepath"
	"testing"

	"wayhop/internal/model"
)

// Switching an exit off with "move it to a group" must never move it into a group that holds it.
//
// Measured: with g=[a,b] and a rule on g, switching a off was refused (409 ENDPOINT_IN_USE) and the
// panel offered [b g]. Picking g was answered 200 and saved g.Members=[g b]; Validate() then failed
// with `group "g": cannot contain itself`. That is not the disabled-reference class publish() refuses,
// so it was stored, and every later Apply failed until someone found and fixed the group by hand.
// The nested form (g1=[a,x], g2=[g1,y], pick g2) saved g1=[g2 x], a cycle Validate() rejects too.
func TestDisableReplacing_NeverMovesAnExitIntoAGroupThatHoldsIt(t *testing.T) {
	ep := func(id, ip string) model.Endpoint {
		return model.Endpoint{ID: id, Enabled: true, Engine: model.EngineSingBox,
			Protocol: model.ProtoTrojan, Server: ip, Port: 443,
			Params: map[string]any{"password": "x"}}
	}
	open := func(t *testing.T, p model.Profile) (*Store, string) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "profile.json")
		st, err := Open(path)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if err := st.Replace(p); err != nil {
			t.Fatalf("seed: %v", err)
		}
		return st, path
	}
	contains := func(ss []string, s string) bool {
		for _, x := range ss {
			if x == s {
				return true
			}
		}
		return false
	}
	members := func(st *Store, id string) []string {
		p := st.Profile()
		if g := p.GroupByID(id); g != nil {
			return g.Members
		}
		return nil
	}
	off := func(e model.Endpoint) model.Endpoint { e.Enabled = false; return e }
	// The stored file is what the next boot and the next Apply see, so check it after a reopen.
	stillValidOnDisk := func(t *testing.T, path string) {
		t.Helper()
		re, err := Open(path)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		p := re.Profile()
		if err := p.Validate(); err != nil {
			t.Fatalf("the saved profile no longer validates, so every later Apply fails: %v", err)
		}
	}

	t.Run("direct holder", func(t *testing.T) {
		a, b := ep("a", "198.51.100.1"), ep("b", "198.51.100.2")
		st, path := open(t, model.Profile{
			Endpoints: []model.Endpoint{a, b},
			Groups:    []model.Group{{ID: "g", Type: "fallback", Members: []string{"a", "b"}}},
			Rules:     []model.Rule{{ID: "default", Default: true, Outbound: "g"}},
		})
		if offered := st.EndpointDisableReplacements("a"); contains(offered, "g") {
			t.Errorf("g holds a, so moving a into g makes g contain itself; offered %v", offered)
		}
		if err := st.SetEndpointDisabledReplacing(off(a), "g"); err == nil {
			t.Errorf("replacing a with the group that holds it was accepted; g.Members=%v", members(st, "g"))
		}
		stillValidOnDisk(t, path)
	})

	t.Run("ancestor of the holder", func(t *testing.T) {
		a, x, y := ep("a", "198.51.100.1"), ep("x", "198.51.100.2"), ep("y", "198.51.100.3")
		st, path := open(t, model.Profile{
			Endpoints: []model.Endpoint{a, x, y},
			Groups: []model.Group{
				{ID: "g1", Type: "fallback", Members: []string{"a", "x"}},
				{ID: "g2", Type: "fallback", Members: []string{"g1", "y"}},
			},
			Rules: []model.Rule{{ID: "default", Default: true, Outbound: "g2"}},
		})
		offered := st.EndpointDisableReplacements("a")
		for _, holder := range []string{"g1", "g2"} {
			if contains(offered, holder) {
				t.Errorf("%s reaches a, so moving a into it closes a cycle; offered %v", holder, offered)
			}
		}
		if err := st.SetEndpointDisabledReplacing(off(a), "g2"); err == nil {
			t.Errorf("replacing a with g2 (which holds g1, which holds a) was accepted; g1.Members=%v", members(st, "g1"))
		}
		stillValidOnDisk(t, path)
	})

	// The refusal must stay narrow: an exit and a group that does NOT reach a are real answers.
	t.Run("unrelated group still works", func(t *testing.T) {
		a, b, c := ep("a", "198.51.100.1"), ep("b", "198.51.100.2"), ep("c", "198.51.100.3")
		st, path := open(t, model.Profile{
			Endpoints: []model.Endpoint{a, b, c},
			Groups: []model.Group{
				{ID: "g", Type: "fallback", Members: []string{"a", "b"}},
				{ID: "h", Type: "fallback", Members: []string{"c"}},
			},
			Rules: []model.Rule{{ID: "default", Default: true, Outbound: "g"}},
		})
		offered := st.EndpointDisableReplacements("a")
		if !contains(offered, "b") || !contains(offered, "h") {
			t.Fatalf("b and h do not hold a and must stay on offer; offered %v", offered)
		}
		if err := st.SetEndpointDisabledReplacing(off(a), "h"); err != nil {
			t.Fatalf("moving a into an unrelated group: %v", err)
		}
		if got := members(st, "g"); len(got) != 2 || got[0] != "h" || got[1] != "b" {
			t.Errorf("g.Members = %v, want [h b]", got)
		}
		stillValidOnDisk(t, path)
	})
}
