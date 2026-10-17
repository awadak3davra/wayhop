package changeset

import (
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// Choosing amneziawg-go for a connection is a row in the review - it restarts the tunnel on another
// engine - and one that Undo can take back on its own.
func TestAWGEngineChoiceIsReviewedAndUndoable(t *testing.T) {
	awgEP := func(userspace bool) model.Endpoint {
		return ep("a", "Home", func(e *model.Endpoint) {
			e.Engine, e.Protocol, e.AWGUserspace = model.EngineAmneziaWG, model.ProtoAmneziaWG, userspace
		})
	}
	base := model.Profile{Endpoints: []model.Endpoint{awgEP(false)}}
	desired := model.Profile{Endpoints: []model.Endpoint{awgEP(true)}}

	rows := Diff("", "", base, desired, config.Config{}, config.Config{}).Changes
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want the engine change alone", rows)
	}
	if r := rows[0]; r.Field != fieldAWGEngine || r.Before != "automatic" || r.After != "amneziawg-go" || !r.MayInterrupt {
		t.Errorf("row = %+v", r)
	}

	got, _, err := Undo(base, desired, config.Config{}, config.Config{},
		UndoRequest{Scope: ScopeField, ID: "a", Field: fieldAWGEngine})
	if err != nil {
		t.Fatal(err)
	}
	if got.Endpoints[0].AWGUserspace {
		t.Error("undo left the connection on amneziawg-go")
	}

	// A connection with no choice to make reports none: no row appears for a proxy.
	proxy := model.Profile{Endpoints: []model.Endpoint{ep("p", "Proxy")}}
	if _, ok := endpointScalarFields(proxy.Endpoints[0])[fieldAWGEngine]; ok {
		t.Error("a non-AmneziaWG connection reports an AmneziaWG engine")
	}
}
