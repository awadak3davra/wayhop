package changeset

import (
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// QUIC tuning on a TUIC connection is two review rows with real values, and undoing one leaves the
// other pending.
func TestDiff_QUICTuningRowsAndUndo(t *testing.T) {
	tuic := func(e *model.Endpoint) { e.Protocol = model.ProtoTUIC }
	base := model.Profile{Endpoints: []model.Endpoint{ep("a", "A", tuic)}}
	desired := model.Profile{Endpoints: []model.Endpoint{ep("a", "A", tuic, func(e *model.Endpoint) {
		e.Params = map[string]any{"password": "SUPERSECRET",
			model.ParamQUICInitialPacketSize: float64(1232), model.ParamQUICDisablePMTUD: true}
	})}}
	cs := Diff("", "", base, desired, config.Config{}, config.Config{})
	size := find(t, cs, "a", "Initial packet size")
	pmtud := find(t, cs, "a", "Disable path mtu discovery")
	if size.Before != "" || size.After != "1232" || size.Secret || pmtud.After != "true" {
		t.Fatalf("rows = %+v / %+v", size, pmtud)
	}
	gotP, gotC, err := Undo(base, desired, config.Config{}, config.Config{}, reqFor(size))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := gotP.Endpoints[0].Params[model.ParamQUICInitialPacketSize]; ok {
		t.Errorf("undo kept the size: %v", gotP.Endpoints[0].Params)
	}
	after := Diff("", "", base, gotP, config.Config{}, gotC)
	if hasRow(after, size) || !hasRow(after, pmtud) {
		t.Errorf("after undoing the size: %+v", after.Changes)
	}
}
