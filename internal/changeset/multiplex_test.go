package changeset

import (
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/model"
)

// TestMultiplexReviewRow: switching multiplex on, changing it and switching it off are each a
// "Multiplex" row with a readable before and after, and undoing the row restores the baseline's block.
func TestMultiplexReviewRow(t *testing.T) {
	for _, c := range []struct {
		m    *model.Multiplex
		want string
	}{
		{nil, "off"},
		{&model.Multiplex{Protocol: "smux", MaxConnections: 4}, "off"},
		{&model.Multiplex{Enabled: true}, "h2mux"},
		{&model.Multiplex{Enabled: true, Protocol: "smux", MaxConnections: 4, MinStreams: 4}, "smux, 4 connections, min 4 streams"},
		{&model.Multiplex{Enabled: true, Protocol: "yamux", MaxStreams: 8, Padding: true}, "yamux, max 8 streams, padding"},
		{&model.Multiplex{Enabled: true, MaxConnections: 4, Padding: true, Brutal: &model.Brutal{Enabled: true, UpMbps: 50, DownMbps: 100}},
			"h2mux, TCP Brutal 50/100 Mbps, pool unused (4 connections), padding"},
		{&model.Multiplex{Enabled: true, Protocol: "smux", Brutal: &model.Brutal{Enabled: true, UpMbps: 50, DownMbps: 100}},
			"smux, TCP Brutal 50/100 Mbps"},
		{&model.Multiplex{Enabled: true, MaxConnections: 2, Brutal: &model.Brutal{UpMbps: 5}}, "h2mux, 2 connections"},
		{&model.Multiplex{Enabled: true, Protocol: "mux.cool"}, "mux.cool"},
	} {
		if got := describeMultiplex(c.m); got != c.want {
			t.Errorf("describeMultiplex(%+v) = %q, want %q", c.m, got, c.want)
		}
	}

	prof := func(m *model.Multiplex) model.Profile {
		return model.Profile{Endpoints: []model.Endpoint{ep("a", "A", func(e *model.Endpoint) { e.Multiplex = m })}}
	}
	on := &model.Multiplex{Enabled: true, Protocol: "smux", MaxConnections: 4, MinStreams: 4}
	for _, c := range []struct {
		name          string
		base, desired *model.Multiplex
		before, after string
	}{
		{"switched on", nil, on, "off", "smux, 4 connections, min 4 streams"},
		{"changed", on, &model.Multiplex{Enabled: true, Protocol: "yamux", MaxStreams: 8}, "smux, 4 connections, min 4 streams", "yamux, max 8 streams"},
		{"switched off", on, nil, "smux, 4 connections, min 4 streams", "off"},
	} {
		base, desired := prof(c.base), prof(c.desired)
		cs := Diff("", "", base, desired, config.Config{}, config.Config{})
		row := find(t, cs, "a", "Multiplex")
		if row.Before != c.before || row.After != c.after || len(cs.Changes) != 1 {
			t.Fatalf("%s: row %+v (all %+v)", c.name, row, cs.Changes)
		}
		undone, _, err := Undo(base, desired, config.Config{}, config.Config{}, reqFor(row))
		if err != nil {
			t.Fatalf("%s: undo: %v", c.name, err)
		}
		if !sameJSON(undone.Endpoints[0].Multiplex, c.base) {
			t.Errorf("%s: undo left %+v, want %+v", c.name, undone.Endpoints[0].Multiplex, c.base)
		}
	}
	// A restored profile can hold a pool beside TCP Brutal (the save refuses one). A change to that
	// pool alone, or the save that drops it, is a row whose before and after differ.
	brutal := func(maxc int) *model.Multiplex {
		return &model.Multiplex{Enabled: true, Protocol: "smux", MaxConnections: maxc, Brutal: &model.Brutal{Enabled: true, UpMbps: 50, DownMbps: 100}}
	}
	for _, c := range [][2]*model.Multiplex{{brutal(4), brutal(8)}, {brutal(4), brutal(0)}} {
		cs := Diff("", "", prof(c[0]), prof(c[1]), config.Config{}, config.Config{})
		if row := find(t, cs, "a", "Multiplex"); row.Before == row.After {
			t.Errorf("a pool change beside TCP Brutal reads the same before and after: %+v", row)
		}
	}
	same := &model.Multiplex{Enabled: true, Protocol: "smux", MaxConnections: 4, MinStreams: 4}
	if cs := Diff("", "", prof(on), prof(same), config.Config{}, config.Config{}); len(cs.Changes) != 0 {
		t.Errorf("an unchanged multiplex reads as a change: %+v", cs.Changes)
	}
}
