package ctflush

import (
	"net/netip"
	"testing"
)

func TestFlushMarkOnlyTheListsFlows(t *testing.T) {
	a := netip.MustParseAddr
	ft := &fakeTable{entries: map[uint8][]Entry{
		2: {
			{Family: 2, Src: a("192.168.50.10"), Dst: a("149.154.167.51"), Mark: 0x00090000},
			{Family: 2, Src: a("192.168.50.11"), Dst: a("91.108.56.130"), Mark: 0x00090000 | 0x250}, // other bits kept
			{Family: 2, Src: a("192.168.50.12"), Dst: a("8.8.8.8"), Mark: 0x00020000},               // another egress
			{Family: 2, Src: a("192.168.50.1"), Dst: a("149.154.167.99"), Mark: 0x00090000},         // the router's own
		},
	}}
	own := func(x netip.Addr) bool { return x == a("192.168.50.1") }
	res, err := FlushMark(ft, 0x00090000, 0x00ff0000, Options{Local: own})
	if err != nil {
		t.Fatal(err)
	}
	if res.Deleted != 2 || len(ft.deleted) != 2 || ft.deleted[0] != a("149.154.167.51") || ft.deleted[1] != a("91.108.56.130") {
		t.Fatalf("deleted %v (%+v)", ft.deleted, res)
	}
	if _, err := FlushMark(ft, 0x250, 0x00ff0000, Options{}); err == nil {
		t.Fatal("a mark outside the mask must be refused")
	}
	ft.deleted = nil
	res, _ = FlushMark(ft, 0x00090000, 0x00ff0000, Options{Limit: 1})
	if res.Deleted != 1 || !res.Capped {
		t.Fatalf("limit: %+v", res)
	}
}
