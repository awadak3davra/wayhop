package server

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"wayhop/internal/ctflush"
	"wayhop/internal/pbr"
)

// leakyTable holds n flows to a tunnel list's destination that the chain missed (no mark).
type leakyTable struct {
	n, dumps, deleted int
}

func (l *leakyTable) Dump(fam uint8, visit func(ctflush.Entry)) error {
	l.dumps++
	if fam != 2 {
		return nil
	}
	for i := 0; i < l.n-l.deleted; i++ {
		visit(ctflush.Entry{Family: 2, Src: netip.MustParseAddr("192.168.50.10"),
			Dst: netip.AddrFrom4([4]byte{172, 64, byte(i >> 8), byte(i)})})
	}
	return nil
}
func (l *leakyTable) Delete(ctflush.Entry) error { l.deleted++; return nil }
func (l *leakyTable) Close() error               { return nil }

// A hook re-run that lands inside the 10 s gap, and a sweep that hit its cap, are not
// forgotten: the sweep owed runs on the first tick after the gap.
func TestLeakSweepOwedAfterGapOrCap(t *testing.T) {
	prof := overlapLANProfile()
	plan, _, err := pbr.Compile(&prof, pbr.Options{CollectDomainZones: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	clock := time.Unix(1_800_000_000, 0)
	tbl := &leakyTable{}
	l := &leakSweeper{open: func() (ctflush.Table, error) { return tbl, nil }, now: func() time.Time { return clock }}

	l.sweep(ctx, plan, nil, nil, true, "the Apply")
	if l.owed() {
		t.Fatal("a clean sweep left one owed")
	}
	// The hook ran 3 s later: inside the gap, skipped, and owed.
	clock = clock.Add(3 * time.Second)
	tbl.n = 5
	l.sweep(ctx, plan, nil, nil, false, "a firewall rebuild")
	if tbl.deleted != 0 {
		t.Fatal("swept inside the gap")
	}
	if l.owed() {
		t.Fatal("owed before the gap has passed")
	}
	clock = clock.Add(leakSweepGap)
	if !l.owed() {
		t.Fatal("the skipped sweep is not owed after the gap")
	}
	l.sweep(ctx, plan, nil, nil, false, "an owed sweep")
	if tbl.deleted != 5 || l.owed() {
		t.Fatalf("owed sweep: deleted %d, owed %v", tbl.deleted, l.owed())
	}
	// A capped sweep owes the rest.
	tbl.n, tbl.deleted = 5+leakSweepLimit+10, 5
	clock = clock.Add(leakSweepGap)
	l.sweep(ctx, plan, nil, nil, false, "a firewall rebuild")
	if tbl.deleted != 5+leakSweepLimit {
		t.Fatalf("capped sweep deleted %d", tbl.deleted)
	}
	clock = clock.Add(leakSweepGap)
	if !l.owed() {
		t.Fatal("a capped sweep owes nothing")
	}
	l.sweep(ctx, plan, nil, nil, false, "an owed sweep")
	if tbl.deleted != tbl.n || l.owed() {
		t.Fatalf("the rest: deleted %d of %d, owed %v", tbl.deleted, tbl.n, l.owed())
	}
}
