package server

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/ctflush"
	"wayhop/internal/pbr"
)

// The fresh-address reset reads the wd_ sets, records on the first look, then resets only unmarked
// flows to new addresses and WAN-marked ones to addresses a tunnel list's names just took, never one a
// device-scoped direct list keeps on the WAN.
func TestKeeneticFreshTickSelection(t *testing.T) {
	s := &Server{cfg: &config.Config{RoutingMode: "fast"}}
	plan := &pbr.Plan{Mask: 0x00ff0000,
		Egresses: []pbr.Egress{{Tag: "direct", Kind: pbr.EgressWAN, Mark: 0x10000, Table: 254},
			{Tag: "awg2", Kind: pbr.EgressInterface, Iface: "awg2", Mark: 0x20000, Table: 151}},
		Zones: []pbr.Zone{
			{Name: "list_home", EgressTag: "direct", Mark: 0x10000, Domains: []string{"cdn.example"}},
			{Name: "list_kid", EgressTag: "direct", Mark: 0x10000, SrcScoped: true, SrcV4: []string{"192.168.77.50/32"}, V4: []string{"192.0.2.0/24"}},
			{Name: "list_tun", EgressTag: "awg2", Mark: 0x20000, Domains: []string{"video.example"}},
		}}
	shared, fresh := netip.MustParseAddr("203.0.113.47"), netip.MustParseAddr("198.51.100.9")
	inTun := false
	oldRead, oldOpen := keeneticSetMembers, ctflushOpen
	t.Cleanup(func() { keeneticSetMembers, ctflushOpen = oldRead, oldOpen })
	keeneticSetMembers = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(_ context.Context, set string) ([]netip.Prefix, error) {
			switch {
			case set == "wd_list_home_4":
				return []netip.Prefix{netip.PrefixFrom(shared, 32)}, nil
			case set == "wd_list_tun_4" && inTun:
				return []netip.Prefix{netip.PrefixFrom(shared, 32), netip.PrefixFrom(fresh, 32)}, nil
			case strings.HasPrefix(set, "wd_"):
				return nil, nil
			}
			return nil, errors.New("not a wd_ set: " + set)
		}
	}
	tbl := &freshTable{entries: []ctflush.Entry{
		{Src: netip.MustParseAddr("192.168.77.10"), Dst: shared, ReplySrc: shared, Mark: 0x10000}, // WAN-saved: stale
		{Src: netip.MustParseAddr("192.168.77.50"), Dst: shared, ReplySrc: shared, Mark: 0x10000}, // kept by list_kid
		{Src: netip.MustParseAddr("192.168.77.11"), Dst: fresh, ReplySrc: fresh},                  // unmarked: reset
		{Src: netip.MustParseAddr("192.168.77.12"), Dst: fresh, ReplySrc: fresh, Mark: 0x20000},   // already the tunnel's
	}}
	ctflushOpen = func() (ctflush.Table, error) { return tbl, nil }
	k := &executionKernelArtifactV1{Plan: plan, Ipset: &executionKernelIpsetArtifactV1{DynamicDomainSets: true}}
	st := s.keeneticFreshTick(context.Background(), fastFresh{}, k)
	st = s.keeneticFreshTick(context.Background(), st, k)
	if len(tbl.deleted) != 0 {
		t.Fatalf("reset with nothing new: %v", tbl.deleted)
	}
	inTun = true
	s.keeneticFreshTick(context.Background(), st, k)
	want := map[netip.Addr]bool{netip.MustParseAddr("192.168.77.10"): true, netip.MustParseAddr("192.168.77.11"): true}
	if len(tbl.deleted) != 2 || !want[tbl.deleted[0]] || !want[tbl.deleted[1]] {
		t.Fatalf("deleted %v, want the stale WAN flow and the unmarked one", tbl.deleted)
	}
	if s.fastDNS.keenetic.freshLast != 2 {
		t.Errorf("freshLast = %d", s.fastDNS.keenetic.freshLast)
	}
}

// The warm-up asks for the plan's names, one at a time, at most fastWarmMax, and stops when the
// resolver stops answering.
func TestKeeneticFastWarmUp(t *testing.T) {
	s, f := useKeeneticFastFakes(t)
	var zones []pbr.Zone
	for i := 0; i < 3; i++ {
		var doms []string
		for j := 0; j < 300; j++ {
			doms = append(doms, fmt.Sprintf("n%d-%d.example", i, j))
		}
		zones = append(zones, pbr.Zone{Name: "list_" + string(rune('a'+i)), Domains: doms})
	}
	plan := &pbr.Plan{Zones: zones}
	if n := len(keeneticWarmNames(plan)); n != fastWarmMax {
		t.Fatalf("warm names = %d, want %d", n, fastWarmMax)
	}
	oldPace, oldResolve := fastWarmPace, fastWarmResolve
	t.Cleanup(func() { fastWarmPace, fastWarmResolve = oldPace, oldResolve })
	fastWarmPace = 0
	asked := 0
	fastWarmResolve = func(context.Context, string) {
		asked++
		if asked == 25 {
			f.mu.Lock()
			f.alive = errors.New("silent")
			f.mu.Unlock()
		}
	}
	s.keeneticFastWarmUp(context.Background(), plan)
	if asked != 30 || !strings.Contains(s.fastDNS.keenetic.warm, "stopped after 30") {
		t.Fatalf("asked %d, status %q", asked, s.fastDNS.keenetic.warm)
	}
}

// shrinkTable is a conntrack table whose deleted entries are gone.
type shrinkTable struct {
	entries []ctflush.Entry
	deletes int
}

func (f *shrinkTable) Dump(fam uint8, yield func(ctflush.Entry)) error {
	if fam == 2 {
		for _, e := range append([]ctflush.Entry(nil), f.entries...) {
			yield(e)
		}
	}
	return nil
}
func (f *shrinkTable) Delete(e ctflush.Entry) error {
	f.deletes++
	for i, x := range f.entries {
		if x.Src == e.Src {
			f.entries = append(f.entries[:i], f.entries[i+1:]...)
			break
		}
	}
	return nil
}
func (f *shrinkTable) Close() error { return nil }

// HUNT-K #6: a reset that hits the per-tick cap, or a conntrack table that cannot be opened, leaves
// the address new for the next tick instead of forgetting it.
func TestKeeneticFreshTickDefersUnfinished(t *testing.T) {
	s := &Server{cfg: &config.Config{RoutingMode: "fast"}}
	plan := &pbr.Plan{Mask: 0x00ff0000, Zones: []pbr.Zone{{Name: "list_tun", Mark: 0x20000, Domains: []string{"video.example"}}}}
	addr := netip.MustParseAddr("198.51.100.9")
	in := false
	oldRead, oldOpen := keeneticSetMembers, ctflushOpen
	t.Cleanup(func() { keeneticSetMembers, ctflushOpen = oldRead, oldOpen })
	keeneticSetMembers = func(executionKernelIpsetArtifactV1) ksMembers {
		return func(_ context.Context, set string) ([]netip.Prefix, error) {
			if set == "wd_list_tun_4" && in {
				return []netip.Prefix{netip.PrefixFrom(addr, 32)}, nil
			}
			return nil, nil
		}
	}
	tbl := &shrinkTable{}
	for i := 0; i < fastFreshFlushMax+100; i++ {
		tbl.entries = append(tbl.entries, ctflush.Entry{Src: netip.AddrFrom4([4]byte{10, 77, byte(i >> 8), byte(i)}), Dst: addr, ReplySrc: addr})
	}
	opens := 0
	ctflushOpen = func() (ctflush.Table, error) {
		opens++
		if opens == 1 {
			return nil, errors.New("netlink busy")
		}
		return tbl, nil
	}
	k := &executionKernelArtifactV1{Plan: plan, Ipset: &executionKernelIpsetArtifactV1{DynamicDomainSets: true}}
	st := s.keeneticFreshTick(context.Background(), fastFresh{}, k)
	in = true
	st = s.keeneticFreshTick(context.Background(), st, k) // open fails: deferred
	if tbl.deletes != 0 || st.addrs[addr] {
		t.Fatalf("after a failed open: deletes=%d remembered=%v", tbl.deletes, st.addrs[addr])
	}
	st = s.keeneticFreshTick(context.Background(), st, k) // capped at fastFreshFlushMax: deferred
	if tbl.deletes == 0 || st.addrs[addr] {
		t.Fatalf("after a capped reset: deletes=%d remembered=%v", tbl.deletes, st.addrs[addr])
	}
	st = s.keeneticFreshTick(context.Background(), st, k) // the rest
	if len(tbl.entries) != 0 || !st.addrs[addr] {
		t.Fatalf("left %d flows, remembered=%v", len(tbl.entries), st.addrs[addr])
	}
}
