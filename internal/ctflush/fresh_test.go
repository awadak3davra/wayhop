package ctflush

import (
	"net/netip"
	"testing"
)

func TestFlushFresh(t *testing.T) {
	a := netip.MustParseAddr
	lan, router := a("192.168.77.10"), a("192.168.77.1")
	dst, other := a("203.0.113.47"), a("198.51.100.8")
	ft := &fakeTable{entries: map[uint8][]Entry{2: {
		{Src: lan, Dst: dst, ReplySrc: dst},                // went direct before the set had it: flushed
		{Src: lan, Dst: dst, ReplySrc: dst, Mark: 0x20000}, // marked by the plane: kept
		{Src: lan, Dst: dst, ReplySrc: dst, Mark: 0x2023},  // the core's TUN has it: kept
		{Src: lan, Dst: dst, ReplySrc: router},             // the core's redirect: kept
		{Src: lan, Dst: other, ReplySrc: other},            // not a new address: kept
		{Src: router, Dst: dst, ReplySrc: dst},             // the router's own: kept
	}}}
	res, err := FlushFresh(ft, map[netip.Addr]bool{dst: true}, Options{Local: func(x netip.Addr) bool { return x == router }},
		Fresh{Mask: 0x00ff0000, CoreMark: 0x2023})
	if err != nil || res.Deleted != 1 || len(ft.deleted) != 1 || ft.deleted[0] != dst {
		t.Fatalf("res=%+v err=%v deleted=%v", res, err, ft.deleted)
	}
	if res, _ := FlushFresh(ft, nil, Options{}, Fresh{}); res.Seen != 0 {
		t.Error("no address dumps nothing")
	}
}

// TestFlushFreshStaleMark: a flow saved with the WAN mark by a weaker direct list goes
// when a tunnel list's names take its address; a flow already on the tunnel, and a WAN flow to an
// address no stronger list took, stay.
func TestFlushFreshStaleMark(t *testing.T) {
	a := netip.MustParseAddr
	lan := a("192.168.77.10")
	taken, plain := a("203.0.113.47"), a("198.51.100.8")
	ft := &fakeTable{entries: map[uint8][]Entry{2: {
		{Src: lan, Dst: taken, ReplySrc: taken, Mark: 0x10000}, // direct by a weaker list: flushed
		{Src: lan, Dst: taken, ReplySrc: taken, Mark: 0x20000}, // on the tunnel already: kept
		{Src: lan, Dst: plain, ReplySrc: plain, Mark: 0x10000}, // its new zone is direct: kept
	}}}
	res, err := FlushFresh(ft, map[netip.Addr]bool{taken: true, plain: true}, Options{},
		Fresh{Mask: 0x00ff0000, Stale: map[netip.Addr]uint32{taken: 0x10000}})
	if err != nil || res.Deleted != 1 || len(ft.deleted) != 1 || ft.deleted[0] != taken {
		t.Fatalf("res=%+v err=%v deleted=%v", res, err, ft.deleted)
	}
}

// TestFlushFreshStaleKeepsExempted: a WAN flow from a source a stronger direct exemption
// covers stays: its replacement would leave by the WAN again.
func TestFlushFreshStaleKeepsExempted(t *testing.T) {
	a := netip.MustParseAddr
	kid, other := a("192.168.77.50"), a("192.168.77.10")
	taken := a("203.0.113.47")
	ft := &fakeTable{entries: map[uint8][]Entry{2: {
		{Src: kid, Dst: taken, ReplySrc: taken, Mark: 0x10000},
		{Src: other, Dst: taken, ReplySrc: taken, Mark: 0x10000},
	}}}
	res, err := FlushFresh(ft, map[netip.Addr]bool{taken: true}, Options{},
		Fresh{Mask: 0x00ff0000, Stale: map[netip.Addr]uint32{taken: 0x10000}, Keep: func(s netip.Addr) bool { return s == kid }})
	if err != nil || res.Deleted != 1 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}
