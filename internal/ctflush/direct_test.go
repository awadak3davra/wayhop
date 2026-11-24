package ctflush

import (
	"net/netip"
	"reflect"
	"testing"

	"wayhop/internal/pbr"
)

// Flows a LAN device opened straight to the provider while the core was down are
// removed when it returns; everything the kernel plane or the core holds, and everything that was
// not opened by the LAN, stays.
func TestFlushDirectRemovesFlowsOpenedBesideTheCore(t *testing.T) {
	const coreMark = 0x2023
	p := plan([]pbr.Egress{{Tag: "direct", Kind: pbr.EgressWAN, Mark: 0x10000}, awg1},
		pbr.Zone{Name: "ru", Mark: 0x20000, V4: []string{"203.0.113.0/24"}})
	p.BypassV4 = []string{"198.51.100.48/32"}
	flow := func(src, dst, reply string, mark uint32) Entry {
		e := Entry{Family: 2, Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst), Mark: mark, tuple: []byte{4, 0, 1, 0}}
		if reply != "" {
			e.ReplySrc = netip.MustParseAddr(reply)
		}
		if e.Dst.Is6() {
			e.Family = 10
		}
		return e
	}
	lan := "192.168.77.20"
	entries := []Entry{
		flow(lan, "93.184.216.34", "93.184.216.34", 0),               // direct, opened in the lapse: removed
		flow(lan, "198.51.100.135", "198.51.100.135", 0x2024),        // the core's own "bypass" mark on a flow it never took: removed
		flow(lan, "198.51.100.136", "192.168.77.1", 0),               // TCP the core redirected to itself
		flow(lan, "198.51.100.137", "198.51.100.137", coreMark),      // UDP the core's TUN carries
		flow(lan, "203.0.113.9", "203.0.113.9", 0),                   // a kernel list's destination: the plane re-marks it
		flow(lan, "198.51.100.138", "198.51.100.138", 0x20000),       // a kernel list's flow by its mark
		flow(lan, "198.51.100.139", "198.51.100.139", 0x10000),       // the operator's direct list
		flow(lan, "192.168.40.9", "192.168.40.9", 0),                 // LAN to LAN
		flow(lan, "198.51.100.48", "198.51.100.48", 0),               // a tunnel's own server
		flow("192.168.77.1", "198.51.100.140", "198.51.100.140", 0),  // the router's own
		flow("203.0.113.200", "198.51.100.141", "198.51.100.141", 0), // not opened by the LAN
		flow(lan, "198.51.100.142", "", 0),                           // a dump without a reply tuple: not judged
		flow("2001:db8:aa::5", "2606:4700::1", "2606:4700::1", 0),    // IPv6
	}
	isLAN := func(a netip.Addr) bool {
		return netip.MustParsePrefix("192.168.77.0/24").Contains(a) || netip.MustParsePrefix("2001:db8:aa::/64").Contains(a)
	}
	local := func(a netip.Addr) bool { return a == netip.MustParseAddr("192.168.77.1") }
	run := func(v6 bool) []netip.Addr {
		f := &fakeTable{entries: map[uint8][]Entry{}}
		for _, e := range entries {
			f.entries[e.Family] = append(f.entries[e.Family], e)
		}
		res, err := FlushDirect(f, p, Options{Limit: 100, Local: local}, Direct{CoreMark: coreMark, LAN: isLAN, V6: v6})
		if err != nil || res.Deleted != len(f.deleted) {
			t.Fatalf("flush: %+v %v", res, err)
		}
		return f.deleted
	}
	want := []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("198.51.100.135")}
	if got := run(false); !reflect.DeepEqual(got, want) {
		t.Fatalf("IPv4-only core: deleted %v, want %v", got, want)
	}
	// A TUN that carries IPv6: IPv6 opened beside the core is its to take back as well.
	if got := run(true); !reflect.DeepEqual(got, append(want, netip.MustParseAddr("2606:4700::1"))) {
		t.Fatalf("dual-stack core: deleted %v", got)
	}
	// Nobody can say who the LAN is: nothing is touched.
	f := &fakeTable{entries: map[uint8][]Entry{2: entries[:2]}}
	if res, err := FlushDirect(f, p, Options{}, Direct{CoreMark: coreMark}); err != nil || res.Deleted != 0 || res.Seen != 0 {
		t.Fatalf("without a LAN test: %+v %v", res, err)
	}
	// The cap holds.
	f = &fakeTable{entries: map[uint8][]Entry{2: entries[:2]}}
	if res, _ := FlushDirect(f, p, Options{Limit: 1}, Direct{CoreMark: coreMark, LAN: isLAN}); res.Deleted != 1 || !res.Capped {
		t.Fatalf("cap: %+v", res)
	}
}

// The reply tuple's source is read from the dump: it is what tells a redirected flow from a direct one.
func TestParseEntryReadsTheReplySource(t *testing.T) {
	attr := func(typ uint16, payload []byte) []byte {
		b := make([]byte, 4, nlAlign(4+len(payload)))
		b[0], b[1] = byte(4+len(payload)), byte((4+len(payload))>>8)
		b[2], b[3] = byte(typ), byte(typ>>8)
		b = append(b, payload...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}
	tuple := func(typ uint16, src, dst [4]byte) []byte {
		ips := append(attr(ctaIPv4Src, src[:]), attr(ctaIPv4Dst, dst[:])...)
		return attr(typ|0x8000, attr(ctaTupleIP|0x8000, ips))
	}
	payload := make([]byte, nfgenHdrLen)
	payload = append(payload, tuple(ctaTupleOrig, [4]byte{192, 168, 77, 20}, [4]byte{93, 184, 216, 34})...)
	payload = append(payload, tuple(ctaTupleRepl, [4]byte{192, 168, 77, 1}, [4]byte{192, 168, 77, 20})...)
	e, err := parseEntry(2, payload)
	if err != nil {
		t.Fatal(err)
	}
	if e.Dst != netip.MustParseAddr("93.184.216.34") || e.ReplySrc != netip.MustParseAddr("192.168.77.1") {
		t.Fatalf("entry %+v: the reply source of a redirected flow is the router", e)
	}
}
