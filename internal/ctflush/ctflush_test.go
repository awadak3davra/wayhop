package ctflush

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"wayhop/internal/pbr"
)

func plan(egresses []pbr.Egress, zones ...pbr.Zone) *pbr.Plan {
	return &pbr.Plan{Mask: 0x00ff0000, Egresses: egresses, Zones: zones}
}

var (
	wan  = pbr.Egress{Tag: "direct", Mark: 0}
	awg1 = pbr.Egress{Tag: "awg1", Mark: 0x20000}
	awg2 = pbr.Egress{Tag: "awg2", Mark: 0x30000}
)

func entry(dst string, mark uint32) Entry {
	return Entry{Family: 2, Src: netip.MustParseAddr("10.20.30.10"), Dst: netip.MustParseAddr(dst), Mark: mark, tuple: []byte{4, 0, 1, 0}}
}

func from(e Entry, src string) Entry { e.Src = netip.MustParseAddr(src); return e }

type staleCase struct {
	name  string
	e     Entry
	stale bool
}

func checkStale(t *testing.T, d decider, cases []staleCase) {
	t.Helper()
	for _, tc := range cases {
		if got := d.stale(tc.e); got != tc.stale {
			t.Errorf("%s: stale = %v, want %v", tc.name, got, tc.stale)
		}
	}
}

func movePlans() (old, cur *pbr.Plan) {
	old = plan([]pbr.Egress{wan, awg1, awg2},
		pbr.Zone{Name: "a-tg", Mark: 0x30000, V4: []string{"198.18.0.0/20", "198.19.4.0/22"}},
		pbr.Zone{Name: "b-ru", Mark: 0x20000, V4: []string{"192.0.2.0/24"}},
		pbr.Zone{Name: "c-gone", Mark: 0x20000, V4: []string{"203.0.113.0/24"}})
	// Telegram moves from awg2 to awg1; c-gone's list is removed; a new zone on awg2 appears.
	cur = plan([]pbr.Egress{wan, awg1, awg2},
		pbr.Zone{Name: "a-tg", Mark: 0x20000, V4: []string{"198.18.0.0/20", "198.19.4.0/22"}},
		pbr.Zone{Name: "b-ru", Mark: 0x20000, V4: []string{"192.0.2.0/24"}},
		pbr.Zone{Name: "d-new", Mark: 0x30000, V4: []string{"198.51.100.0/24"}})
	cur.BypassV4 = []string{"198.18.7.99/32"}
	return old, cur
}

// nft: a saved egress mark is restored and ends the chain, so only such flows are pinned; the zones
// re-mark every other flow on its next packet.
func TestStaleNft(t *testing.T) {
	old, cur := movePlans()
	d := newDecider(old, cur, Options{Local: func(a netip.Addr) bool { return a == netip.MustParseAddr("100.64.7.7") }})
	checkStale(t, d, []staleCase{
		{"moved list: telegram flow pinned to awg2", entry("198.18.7.51", 0x30000), true},
		{"unchanged list keeps its flow", entry("192.0.2.242", 0x20000), false},
		{"already on the new exit", entry("198.19.4.10", 0x20000), false},
		{"removed list: flow still pinned to its tunnel", entry("203.0.113.9", 0x20000), true},
		{"marked, in no zone now: the plan sends it to the WAN", entry("198.19.200.8", 0x20000), true},
		{"unmarked flow into a new zone: the zones re-mark it", entry("198.51.100.7", 0), false},
		{"plain WAN traffic in no zone", entry("198.19.200.1", 0), false},
		{"private destination: pinned to main ahead of the marks", entry("10.20.31.1", 0x30000), false},
		{"bypass destination: routed WAN ahead of the restore", entry("198.18.7.99", 0x30000), false},
		{"the router's own connection", from(entry("198.18.7.51", 0x30000), "100.64.7.7"), false},
		{"a connection to the router's own address", entry("100.64.7.7", 0x30000), false},
		{"mark bits outside the mask are not ours", entry("198.19.200.1", 0x00000042), false},
		{"a masked mark no egress has (Keenetic 0xffffaab): re-marked by the zones", entry("198.51.100.7", 0x0ffffaab), false},
		{"loopback", entry("127.0.0.2", 0x30000), false},
		{"IPv4-mapped destination is judged as IPv4", Entry{Family: 10, Src: netip.MustParseAddr("10.20.30.10"),
			Dst: netip.MustParseAddr("::ffff:198.51.100.7"), Mark: 0x20000, tuple: []byte{4, 0, 1, 0}}, true},
	})

	// Adding an exit renumbers the marks: 0x20000 now means awg0, and the restore pins the flow there.
	renum := plan([]pbr.Egress{wan, {Tag: "awg0", Mark: 0x20000}, {Tag: "awg1", Mark: 0x30000}, {Tag: "awg2", Mark: 0x40000}},
		pbr.Zone{Name: "a-tg", Mark: 0x30000, V4: []string{"198.18.0.0/20"}})
	checkStale(t, newDecider(old, renum, Options{}), []staleCase{
		{"renumbered mark now pins another exit", entry("198.18.7.51", 0x20000), true},
		{"the flow already carries its exit's new mark", entry("198.18.7.51", 0x30000), false},
	})
	// No known previous plan (first Apply, a baseline from before the schema, a failed Apply that never
	// reached the kernel): the decision does not need it.
	checkStale(t, newDecider(nil, cur, Options{}), []staleCase{
		{"pinned to awg2 while the plan says awg1", entry("192.0.2.1", 0x30000), true},
		{"consistent with the plane", entry("192.0.2.1", 0x20000), false},
	})
}

// RT-09: a private destination a zone names is routed by its mark (pbr carves it out of the private
// pin), so a flow to it that the plan moves is stale like any other; private space no zone names is
// still pinned to main and left alone.
func TestStaleListedPrivateDestination(t *testing.T) {
	k1 := pbr.Egress{Tag: "awg1", Kind: pbr.EgressInterface, Mark: 0x20000, Table: 151}
	k2 := pbr.Egress{Tag: "awg2", Kind: pbr.EgressInterface, Mark: 0x30000, Table: 152}
	w := pbr.Egress{Tag: "direct", Kind: pbr.EgressWAN}
	old := plan([]pbr.Egress{w, k1, k2}, pbr.Zone{Name: "office", EgressTag: "awg2", Mark: 0x30000, V4: []string{"10.40.0.0/16"}})
	cur := plan([]pbr.Egress{w, k1, k2}, pbr.Zone{Name: "office", EgressTag: "awg1", Mark: 0x20000, V4: []string{"10.40.0.0/16"}})
	checkStale(t, newDecider(old, cur, Options{}), []staleCase{
		{"listed private range moved to another exit", entry("10.40.1.1", 0x30000), true},
		{"listed private range already on its exit", entry("10.40.1.1", 0x20000), false},
		{"private range no zone names", entry("10.20.31.1", 0x30000), false},
	})
}

// Hybrid: an unmarked flow may be the TUN's (redirected to sing-box) and cannot follow a destination
// that now goes to a kernel exit; one the plan sends to the WAN is left to sing-box.
func TestStaleNftHybrid(t *testing.T) {
	old, cur := movePlans()
	d := newDecider(old, cur, Options{Hybrid: true})
	checkStale(t, d, []staleCase{
		{"unmarked flow into a kernel zone", entry("198.51.100.7", 0), true},
		{"unmarked flow in no zone", entry("198.19.200.1", 0), false},
		{"pinned flow still judged as on nft", entry("198.18.7.51", 0x30000), true},
	})
}

// iptables + ipset (Keenetic): the restore does not end the chain, so a matching zone re-marks the flow;
// only a destination no zone matches keeps the restored mark.
func TestStaleIpset(t *testing.T) {
	old, cur := movePlans()
	d := newDecider(old, cur, Options{Plane: PlaneIpset})
	checkStale(t, d, []staleCase{
		{"moved list: the zone re-marks it to awg1", entry("198.18.7.51", 0x30000), false},
		{"removed list: restored to its tunnel, no zone to override", entry("203.0.113.9", 0x20000), true},
		{"WAN traffic", entry("198.19.200.1", 0), false},
		{"a firmware mark in no zone routes main", entry("198.19.200.1", 0x0ffffaab), false},
	})
	renum := plan([]pbr.Egress{wan, {Tag: "awg0", Mark: 0x20000}, {Tag: "awg1", Mark: 0x30000}},
		pbr.Zone{Name: "a-tg", Mark: 0x30000, V4: []string{"198.18.0.0/20"}})
	if newDecider(old, renum, Options{Plane: PlaneIpset}).stale(entry("198.18.7.51", 0x20000)) {
		t.Error("a renumbered flow its zone re-marks onto the same exit must be kept")
	}
}

// The plane removed (routing off, teardown rollback): a flow the old plane sent to a tunnel goes; a
// WAN-marked one routes the same with or without the plane and stays.
func TestStaleRemoved(t *testing.T) {
	wanK := pbr.Egress{Tag: "wan", Kind: pbr.EgressWAN, Mark: 0x10000}
	old := plan([]pbr.Egress{wanK, awg1}, pbr.Zone{Name: "direct", Mark: 0x10000, V4: []string{"203.0.113.0/24"}})
	checkStale(t, newDecider(old, nil, Options{}), []staleCase{
		{"tunnel-marked", entry("198.19.200.8", 0x20000), true},
		{"WAN-marked", entry("203.0.113.5", 0x10000), false},
		{"unmarked", entry("198.19.200.1", 0), false},
		{"a mark the old plan did not own", entry("198.19.200.1", 0x0ffffaab), false},
	})
	if newDecider(nil, nil, Options{}).stale(entry("198.19.200.8", 0x20000)) {
		t.Error("with no plan on either side nothing is ours to judge")
	}
}

// The WAN egress has a mark of its own, but it routes like no mark at all.
func TestStaleWANMarkRoutesLikeNone(t *testing.T) {
	wanK := pbr.Egress{Tag: "wan", Kind: pbr.EgressWAN, Mark: 0x10000}
	tun := pbr.Egress{Tag: "awg1", Kind: pbr.EgressInterface, Mark: 0x20000}
	old := plan([]pbr.Egress{wanK, tun}, pbr.Zone{Name: "direct", Mark: 0x10000, V4: []string{"203.0.113.0/24"}})
	cur := plan([]pbr.Egress{wanK, tun})
	if newDecider(old, cur, Options{}).stale(entry("203.0.113.5", 0x10000)) {
		t.Error("a WAN-marked flow whose direct zone was removed still leaves by the WAN")
	}
	cur.Zones = []pbr.Zone{{Name: "tun", Mark: 0x20000, V4: []string{"203.0.113.0/24"}}}
	if !newDecider(old, cur, Options{}).stale(entry("203.0.113.5", 0x10000)) {
		t.Error("a WAN-marked flow whose destination now goes to a tunnel must move")
	}
}

// Source-scoped zones mark only their sources, and the kernel's last match decides; what conntrack
// cannot show (MAC, interface, port) or dnsmasq fills at query time is never guessed.
func TestStaleSourceScopeAndDomains(t *testing.T) {
	eg := []pbr.Egress{wan, awg1, awg2}
	cur := plan(eg,
		pbr.Zone{Name: "a", Mark: 0x20000, V4: []string{"198.51.100.0/24"}},
		pbr.Zone{Name: "b-only", Mark: 0x30000, V4: []string{"198.51.100.0/24"}, SrcScoped: true, SrcV4: []string{"10.20.30.50/32"}},
		pbr.Zone{Name: "c-except", Mark: 0x30000, V4: []string{"203.0.113.0/24"}, SrcScoped: true, SrcNegate: true, SrcV4: []string{"10.20.30.60/32"}},
		pbr.Zone{Name: "d-mac", Mark: 0x30000, V4: []string{"192.0.2.0/24"}, SrcScoped: true, SrcMAC: []string{"aa:bb:cc:dd:ee:ff"}},
		pbr.Zone{Name: "e-device", Mark: 0x20000, SrcScoped: true, SrcV4: []string{"10.20.30.70/32"}},
		pbr.Zone{Name: "f-v6only", Mark: 0x30000, V4: []string{"233.252.0.0/24"}, SrcScoped: true, SrcV6: []string{"fd00::1/128"}})
	checkStale(t, newDecider(plan(eg), cur, Options{}), []staleCase{
		{"'only' zone, a member device pinned to awg1: awg2 now", from(entry("198.51.100.9", 0x20000), "10.20.30.50"), true},
		{"'only' zone, another device: the earlier zone's awg1", from(entry("198.51.100.9", 0x20000), "10.20.30.51"), false},
		{"'except' zone, the excepted device pinned to awg2: nothing marks it now", from(entry("203.0.113.9", 0x30000), "10.20.30.60"), true},
		{"'except' zone, everyone else pinned to awg1: awg2", from(entry("203.0.113.9", 0x20000), "10.20.30.61"), true},
		{"MAC scope cannot be seen: kept", from(entry("192.0.2.9", 0x20000), "10.20.30.61"), false},
		{"source-only device rule, pinned elsewhere", from(entry("198.19.200.1", 0x30000), "10.20.30.70"), true},
		{"source-only device rule, already marked", from(entry("198.19.200.1", 0x20000), "10.20.30.70"), false},
		{"a v6-only group has no IPv4 rule", from(entry("233.252.0.9", 0x30000), "10.20.30.61"), true},
		{"source unknown: kept", Entry{Family: 2, Dst: netip.MustParseAddr("198.51.100.9"), Mark: 0x20000, tuple: []byte{4, 0, 1, 0}}, false},
	})

	// Keenetic: a later domain zone may hold the address (dnsmasq added it at query time), so an
	// earlier static zone does not decide.
	dom := plan(eg,
		pbr.Zone{Name: "a-static", Mark: 0x20000, V4: []string{"198.51.100.0/24"}},
		pbr.Zone{Name: "b-domains", Mark: 0x30000, Domains: []string{"example.org"}})
	for _, plane := range []Plane{PlaneNft, PlaneIpset} {
		if newDecider(dom, dom, Options{Plane: plane}).stale(entry("198.51.100.9", 0x30000)) {
			t.Errorf("plane %d: a flow a later domain zone may have marked must be kept", plane)
		}
	}
	// The domain zone removed: nothing can mark the destination any more.
	noDom := plan(eg, pbr.Zone{Name: "a-static", Mark: 0x20000, V4: []string{"198.51.100.0/24"}})
	for _, plane := range []Plane{PlaneNft, PlaneIpset} {
		if !newDecider(dom, noDom, Options{Plane: plane}).stale(entry("198.19.200.8", 0x30000)) {
			t.Errorf("plane %d: a flow of a removed domain zone, now in no zone, must move", plane)
		}
	}
}

func TestChanged(t *testing.T) {
	base := func() *pbr.Plan {
		return plan([]pbr.Egress{wan, awg1}, pbr.Zone{Name: "a", Mark: 0x20000, V4: []string{"203.0.113.0/24"}})
	}
	if Changed(base(), base()) || Changed(nil, nil) || !Changed(base(), nil) || !Changed(nil, base()) {
		t.Error("Changed must see only real differences")
	}
	for name, edit := range map[string]func(p *pbr.Plan){
		"source scope": func(p *pbr.Plan) { p.Zones[0].SrcScoped, p.Zones[0].SrcV4 = true, []string{"10.20.30.5/32"} },
		"negation":     func(p *pbr.Plan) { p.Zones[0].SrcNegate = true },
		"domains":      func(p *pbr.Plan) { p.Zones[0].Domains = []string{"example.org"} },
		"bypass":       func(p *pbr.Plan) { p.BypassV4 = []string{"198.51.100.1/32"} },
		"egress kind":  func(p *pbr.Plan) { p.Egresses[1].Kind = pbr.EgressBlackhole },
	} {
		p := base()
		edit(p)
		if !Changed(base(), p) {
			t.Errorf("a change of %s must count", name)
		}
	}
}

type fakeTable struct {
	entries map[uint8][]Entry
	errs    map[uint8]error
	deleted []netip.Addr
	gone    map[netip.Addr]bool
}

func (f *fakeTable) Dump(fam uint8, visit func(Entry)) error {
	for _, e := range f.entries[fam] {
		visit(e)
	}
	return f.errs[fam]
}
func (f *fakeTable) Delete(e Entry) error {
	if f.gone[e.Dst] {
		return errNoEntry
	}
	f.deleted = append(f.deleted, e.Dst)
	return nil
}
func (f *fakeTable) Close() error { return nil }

func TestFlushCountsAndCap(t *testing.T) {
	old := plan([]pbr.Egress{wan, awg1}, pbr.Zone{Name: "a", Mark: 0x20000, V4: []string{"203.0.113.0/24"}})
	cur := plan([]pbr.Egress{wan, awg1}) // the list removed, its exit kept
	f := &fakeTable{entries: map[uint8][]Entry{2: {entry("203.0.113.1", 0x20000), entry("203.0.113.2", 0x20000), entry("198.19.200.1", 0), entry("203.0.113.3", 0x20000)}},
		gone: map[netip.Addr]bool{netip.MustParseAddr("203.0.113.2"): true}}
	res, err := Flush(f, old, cur, Options{})
	if err != nil || res.Seen != 4 || res.Deleted != 2 || res.Gone != 1 || res.Capped {
		t.Errorf("flush = %+v, %v; want 4 seen, 2 deleted, 1 gone", res, err)
	}
	f.deleted = nil
	res, _ = Flush(f, old, cur, Options{Limit: 1})
	if res.Deleted != 1 || !res.Capped {
		t.Errorf("capped flush = %+v, want 1 deleted and capped", res)
	}
	// The router's own addresses are never touched, whatever the plan says.
	f.deleted = nil
	if res, _ = Flush(f, old, cur, Options{Local: func(a netip.Addr) bool { return a.Is4() }}); res.Deleted != 0 {
		t.Errorf("flush with every address local deleted %d", res.Deleted)
	}
	// A failed dump ends the flush before any delete; a missing module says so as itself.
	f.deleted = nil
	f.errs = map[uint8]error{10: errors.New("read dump: resource temporarily unavailable")}
	if res, err = Flush(f, old, cur, Options{}); err == nil || res.Deleted != 0 || len(f.deleted) != 0 {
		t.Errorf("a failed dump: %+v, %v, deleted %v; want an error and nothing deleted", res, err, f.deleted)
	}
	f.errs = map[uint8]error{2: ErrNoModule}
	if _, err = Flush(f, old, cur, Options{}); !errors.Is(err, ErrNoModule) {
		t.Errorf("missing module = %v", err)
	}
}

// nla builds one attribute; nested ones carry the kernel's NLA_F_NESTED flag.
func nla(typ uint16, payload []byte, nested bool) []byte {
	l := nlaHdrLen + len(payload)
	b := make([]byte, nlAlign(l))
	binary.NativeEndian.PutUint16(b[0:2], uint16(l))
	if nested {
		typ |= 0x8000
	}
	binary.NativeEndian.PutUint16(b[2:4], typ)
	copy(b[4:], payload)
	return b
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// A dump message as the kernel writes it parses into an Entry, and the delete request carries the
// original tuple back byte for byte.
func TestParseDumpAndEncodeDelete(t *testing.T) {
	ip := nla(ctaTupleIP, cat(nla(ctaIPv4Src, []byte{10, 20, 30, 10}, false), nla(ctaIPv4Dst, []byte{198, 18, 7, 51}, false)), true)
	proto := nla(2, cat(nla(1, []byte{17}, false), nla(2, []byte{0x30, 0x39}, false), nla(3, []byte{0x01, 0xbb}, false)), true)
	tuple := nla(ctaTupleOrig, cat(ip, proto), true)
	mark := make([]byte, 4)
	binary.BigEndian.PutUint32(mark, 0x30000)
	body := cat(make([]byte, nfgenHdrLen), tuple, nla(ctaMark, mark, false), nla(ctaID, []byte{0xde, 0xad, 0xbe, 0xef}, false),
		nla(ctaZone, []byte{0, 0}, false))
	msg := make([]byte, nlmsgHdrLen)
	binary.NativeEndian.PutUint32(msg[0:4], uint32(nlmsgHdrLen+len(body)))
	binary.NativeEndian.PutUint16(msg[4:6], nfnlSubsysCT<<8|ctMsgNew)
	msg = append(msg, body...)
	done := make([]byte, nlmsgHdrLen+4)
	binary.NativeEndian.PutUint32(done[0:4], uint32(len(done)))
	binary.NativeEndian.PutUint16(done[4:6], nlmsgDone)

	var entries []Entry
	buf := cat(msg, done)
	fin, errno, err := readMessages(buf, 2, 0, func(e Entry) { entries = append(entries, e.detach()) })
	if err != nil || !fin || errno != 0 || len(entries) != 1 {
		t.Fatalf("readMessages = %d entries, done %v, errno %d, err %v", len(entries), fin, errno, err)
	}
	e := entries[0]
	for i := range buf {
		buf[i] = 0 // the receive buffer is reused: a kept entry must not point into it
	}
	if !bytes.Equal(e.tuple, tuple) {
		t.Fatal("detach must copy the tuple out of the receive buffer")
	}
	// A reply to another request (a dump that timed out earlier) is skipped, not read as ours.
	stale := cat(msg, done)
	binary.NativeEndian.PutUint32(stale[8:12], 41)
	n := 0
	if fin, _, _ := readMessages(stale, 2, 42, func(Entry) { n++ }); n != 0 || fin {
		t.Errorf("another request's messages were taken as ours: %d entries, done %v", n, fin)
	}
	if e.Dst != netip.MustParseAddr("198.18.7.51") || e.Src != netip.MustParseAddr("10.20.30.10") ||
		e.Mark != 0x30000 || len(e.zone) == 0 || len(e.id) == 0 {
		t.Fatalf("entry = %+v", e)
	}
	req, err := deleteRequest(7, e)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.NativeEndian.Uint16(req[4:6]); got != nfnlSubsysCT<<8|ctMsgDelete {
		t.Errorf("delete type = %#x", got)
	}
	if flags := binary.NativeEndian.Uint16(req[6:8]); flags != nlmFRequest|nlmFAck {
		t.Errorf("delete flags = %#x", flags)
	}
	if req[16] != 2 || string(req[nlmsgHdrLen+nfgenHdrLen:nlmsgHdrLen+nfgenHdrLen+len(tuple)]) != string(tuple) {
		t.Error("the delete must carry the family and the original tuple unchanged")
	}
	if !bytes.Contains(req, e.id) {
		t.Error("the delete must carry the dumped entry's id")
	}
	if int(binary.NativeEndian.Uint32(req[0:4])) != len(req) {
		t.Error("nlmsg_len must equal the message length")
	}
	if dump := dumpRequest(9, 10); binary.NativeEndian.Uint16(dump[4:6]) != nfnlSubsysCT<<8|ctMsgGet ||
		binary.NativeEndian.Uint16(dump[6:8]) != nlmFRequest|nlmFDump || dump[16] != 10 {
		t.Error("a dump is a GET with NLM_F_DUMP for one family")
	}
	// No tuple, or a malformed one, is the kernel's flush-everything request: never sent.
	for _, bad := range [][]byte{nil, {4, 0, 1, 0}, {8, 0, 2, 0, 1, 2, 3, 4}, {9, 0, 1, 0, 1, 2, 3, 4}} {
		if _, err := deleteRequest(8, Entry{Family: 2, tuple: bad}); err == nil {
			t.Errorf("delete with tuple %v was not refused", bad)
		}
	}

	// The kernel's answer to a delete: ENOENT arrives as a negative errno.
	ack := make([]byte, nlmsgHdrLen+4)
	binary.NativeEndian.PutUint32(ack[0:4], uint32(len(ack)))
	binary.NativeEndian.PutUint16(ack[4:6], nlmsgError)
	en := int32(-enoent)
	binary.NativeEndian.PutUint32(ack[nlmsgHdrLen:], uint32(en))
	if _, errno, _ := readMessages(ack, 2, 0, nil); errno != -enoent {
		t.Errorf("errno = %d, want -ENOENT", errno)
	}
	// A truncated message is an error, not a panic.
	if _, _, err := readMessages(msg[:nlmsgHdrLen+8], 2, 0, nil); err == nil {
		t.Error("a message longer than the buffer must be refused")
	}
}
