package rtblackhole

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
)

// A request reads back as the blackhole route it asks for, in its table, v4 and v6, and a table id
// above 255 travels in RTA_TABLE.
func TestEncodeRouteRoundTrip(t *testing.T) {
	for _, s := range []string{"149.154.160.0/19", "192.0.2.7/32", "2001:67c:4e8::/48", "2001:db8::1/128"} {
		p := netip.MustParsePrefix(s)
		msg := encodeRoute(rtmNewRoute, 7, 407, p)
		if int(binary.NativeEndian.Uint32(msg[0:4])) != len(msg) || len(msg)%4 != 0 {
			t.Fatalf("%s: length field %d, message %d", s, binary.NativeEndian.Uint32(msg[0:4]), len(msg))
		}
		flags := binary.NativeEndian.Uint16(msg[6:8])
		if flags&(nlmFCreate|nlmFReplace|nlmFAck) != nlmFCreate|nlmFReplace|nlmFAck {
			t.Fatalf("%s: flags %#x", s, flags)
		}
		if msg[nlmsgHdrLen+4] != rtTableCompat || msg[nlmsgHdrLen+7] != rtnBlackhole {
			t.Fatalf("%s: rtmsg %v", s, msg[nlmsgHdrLen:nlmsgHdrLen+rtmsgLen])
		}
		var got []netip.Prefix
		done, errno, err := parseMessages(msg, 7, 407, func(q netip.Prefix) { got = append(got, q) })
		if err != nil || done || errno != 0 || !slices.Equal(got, []netip.Prefix{p}) {
			t.Fatalf("%s: parsed %v done=%v errno=%d err=%v", s, got, done, errno, err)
		}
		_, _, _ = parseMessages(msg, 7, 151, func(q netip.Prefix) { t.Fatalf("route of table 407 read as 151: %s", q) })
	}
	if del := encodeRoute(rtmDelRoute, 1, 407, netip.MustParsePrefix("10.0.0.0/8")); binary.NativeEndian.Uint16(del[6:8])&nlmFCreate != 0 {
		t.Fatal("a delete carries NLM_F_CREATE")
	}
}

func TestParseAckAndDone(t *testing.T) {
	ack := make([]byte, nlmsgHdrLen+4)
	binary.NativeEndian.PutUint32(ack[0:4], uint32(len(ack)))
	binary.NativeEndian.PutUint16(ack[4:6], nlmsgError)
	binary.NativeEndian.PutUint32(ack[8:12], 9)
	e := int32(-17)
	binary.NativeEndian.PutUint32(ack[16:20], uint32(e))
	if done, errno, err := parseMessages(ack, 9, 407, nil); !done || errno != -17 || err != nil {
		t.Fatalf("ack: done=%v errno=%d err=%v", done, errno, err)
	}
	if done, _, _ := parseMessages(ack, 10, 407, nil); done {
		t.Fatal("another request's ack ended the wait")
	}
}

func TestDiff(t *testing.T) {
	p := netip.MustParsePrefix
	have := []netip.Prefix{p("10.0.0.0/8"), p("192.0.2.0/24"), p("2001:db8::/32")}
	want := []netip.Prefix{p("10.0.0.0/8"), p("198.51.100.0/24"), p("198.51.100.0/24"), p("2001:db8::/32")}
	add, del := Diff(have, want, false)
	if !slices.Equal(add, []netip.Prefix{p("198.51.100.0/24")}) || !slices.Equal(del, []netip.Prefix{p("192.0.2.0/24")}) {
		t.Fatalf("add=%v del=%v", add, del)
	}
	if _, del := Diff(have, want, true); del != nil {
		t.Fatalf("add-only removed %v", del)
	}
}
