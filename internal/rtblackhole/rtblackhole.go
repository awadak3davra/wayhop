// Package rtblackhole keeps one routing table holding blackhole routes, over rtnetlink.
//
// It is the kill switch backstop's datapath on KeeneticOS (see pbr/backstop.go): tens of thousands of
// prefixes, which `ip route add` would install one fork each, minutes on a router CPU. Netlink takes
// one message per route on one socket. Routes in a table survive NDM's netfilter rebuilds, which is
// the point: the table does not depend on iptables.
package rtblackhole

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sort"
)

// ErrUnsupported is returned where there is no rtnetlink (not Linux).
var ErrUnsupported = errors.New("rtnetlink is not available on this platform")

// ErrFamilyUnsupported wraps the kernel's refusal of an IPv6 route operation as such (EOPNOTSUPP,
// EAFNOSUPPORT: a kernel without IPv6 routing). Nothing of that family is forwarded
// there, so a caller may skip the family. Never returned for IPv4.
var ErrFamilyUnsupported = errors.New("the kernel does not route IPv6")

// Table is one routing table's blackhole routes.
type Table interface {
	// List returns the blackhole routes the table holds, both families.
	List() ([]netip.Prefix, error)
	// Add installs a blackhole route for p (replacing an existing route for p).
	Add(p netip.Prefix) error
	// Del removes the route for p; a route that is not there is not an error.
	Del(p netip.Prefix) error
	// DelThrow removes a throw route for p (the boot hold's exemptions); a route that is
	// not there is not an error.
	DelThrow(p netip.Prefix) error
	Close() error
}

// Diff returns what to add and what to remove so that the table holding have holds want. Both lists
// come out sorted. With addOnly nothing is removed: a plane being replaced keeps the old plane's
// routes until the old plane's rules are gone.
func Diff(have, want []netip.Prefix, addOnly bool) (add, del []netip.Prefix) {
	h := make(map[netip.Prefix]bool, len(have))
	for _, p := range have {
		h[p.Masked()] = true
	}
	w := make(map[netip.Prefix]bool, len(want))
	for _, p := range want {
		p = p.Masked()
		if w[p] {
			continue
		}
		w[p] = true
		if !h[p] {
			add = append(add, p)
		}
	}
	if !addOnly {
		for p := range h {
			if !w[p] {
				del = append(del, p)
			}
		}
	}
	sortPrefixes(add)
	sortPrefixes(del)
	return add, del
}

func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].Addr() != ps[j].Addr() {
			return ps[i].Addr().Less(ps[j].Addr())
		}
		return ps[i].Bits() < ps[j].Bits()
	})
}

// The rtnetlink wire format (linux/rtnetlink.h). Headers are in host byte order (MIPS routers are
// big-endian); the address payload of RTA_DST is in network order, as netip gives it.
const (
	nlmsgHdrLen = 16
	rtmsgLen    = 12
	nlaHdrLen   = 4

	nlmsgError = 2
	nlmsgDone  = 3

	rtmNewRoute = 24
	rtmDelRoute = 25
	rtmGetRoute = 26

	nlmFRequest = 0x1
	nlmFAck     = 0x4
	nlmFDump    = 0x300
	nlmFReplace = 0x100
	nlmFCreate  = 0x400

	rtaDst   = 1
	rtaTable = 15

	rtnBlackhole   = 6
	rtnThrow       = 9
	rtprotStatic   = 4
	rtScopeUniv    = 0
	rtTableUnspec  = 0
	rtTableCompat  = 252
	afInet         = 2
	afInet6        = 10
	enoent         = 2
	esrch          = 3
	nlaTypeMask    = 0x3fff
	maxRouteTable8 = 255
)

func nlAlign(n int) int { return (n + 3) &^ 3 }

func family(p netip.Prefix) uint8 {
	if p.Addr().Is4() {
		return afInet
	}
	return afInet6
}

// encodeRoute builds an RTM_NEWROUTE / RTM_DELROUTE for a blackhole route to p in table.
func encodeRoute(msgType uint16, seq uint32, table uint32, p netip.Prefix) []byte {
	return encodeRouteType(msgType, seq, table, p, rtnBlackhole)
}

// encodeRouteType is encodeRoute for a route of type rtype (the kernel matches the type on delete).
func encodeRouteType(msgType uint16, seq uint32, table uint32, p netip.Prefix, rtype uint8) []byte {
	p = p.Masked()
	addr := p.Addr().AsSlice()
	dst := nlaHdrLen + len(addr)
	n := nlmsgHdrLen + rtmsgLen + nlAlign(dst) + nlAlign(nlaHdrLen+4)
	b := make([]byte, n)
	flags := uint16(nlmFRequest | nlmFAck)
	if msgType == rtmNewRoute {
		flags |= nlmFCreate | nlmFReplace
	}
	binary.NativeEndian.PutUint32(b[0:4], uint32(n))
	binary.NativeEndian.PutUint16(b[4:6], msgType)
	binary.NativeEndian.PutUint16(b[6:8], flags)
	binary.NativeEndian.PutUint32(b[8:12], seq)
	r := b[nlmsgHdrLen:]
	r[0] = family(p)
	r[1] = uint8(p.Bits())
	r[4] = rtTableCompat // the real id is in RTA_TABLE; ids above 255 do not fit here
	if table <= maxRouteTable8 {
		r[4] = uint8(table)
	}
	r[5] = rtprotStatic
	r[6] = rtScopeUniv
	r[7] = rtype
	off := nlmsgHdrLen + rtmsgLen
	binary.NativeEndian.PutUint16(b[off:], uint16(dst))
	binary.NativeEndian.PutUint16(b[off+2:], rtaDst)
	copy(b[off+nlaHdrLen:], addr)
	off += nlAlign(dst)
	binary.NativeEndian.PutUint16(b[off:], nlaHdrLen+4)
	binary.NativeEndian.PutUint16(b[off+2:], rtaTable)
	binary.NativeEndian.PutUint32(b[off+nlaHdrLen:], table)
	return b
}

// parseMessages walks one datagram of replies to seq. It hands every blackhole route of table to
// visit, and reports done at NLMSG_DONE or an NLMSG_ERROR (errno 0 is an ack).
func parseMessages(buf []byte, seq, table uint32, visit func(netip.Prefix)) (done bool, errno int32, err error) {
	for len(buf) >= nlmsgHdrLen {
		l := int(binary.NativeEndian.Uint32(buf[0:4]))
		if l < nlmsgHdrLen || l > len(buf) {
			return false, 0, errors.New("netlink: truncated message")
		}
		typ := binary.NativeEndian.Uint16(buf[4:6])
		mseq := binary.NativeEndian.Uint32(buf[8:12])
		body := buf[nlmsgHdrLen:l]
		buf = buf[nlAlign(l):]
		if mseq != seq {
			continue // a late reply to an earlier request
		}
		switch typ {
		case nlmsgDone:
			return true, 0, nil
		case nlmsgError:
			if len(body) < 4 {
				return true, 0, errors.New("netlink: short error message")
			}
			return true, int32(binary.NativeEndian.Uint32(body[0:4])), nil
		case rtmNewRoute:
			if p, ok := parseRoute(body, table); ok && visit != nil {
				visit(p)
			}
		}
	}
	return false, 0, nil
}

// parseRoute reads one route message: a blackhole route in table, or ok=false.
func parseRoute(body []byte, table uint32) (netip.Prefix, bool) {
	if len(body) < rtmsgLen {
		return netip.Prefix{}, false
	}
	fam, bits, tbl, typ := body[0], int(body[1]), uint32(body[4]), body[7]
	var dst []byte
	for a := body[rtmsgLen:]; len(a) >= nlaHdrLen; {
		al := int(binary.NativeEndian.Uint16(a[0:2]))
		if al < nlaHdrLen || al > len(a) {
			break
		}
		switch binary.NativeEndian.Uint16(a[2:4]) & nlaTypeMask {
		case rtaDst:
			dst = a[nlaHdrLen:al]
		case rtaTable:
			if al >= nlaHdrLen+4 {
				tbl = binary.NativeEndian.Uint32(a[nlaHdrLen:])
			}
		}
		a = a[nlAlign(al):]
	}
	if tbl != table || typ != rtnBlackhole {
		return netip.Prefix{}, false
	}
	var addr netip.Addr
	switch {
	case fam == afInet && len(dst) == 4:
		addr = netip.AddrFrom4([4]byte(dst))
	case fam == afInet6 && len(dst) == 16:
		addr = netip.AddrFrom16([16]byte(dst))
	case fam == afInet && dst == nil && bits == 0:
		addr = netip.IPv4Unspecified()
	case fam == afInet6 && dst == nil && bits == 0:
		addr = netip.IPv6Unspecified()
	default:
		return netip.Prefix{}, false
	}
	p, err := addr.Prefix(bits)
	return p, err == nil
}
