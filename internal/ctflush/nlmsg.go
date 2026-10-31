package ctflush

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// The ctnetlink wire format (linux/netfilter/nfnetlink.h, nfnetlink_conntrack.h). Netlink headers and
// attribute headers are in host byte order (NativeEndian: MIPS routers are big-endian); attribute
// payloads such as CTA_MARK are network byte order.
const (
	nlmsgHdrLen  = 16
	nfgenHdrLen  = 4
	nlaHdrLen    = 4
	nlmsgError   = 2
	nlmsgDone    = 3
	nlmFRequest  = 0x1
	nlmFAck      = 0x4
	nlmFDump     = 0x300
	nlaTypeMask  = 0x3fff // drops NLA_F_NESTED / NLA_F_NET_BYTEORDER
	nfnlSubsysCT = 1
	ctMsgNew     = 0
	ctMsgGet     = 1
	ctMsgDelete  = 2
	ctaTupleOrig = 1
	ctaMark      = 8
	ctaID        = 12
	ctaZone      = 18
	ctaTupleIP   = 1
	ctaIPv4Src   = 1
	ctaIPv4Dst   = 2
	ctaIPv6Src   = 3
	ctaIPv6Dst   = 4
	enoent       = 2
)

func nlAlign(n int) int { return (n + 3) &^ 3 }

// encodeRequest builds one ctnetlink message: header, nfgenmsg for family, then attrs (already encoded).
func encodeRequest(msgType, flags uint16, seq uint32, family uint8, attrs ...[]byte) []byte {
	n := nlmsgHdrLen + nfgenHdrLen
	for _, a := range attrs {
		n += nlAlign(len(a))
	}
	b := make([]byte, n)
	binary.NativeEndian.PutUint32(b[0:4], uint32(n))
	binary.NativeEndian.PutUint16(b[4:6], nfnlSubsysCT<<8|msgType)
	binary.NativeEndian.PutUint16(b[6:8], flags)
	binary.NativeEndian.PutUint32(b[8:12], seq)
	b[16] = family // nfgen_family; version 0 (NFNETLINK_V0), res_id 0
	off := nlmsgHdrLen + nfgenHdrLen
	for _, a := range attrs {
		copy(b[off:], a)
		off += nlAlign(len(a))
	}
	return b
}

func dumpRequest(seq uint32, family uint8) []byte {
	return encodeRequest(ctMsgGet, nlmFRequest|nlmFDump, seq, family)
}

// deleteRequest addresses one entry by its original tuple (and its id and zone, when the dump gave
// them). A delete with no tuple is the kernel's flush-everything request (nf_conntrack_netlink.c,
// ctnetlink_del_conntrack -> ctnetlink_flush_conntrack), so a missing or malformed tuple is refused here
// rather than sent.
func deleteRequest(seq uint32, e Entry) ([]byte, error) {
	if len(e.tuple) <= nlaHdrLen || int(binary.NativeEndian.Uint16(e.tuple[0:2])) != len(e.tuple) ||
		binary.NativeEndian.Uint16(e.tuple[2:4])&nlaTypeMask != ctaTupleOrig {
		return nil, errors.New("conntrack delete refused: the entry has no original tuple")
	}
	attrs := [][]byte{e.tuple}
	if len(e.id) > 0 {
		attrs = append(attrs, e.id)
	}
	if len(e.zone) > 0 {
		attrs = append(attrs, e.zone)
	}
	return encodeRequest(ctMsgDelete, nlmFRequest|nlmFAck, seq, e.Family, attrs...), nil
}

// nlAttr is one attribute: its type (flags masked off), its payload, and its whole raw bytes.
type nlAttr struct {
	typ     uint16
	payload []byte
	raw     []byte
}

func parseAttrs(b []byte) ([]nlAttr, error) {
	var out []nlAttr
	for len(b) >= nlaHdrLen {
		l := int(binary.NativeEndian.Uint16(b[0:2]))
		if l < nlaHdrLen || l > len(b) {
			return out, fmt.Errorf("netlink attribute length %d out of range", l)
		}
		out = append(out, nlAttr{typ: binary.NativeEndian.Uint16(b[2:4]) & nlaTypeMask, payload: b[nlaHdrLen:l], raw: b[:l]})
		if a := nlAlign(l); a < len(b) {
			b = b[a:]
		} else {
			b = nil
		}
	}
	return out, nil
}

// parseEntry reads one dump message's payload (after the nlmsghdr) into an Entry.
func parseEntry(family uint8, payload []byte) (Entry, error) {
	e := Entry{Family: family}
	if len(payload) < nfgenHdrLen {
		return e, errors.New("short ctnetlink message")
	}
	attrs, err := parseAttrs(payload[nfgenHdrLen:])
	if err != nil {
		return e, err
	}
	for _, a := range attrs {
		switch a.typ {
		case ctaTupleOrig:
			e.tuple = a.raw
			inner, err := parseAttrs(a.payload)
			if err != nil {
				return e, err
			}
			for _, t := range inner {
				if t.typ != ctaTupleIP {
					continue
				}
				ips, err := parseAttrs(t.payload)
				if err != nil {
					return e, err
				}
				for _, ip := range ips {
					switch {
					case ip.typ == ctaIPv4Src && len(ip.payload) == 4:
						e.Src = netip.AddrFrom4([4]byte(ip.payload))
					case ip.typ == ctaIPv6Src && len(ip.payload) == 16:
						e.Src = netip.AddrFrom16([16]byte(ip.payload))
					case ip.typ == ctaIPv4Dst && len(ip.payload) == 4:
						e.Dst = netip.AddrFrom4([4]byte(ip.payload))
					case ip.typ == ctaIPv6Dst && len(ip.payload) == 16:
						e.Dst = netip.AddrFrom16([16]byte(ip.payload))
					}
				}
			}
		case ctaMark:
			if len(a.payload) == 4 {
				e.Mark = binary.BigEndian.Uint32(a.payload)
			}
		case ctaZone:
			e.zone = a.raw
		case ctaID:
			if len(a.payload) == 4 {
				e.id = a.raw
			}
		}
	}
	if len(e.tuple) == 0 {
		return e, errors.New("ctnetlink entry without an original tuple")
	}
	return e, nil
}

// readMessages walks the netlink messages in one receive buffer, handing each conntrack entry to
// visit (its raw attributes point into buf: valid only during the call). Only replies to request seq
// count: a late answer to an earlier request (a dump that timed out) is skipped, not misread. It
// reports whether that request is complete and the kernel's error if it sent one (a negative errno).
func readMessages(buf []byte, family uint8, seq uint32, visit func(Entry)) (done bool, errno int32, err error) {
	for len(buf) >= nlmsgHdrLen {
		l := int(binary.NativeEndian.Uint32(buf[0:4]))
		if l < nlmsgHdrLen || l > len(buf) {
			return false, 0, fmt.Errorf("netlink message length %d out of range", l)
		}
		typ := binary.NativeEndian.Uint16(buf[4:6])
		payload := buf[nlmsgHdrLen:l]
		if binary.NativeEndian.Uint32(buf[8:12]) == seq {
			switch typ {
			case nlmsgDone:
				return true, 0, nil
			case nlmsgError:
				if len(payload) < 4 {
					return true, 0, errors.New("short netlink error message")
				}
				return true, int32(binary.NativeEndian.Uint32(payload[0:4])), nil
			case nfnlSubsysCT<<8 | ctMsgNew:
				if e, perr := parseEntry(family, payload); perr == nil && visit != nil {
					visit(e)
				}
			}
		}
		if a := nlAlign(l); a < len(buf) {
			buf = buf[a:]
		} else {
			buf = nil
		}
	}
	return false, 0, nil
}

// detach copies the raw attributes an entry points at, so it outlives the receive buffer.
func (e Entry) detach() Entry {
	e.tuple = append([]byte(nil), e.tuple...)
	if e.zone != nil {
		e.zone = append([]byte(nil), e.zone...)
	}
	if e.id != nil {
		e.id = append([]byte(nil), e.id...)
	}
	return e
}
