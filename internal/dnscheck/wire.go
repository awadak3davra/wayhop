package dnscheck

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	dnsClassIN   = 1
	dnsTypeA     = 1
	dnsTypeTXT   = 16
	dnsTypeAAAA  = 28
	dnsTypeRRSIG = 46
)

// DNSAnswer is the part of an answer record used by the probes. Address is set for A and AAAA records,
// and TXT holds the individual strings of a TXT record.
type DNSAnswer struct {
	Type    uint16
	TTL     uint32
	Address string
	TXT     []string
}

// DNSReply is a parsed DNS message. RRSIGCount counts signatures in the answer section.
type DNSReply struct {
	ID         uint16
	Rcode      int
	AD         bool
	AA         bool
	TC         bool
	Answers    []DNSAnswer
	RRSIGCount int
}

// BuildQuery builds one recursive DNS question. When do is true, an EDNS OPT record asks for DNSSEC
// records and permits replies up to 1232 bytes.
func BuildQuery(name string, qtype, qclass uint16, do bool) ([]byte, error) {
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("random DNS query id: %w", err)
	}

	wireName, err := encodeDNSName(name)
	if err != nil {
		return nil, err
	}
	q := make([]byte, 12, 12+len(wireName)+4+11)
	binary.BigEndian.PutUint16(q[0:2], binary.BigEndian.Uint16(id[:]))
	binary.BigEndian.PutUint16(q[2:4], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(q[4:6], 1)
	if do {
		binary.BigEndian.PutUint16(q[10:12], 1)
	}
	q = append(q, wireName...)
	q = binary.BigEndian.AppendUint16(q, qtype)
	q = binary.BigEndian.AppendUint16(q, qclass)
	if do {
		q = append(q, 0) // root owner of the OPT record
		q = binary.BigEndian.AppendUint16(q, 41)
		q = binary.BigEndian.AppendUint16(q, 1232)
		q = binary.BigEndian.AppendUint32(q, 0x00008000) // DNSSEC OK
		q = binary.BigEndian.AppendUint16(q, 0)
	}
	return q, nil
}

func encodeDNSName(name string) ([]byte, error) {
	if name == "" {
		return nil, errors.New("DNS name is empty")
	}
	if name == "." {
		return []byte{0}, nil
	}
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return nil, errors.New("DNS name is empty")
	}

	var out []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid DNS label in %q", name)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
		if len(out)+1 > 255 {
			return nil, fmt.Errorf("DNS name %q is too long", name)
		}
	}
	return append(out, 0), nil
}

// ParseReply parses the header, questions and answer section of msg. The name reader follows compressed
// names with cycle detection, so malformed packets are errors rather than loops or panics.
func ParseReply(msg []byte) (DNSReply, error) {
	var out DNSReply
	if len(msg) < 12 {
		return out, errors.New("short DNS header")
	}
	out.ID = binary.BigEndian.Uint16(msg[0:2])
	flags := binary.BigEndian.Uint16(msg[2:4])
	out.Rcode = int(flags & 0x000f)
	out.AD = flags&0x0020 != 0
	out.AA = flags&0x0400 != 0
	out.TC = flags&0x0200 != 0

	off := 12
	questions := int(binary.BigEndian.Uint16(msg[4:6]))
	for i := 0; i < questions; i++ {
		next, err := skipDNSName(msg, off)
		if err != nil {
			return DNSReply{}, fmt.Errorf("DNS question name: %w", err)
		}
		off = next
		if len(msg)-off < 4 {
			return DNSReply{}, errors.New("short DNS question")
		}
		off += 4
	}

	answers := int(binary.BigEndian.Uint16(msg[6:8]))
	out.Answers = make([]DNSAnswer, 0, answers)
	for i := 0; i < answers; i++ {
		next, err := skipDNSName(msg, off)
		if err != nil {
			return DNSReply{}, fmt.Errorf("DNS answer name: %w", err)
		}
		off = next
		if len(msg)-off < 10 {
			return DNSReply{}, errors.New("short DNS answer header")
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		ttl := binary.BigEndian.Uint32(msg[off+4 : off+8])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if rdlen > len(msg)-off {
			return DNSReply{}, errors.New("short DNS answer data")
		}
		end := off + rdlen
		answer := DNSAnswer{Type: typ, TTL: ttl}
		switch typ {
		case dnsTypeA:
			if rdlen != net.IPv4len {
				return DNSReply{}, fmt.Errorf("an A record has %d bytes", rdlen)
			}
			answer.Address = net.IP(msg[off:end]).String()
		case dnsTypeAAAA:
			if rdlen != net.IPv6len {
				return DNSReply{}, fmt.Errorf("AAAA record has %d bytes", rdlen)
			}
			answer.Address = net.IP(msg[off:end]).String()
		case dnsTypeTXT:
			for off < end {
				length := int(msg[off])
				off++
				if length > end-off {
					return DNSReply{}, errors.New("short TXT string")
				}
				answer.TXT = append(answer.TXT, string(msg[off:off+length]))
				off += length
			}
		case dnsTypeRRSIG:
			out.RRSIGCount++
		}
		off = end
		out.Answers = append(out.Answers, answer)
	}
	return out, nil
}

// skipDNSName returns the first byte after the name at its original location, not after its pointer target.
func skipDNSName(msg []byte, start int) (int, error) {
	if start < 0 || start >= len(msg) {
		return 0, errors.New("DNS name starts out of bounds")
	}
	off := start
	next := -1
	expanded := 0
	visited := make(map[int]struct{})
	for {
		if off < 0 || off >= len(msg) {
			return 0, errors.New("DNS name runs out of bounds")
		}
		if _, seen := visited[off]; seen {
			return 0, errors.New("DNS compression pointer cycle")
		}
		visited[off] = struct{}{}

		length := int(msg[off])
		switch length & 0xc0 {
		case 0xc0:
			if len(msg)-off < 2 {
				return 0, errors.New("short DNS compression pointer")
			}
			if next < 0 {
				next = off + 2
			}
			off = (length&0x3f)<<8 | int(msg[off+1])
		case 0x00:
			if length == 0 {
				if next >= 0 {
					return next, nil
				}
				return off + 1, nil
			}
			if length > 63 || len(msg)-off-1 < length {
				return 0, errors.New("short DNS label")
			}
			expanded += length + 1
			if expanded > 255 {
				return 0, errors.New("expanded DNS name is too long")
			}
			off += length + 1
		default:
			return 0, errors.New("unsupported DNS label type")
		}
	}
}
