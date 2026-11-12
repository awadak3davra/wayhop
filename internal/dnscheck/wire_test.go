package dnscheck

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestBuildQuery(t *testing.T) {
	q, err := BuildQuery("www.example.com", dnsTypeA, dnsClassIN, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(q) < 12 || binary.BigEndian.Uint16(q[4:6]) != 1 || binary.BigEndian.Uint16(q[10:12]) != 1 {
		t.Fatalf("bad DNS header: %x", q)
	}
	if got := binary.BigEndian.Uint16(q[2:4]); got != 0x0100 {
		t.Fatalf("flags = %#x, want RD", got)
	}
	if !strings.HasSuffix(string(q), "\x00\x00\x29\x04\xd0\x00\x00\x80\x00\x00\x00") {
		t.Fatalf("missing EDNS DO record: %x", q)
	}
}

func TestBuildQueryRejectsBadNames(t *testing.T) {
	for _, name := range []string{"", "a..b", ".example.com", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 128) + "com"} {
		if _, err := BuildQuery(name, dnsTypeA, dnsClassIN, false); err == nil {
			t.Errorf("BuildQuery(%q) succeeded", name)
		}
	}
}

func TestParseReplyRealShapes(t *testing.T) {
	q, err := BuildQuery("cloudflare.com", dnsTypeA, dnsClassIN, false)
	if err != nil {
		t.Fatal(err)
	}
	q[0], q[1] = 0x12, 0x34
	msg := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(msg[2:4], 0x87a0) // QR, AA, TC, RD, RA and AD
	binary.BigEndian.PutUint16(msg[6:8], 4)
	binary.BigEndian.PutUint16(msg[8:12], 0)
	appendRR := func(typ uint16, ttl uint32, rdata []byte) {
		msg = append(msg, 0xc0, 0x0c)
		msg = binary.BigEndian.AppendUint16(msg, typ)
		msg = binary.BigEndian.AppendUint16(msg, dnsClassIN)
		msg = binary.BigEndian.AppendUint32(msg, ttl)
		msg = binary.BigEndian.AppendUint16(msg, uint16(len(rdata)))
		msg = append(msg, rdata...)
	}
	appendRR(dnsTypeA, 300, net.ParseIP("203.0.113.10").To4())
	appendRR(dnsTypeAAAA, 60, net.ParseIP("2001:db8::1").To16())
	appendRR(dnsTypeTXT, 5, []byte{3, 'a', 'r', 'n', 2, '0', '2'})
	appendRR(dnsTypeRRSIG, 300, make([]byte, 18))

	got, err := ParseReply(msg)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != 0x1234 || got.Rcode != 0 || !got.AD || !got.AA || !got.TC || got.RRSIGCount != 1 {
		t.Fatalf("unexpected header: %+v", got)
	}
	if len(got.Answers) != 4 {
		t.Fatalf("got %d answers", len(got.Answers))
	}
	if got.Answers[0].Address != "203.0.113.10" || got.Answers[0].TTL != 300 {
		t.Errorf("A answer = %+v", got.Answers[0])
	}
	if got.Answers[1].Address != "2001:db8::1" {
		t.Errorf("AAAA answer = %+v", got.Answers[1])
	}
	if len(got.Answers[2].TXT) != 2 || got.Answers[2].TXT[0] != "arn" || got.Answers[2].TXT[1] != "02" {
		t.Errorf("TXT answer = %+v", got.Answers[2])
	}

	nx := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(nx[2:4], 0x8183)
	binary.BigEndian.PutUint16(nx[6:8], 0)
	nx = nx[:len(q)]
	nxReply, err := ParseReply(nx)
	if err != nil {
		t.Fatal(err)
	}
	if nxReply.Rcode != 3 || len(nxReply.Answers) != 0 {
		t.Errorf("NXDOMAIN reply = %+v", nxReply)
	}
}

func TestParseReplyRejectsMalformedMessages(t *testing.T) {
	cycle := make([]byte, 18)
	binary.BigEndian.PutUint16(cycle[4:6], 1)
	cycle[12], cycle[13] = 0xc0, 0x0c

	pointerOut := append([]byte(nil), cycle...)
	pointerOut[13] = 0xff

	badLabel := append([]byte(nil), cycle...)
	badLabel[12] = 0x40

	shortTXT := make([]byte, 12)
	binary.BigEndian.PutUint16(shortTXT[6:8], 1)
	shortTXT = append(shortTXT, 0)
	shortTXT = binary.BigEndian.AppendUint16(shortTXT, dnsTypeTXT)
	shortTXT = binary.BigEndian.AppendUint16(shortTXT, dnsClassIN)
	shortTXT = binary.BigEndian.AppendUint32(shortTXT, 0)
	shortTXT = binary.BigEndian.AppendUint16(shortTXT, 2)
	shortTXT = append(shortTXT, 3, 'x')

	for name, msg := range map[string][]byte{
		"empty": nil, "header": make([]byte, 11), "pointer cycle": cycle,
		"pointer out of bounds": pointerOut, "label type": badLabel, "TXT length": shortTXT,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseReply(msg); err == nil {
				t.Fatal("ParseReply succeeded")
			}
		})
	}
}

func FuzzParseReply(f *testing.F) {
	valid, err := BuildQuery("www.example.com", dnsTypeA, dnsClassIN, false)
	if err != nil {
		f.Fatal(err)
	}
	valid = append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(valid[2:4], 0x8180)
	cycle := make([]byte, 18)
	binary.BigEndian.PutUint16(cycle[4:6], 1)
	cycle[12], cycle[13] = 0xc0, 0x0c
	for _, seed := range [][]byte{nil, {0}, make([]byte, 12), valid, cycle, {0xc0, 0x0c, 0xff, 0xff}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, msg []byte) {
		_, _ = ParseReply(msg)
	})
}
