package server

import "testing"

func TestParseNetDev(t *testing.T) {
	sample := "Inter-|   Receive                                                |  Transmit\n" +
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes\n" +
		"    lo:  100 1 0 0 0 0 0 0  100 1 0 0 0 0 0 0\n" +
		"   wan: 668604848809 1 0 0 0 0 0 0 17398331958 2 0 0 0 0 0 0\n" +
		"  awg0: 124375830084 9 0 0 0 0 0 0 2731574042 9 0 0 0 0 0 0\n"
	ifs := parseNetDev(sample)
	if len(ifs) != 2 { // lo dropped
		t.Fatalf("got %d ifaces, want 2 (lo dropped): %+v", len(ifs), ifs)
	}
	if ifs[0].Name != "wan" || ifs[0].RxBytes != 668604848809 || ifs[0].TxBytes != 17398331958 {
		t.Errorf("wan = %+v", ifs[0])
	}
	if ifs[1].Name != "awg0" || ifs[1].TxBytes != 2731574042 {
		t.Errorf("awg0 = %+v", ifs[1])
	}
}

func TestParseConntrack(t *testing.T) {
	sample := "ipv4     2 tcp      6 7435 ESTABLISHED src=192.168.2.238 dst=203.0.113.40 sport=49787 dport=443 packets=15 bytes=10049 src=203.0.113.40 dst=192.168.1.70 sport=443 dport=49787 packets=15 bytes=5744 [ASSURED] mark=0 zone=0 use=2\n" +
		"ipv4     2 udp      17 30 src=192.168.2.50 dst=198.51.100.77 sport=5000 dport=4500 packets=8 bytes=1200 src=198.51.100.77 dst=192.168.1.70 sport=4500 dport=5000 packets=6 bytes=900 mark=196608 zone=0 use=2\n" +
		"garbage line\n"
	cs := parseConntrack(sample)
	if len(cs) != 2 {
		t.Fatalf("got %d conns, want 2: %+v", len(cs), cs)
	}
	tcp := cs[0]
	if tcp.Proto != "tcp" || tcp.Src != "192.168.2.238" || tcp.Dst != "203.0.113.40" ||
		tcp.Dport != 443 || tcp.State != "ESTABLISHED" || tcp.UpBytes != 10049 || tcp.DownBytes != 5744 || tcp.Mark != 0 {
		t.Errorf("tcp conn = %+v", tcp)
	}
	udp := cs[1]
	if udp.Proto != "udp" || udp.Dport != 4500 || udp.State != "" || udp.UpBytes != 1200 ||
		udp.DownBytes != 900 || udp.Mark != 196608 { // 196608 = 0x30000 (RU tunnel egress mark)
		t.Errorf("udp conn = %+v", udp)
	}
}

func TestParseLeases(t *testing.T) {
	// Fixture MAC and device name. This line used to carry a real lease copied off the LAN — a
	// genuine hardware MAC beside a real handset model — while the two below it were already
	// placeholders. No publish-scrub rule could see it: none of the 53 deny patterns names a MAC
	// or a device name that nobody thought to list.
	sample := "1782091623 02:00:00:00:00:01 192.168.2.175 handset-a 01:02:00:00:00:00:01\n" +
		"1782091000 aa:bb:cc:dd:ee:ff 192.168.2.50 * 01:aa:bb:cc:dd:ee:ff\n" +
		"1782090000 11:22:33:44:55:66 192.168.2.99 laptop\n"
	m := parseLeases(sample)
	if m["192.168.2.175"] != "handset-a" {
		t.Errorf("lease name = %q, want handset-a", m["192.168.2.175"])
	}
	if m["192.168.2.99"] != "laptop" {
		t.Errorf("lease name = %q, want laptop", m["192.168.2.99"])
	}
	if _, ok := m["192.168.2.50"]; ok {
		t.Errorf("a '*' (unknown) hostname must be dropped, got %q", m["192.168.2.50"])
	}
}
