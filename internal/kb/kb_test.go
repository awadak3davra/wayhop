package kb

import "testing"

func TestMatchRealLines(t *testing.T) {
	cases := []struct{ line, wantID string }{
		{`FATAL[0000] start service: start inbound/tun[tun-in]: configure tun interface: file exists`, "sb-tun-file-exists"},
		{`FATAL[0000] start service: start inbound/tun[tun-in]: configure tun interface: invalid argument`, "sb-tun-invalid-arg"},
		{`FATAL[0000] start service: start outbound/wireguard[WG]: add route 0: file exists`, "sb-wg-route-exists"},
		{`REALITY: processed invalid connection`, "xr-reality-invalid"},
		{`[Warning] app/dispatcher: failed to find an available destination: context deadline exceeded`, "xr-deadline"},
		{`Handshake did not complete after 5 seconds, retrying`, "wg-handshake-timeout"},
		{`Receiving handshake initiation from unknown peer`, "wg-unknown-peer"},
		{`Sending dummy junk packets to blur the profile`, "awg-junk-mismatch"},
		{`tls: failed to verify certificate: x509: certificate signed by unknown authority`, "hy-tls-verify"},
		{`client error: authentication failed`, "hy-auth"},
		{`dial tcp: lookup vpn.example.com: no such host`, "gen-no-host"},
		{`dial tcp 1.2.3.4:443: connect: connection refused`, "gen-conn-refused"},
		{`read tcp 10.0.0.2->1.2.3.4: i/o timeout`, "gen-io-timeout"},
		{`x509: certificate has expired or is not yet valid`, "gen-clock"},
		{`tun: operation not permitted`, "gen-permission"},
	}
	for _, c := range cases {
		matched := false
		for _, e := range Match(c.line) {
			if e.ID == c.wantID {
				matched = true
			}
		}
		if !matched {
			ids := []string{}
			for _, e := range Match(c.line) {
				ids = append(ids, e.ID)
			}
			t.Errorf("line %q did not match %q (got %v)", c.line, c.wantID, ids)
		}
	}
}

func TestNoFalsePositiveOnInfoLine(t *testing.T) {
	if m := Match("INFO router started, 5 outbounds loaded"); len(m) != 0 {
		t.Fatalf("info line matched %d entries, want 0", len(m))
	}
}

func TestIsErrorLine(t *testing.T) {
	if !IsErrorLine("FATAL boom") {
		t.Fatal("FATAL should be an error line")
	}
	if IsErrorLine("INFO all good") {
		t.Fatal("INFO should not be an error line")
	}
}

func TestEveryEntryCompiles(t *testing.T) {
	for _, e := range Entries() {
		if e.re == nil {
			t.Fatalf("entry %s has no compiled regexp", e.ID)
		}
		if e.Title == "" || e.Explanation == "" || e.Fix == "" {
			t.Fatalf("entry %s missing text", e.ID)
		}
	}
}
