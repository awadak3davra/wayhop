package server

import "testing"

// TestBlockInternalDial pins the subscription-fetch SSRF guard's exact behaviour:
// it must REJECT a dial to any loopback / private / link-local / unspecified address
// (so a user-supplied subscription URL can't be turned into a request-forgery sink
// reaching the router's own Clash API, other LAN hosts, or cloud metadata), and ALLOW
// public addresses. The dial-time check runs on the already-resolved IP, so it also
// covers redirects + DNS-rebinding — a regression here is a real SSRF hole.
func TestBlockInternalDial(t *testing.T) {
	reject := []struct{ name, addr string }{
		{"loopback v4", "127.0.0.1:80"},
		{"loopback v6", "[::1]:80"},
		{"private 10/8", "10.0.0.5:443"},
		{"private 192.168/16", "192.168.50.1:80"},
		{"private 172.16/12", "172.16.5.9:80"},
		{"cloud-metadata (link-local v4)", "169.254.169.254:80"}, // AWS/GCP IMDS — the classic SSRF target
		{"link-local v6", "[fe80::1]:80"},
		{"ULA private v6", "[fc00::1]:80"},
		{"unspecified v4", "0.0.0.0:80"},
		{"unspecified v6", "[::]:80"},
		{"cgnat 100.64/10 low", "100.64.0.1:80"},           // RFC6598 carrier-grade NAT shared range
		{"cgnat 100.64/10 mid", "100.96.5.9:443"},          // inside 100.64.0.0/10
		{"cgnat 100.64/10 high", "100.127.255.254:80"},     // top of the /10
		{"cgnat ipv4-mapped-v6", "[::ffff:100.64.0.1]:80"}, // same CGNAT addr in mapped form
	}
	for _, c := range reject {
		if err := blockInternalDial("tcp", c.addr, nil); err == nil {
			t.Errorf("%s (%s): SSRF guard must REJECT, got nil", c.name, c.addr)
		}
	}

	allow := []struct{ name, addr string }{
		{"public v4", "8.8.8.8:443"},
		{"public v6 (Cloudflare)", "[2606:4700:4700::1111]:443"},
		{"public just below cgnat (100.63)", "100.63.255.255:80"}, // boundary: outside 100.64.0.0/10
		{"public just above cgnat (100.128)", "100.128.0.0:80"},   // boundary: outside 100.64.0.0/10
	}
	for _, c := range allow {
		if err := blockInternalDial("tcp", c.addr, nil); err != nil {
			t.Errorf("%s (%s): guard must ALLOW a public address, got %v", c.name, c.addr, err)
		}
	}

	// Malformed inputs must error (fail CLOSED), never pass through or panic.
	for _, bad := range []string{"not-an-ip:80", "no-port-here"} {
		if err := blockInternalDial("tcp", bad, nil); err == nil {
			t.Errorf("malformed addr %q: expected an error (fail closed), got nil", bad)
		}
	}
}
