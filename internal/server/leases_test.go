package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDhcpDevices locks the device-list parser: it keeps the MAC (lowercased), drops a "*"
// hostname, skips malformed / bad-IP / bad-MAC lines, and sorts named devices before unnamed.
func TestDhcpDevices(t *testing.T) {
	in := strings.Join([]string{
		"1735689600 AA:BB:CC:DD:EE:FF 192.168.1.50 laptop *", // uppercase MAC → lowercased
		"1735689600 11:22:33:44:55:66 192.168.1.51 * *",      // unknown hostname → omitted
		"1735689600 de:ad:be:ef:00:01 192.168.1.10 nas clientid",
		"garbage", // too few fields → skipped
		"1735689600 not-a-mac 192.168.1.99 bad *",        // bad MAC → skipped
		"1735689600 aa:aa:aa:aa:aa:aa not-an-ip host2 *", // bad IP → skipped
	}, "\n")
	got := dhcpDevices(in)
	if len(got) != 3 {
		t.Fatalf("want 3 valid devices, got %d: %+v", len(got), got)
	}
	// Named first (laptop < nas), unnamed last.
	if got[0].Hostname != "laptop" || got[0].MAC != "aa:bb:cc:dd:ee:ff" || got[0].IP != "192.168.1.50" {
		t.Errorf("got[0] = %+v, want laptop / lowercased mac / .50", got[0])
	}
	if got[1].Hostname != "nas" {
		t.Errorf("got[1].Hostname = %q, want nas", got[1].Hostname)
	}
	if got[2].Hostname != "" || got[2].IP != "192.168.1.51" {
		t.Errorf("got[2] = %+v, want the unnamed .51 device last", got[2])
	}
}

// TestParseARP: the cross-platform ARP fallback keeps complete LAN-bridge private entries (MAC
// lowercased), and drops the header row, incomplete entries, non-bridge (WAN) devices, public IPs
// and zero MACs — so a WAN neighbour never appears in the LAN device picker.
func TestParseARP(t *testing.T) {
	in := strings.Join([]string{
		"IP address       HW type     Flags       HW address            Mask     Device",
		"192.168.1.50     0x1         0x2         AA:BB:CC:DD:EE:FF     *        br-lan", // kept, lowercased
		"192.168.1.60     0x1         0x2         11:22:33:44:55:66     *        br0",    // kept (Keenetic bridge)
		"192.168.1.70     0x1         0x0         de:ad:be:ef:00:11     *        br-lan", // incomplete flag → skip
		"10.0.0.1         0x1         0x2         de:ad:be:ef:00:99     *        eth0",   // non-bridge (WAN) → skip
		"8.8.8.8          0x1         0x2         de:ad:be:ef:00:aa     *        br-lan", // public IP → skip
		"192.168.1.80     0x1         0x2         00:00:00:00:00:00     *        br-lan", // zero MAC → skip
	}, "\n")
	got := parseARP(in)
	if len(got) != 2 {
		t.Fatalf("want 2 LAN devices, got %d: %+v", len(got), got)
	}
	if got[0].MAC != "aa:bb:cc:dd:ee:ff" || got[0].IP != "192.168.1.50" || got[0].Hostname != "" {
		t.Errorf("got[0] = %+v", got[0])
	}
	if got[1].MAC != "11:22:33:44:55:66" {
		t.Errorf("got[1] = %+v", got[1])
	}
}

// TestHandleDevices checks the endpoint wiring: 200 + a decodable {devices:[...]} payload (empty
// when the lease file is absent, e.g. on the dev/CI host).
func TestHandleDevices(t *testing.T) {
	s, _ := sharehandlers_server(t)
	req := httptest.NewRequest(http.MethodGet, "/api/devices", nil)
	w := httptest.NewRecorder()
	s.handleDevices(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Devices []deviceInfo `json:"devices"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, w.Body.String())
	}
	if resp.Devices == nil {
		t.Error("devices should be an array (possibly empty), not null")
	}
}
