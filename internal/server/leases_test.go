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
