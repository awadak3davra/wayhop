package server

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"velinx/internal/model"
)

// TestFilterInterfaces locks the pure filter: loopback dropped, the rest sorted by name with the
// up flag + addresses preserved.
func TestFilterInterfaces(t *testing.T) {
	raw := []rawIface{
		{name: "lo", flags: net.FlagUp | net.FlagLoopback, addrs: []string{"127.0.0.1/8"}},
		{name: "br-lan", flags: net.FlagUp | net.FlagBroadcast, addrs: []string{"192.168.1.1/24", "fd00::1/64"}},
		{name: "eth0", flags: net.FlagBroadcast}, // down (no FlagUp)
		{name: "awg0", flags: net.FlagUp | net.FlagPointToPoint, addrs: []string{"10.0.0.2/32"}},
	}
	got := filterInterfaces(raw)
	if len(got) != 3 {
		t.Fatalf("want 3 (loopback dropped), got %d: %+v", len(got), got)
	}
	wantOrder := []string{"awg0", "br-lan", "eth0"}
	for i, w := range wantOrder {
		if got[i].Name != w {
			t.Errorf("sorted order[%d] = %q, want %q", i, got[i].Name, w)
		}
	}
	for _, ii := range got {
		if ii.Name == "lo" {
			t.Error("loopback must be excluded")
		}
		switch ii.Name {
		case "br-lan":
			if !ii.Up || len(ii.Addrs) != 2 {
				t.Errorf("br-lan: up=%v addrs=%v, want up + 2 addrs", ii.Up, ii.Addrs)
			}
		case "eth0":
			if ii.Up {
				t.Error("eth0 should be reported down")
			}
		}
	}
}

// TestHandleInterfaces checks the endpoint wiring: 200 + a decodable {interfaces:[...]} payload
// (no loopback among the addresses).
func TestHandleInterfaces(t *testing.T) {
	s, _ := sharehandlers_server(t)
	req := httptest.NewRequest(http.MethodGet, "/api/interfaces", nil)
	w := httptest.NewRecorder()
	s.handleInterfaces(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Interfaces []ifaceInfo `json:"interfaces"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v; body=%s", err, w.Body.String())
	}
	for _, ii := range resp.Interfaces {
		if ii.Name == "" {
			t.Error("interface name should not be empty")
		}
		for _, a := range ii.Addrs {
			if a == "127.0.0.1/8" || a == "::1/128" {
				t.Errorf("loopback address leaked: %s", a)
			}
		}
	}
}

// TestCheckSourceIfaces locks the source-iface diagnostic: an existing or wildcard-matched
// interface passes; a typo'd / unmatched-wildcard interface is flagged; disabled rules and blank
// entries are skipped.
func TestCheckSourceIfaces(t *testing.T) {
	names := []string{"br-lan", "eth0", "wg0"}
	rules := []model.Rule{
		{ID: "ok", SourceIface: []string{"br-lan"}, IPCIDR: []string{"8.8.8.0/24"}, Outbound: "x"},
		{ID: "typo", SourceIface: []string{"br-gust"}, IPCIDR: []string{"8.8.8.0/24"}, Outbound: "x"},
		{ID: "wild", SourceIface: []string{"wg*"}, IPCIDR: []string{"8.8.8.0/24"}, Outbound: "x"},
		{ID: "wildmiss", SourceIface: []string{"tun*"}, IPCIDR: []string{"8.8.8.0/24"}, Outbound: "x"},
		{ID: "off", SourceIface: []string{"nope"}, IPCIDR: []string{"8.8.8.0/24"}, Outbound: "x", Disabled: true},
		{ID: "blank", SourceIface: []string{"  "}, IPCIDR: []string{"8.8.8.0/24"}, Outbound: "x"},
	}
	bad := checkSourceIfaces(rules, names)
	// Exactly two findings (typo + wildmiss) — which also proves the valid/disabled/blank rules
	// were NOT flagged.
	if len(bad) != 2 {
		t.Fatalf("want 2 findings (typo + wildmiss), got %d: %v", len(bad), bad)
	}
	joined := strings.Join(bad, " ")
	if !strings.Contains(joined, "typo") || !strings.Contains(joined, "wildmiss") {
		t.Errorf("findings should name the typo + wildmiss rules, got %v", bad)
	}
}

// TestSourceRuleCheck: the battery probe passes on an empty profile and warns when a source rule
// references a nonexistent interface.
func TestSourceRuleCheck(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if got := s.sourceRuleCheck(context.Background()); got.Status != "pass" {
		t.Fatalf("empty profile: status=%s, want pass", got.Status)
	}
	if err := s.store.UpsertEndpoint(model.Endpoint{ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20", Enabled: true, Params: map[string]any{"interface": "awg1"}}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	if err := s.store.UpsertRule(model.Rule{ID: "r", SourceIface: []string{"zzz-nonexistent-iface-99"}, IPCIDR: []string{"8.8.8.0/24"}, Outbound: "ru-awg1"}); err != nil {
		t.Fatalf("UpsertRule: %v", err)
	}
	got := s.sourceRuleCheck(context.Background())
	if got.Status != "warn" {
		t.Fatalf("missing-iface rule: status=%s detail=%q, want warn", got.Status, got.Detail)
	}
}
