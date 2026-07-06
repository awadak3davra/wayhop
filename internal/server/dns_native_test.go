package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"wayhop/internal/nativedns"
)

func TestHandleDNSNativePlan_Keenetic(t *testing.T) {
	s := applyhealth_server(t)
	nd := nativedns.NativeDNS{Platform: "keenetic", StrictOrder: true, NoResolv: true, Resolvers: []nativedns.NativeResolver{
		{Kind: nativedns.KindPlain, Address: "10.8.1.0", Tier: nativedns.TierHidden, ViaTunnel: true},
		{Kind: nativedns.KindPlain, Address: "77.88.8.8", Tier: nativedns.TierFallback},
	}}
	body, _ := json.Marshal(map[string]any{"native": nd})
	w := httptest.NewRecorder()
	s.handleDNSNativePlan(w, httptest.NewRequest(http.MethodPost, "/api/dns/native/plan", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}
	var resp struct {
		Platform string   `json:"platform"`
		Content  string   `json:"content"`
		Apply    []string `json:"apply"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Platform != "keenetic" || !strings.Contains(resp.Content, "server=77.88.8.8") || !strings.Contains(resp.Content, "strict-order") {
		t.Errorf("bad keenetic plan: %+v", resp)
	}
	if len(resp.Apply) == 0 || !strings.Contains(strings.Join(resp.Apply, " "), "S56dnsmasq") {
		t.Errorf("apply cmds missing/incomplete: %v", resp.Apply)
	}
}

func TestHandleDNSNativePlan_OpenWrt(t *testing.T) {
	s := applyhealth_server(t)
	nd := nativedns.NativeDNS{Platform: "openwrt", NoResolv: true, Resolvers: []nativedns.NativeResolver{
		{Kind: nativedns.KindDoH, Address: "https://1.1.1.1/dns-query", Tier: nativedns.TierHidden},
	}}
	body, _ := json.Marshal(map[string]any{"native": nd})
	w := httptest.NewRecorder()
	s.handleDNSNativePlan(w, httptest.NewRequest(http.MethodPost, "/api/dns/native/plan", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), "resolver_url=") {
		t.Errorf("openwrt plan should contain uci resolver_url set: %s", w.Body)
	}
}

func TestHandleDNSNativePlan_InvalidRejected(t *testing.T) {
	s := applyhealth_server(t)
	body, _ := json.Marshal(map[string]any{"native": nativedns.NativeDNS{Platform: "openwrt"}}) // no resolvers
	w := httptest.NewRecorder()
	s.handleDNSNativePlan(w, httptest.NewRequest(http.MethodPost, "/api/dns/native/plan", bytes.NewReader(body)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty native should be 400, got %d: %s", w.Code, w.Body)
	}
}
