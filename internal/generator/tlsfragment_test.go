package generator

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"wayhop/internal/model"
)

// tlsFragmentProfile has a direct list per fragment mode and a tunnelled list that asks for one too.
func tlsFragmentProfile() *model.Profile {
	nl := generator_singBoxEndpoint("nl", model.ProtoVLESS, map[string]any{"uuid": "11111111-2222-3333-4444-555555555555"})
	return &model.Profile{
		Endpoints: []model.Endpoint{nl},
		Rules:     []model.Rule{{ID: "d", Default: true, Outbound: model.OutboundDirect}},
		RoutingLists: []model.RoutingList{
			{ID: "yt", Name: "YouTube", Manual: []string{"youtube.com", "googlevideo.com"}, Outbound: model.OutboundDirect, TLSFragment: model.TLSFragmentRecord, Enabled: true},
			{ID: "hs", Name: "Handshake", Manual: []string{"example.org"}, Outbound: model.OutboundDirect, TLSFragment: model.TLSFragmentHandshake, Enabled: true},
			{ID: "tun", Name: "Via NL", Manual: []string{"example.net"}, Outbound: "nl", TLSFragment: model.TLSFragmentRecord, Enabled: true},
			{ID: "plain", Name: "Plain", Manual: []string{"example.com"}, Outbound: model.OutboundDirect, Enabled: true},
		},
	}
}

// A direct list carries sing-box's route options on its own rule; a tunnelled list never does (the
// ClientHello travels inside the tunnel), and a list without the setting is unchanged.
func TestRoutingListTLSFragment(t *testing.T) {
	res, err := Generate(tlsFragmentProfile(), Options{MixedPort: 7890})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	byList := map[string]map[string]any{}
	for _, r := range res.Config["route"].(map[string]any)["rules"].([]map[string]any) {
		tags, _ := r["rule_set"].([]string)
		for _, tag := range tags {
			byList[strings.TrimPrefix(tag, "rsm-")] = r
		}
	}
	if r := byList["yt"]; r == nil || r["tls_record_fragment"] != true || r["tls_fragment"] != nil {
		t.Errorf("record list rule = %v", r)
	}
	if r := byList["hs"]; r == nil || r["tls_fragment"] != true || r["tls_record_fragment"] != nil {
		t.Errorf("handshake list rule = %v", r)
	}
	if r := byList["tun"]; r == nil || r["tls_fragment"] != nil || r["tls_record_fragment"] != nil {
		t.Errorf("a tunnelled list must not fragment: %v", r)
	}
	if r := byList["plain"]; r == nil || r["tls_fragment"] != nil || r["tls_record_fragment"] != nil {
		t.Errorf("a list without the setting must be unchanged: %v", r)
	}
	p := tlsFragmentProfile()
	p.RoutingLists[0].TLSFragment = "split"
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "tls_fragment") {
		t.Errorf("an unknown mode must be refused: %v", err)
	}
}

// The rule passes the real core's check (route options since 1.12), on whatever WR_SINGBOX is.
func TestRoutingListTLSFragmentSingBoxCheck(t *testing.T) {
	bin := os.Getenv("WR_SINGBOX")
	if bin == "" {
		t.Skip("WR_SINGBOX not set — set it to a sing-box binary for a real `check`")
	}
	ver := singboxVersionOf(t, bin)
	res, err := Generate(tlsFragmentProfile(), Options{MixedPort: 7890, CoreVersion: ver})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	data, _ := json.MarshalIndent(res.Config, "", "  ")
	f := filepath.Join(t.TempDir(), "tls-fragment.json")
	if err := os.WriteFile(f, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", f).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check rejected the route options: %v\n%s", err, out)
	}
}
