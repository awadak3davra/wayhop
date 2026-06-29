package keenetic

import (
	"context"
	"strings"
	"testing"

	"velinx/internal/model"
)

// TestPlanApply drives the full write path against the httptest RCI mock (NOT a real
// device): Compile a profile, Apply it, and assert the exact native commands were submitted
// over /rci/parse — interface block, routes, anti-loop bypass, and the config save.
func TestPlanApply(t *testing.T) {
	ts, recorded := fakeKeenetic(t, "admin", "secret")
	rci, err := NewRCIClient(ts.URL, "admin", "secret")
	if err != nil {
		t.Fatal(err)
	}

	awg := awgEndpoint()
	awg.ID, awg.Enabled = "awg-nl", true
	p := &model.Profile{
		Endpoints: []model.Endpoint{awg},
		RoutingLists: []model.RoutingList{
			{ID: "ru", Manual: []string{"109.254.0.0/16"}, Outbound: "awg-nl", Enabled: true},
		},
	}
	plan, err := Compile(p, CompileOptions{BaseIndex: 10})
	if err != nil {
		t.Fatal(err)
	}

	if err := plan.Apply(context.Background(), rci, ApplyOptions{Save: true}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got := strings.Join(*recorded, "\n")
	for _, w := range []string{
		"interface Wireguard10",                        // native iface created
		"wireguard asc",                                // AmneziaWG obfuscation params
		"ip route 109.254.0.0 255.255.0.0 Wireguard10", // list → native iface
		"ip route 203.0.113.10 255.255.255.255 ISP",    // anti-loop bypass
		"system configuration save",                    // persisted
	} {
		if !strings.Contains(got, w) {
			t.Errorf("Apply did not submit %q\n--- submitted ---\n%s", w, got)
		}
	}
}

// TestPlanDeploy: the combined entry point applies BOTH planes — sing-box service restart
// (fallback TUNs) AND the NDM interfaces/routes over RCI.
func TestPlanDeploy(t *testing.T) {
	ts, recorded := fakeKeenetic(t, "admin", "secret")
	rci, _ := NewRCIClient(ts.URL, "admin", "secret")

	awg := awgEndpoint()
	awg.ID, awg.Enabled = "awg-nl", true
	vless := model.Endpoint{ID: "vless-nl", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "9.9.9.9", Port: 443, Enabled: true, Params: map[string]any{"uuid": "u"}}
	p := &model.Profile{
		Endpoints: []model.Endpoint{awg, vless},
		RoutingLists: []model.RoutingList{
			{ID: "proxy", Manual: []string{"172.16.0.0/24"}, Outbound: "vless-nl", Enabled: true},
		},
	}
	plan, err := Compile(p, CompileOptions{BaseIndex: 10})
	if err != nil {
		t.Fatal(err)
	}

	run := &recRunner{}
	dir := t.TempDir()
	if err := plan.Deploy(context.Background(), rci, run,
		ApplyOptions{Save: true},
		SingboxApplyOptions{ConfigPath: dir + "/config.json"}); err != nil {
		t.Fatalf("Deploy: %v", err)
	}

	// sing-box plane: service restarted.
	if len(run.calls) != 1 || !strings.Contains(run.calls[0], "S99sing-box restart") {
		t.Errorf("sing-box restart calls = %v", run.calls)
	}
	// NDM plane: native interface + the fallback route + save all hit RCI.
	got := strings.Join(*recorded, "\n")
	for _, w := range []string{"interface Wireguard10", "ip route 172.16.0.0 255.255.255.0 wrtun0", "system configuration save"} {
		if !strings.Contains(got, w) {
			t.Errorf("Deploy did not submit %q", w)
		}
	}
}

// TestPlanApply_NoSave: without Save, no `system configuration save` is submitted.
func TestPlanApply_NoSave(t *testing.T) {
	ts, recorded := fakeKeenetic(t, "admin", "secret")
	rci, _ := NewRCIClient(ts.URL, "admin", "secret")
	plan := &Plan{Routes: []string{"ip route 1.2.3.0 255.255.255.0 ISP"}}
	if err := plan.Apply(context.Background(), rci, ApplyOptions{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(*recorded, "\n"), "configuration save") {
		t.Error("Save=false must not submit a config save")
	}
}
