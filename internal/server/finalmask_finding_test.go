package server

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/platform"
)

// QA-136: the Apply review names the Xray masks a link carries that only the client's sending side
// applies, which sing-box leaves out (a note: the connection works without them). A mask the server
// undoes, or fm that is no finalmask, which an import refuses, is named as failing the connection when
// it arrives another way. A finalmask that asks nothing of a client, and no finalmask, say nothing.
func TestEndpointFindings_FinalMask(t *testing.T) {
	s, _ := sharehandlers_server(t)
	bin := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(bin, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	s.cfg.SingBox.Bin = bin
	s.coreVersionOf = func(context.Context, string) (string, error) { return "sing-box version 1.13.21\n", nil }
	ep := func(id, fm string) model.Endpoint {
		e := model.Endpoint{ID: id, Name: id, Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
			Server: "192.0.2.136", Port: 443, Params: map[string]any{"uuid": "00000000-0000-4000-8000-000000000136"},
			TLS: &model.TLS{Enabled: true, Type: "tls", SNI: "example.com"}}
		if fm != "" {
			e.Params[model.ParamFinalMask] = fm
		}
		return e
	}
	prof := model.Profile{Endpoints: []model.Endpoint{
		ep("sender", `{"tcp":[{"type":"fragment"}],"udp":[{"type":"noise"},{"type":"udphop"}]}`),
		ep("filter", `{"tcp":[{"type":"filter"}],"quicParams":{"congestion":"bbr"}}`),
		ep("peer", `{"tcp":[{"type":"fragment"}],"udp":[{"type":"salamander","settings":{"password":"invented-obfs-secret"}}]}`),
		ep("broken", `{"tcp":[`),
		ep("none", ""),
	}}
	got := map[string]PlanFinding{}
	for _, f := range s.endpointFindings(prof, platform.CapabilitySet{}) {
		if !strings.HasPrefix(f.ID, "endpoint.finalmask") {
			continue
		}
		if code, title, detail, remedy := findingTemplate(f); code == "" || title == "" || detail == "" || remedy == "" ||
			strings.HasPrefix(code, "ENDPOINT") {
			t.Errorf("%s has no template: %q %q", f.ID, code, title)
		}
		if strings.Contains(f.Requested+f.Effective+f.Detail, "invented-obfs-secret") {
			t.Errorf("%s on %s carries a mask's settings: %+v", f.ID, f.Item, f)
		}
		got[f.Item] = f
	}
	want := map[string]struct{ id, requested, blocks string }{
		"sender": {"endpoint.finalmask.sender", "Xray finalmask: fragment, noise, udphop", platform.BlocksNothing},
		"peer":   {"endpoint.finalmask.peer", "Xray finalmask: salamander", platform.BlocksFeature},
		"broken": {"endpoint.finalmask.peer", "Xray finalmask (not valid JSON)", platform.BlocksFeature},
	}
	if len(got) != len(want) {
		t.Errorf("findings on %v, want on %v", reflect.ValueOf(got).MapKeys(), reflect.ValueOf(want).MapKeys())
	}
	for item, w := range want {
		f, ok := got[item]
		if !ok || f.ID != w.id || f.Requested != w.requested || f.Blocks != w.blocks || f.Severity != platform.SeverityDegraded ||
			f.Effective != "not applied" {
			t.Errorf("%s: %+v, want %s %q blocking %s", item, f, w.id, w.requested, w.blocks)
		}
	}
}
