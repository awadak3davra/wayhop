package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"wayhop/internal/generator"
	"wayhop/internal/model"
	"wayhop/internal/netdiag"
	"wayhop/internal/pbr"
	"wayhop/internal/store"
)

// Each exit is asked through a client that really leaves by it, and an exit that cannot be asked says
// why instead of reading as a dead service.
func TestNetDiagServicesPicksTheClientPerExit(t *testing.T) {
	s, _ := sharehandlers_server(t)
	prof := model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "ext", Name: "Ext", Enabled: true, Engine: model.EngineExternal, Params: map[string]any{"interface": "wg0"}},
			{ID: "gone", Name: "Gone", Enabled: true, Engine: model.EngineExternal, Params: map[string]any{"interface": "wg9"}},
			{ID: "nl", Name: "NL", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "nl.example.net", Port: 443,
				Params: map[string]any{"uuid": "11111111-2222-3333-4444-555555555555"}},
			{ID: "de", Name: "DE", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "de.example.net", Port: 443,
				Params: map[string]any{"uuid": "11111111-2222-3333-4444-555555555555"}},
		},
		Groups: []model.Group{{ID: "auto", Name: "Auto", Type: model.GroupURLTest, Members: []string{"nl"}}},
	}
	if err := s.store.Replace(prof); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(t.TempDir(), "singbox.json")
	s.cfg.SingBox.Config = cfgPath
	users := []map[string]any{}
	for _, tag := range []string{model.OutboundDirect, "nl", "auto"} {
		users = append(users, map[string]any{"username": generator.ProbeUser(tag), "password": "pw-" + tag})
	}
	running, _ := json.Marshal(map[string]any{"inbounds": []map[string]any{
		{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890},
		{"type": "mixed", "tag": generator.ProbeInboundTag, "listen": "127.0.0.1", "listen_port": 17890, "users": users},
	}})
	ctrl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer ctrl.Close()

	origUp := ifaceUp
	t.Cleanup(func() { ifaceUp = origUp })
	ifaceUp = func(name string) bool { return name == "wg0" }

	var mu sync.Mutex
	asked := map[string]string{} // proxy user (or "bound") -> count marker
	orig := checkServices
	t.Cleanup(func() { checkServices = orig })
	checkServices = func(_ context.Context, c *http.Client) netdiag.ExitServices {
		who := "unbound"
		if tr, ok := c.Transport.(*http.Transport); ok && tr.Proxy != nil {
			u, _ := tr.Proxy(&http.Request{})
			pw, _ := u.User.Password()
			who = u.User.Username() + ":" + pw + "@" + u.Host
		}
		mu.Lock()
		asked[who] = "yes"
		mu.Unlock()
		return netdiag.ExitServices{Identity: netdiag.ExitIdentity{Country: "ZZ"}}
	}
	run := func(body string) (int, map[string]exitServices) {
		t.Helper()
		rec := httptest.NewRecorder()
		s.handleNetDiagServices(rec, httptest.NewRequest(http.MethodPost, "/api/netdiag/services", strings.NewReader(body)))
		var out struct {
			Results []exitServices `json:"results"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		rows := map[string]exitServices{}
		for _, r := range out.Results {
			rows[r.Egress] = r
		}
		return rec.Code, rows
	}

	// Core running, probe inbound in the running config.
	if err := os.WriteFile(cfgPath, running, 0o600); err != nil {
		t.Fatal(err)
	}
	s.cfg.Clash.Controller = strings.TrimPrefix(ctrl.URL, "http://")
	_, rows := run("")
	for tag, want := range map[string]struct{ via, iface, err string }{
		model.OutboundDirect: {"core", "", ""}, "ext": {"interface", "wg0", ""}, "nl": {"core", "", ""},
		"auto": {"core", "", ""}, "de": {"", "", servicesNotReadable}, "gone": {"interface", "wg9", servicesNoIface},
	} {
		r := rows[tag]
		if r.Via != want.via || r.Iface != want.iface || r.Err != want.err {
			t.Errorf("%s = via %q iface %q err %q, want %+v", tag, r.Via, r.Iface, r.Err, want)
		}
		if want.err == "" && r.Identity.Country != "ZZ" {
			t.Errorf("%s was not checked: %+v", tag, r)
		}
	}
	for _, who := range []string{"x-direct:pw-direct@127.0.0.1:17890", "x-nl:pw-nl@127.0.0.1:17890", "x-auto:pw-auto@127.0.0.1:17890"} {
		if asked[who] == "" {
			t.Errorf("never asked through %s; asked %v", who, asked)
		}
	}

	// One exit only; an unknown one is refused.
	if code, rows := run(`{"egress":"nl"}`); code != http.StatusOK || len(rows) != 1 || rows["nl"].Via != "core" {
		t.Errorf("one exit: %d %v", code, rows)
	}
	if code, _ := run(`{"egress":"nope"}`); code != http.StatusNotFound {
		t.Errorf("unknown exit: %d", code)
	}

	// Not Applied since the probe inbound existed: say so; the WAN is still asked, unbound.
	if err := os.WriteFile(cfgPath, []byte(`{"inbounds":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, rows = run("")
	if rows["nl"].Err != servicesNeedApply || rows[model.OutboundDirect].Via != "interface" || rows[model.OutboundDirect].Err != "" {
		t.Errorf("no probe inbound: nl %+v, direct %+v", rows["nl"], rows[model.OutboundDirect])
	}

	// Core down: a sing-box exit says the core is not running rather than "unreachable".
	if err := os.WriteFile(cfgPath, running, 0o600); err != nil {
		t.Fatal(err)
	}
	s.cfg.Clash.Controller = ""
	_, rows = run("")
	if rows["nl"].Err != servicesCoreDown || rows[model.OutboundDirect].Via != "interface" {
		t.Errorf("core down: nl %+v, direct %+v", rows["nl"], rows[model.OutboundDirect])
	}
}

// Only a loopback probe inbound counts; anything else in the file is not ours to use.
func TestRunningProbeInbound(t *testing.T) {
	dir := t.TempDir()
	for name, tc := range map[string]struct {
		body string
		ok   bool
	}{
		"loopback":    {`{"inbounds":[{"tag":"probe-in","listen":"127.0.0.1","listen_port":17890,"users":[{"username":"x-a","password":"p"}]}]}`, true},
		"all address": {`{"inbounds":[{"tag":"probe-in","listen":"0.0.0.0","listen_port":17890}]}`, false},
		"no port":     {`{"inbounds":[{"tag":"probe-in","listen":"127.0.0.1"}]}`, false},
		"garbage":     {`not json`, false},
	} {
		p := filepath.Join(dir, name+".json")
		_ = os.WriteFile(p, []byte(tc.body), 0o600)
		got, ok := runningProbeInbound(p)
		if ok != tc.ok || (ok && got.users["x-a"] != "p") {
			t.Errorf("%s: %+v %v, want ok=%v", name, got, ok, tc.ok)
		}
	}
	if _, ok := runningProbeInbound(filepath.Join(dir, "missing.json")); ok {
		t.Error("a missing file has no probe inbound")
	}
}

// A group is checked through the member it is on now. The first cut asked its first member that has
// an interface, so a group on a proxy member, or failed over off a dead tunnel, showed another exit's
// answers - or every service dead while the group worked.
func TestNetDiagServicesAsksAGroupThroughItsLiveMember(t *testing.T) {
	tables := &fakeTables{show: map[bool]string{false: "default dev wg0 table 1002 metric 1024\n"}}
	plan := &pbr.Plan{Table: "wayhop", Egresses: []pbr.Egress{
		{Tag: model.OutboundDirect, Kind: pbr.EgressWAN, Mark: 0x10000, Table: 150},
		{Tag: "list", Kind: pbr.EgressInterface, Iface: "wg9", Mark: 0x20000, Table: 1002},
	}}
	s := restoreServer(t, plan, tables)
	st, err := store.Open(filepath.Join(t.TempDir(), "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.store = st
	if err := s.store.Replace(model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "ext", Name: "Ext", Enabled: true, Engine: model.EngineExternal, Params: map[string]any{"interface": "wg0"}},
			{ID: "gone", Name: "Gone", Enabled: true, Engine: model.EngineExternal, Params: map[string]any{"interface": "wg9"}},
			{ID: "nl", Name: "NL", Enabled: true, Engine: model.EngineSingBox, Protocol: model.ProtoVLESS, Server: "nl.example.net", Port: 443,
				Params: map[string]any{"uuid": "11111111-2222-3333-4444-555555555555"}},
		},
		Groups: []model.Group{
			{ID: "auto", Name: "Auto", Type: model.GroupURLTest, Members: []string{"ext", "nl"}},
			{ID: "list", Name: "List", Type: model.GroupFallback, Members: []string{"gone", "ext"}},
		},
	}); err != nil {
		t.Fatal(err)
	}
	origUp := ifaceUp
	t.Cleanup(func() { ifaceUp = origUp })
	ifaceUp = func(name string) bool { return name == "wg0" }
	probe := probeInbound{port: 17890, users: map[string]string{generator.ProbeUser("auto"): "pw"}}

	// A group the core carries: its own probe user, so the core's current pick answers.
	if c, via, iface, why := s.serviceClient(context.Background(), "auto", probe, true, true); c == nil || via != "core" || iface != "" || why != "" {
		t.Errorf("core group = %v %q %q %q, want the core's probe user", c != nil, via, iface, why)
	}
	// A routing list's group: the device its table holds now (failed over to ext), not wg9.
	if c, via, iface, why := s.serviceClient(context.Background(), "list", probe, true, true); c == nil || via != "interface" || iface != "wg0" || why != "" {
		t.Errorf("kernel group = %v %q %q %q, want its table's live device wg0", c != nil, via, iface, why)
	}
	// Tables unreadable and no probe user: nothing says which member it is on, and its first member
	// with an interface (wg9) is a guess that answers for another exit - it says so instead (QA-049).
	tables.readErr = map[bool]error{false: errors.New("no ip")}
	if c, _, iface, why := s.serviceClient(context.Background(), "list", probe, true, true); c != nil || iface != "" || why != servicesNotReadable {
		t.Errorf("unreadable tables = %v %q %q, want not readable", c != nil, iface, why)
	}
	if _, _, _, why := s.serviceClient(context.Background(), "list", probeInbound{}, false, false); why != servicesNeedApply {
		t.Errorf("no probe inbound at all = %q, want %q", why, servicesNeedApply)
	}
}
