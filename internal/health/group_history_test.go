package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"wayhop/internal/clash"
	"wayhop/internal/model"
)

// TestTickDerivesGroupHistoryFromMembers is the Keenetic regression: native-first groups are not
// guaranteed to exist as Clash outbounds. A direct /proxies/{group}/delay request used to fail and
// fill Diagnostics with 0% samples + a false Down event while every member was healthy.
func TestTickDerivesGroupHistoryFromMembers(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/proxies/exit-a/delay":
			_ = json.NewEncoder(w).Encode(map[string]int{"delay": 23})
		case "/connections":
			_ = json.NewEncoder(w).Encode(map[string]any{"connections": []any{}})
		case "/proxies":
			_ = json.NewEncoder(w).Encode(map[string]any{"proxies": map[string]any{}})
		default:
			http.Error(w, `{"message":"proxy not found"}`, http.StatusServiceUnavailable)
		}
	}))
	defer ts.Close()

	cl, err := clash.New(strings.TrimPrefix(ts.URL, "http://"), "")
	if err != nil {
		t.Fatalf("clash.New: %v", err)
	}
	p := model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "exit-a", Name: "Exit A", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
			Server: "example.test", Port: 443, Enabled: true,
		}},
		Groups: []model.Group{
			// Parent intentionally precedes child to exercise the nested-group fixpoint.
			{ID: "all-vpn", Name: "All VPN", Type: model.GroupURLTest, Members: []string{"inner"}},
			{ID: "inner", Name: "Inner", Type: model.GroupURLTest, Members: []string{"exit-a"}},
		},
	}
	m := NewMonitor(cl, health_newStore(t, p), nil, false)

	for i := 0; i < healthWindow; i++ {
		m.tick(context.Background())
	}

	mu.Lock()
	gotPaths := append([]string(nil), paths...)
	mu.Unlock()
	groupProbe := "/proxies/all-vpn/delay"
	innerProbe := "/proxies/inner/delay"
	endpointProbes := 0
	for _, path := range gotPaths {
		if path == groupProbe || path == innerProbe {
			t.Fatalf("group was incorrectly sent to Clash Delay: %s (all paths: %v)", path, gotPaths)
		}
		if path == "/proxies/exit-a/delay" {
			endpointProbes++
		}
	}
	if endpointProbes != healthWindow {
		t.Fatalf("endpoint delay probes = %d, want %d", endpointProbes, healthWindow)
	}

	windows := map[string]RecentWindow{}
	for _, window := range m.RecentWindows() {
		windows[window.ID] = window
	}
	for _, id := range []string{"inner", "all-vpn"} {
		window, ok := windows[id]
		if !ok {
			t.Fatalf("missing derived group history for %s", id)
		}
		if len(window.Samples) != healthWindow {
			t.Fatalf("%s samples = %d, want %d", id, len(window.Samples), healthWindow)
		}
		for i, answered := range window.Samples {
			if !answered {
				t.Fatalf("%s sample %d = no answer; healthy member must make the group healthy", id, i)
			}
		}
	}
	for _, event := range m.Events(100) {
		if (event.ID == "inner" || event.ID == "all-vpn") && event.Kind == EventDown {
			t.Fatalf("healthy derived group produced a false Down event: %+v", event)
		}
	}
}

// TestApplyResultsIgnoresStandaloneGroupProbe locks the API boundary independently of tick(): even
// if a caller supplies Down for the group slot, only endpoint observations are authoritative.
func TestApplyResultsIgnoresStandaloneGroupProbe(t *testing.T) {
	m := &Monitor{stats: map[string]*stat{}}
	tgs := []target{
		{id: "exit-a", name: "Exit A", kind: "endpoint"},
		{id: "all-vpn", name: "All VPN", kind: "group"},
	}
	groups := []model.Group{{
		ID: "all-vpn", Name: "All VPN", Type: model.GroupURLTest, Members: []string{"exit-a"},
	}}
	for i := 0; i < healthWindow; i++ {
		m.applyResultsWithGroups(tgs, groups, []State{Alive, Down}, []int{19, 0}, int64(1000+i*1000))
	}

	var group RecentWindow
	for _, window := range m.RecentWindows() {
		if window.ID == "all-vpn" {
			group = window
		}
	}
	if len(group.Samples) != healthWindow {
		t.Fatalf("group samples = %d, want %d", len(group.Samples), healthWindow)
	}
	for i, answered := range group.Samples {
		if !answered {
			t.Fatalf("group sample %d accepted the false standalone Down result", i)
		}
	}
}

// TestProbeOneGroupDoesNotCallClash ensures the manual health endpoint cannot reintroduce the same
// false negative outside the background tick.
func TestProbeOneGroupDoesNotCallClash(t *testing.T) {
	var mu sync.Mutex
	requests := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		http.Error(w, "must not be called", http.StatusInternalServerError)
	}))
	defer ts.Close()
	cl, err := clash.New(strings.TrimPrefix(ts.URL, "http://"), "")
	if err != nil {
		t.Fatalf("clash.New: %v", err)
	}
	p := model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "exit-a", Name: "Exit A", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
			Server: "example.test", Port: 443, Enabled: true,
		}},
		Groups: []model.Group{{ID: "all-vpn", Name: "All VPN", Type: model.GroupURLTest, Members: []string{"exit-a"}}},
	}
	m := NewMonitor(cl, health_newStore(t, p), nil, false)
	m.record("exit-a", "Exit A", "endpoint", Alive, 17, nowMS())

	v := m.ProbeOne(context.Background(), "all-vpn")
	if v.State != string(Alive) || v.SuccessRate != 100 {
		t.Fatalf("derived group view = state %q, success %d; want alive/100", v.State, v.SuccessRate)
	}
	mu.Lock()
	gotRequests := requests
	mu.Unlock()
	if gotRequests != 0 {
		t.Fatalf("manual group probe made %d Clash requests, want 0", gotRequests)
	}
}
