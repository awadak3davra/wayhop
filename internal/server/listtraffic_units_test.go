package server

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"wayhop/internal/clash"
	"wayhop/internal/config"
	"wayhop/internal/model"
	"wayhop/internal/pbr"
	"wayhop/internal/platform"
	"wayhop/internal/store"
)

// QA-113. The Matched column read the kernel's packet counters out of the connections field, so a
// list the kernel had matched 52,341 packets for read "52341 conns", and dropped to "1 conn" as soon
// as the core attributed one connection to it. The kernel's numbers have their own field, in packets,
// and stay there whatever the core reports; the connection count is only ever the core's.
func TestRoutingTrafficKeepsKernelPacketsApartFromConnections(t *testing.T) {
	dir := t.TempDir()
	set4 := keeneticPBROptions("").ZoneSetName(pbr.ListZoneName("mix"), "4")
	listing := "Chain WR_PREROUTING (1 references)\n" +
		"    pkts      bytes target     prot opt in     out     source               destination\n" +
		"   52341 38000000 MARK       all  --  *      *       0.0.0.0/0            0.0.0.0/0            match-set " + set4 + " dst MARK set 0x10\n"
	out := filepath.Join(dir, "ipt.txt")
	if err := os.WriteFile(out, []byte(listing), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		_ = os.WriteFile(filepath.Join(bin, "iptables.bat"), []byte("@type \""+out+"\"\r\n"), 0o755)
		_ = os.WriteFile(filepath.Join(bin, "ip6tables.bat"), []byte("@exit /b 1\r\n"), 0o755)
	} else {
		_ = os.WriteFile(filepath.Join(bin, "iptables"), []byte("#!/bin/sh\ncat '"+out+"'\n"), 0o755)
		_ = os.WriteFile(filepath.Join(bin, "ip6tables"), []byte("#!/bin/sh\nexit 1\n"), 0o755)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	cfg := config.Default()
	cfg.DataDir = dir
	cfg.RoutingMode = "hybrid"
	cfg.SingBox.Config = filepath.Join(dir, "singbox.json")
	if err := os.WriteFile(cfg.SingBox.Config, []byte(`{"route":{"rule_set":[{"tag":"rsm-mix","type":"inline"}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Replace(model.Profile{RoutingLists: []model.RoutingList{{
		ID: "mix", Name: "mix", Enabled: true, Outbound: "direct",
		Manual: []string{"example.com", "203.0.113.0/24"},
	}}}); err != nil {
		t.Fatal(err)
	}
	cl, _ := clash.New("127.0.0.1:1", "")
	s := &Server{cfg: cfg, store: st, clash: cl, outbound: newObSampler(),
		platformOf: func() platform.Platform { return platform.Keenetic }}
	type kernel struct {
		Packets int64 `json:"packets"`
		Bytes   int64 `json:"bytes"`
	}
	type row struct {
		Conns  int64   `json:"conns"`
		Bytes  int64   `json:"bytes"`
		Kernel *kernel `json:"kernel"`
	}
	get := func() row {
		rec := httptest.NewRecorder()
		s.handleRoutingTraffic(rec, httptest.NewRequest("GET", "/api/routing/traffic", nil))
		var body struct {
			Lists map[string]row `json:"lists"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Lists["mix"]
	}

	// The core has seen nothing: no connections, and the kernel's packets on their own field.
	if r := get(); r.Conns != 0 || r.Bytes != 0 || r.Kernel == nil || r.Kernel.Packets != 52341 || r.Kernel.Bytes != 38000000 {
		t.Fatalf("core silent: %+v (kernel %+v), want 0 conns and the kernel's 52341 packets / 38000000 bytes apart", r, r.Kernel)
	}

	// The core attributes one connection: that is the connection count, and the kernel's packets stay.
	s.outbound.mu.Lock()
	s.outbound.listConns["mix"] = 1
	s.outbound.mu.Unlock()
	if r := get(); r.Conns != 1 || r.Kernel == nil || r.Kernel.Packets != 52341 {
		t.Fatalf("one core connection: %+v (kernel %+v), want 1 conn and the kernel's 52341 packets kept", r, r.Kernel)
	}
}
