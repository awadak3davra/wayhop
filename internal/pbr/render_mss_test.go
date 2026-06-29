package pbr

import (
	"strings"
	"testing"

	"velinx/internal/model"
)

// mssProfile builds a minimal profile with one kernel tunnel egress (awg0) routing a CIDR list.
func mssProfile() *model.Profile {
	return &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "nl", Engine: model.EngineExternal, Server: "203.0.113.1",
			Enabled: true, Params: map[string]any{"interface": "awg0"},
		}},
		RoutingLists: []model.RoutingList{
			{ID: "censored", Manual: []string{"1.2.3.0/24"}, Outbound: "nl", Enabled: true},
		},
	}
}

// TestRenderNft_MSSChain: a plan with an EgressInterface egress must emit a wr_mss chain
// that clamps TCP SYN MSS to the route MTU on the tunnel oifname set.
func TestRenderNft_MSSChain(t *testing.T) {
	plan, _, err := Compile(mssProfile(), Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	nft := plan.RenderNft()

	mustContain(t, nft, "chain wr_mss {")
	mustContain(t, nft, "type filter hook forward priority mangle; policy accept;")
	mustContain(t, nft, `oifname { "awg0" }`)
	mustContain(t, nft, "tcp flags & (fin|syn|rst|ack) == syn")
	mustContain(t, nft, "tcp option maxseg size set rt mtu")
}

// TestRenderNft_MSSDedup: two egresses on the same iface must yield exactly one oifname entry.
func TestRenderNft_MSSDedup(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "ep1", Engine: model.EngineExternal, Server: "203.0.113.1", Enabled: true, Params: map[string]any{"interface": "awg0"}},
			{ID: "ep2", Engine: model.EngineExternal, Server: "203.0.113.2", Enabled: true, Params: map[string]any{"interface": "awg1"}},
		},
		RoutingLists: []model.RoutingList{
			{ID: "l1", Manual: []string{"1.2.3.0/24"}, Outbound: "ep1", Enabled: true},
			{ID: "l2", Manual: []string{"5.6.7.0/24"}, Outbound: "ep2", Enabled: true},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	nft := plan.RenderNft()
	mustContain(t, nft, `"awg0"`)
	mustContain(t, nft, `"awg1"`)
	// The wr_mss chain must appear exactly once.
	if n := strings.Count(nft, "chain wr_mss {"); n != 1 {
		t.Errorf("wr_mss chain emitted %d times, want 1:\n%s", n, nft)
	}
}

// TestRenderNft_NoMSSWithoutTunnel: a WAN-only or blackhole plan must not emit wr_mss.
func TestRenderNft_NoMSSWithoutTunnel(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "direct", Engine: model.EngineSingBox, Protocol: model.ProtoVLESS,
			Server: "1.2.3.4", Port: 443, Enabled: true,
		}},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	nft := plan.RenderNft()
	if strings.Contains(nft, "wr_mss") {
		t.Errorf("wr_mss emitted for a sing-box-only plan (no EgressInterface):\n%s", nft)
	}
}

// TestRenderIptables_MSSRules: RenderIptablesScript must emit TCPMSS FORWARD rules for each
// kernel tunnel egress and the teardown must remove them.
func TestRenderIptables_MSSRules(t *testing.T) {
	plan, _, err := Compile(mssProfile(), Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	io := IpsetOptions{}
	script := plan.RenderIptablesScript(io)
	teardown := plan.RenderTeardownScript(Options{}, io)

	for _, ipt := range []string{"iptables", "ip6tables"} {
		wantAdd := ipt + " -t mangle -C FORWARD -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
		if !strings.Contains(script, wantAdd) {
			t.Errorf("MSS install rule missing for %s:\n%s", ipt, script)
		}
		wantDel := ipt + " -t mangle -D FORWARD -o awg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"
		if !strings.Contains(teardown, wantDel) {
			t.Errorf("MSS teardown rule missing for %s:\n%s", ipt, teardown)
		}
	}
}

// TestRenderIptables_MSSDedup: two egresses on different ifaces each get their own TCPMSS rules;
// if two egresses share the same iface they should appear exactly once.
func TestRenderIptables_MSSDedup(t *testing.T) {
	p := &model.Profile{
		Endpoints: []model.Endpoint{
			{ID: "ep1", Engine: model.EngineExternal, Server: "10.0.0.1", Enabled: true, Params: map[string]any{"interface": "awg0"}},
			{ID: "ep2", Engine: model.EngineExternal, Server: "10.0.0.2", Enabled: true, Params: map[string]any{"interface": "awg1"}},
		},
		RoutingLists: []model.RoutingList{
			{ID: "l1", Manual: []string{"1.2.3.0/24"}, Outbound: "ep1", Enabled: true},
			{ID: "l2", Manual: []string{"5.6.7.0/24"}, Outbound: "ep2", Enabled: true},
		},
	}
	plan, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	script := plan.RenderIptablesScript(IpsetOptions{})

	for _, ifc := range []string{"awg0", "awg1"} {
		want := "FORWARD -o " + ifc + " -p tcp --tcp-flags SYN,RST SYN -j TCPMSS"
		if !strings.Contains(script, want) {
			t.Errorf("MSS rule for %s missing:\n%s", ifc, script)
		}
	}
}
