package pbr

import (
	"errors"
	"strings"
	"testing"

	"velinx/internal/model"
)

func vowifiPlan(t *testing.T) *Plan {
	t.Helper()
	p := &model.Profile{
		Endpoints: []model.Endpoint{{
			ID: "ru-awg1", Engine: model.EngineExternal, Server: "198.51.100.20",
			Enabled: true, Params: map[string]any{"interface": "awg1"},
		}},
		RoutingLists: []model.RoutingList{{
			ID: "carrier-carveout", Manual: []string{"198.51.100.0/24"}, Outbound: "ru-awg1", Enabled: true,
		}},
	}
	pl, _, err := Compile(p, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return pl
}

func indexOfContains(ss []string, sub string) int {
	for i, s := range ss {
		if strings.Contains(s, sub) {
			return i
		}
	}
	return -1
}

func TestApply(t *testing.T) {
	pl := vowifiPlan(t)
	r := &RecordRunner{}
	if err := pl.Apply(r, Options{}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(r.Calls) == 0 || r.Calls[0] != "nft -f -" {
		t.Fatalf("first call = %v, want 'nft -f -'", r.Calls)
	}
	if !strings.Contains(r.Stdin[0], "198.51.100.0/24") || !strings.Contains(r.Stdin[0], "delete table inet velinx_pbr") {
		t.Errorf("nft stdin missing zone or self-flush:\n%s", r.Stdin[0])
	}
	// ip rules must be removed before being added (idempotent re-apply).
	del := indexOfContains(r.Calls, "ip rule del fwmark 0x00020000")
	add := indexOfContains(r.Calls, "ip rule add fwmark 0x00020000/0x00ff0000 table 151 priority 150")
	if del < 0 || add < 0 || del >= add {
		t.Errorf("expected del(%d) before add(%d): %v", del, add, r.Calls)
	}
	if indexOfContains(r.Calls, "ip route replace default dev awg1 table 151") < 0 {
		t.Errorf("missing route replace: %v", r.Calls)
	}
}

func TestApply_NftError(t *testing.T) {
	pl := vowifiPlan(t)
	r := &RecordRunner{Fail: map[string]error{"nft -f": errors.New("boom")}}
	if err := pl.Apply(r, Options{}); err == nil {
		t.Fatal("expected nft load error")
	}
}

func TestApply_IPAddError(t *testing.T) {
	pl := vowifiPlan(t)
	r := &RecordRunner{Fail: map[string]error{"ip rule add": errors.New("boom")}}
	if err := pl.Apply(r, Options{}); err == nil {
		t.Fatal("expected ip rule add error")
	}
}

func TestTeardown(t *testing.T) {
	pl := vowifiPlan(t)
	r := &RecordRunner{}
	if err := pl.Teardown(r, Options{}); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if indexOfContains(r.Calls, "nft delete table inet velinx_pbr") < 0 {
		t.Errorf("missing nft delete: %v", r.Calls)
	}
	if indexOfContains(r.Calls, "ip rule del fwmark 0x00020000") < 0 {
		t.Errorf("missing ip rule del: %v", r.Calls)
	}
	if indexOfContains(r.Calls, "ip route flush table 151") < 0 {
		t.Errorf("missing route flush: %v", r.Calls)
	}
}

func TestDryRun(t *testing.T) {
	pl := vowifiPlan(t)
	d := pl.DryRun(Options{})
	if len(d) == 0 || !strings.Contains(d[0], "table inet velinx_pbr") {
		t.Fatalf("DryRun[0] should be the nft ruleset: %v", d)
	}
	if indexOfContains(d, "ip route replace default dev awg1 table 151") < 0 {
		t.Errorf("DryRun missing ip commands: %v", d)
	}
}
