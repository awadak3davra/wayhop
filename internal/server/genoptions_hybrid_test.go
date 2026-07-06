package server

import (
	"reflect"
	"testing"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// TestGenOptionsHybrid verifies the RoutingMode wiring: "hybrid" compiles the profile
// into a pbr.Plan and folds its zone+bypass CIDRs into the generator's KernelExclude
// lists (the single source of truth), forcing the TUN on; the default "" mode leaves
// Hybrid off and derives TunEnabled from Gateway (back-compat, unchanged).
func TestGenOptionsHybrid(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertEndpoint(model.Endpoint{
		ID: "ru-awg1", Name: "RU", Engine: model.EngineExternal, Server: "198.51.100.20",
		Enabled: true, Params: map[string]any{"interface": "awg1"},
	}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	if err := s.store.UpsertRoutingList(model.RoutingList{
		ID: "carrier-carveout", Name: "VoWiFi", Manual: []string{"198.51.100.0/24"}, Outbound: "ru-awg1", Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertRoutingList: %v", err)
	}
	p := s.store.Profile()

	// Default mode: no hybrid, TunEnabled follows Gateway (false here).
	s.cfg.RoutingMode = ""
	s.cfg.Gateway = false
	if o := s.genOptions(&p); o.Hybrid || o.TunEnabled || len(o.KernelExcludeV4) > 0 {
		t.Errorf("default mode: Hybrid=%v TunEnabled=%v exclude=%v, want all empty/false", o.Hybrid, o.TunEnabled, o.KernelExcludeV4)
	}

	// Hybrid mode: Hybrid on, TUN forced on, exclude == pbr.Compile union.
	s.cfg.RoutingMode = "hybrid"
	o := s.genOptions(&p)
	if !o.Hybrid || !o.TunEnabled {
		t.Fatalf("hybrid mode: Hybrid=%v TunEnabled=%v, want both true", o.Hybrid, o.TunEnabled)
	}
	plan, _, err := pbr.Compile(&p, pbr.Options{})
	if err != nil {
		t.Fatalf("pbr.Compile: %v", err)
	}
	var wantV4, wantV6 []string
	for _, z := range plan.Zones {
		wantV4 = append(wantV4, z.V4...)
		wantV6 = append(wantV6, z.V6...)
	}
	wantV4 = append(wantV4, plan.BypassV4...)
	wantV6 = append(wantV6, plan.BypassV6...)
	if !reflect.DeepEqual(o.KernelExcludeV4, wantV4) {
		t.Errorf("KernelExcludeV4 = %v, want %v (pbr.Plan zones+bypass)", o.KernelExcludeV4, wantV4)
	}
	if !reflect.DeepEqual(o.KernelExcludeV6, wantV6) {
		t.Errorf("KernelExcludeV6 = %v, want %v", o.KernelExcludeV6, wantV6)
	}
	// The VoWiFi zone CIDR and the peer anti-loop /32 must both be excluded.
	if !genopts_has(o.KernelExcludeV4, "198.51.100.0/24") {
		t.Errorf("exclude missing the VoWiFi zone: %v", o.KernelExcludeV4)
	}
	if !genopts_has(o.KernelExcludeV4, "198.51.100.20/32") {
		t.Errorf("exclude missing the peer anti-loop /32: %v", o.KernelExcludeV4)
	}

	// Block stays in the sing-box reject plane: a block list's CIDR must NOT be
	// excluded from the TUN (excluding it would let blocked traffic fall through to WAN),
	// while the kernel zones remain excluded.
	if err := s.store.UpsertRoutingList(model.RoutingList{
		ID: "blk", Name: "Block", Manual: []string{"10.10.0.0/16"}, Outbound: model.OutboundBlock, Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertRoutingList block: %v", err)
	}
	pb := s.store.Profile()
	ob := s.genOptions(&pb)
	if genopts_has(ob.KernelExcludeV4, "10.10.0.0/16") {
		t.Errorf("block CIDR must NOT be in the TUN exclude (enforced by sing-box reject): %v", ob.KernelExcludeV4)
	}
	if !genopts_has(ob.KernelExcludeV4, "198.51.100.0/24") {
		t.Errorf("kernel zone CIDR lost after adding a block list: %v", ob.KernelExcludeV4)
	}
}

// TestGenOptionsFast verifies "fast" mode: like hybrid (Hybrid flag on, pbr plan compiled
// AND returned so handleApply installs the kernel carve-outs) but with the capture-all TUN
// OFF — general LAN traffic stays on the kernel fast-path, only IP/CIDR carve-outs
// (TG-calls/VoWiFi) are kernel-PBR'd. No route_exclude (there is no TUN to exclude from).
func TestGenOptionsFast(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertEndpoint(model.Endpoint{
		ID: "ru-awg1", Name: "RU", Engine: model.EngineExternal, Server: "198.51.100.20",
		Enabled: true, Params: map[string]any{"interface": "awg1"},
	}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	if err := s.store.UpsertRoutingList(model.RoutingList{
		ID: "carrier-carveout", Name: "VoWiFi", Manual: []string{"198.51.100.0/24"}, Outbound: "ru-awg1", Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertRoutingList: %v", err)
	}
	p := s.store.Profile()

	s.cfg.RoutingMode = "fast"
	opts, plan := s.genOptionsWithPlan(&p, s.config())
	if !opts.Hybrid {
		t.Errorf("fast mode: Hybrid=%v, want true (kernel partition applies)", opts.Hybrid)
	}
	if opts.TunEnabled {
		t.Errorf("fast mode: TunEnabled=%v, want false (no capture-all TUN — general bypasses sing-box)", opts.TunEnabled)
	}
	if plan == nil {
		t.Fatal("fast mode: plan is nil, want a compiled pbr.Plan so handleApply installs the kernel carve-outs")
	}
	var zoneV4 []string
	for _, z := range plan.Zones {
		zoneV4 = append(zoneV4, z.V4...)
	}
	if !genopts_has(zoneV4, "198.51.100.0/24") {
		t.Errorf("fast mode: VoWiFi carve-out missing from kernel plan zones: %v", zoneV4)
	}
	if len(opts.KernelExcludeV4) > 0 || len(opts.KernelExcludeV6) > 0 {
		t.Errorf("fast mode: KernelExclude should be empty (no TUN to exclude from), got v4=%v v6=%v", opts.KernelExcludeV4, opts.KernelExcludeV6)
	}
}

// TestGenOptionsFast_Offload verifies the Phase-1b config wiring: in "fast" mode,
// config.Offload + OffloadDevices flow through to the compiled plan's Flowtable; in
// "hybrid" mode offload is NOT applied (general transits the capture-all TUN there, so
// there's no LAN↔WAN flow to offload). Default (no Offload) leaves Flowtable nil.
func TestGenOptionsFast_Offload(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertEndpoint(model.Endpoint{
		ID: "ru-awg1", Name: "RU", Engine: model.EngineExternal, Server: "198.51.100.20",
		Enabled: true, Params: map[string]any{"interface": "awg1"},
	}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	if err := s.store.UpsertRoutingList(model.RoutingList{
		ID: "carrier-carveout", Name: "VoWiFi", Manual: []string{"198.51.100.0/24"}, Outbound: "ru-awg1", Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertRoutingList: %v", err)
	}
	p := s.store.Profile()

	// fast WITHOUT offload → no flowtable (default, unchanged behaviour).
	s.cfg.RoutingMode = "fast"
	if _, plan := s.genOptionsWithPlan(&p, s.config()); plan == nil || plan.Flowtable != nil {
		t.Fatalf("fast default: Flowtable should be nil, got %+v", plan)
	}

	// fast + offload sw + devices → plan carries the flowtable (sw, both devices).
	s.cfg.Offload = "sw"
	s.cfg.OffloadDevices = []string{"wan", "br-lan"}
	_, plan := s.genOptionsWithPlan(&p, s.config())
	if plan == nil || plan.Flowtable == nil {
		t.Fatalf("fast+offload: plan.Flowtable = nil, want set")
	}
	if plan.Flowtable.HW {
		t.Errorf("sw offload must have HW=false")
	}
	if len(plan.Flowtable.Devices) != 2 {
		t.Errorf("flowtable devices = %v, want 2 (wan, br-lan)", plan.Flowtable.Devices)
	}

	// hybrid + offload sw → offload NOT applied (general transits the TUN there).
	s.cfg.RoutingMode = "hybrid"
	_, hplan := s.genOptionsWithPlan(&p, s.config())
	if hplan == nil {
		t.Fatal("hybrid: plan nil")
	}
	if hplan.Flowtable != nil {
		t.Errorf("hybrid must NOT enable offload (general is on the TUN), got %+v", hplan.Flowtable)
	}
}

// TestGenOptions_AutoRefreshKernelModesOnly documents + locks a real constraint of the
// CIDR auto-refresh: CIDRCache is routed ONLY by the kernel plane (hybrid/fast). In tun/
// mixed there is no pbr plan and the generator does not read CIDRCache, so a CIDRSource
// list's cache is NOT routed there — a CIDRSource is meaningful only in kernel modes.
func TestGenOptions_AutoRefreshKernelModesOnly(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertEndpoint(model.Endpoint{
		ID: "ru-awg1", Name: "RU", Engine: model.EngineExternal, Server: "198.51.100.20",
		Enabled: true, Params: map[string]any{"interface": "awg1"},
	}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	if err := s.store.UpsertRoutingList(model.RoutingList{
		ID: "ru", Name: "RU", CIDRSource: "asn:13238", CIDRCache: []string{"5.45.192.0/18"},
		Outbound: "ru-awg1", Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertRoutingList: %v", err)
	}
	p := s.store.Profile()

	// mixed (no kernel plane) → no plan → CIDRCache is not kernel-routed.
	s.cfg.RoutingMode = "mixed"
	if _, plan := s.genOptionsWithPlan(&p, s.config()); plan != nil {
		t.Errorf("mixed: want nil plan (CIDRCache is kernel-modes-only), got %+v", plan)
	}

	// fast → the kernel plan carries the cached CIDR.
	s.cfg.RoutingMode = "fast"
	_, plan := s.genOptionsWithPlan(&p, s.config())
	if plan == nil {
		t.Fatal("fast: want a plan")
	}
	var found bool
	for _, z := range plan.Zones {
		for _, c := range z.V4 {
			if c == "5.45.192.0/18" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("fast: CIDRCache should be kernel-routed, zones=%+v", plan.Zones)
	}
}

// TestGenOptionsHybrid_SourceScopedExcludeSkip verifies §6.4: in hybrid mode a SOURCE-SCOPED
// zone's dest CIDR must NOT be excluded from the TUN (non-matching clients still reach that dest
// via the tunnel default — excluding it would strand them with neither a kernel mark nor a TUN
// route → WAN leak), while a plain zone's dest IS excluded.
func TestGenOptionsHybrid_SourceScopedExcludeSkip(t *testing.T) {
	s, _ := sharehandlers_server(t)
	if err := s.store.UpsertEndpoint(model.Endpoint{
		ID: "ru-awg1", Name: "RU", Engine: model.EngineExternal, Server: "198.51.100.20",
		Enabled: true, Params: map[string]any{"interface": "awg1"},
	}); err != nil {
		t.Fatalf("UpsertEndpoint: %v", err)
	}
	if err := s.store.UpsertRule(model.Rule{ID: "plain", IPCIDR: []string{"9.9.9.0/24"}, Outbound: "ru-awg1"}); err != nil {
		t.Fatalf("UpsertRule plain: %v", err)
	}
	if err := s.store.UpsertRule(model.Rule{ID: "scoped", IPCIDR: []string{"8.8.8.0/24"}, SourceIPCIDR: []string{"192.168.1.50/32"}, Outbound: "ru-awg1"}); err != nil {
		t.Fatalf("UpsertRule scoped: %v", err)
	}
	p := s.store.Profile()
	s.cfg.RoutingMode = "hybrid"
	o := s.genOptions(&p)
	if !genopts_has(o.KernelExcludeV4, "9.9.9.0/24") {
		t.Errorf("plain dest zone must be TUN-excluded: %v", o.KernelExcludeV4)
	}
	if genopts_has(o.KernelExcludeV4, "8.8.8.0/24") {
		t.Errorf("§6.4: source-scoped dest must NOT be TUN-excluded: %v", o.KernelExcludeV4)
	}
}

func genopts_has(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
