package platform

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// --- Synthetic samples (NOT real device dumps) ---------------------------------------------

// /proc/modules excerpt with the amneziawg kmod loaded (the live AX3000T case: amneziawg, no
// plain wireguard kmod). Fields after the name are size/refcount/deps/state — irrelevant here.
const lsmodAWG = `amneziawg 90112 0 - Live 0x0000000000000000
chacha20poly1305 16384 1 amneziawg, Live 0x0000000000000000
curve25519_neon 16384 1 amneziawg, Live 0x0000000000000000
udp_tunnel 16384 1 amneziawg, Live 0x0000000000000000
tun 49152 1 - Live 0x0000000000000000
`

// /proc/modules excerpt with the plain wireguard kmod loaded and no amneziawg.
const lsmodWG = `wireguard 94208 0 - Live 0x0000000000000000
udp_tunnel 16384 1 wireguard, Live 0x0000000000000000
ip6_udp_tunnel 16384 1 wireguard, Live 0x0000000000000000
`

// `ndmc -c "show version"` component excerpt (Keenetic reference router, native wireguard present).
const ndmcVersionWG = `release: 5.0.11
sandbox: stable
components: wireguard, ipsec, ike-client, l2tp, pptp, openvpn, openconnect, zerotier, ppe, pppoe
`

// `ndmc -c "show interface"` excerpt declaring a Wireguard-typed interface (NDM AWG tunnel).
const ndmcIfaceWG = `interface, name = Wireguard0
    type: Wireguard
    description: NL tunnel
    state: up
interface, name = ISP
    type: PPPoE
    state: up
`

// TestDecideOpenWrt_Accel: the flow-offload accelerator capability is derived from the loaded kernel
// modules — nf_flow_table/nft_flow_offload ⇒ nft-flowtable; the hw-offload module ⇒ HW; absent ⇒ none.
func TestDecideOpenWrt_Accel(t *testing.T) {
	cases := []struct {
		name     string
		lsmod    string
		wantKind string
		wantHW   bool
	}{
		{"software flowtable", "nf_flow_table 16384 0 - Live 0x0\n", "nft-flowtable", false},
		{"nft_flow_offload alias", "nft_flow_offload 16384 0 - Live 0x0\n", "nft-flowtable", false},
		{"hardware offload", "nf_flow_table 16384 0\nnf_flow_table_hw 16384 0\n", "nft-flowtable", true},
		{"mtk ppe hw", "nf_flow_table 16384 0\nmtk_ppe 32768 0\n", "nft-flowtable", true},
		{"no flowtable", lsmodWG, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := decideOpenWrt(hostInputs{lsmod: c.lsmod}).Accel; got.Kind != c.wantKind || got.HW != c.wantHW {
				t.Errorf("Accel = %+v, want {Kind:%q HW:%v}", got, c.wantKind, c.wantHW)
			}
		})
	}
	// A built-in (non-loadable) flowtable is invisible to /proc/modules but present in sysfs.
	if got := decideOpenWrt(hostInputs{flowtableSysfs: true}).Accel; got.Kind != "nft-flowtable" {
		t.Errorf("built-in flowtable Accel = %+v, want Kind nft-flowtable", got)
	}
}

// TestDecideKeenetic_Accel: KeeneticOS reports its native hardware NAT/PPE via the "ppe" firmware
// component, surfaced as Accel{Kind:"ppe"} so the UI never offers the inapplicable nft flow-offload.
func TestDecideKeenetic_Accel(t *testing.T) {
	if got := decideKeenetic(hostInputs{ndmcVersion: ndmcVersionWG}).Accel; got.Kind != "ppe" || !got.HW {
		t.Errorf("Accel = %+v, want {Kind:ppe HW:true}", got)
	}
	if got := decideKeenetic(hostInputs{ndmcVersion: "components: wireguard, ipsec, l2tp\n"}).Accel; got.Kind != "" {
		t.Errorf("Accel = %+v, want empty (no ppe component)", got)
	}
}

// --- decideOpenWrt --------------------------------------------------------------------------

func TestDecideOpenWrt(t *testing.T) {
	tests := []struct {
		name        string
		in          hostInputs
		wantNative  map[string]bool
		wantInstall map[string]string
		wantSbPres  bool
	}{
		{
			// The live AX3000T case: amneziawg kmod, no plain wireguard. The amneziawg kmod
			// is a WireGuard superset, so vanilla WG rides it — both are native and neither
			// needs an install (design §1-2: "WireGuard | native via amneziawg kmod").
			name:        "amneziawg kmod loaded -> awg+wg native (WG rides the awg kmod)",
			in:          hostInputs{lsmod: lsmodAWG, tools: map[string]bool{"sing-box": true}},
			wantNative:  map[string]bool{"amneziawg": true, "wireguard": true},
			wantInstall: map[string]string{},
			wantSbPres:  true,
		},
		{
			name:        "wireguard kmod loaded -> wg native, awg installable",
			in:          hostInputs{lsmod: lsmodWG},
			wantNative:  map[string]bool{"wireguard": true},
			wantInstall: map[string]string{"amneziawg": "kmod-amneziawg"},
			wantSbPres:  false,
		},
		{
			name:        "awg CLI present (no kmod text) -> awg+wg native (WG rides the awg kmod)",
			in:          hostInputs{tools: map[string]bool{"awg": true}},
			wantNative:  map[string]bool{"amneziawg": true, "wireguard": true},
			wantInstall: map[string]string{},
			wantSbPres:  false,
		},
		{
			name:        "wg CLI present -> wg native",
			in:          hostInputs{tools: map[string]bool{"wg": true}},
			wantNative:  map[string]bool{"wireguard": true},
			wantInstall: map[string]string{"amneziawg": "kmod-amneziawg"},
			wantSbPres:  false,
		},
		{
			name:        "netifd proto handlers present -> both native",
			in:          hostInputs{netifdProtos: []string{"amneziawg.sh", "wireguard.sh", "ppp.sh"}},
			wantNative:  map[string]bool{"amneziawg": true, "wireguard": true},
			wantInstall: map[string]string{},
			wantSbPres:  false,
		},
		{
			name:        "nothing native -> both installable",
			in:          hostInputs{},
			wantNative:  map[string]bool{},
			wantInstall: map[string]string{"amneziawg": "kmod-amneziawg", "wireguard": "kmod-wireguard"},
			wantSbPres:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decideOpenWrt(tt.in)
			if got.Platform != string(OpenWrt) {
				t.Errorf("Platform = %q, want %q", got.Platform, OpenWrt)
			}
			if !reflect.DeepEqual(got.Native, tt.wantNative) {
				t.Errorf("Native = %v, want %v", got.Native, tt.wantNative)
			}
			if !reflect.DeepEqual(got.Installable, tt.wantInstall) {
				t.Errorf("Installable = %v, want %v", got.Installable, tt.wantInstall)
			}
			if got.SingboxPresent != tt.wantSbPres {
				t.Errorf("SingboxPresent = %v, want %v", got.SingboxPresent, tt.wantSbPres)
			}
			assertSingboxRequired(t, got)
		})
	}
}

// --- decideKeenetic -------------------------------------------------------------------------

func TestDecideKeenetic(t *testing.T) {
	tests := []struct {
		name       string
		in         hostInputs
		wantWG     bool // wireguard + amneziawg expected native
		wantOthers []string
	}{
		{
			name:       "wireguard component present -> wg+awg native + firmware set",
			in:         hostInputs{ndmcVersion: ndmcVersionWG},
			wantWG:     true,
			wantOthers: []string{"ipsec", "openvpn", "l2tp", "pptp", "openconnect"},
		},
		{
			name:   "no component but Wireguard interface type -> wg+awg native",
			in:     hostInputs{ndmcInterface: ndmcIfaceWG},
			wantWG: true,
		},
		{
			name:   "neither -> wg+awg installable, not native",
			in:     hostInputs{},
			wantWG: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decideKeenetic(tt.in)
			if got.Platform != string(Keenetic) {
				t.Errorf("Platform = %q, want %q", got.Platform, Keenetic)
			}
			if got.Native["wireguard"] != tt.wantWG {
				t.Errorf("Native[wireguard] = %v, want %v", got.Native["wireguard"], tt.wantWG)
			}
			if got.Native["amneziawg"] != tt.wantWG {
				t.Errorf("Native[amneziawg] = %v, want %v", got.Native["amneziawg"], tt.wantWG)
			}
			if !tt.wantWG {
				// When not native, WG/AWG must be recommended for install.
				if got.Installable["wireguard"] == "" {
					t.Errorf("Installable[wireguard] empty, want a recommended component")
				}
				if got.Installable["amneziawg"] == "" {
					t.Errorf("Installable[amneziawg] empty, want a recommended component")
				}
			}
			for _, p := range tt.wantOthers {
				if !got.Native[p] {
					t.Errorf("Native[%s] = false, want true", p)
				}
			}
			assertSingboxRequired(t, got)
		})
	}
}

// --- helper-fn unit coverage ----------------------------------------------------------------

func TestProtoSet(t *testing.T) {
	got := protoSet([]string{"amneziawg.sh", " WireGuard.sh ", "ppp.sh"})
	want := map[string]bool{"amneziawg": true, "wireguard": true, "ppp": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("protoSet = %v, want %v", got, want)
	}
}

func TestListProtoHandlers(t *testing.T) {
	dir := t.TempDir()
	// Real proto handlers (*.sh files) — the only things that should be returned.
	for _, f := range []string{"amneziawg.sh", "wireguard.sh", "ppp.sh"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("#!/bin/sh\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Noise that must be excluded: a non-.sh file and a directory that happens to end in .sh.
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir.sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := listProtoHandlers(dir)
	sort.Strings(got)
	want := []string{"amneziawg.sh", "ppp.sh", "wireguard.sh"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("listProtoHandlers = %v, want %v", got, want)
	}
	// A missing dir (non-router host) is tolerated → nil, never an error/panic.
	if got := listProtoHandlers(filepath.Join(dir, "does-not-exist")); got != nil {
		t.Errorf("listProtoHandlers(missing) = %v, want nil", got)
	}
}

func TestNdmHasInterfaceType(t *testing.T) {
	lowered := "    type: wireguard\n    type = pppoe\nname: type-named-iface\n"
	if !ndmHasInterfaceType(lowered, "Wireguard") {
		t.Error("expected Wireguard type to match")
	}
	if !ndmHasInterfaceType(lowered, "PPPoE") {
		t.Error("expected PPPoE type to match")
	}
	if ndmHasInterfaceType(lowered, "Vlan") {
		t.Error("did not expect Vlan to match")
	}
	// A line that merely mentions the word but is not a type declaration must not match.
	if ndmHasInterfaceType("name: type-wireguard\n", "wireguard") {
		t.Error("a non-type line should not match the type token")
	}
}

// --- DetectCapabilities host wrapper (off-router) -------------------------------------------

func TestDetectCapabilities_OffRouter(t *testing.T) {
	// On a dev host (no ndmc, no openwrt markers) Detect() returns Unknown, so the wrapper must
	// produce a zero-but-valid Capabilities without panicking.
	caps := DetectCapabilities()
	if caps.Platform == "" {
		t.Fatal("Platform must be set")
	}
	if caps.Native == nil || caps.Installable == nil {
		t.Fatal("Native/Installable maps must be non-nil")
	}
	assertSingboxRequired(t, caps)
}

func assertSingboxRequired(t *testing.T, caps Capabilities) {
	t.Helper()
	got := append([]string(nil), caps.SingboxRequired...)
	want := []string{
		"anytls", "http", "hysteria2", "shadowsocks", "socks", "trojan", "tuic", "vless", "vmess",
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("SingboxRequired = %v, want (sorted) %v", caps.SingboxRequired, want)
	}
}

// TestInstallCmdsByPackageManager: the recommend install command uses the host's actual package
// manager (apk add vs opkg install); a firmware-component note (Keenetic) gets no command.
func TestInstallCmdsByPackageManager(t *testing.T) {
	// OpenWrt, nothing native → Installable has real packages; apk present → "apk add".
	apk := decideOpenWrt(hostInputs{tools: map[string]bool{"apk": true}})
	if apk.PackageManager != "apk" {
		t.Errorf("PackageManager = %q, want apk", apk.PackageManager)
	}
	if apk.InstallCmds["amneziawg"] != "apk add kmod-amneziawg" || apk.InstallCmds["wireguard"] != "apk add kmod-wireguard" {
		t.Errorf("apk install cmds = %v, want apk-add forms", apk.InstallCmds)
	}
	// opkg present → "opkg install".
	opkg := decideOpenWrt(hostInputs{tools: map[string]bool{"opkg": true}})
	if opkg.PackageManager != "opkg" || opkg.InstallCmds["wireguard"] != "opkg install kmod-wireguard" {
		t.Errorf("opkg: pm=%q cmd=%q", opkg.PackageManager, opkg.InstallCmds["wireguard"])
	}
	// apk wins when both are present (a transitional system).
	both := decideOpenWrt(hostInputs{tools: map[string]bool{"apk": true, "opkg": true}})
	if both.PackageManager != "apk" {
		t.Errorf("both managers: pm=%q, want apk (newer wins)", both.PackageManager)
	}
	// No manager → no commands.
	none := decideOpenWrt(hostInputs{})
	if none.PackageManager != "" || len(none.InstallCmds) != 0 {
		t.Errorf("no manager: pm=%q cmds=%v, want empty", none.PackageManager, none.InstallCmds)
	}
	// Keenetic WG/AWG are firmware components (value has a space) → no apk/opkg command emitted.
	keen := decideKeenetic(hostInputs{tools: map[string]bool{"opkg": true}})
	if len(keen.InstallCmds) != 0 {
		t.Errorf("firmware-component notes must not get an install command, got %v", keen.InstallCmds)
	}
}

// --- hardware offload on a built-in datapath ------------------------------------------------
//
// Observed on a Xiaomi AX3000T running OpenWrt 25.12.2 (mediatek/filogic, kernel 6.12.74):
//   /sys/module/nf_flow_table   exists
//   /proc/modules               nf_flow_table, nf_flow_table_inet, nft_flow_offload, nf_tables
//   NOT in /proc/modules        nf_flow_table_hw, mtk_ppe, mtk_hnat, mtk_eth_soc
//   /sys/kernel/debug/ppe0      exists  <- the PPE is live, just compiled in
//
// The module scan alone therefore reports HW=false on hardware that genuinely has a hardware
// offload path. These pin the fix.

// The exact module list read off that router.
const ax3000tLsmod = "nf_flow_table_inet 16384 1 - Live 0x0\n" +
	"nft_flow_offload 16384 1 - Live 0x0\n" +
	"nf_tables 200704 30 - Live 0x0\n" +
	"nf_flow_table 32768 2 - Live 0x0\n" +
	"nf_conntrack 90112 4 - Live 0x0\n"

func TestDecideOpenWrt_FlowtableDetectedFromSysfs(t *testing.T) {
	// This is what 0.5.5 would report on that router, and answers whether the observed
	// accel:null there was a probe bug: it was not - that device runs 0.5.4.
	caps := decideOpenWrt(hostInputs{lsmod: ax3000tLsmod, flowtableSysfs: true})
	if caps.Accel.Kind != "nft-flowtable" {
		t.Fatalf("Accel.Kind = %q, want nft-flowtable", caps.Accel.Kind)
	}
}

func TestDecideOpenWrt_BuiltInPPECountsAsHardware(t *testing.T) {
	// Without the sysfs signal the module scan misses a built-in PPE entirely.
	if caps := decideOpenWrt(hostInputs{lsmod: ax3000tLsmod, flowtableSysfs: true}); caps.Accel.HW {
		t.Fatal("sanity: the module list alone must not report HW")
	}
	// With it, the hardware path is reported.
	caps := decideOpenWrt(hostInputs{lsmod: ax3000tLsmod, flowtableSysfs: true, hwOffloadSysfs: true})
	if !caps.Accel.HW {
		t.Error("a live PPE at /sys/kernel/debug/ppe0 must be reported as a hardware offload path; " +
			"on Filogic the driver is built in and never appears in /proc/modules")
	}
	if caps.Accel.Kind != "nft-flowtable" {
		t.Errorf("Accel.Kind = %q, want nft-flowtable", caps.Accel.Kind)
	}
}

func TestDecideOpenWrt_LoadableHWModuleStillWorks(t *testing.T) {
	// The original module-name path must keep working for platforms that do ship them loadable.
	for _, mod := range []string{"nf_flow_table_hw", "mtk_ppe", "mtk_hnat"} {
		caps := decideOpenWrt(hostInputs{lsmod: ax3000tLsmod + mod + " 16384 0 - Live 0x0\n", flowtableSysfs: true})
		if !caps.Accel.HW {
			t.Errorf("%s in /proc/modules must still report HW", mod)
		}
	}
}

func TestDecideOpenWrt_NoAcceleratorStaysUnset(t *testing.T) {
	// No flowtable anywhere: offload must stay unset so the apply gate forces it off rather than
	// loading a flowtable the kernel would reject.
	caps := decideOpenWrt(hostInputs{lsmod: "nf_conntrack 90112 4 - Live 0x0\n"})
	if caps.Accel.Kind != "" || caps.Accel.HW {
		t.Errorf("want an unset accelerator, got %+v", caps.Accel)
	}
}
