package platform

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Capabilities is the platform capability probe — which VPN/proxy protocols this router can
// carry on a kernel/firmware-native path RIGHT NOW, which ones it could carry after installing
// a package, and which proxy protocols mandatorily need the sing-box userspace core (no kernel
// path exists anywhere). It is the "detect" half of the detect→use→recommend design
// (docs/NATIVE_INTEGRATION_DESIGN.md §3a) in the development repository. All map keys are the
// lowercase proto strings.
//
// SHARED CONTRACT — agents wiring the API/UI and the Keenetic backend depend on this exact
// shape; do not reorder or rename fields/keys.
type Capabilities struct {
	Platform        string            `json:"platform"`         // "openwrt" | "keenetic" | "unknown"
	Native          map[string]bool   `json:"native"`           // proto -> a kernel/firmware path is present NOW
	Installable     map[string]string `json:"installable"`      // proto -> recommended package to install
	SingboxRequired []string          `json:"singbox_required"` // proxy protos with NO native path
	SingboxPresent  bool              `json:"singbox_present"`
	// PackageManager is the detected installer ("apk" | "opkg" | ""), and InstallCmds maps a
	// proto from Installable to the exact copy-paste install command for THIS host — so the
	// recommend UX shows `apk add …` on newer OpenWrt and `opkg install …` elsewhere instead of
	// a hardcoded (and possibly wrong) verb. Only real packages get a command; firmware-component
	// notes (Keenetic) are omitted. Additive — existing keys are unchanged.
	PackageManager string            `json:"package_manager,omitempty"`
	InstallCmds    map[string]string `json:"install_cmds,omitempty"`
	// Legacy maps a detected protocol to a security warning (see LegacyProtocolWarning). Populated
	// only for protocols this host actually reports, so the UI can mark them at the point of choice
	// rather than after the fact. Additive.
	Legacy map[string]string `json:"legacy,omitempty"`
	// Accel reports the router's forwarding accelerator so the UI/apply only offer WayHop's nft
	// flow-offload where it actually works — never on Keenetic (offload there is firmware PPE) or a
	// kernel with no flowtable support (where it would brick the whole ruleset). Additive.
	Accel Accel `json:"accel"`
	// NetifdProtos is the set of protocol handlers netifd actually has, keyed by bare proto name
	// ("amneziawg", "wireguard"), read from /lib/netifd/proto/*.sh. It answers a narrower question
	// than Native and must not be confused with it: on a live AX3000T `Native["wireguard"]`
	// is TRUE — the amneziawg kmod is a WireGuard superset, which is exactly what Native records —
	// while `/lib/netifd/proto/wireguard.sh` is ABSENT. Anything that WRITES a uci `proto=` has to
	// gate on this one, or it produces a section netifd cannot bring up.
	//
	// NIL means not probed (not OpenWrt, or the directory could not be read). An empty non-nil map
	// means probed and nothing found. Native writers fail closed on both: nil is a retryable unknown;
	// empty is proof the requested handler is absent. Additive.
	NetifdProtos map[string]bool `json:"netifd_protos,omitempty"`
}

// Accel describes the router's forwarding accelerator. Kind: "nft-flowtable" = WayHop's own
// nftables flowtable knob works (OpenWrt with the flow-offload kmod); "ppe" = KeeneticOS's native
// hardware NAT/PPE, managed by the firmware and NOT the WayHop offload dropdown; "" = none detected.
// HW = a hardware fast path is available (nft `flags offload` on OpenWrt; PPE on Keenetic).
type Accel struct {
	Kind string `json:"kind"`
	HW   bool   `json:"hw,omitempty"`
}

// Proxy protocols have no kernel/firmware path on any platform, so sing-box is always required
// for them. This is the floor: run any of these and the userspace core must run.
var singboxRequired = []string{
	"vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic",
	"anytls", "socks", "http",
}

// hostInputs is everything the pure decision functions read from the live host, captured up
// front so the decision (decideOpenWrt / decideKeenetic) is a pure function unit-tested with
// synthetic samples — mirroring server.parseConntrack and netvpn.parseWgDump.
type hostInputs struct {
	// OpenWrt surfaces.
	lsmod          string          // `cat /proc/modules` / `lsmod` text
	netifdProtos   []string        // base names from /lib/netifd/proto/*.sh (e.g. "amneziawg.sh")
	tools          map[string]bool // present CLIs: awg, wg, openvpn, sing-box
	flowtableSysfs bool            // /sys/module/nf_flow_table exists (catches a BUILT-IN flowtable that /proc/modules omits)
	// hwOffloadSysfs is the same lesson applied to the HARDWARE half. Looking for mtk_ppe / mtk_hnat
	// / nf_flow_table_hw in /proc/modules finds nothing on a modern Filogic OpenWrt, because
	// mtk_eth_soc and its PPE are compiled into the kernel rather than loaded. Verified on a Xiaomi
	// AX3000T (OpenWrt 25.12.2): PPE is live at /sys/kernel/debug/ppe0 while none of those three
	// module names exist, so the module scan alone reports HW=false on hardware that genuinely has it.
	hwOffloadSysfs bool

	// Keenetic surfaces.
	ndmcVersion   string // `ndmc -c "show version"` component text
	ndmcInterface string // `ndmc -c "show interface"` text
}

// decideOpenWrt builds the OpenWrt capability matrix from the captured host inputs. Pure.
//
// Rules (docs/NATIVE_INTEGRATION_DESIGN.md §1-2) in the development repository: AmneziaWG is native
// if the amneziawg kmod is loaded, OR the amneziawg netifd proto handler exists, OR the awg CLI is
// present. Plain WireGuard is native if the wireguard kmod is loaded, OR the wg CLI is present, OR
// the wireguard netifd proto handler exists — OR AmneziaWG is native: the amneziawg kmod is a
// WireGuard superset, so vanilla WG rides it ("WireGuard | native via amneziawg kmod" in the design
// matrix). That implication is ONE-WAY — plain WireGuard does not provide AmneziaWG's obfuscation,
// so WG-native must never back-imply AmneziaWG-native. When a proto has no native path, recommend
// the standard OpenWrt package to install instead.
func decideOpenWrt(in hostInputs) Capabilities {
	lsmod := strings.ToLower(in.lsmod)
	protos := protoSet(in.netifdProtos)

	caps := Capabilities{
		Platform: string(OpenWrt),
		// Carried out as its own answer. `protos` is used below to widen Native by implication;
		// NetifdProtos is the unwidened truth, which is what a writer must gate on. nil when the
		// directory could not be read — see the field comment for why that distinction matters.
		NetifdProtos:    protos,
		Native:          map[string]bool{},
		Installable:     map[string]string{},
		SingboxRequired: append([]string(nil), singboxRequired...),
		SingboxPresent:  in.tools["sing-box"],
	}

	awgNative := strings.Contains(lsmod, "amneziawg") || protos["amneziawg"] || in.tools["awg"]
	if awgNative {
		caps.Native["amneziawg"] = true
	} else {
		// amneziawg-go is the userspace-kernel hybrid package on OpenWrt; kmod-amneziawg is the
		// pure kernel module. Recommend the kmod (kernel-speed) as the standard name.
		caps.Installable["amneziawg"] = "kmod-amneziawg"
	}

	// awgNative implies wgNative: the amneziawg kmod is a WireGuard superset (configure with
	// zero obfuscation = plain WG), so a router with AmneziaWG already carries vanilla WG —
	// don't recommend installing kmod-wireguard it doesn't need (design §1-2).
	wgNative := awgNative || strings.Contains(lsmod, "wireguard") || in.tools["wg"] || protos["wireguard"]
	if wgNative {
		caps.Native["wireguard"] = true
	} else {
		// kmod-wireguard is the kernel module; wireguard-tools provides the wg CLI.
		caps.Installable["wireguard"] = "kmod-wireguard"
	}

	// nft flow-offload: WayHop's software flowtable needs the nf_flow_table / nft_flow_offload kernel
	// module; hardware offload additionally needs a SoC/NIC that advertises `flags offload` (e.g. the
	// MediaTek PPE / hnat). When the flowtable module is absent, offload is left unset so the gate in
	// pbrCompileOptions forces it off instead of bricking the ruleset.
	if in.flowtableSysfs || strings.Contains(lsmod, "nf_flow_table") || strings.Contains(lsmod, "nft_flow_offload") {
		// A positive sysfs signal is proof; the module names remain as a fallback for platforms that
		// DO ship them loadable. Absence stays absence: debugfs may simply not be mounted, so a
		// missing ppe node is never treated as proof there is no hardware path.
		hw := in.hwOffloadSysfs ||
			strings.Contains(lsmod, "nf_flow_table_hw") || strings.Contains(lsmod, "mtk_ppe") || strings.Contains(lsmod, "mtk_hnat")
		caps.Accel = Accel{Kind: "nft-flowtable", HW: hw}
	}

	return withInstallCmds(caps, in.packageManager())
}

// decideKeenetic builds the Keenetic capability matrix from the NDM component + interface text.
// Pure.
//
// Rules (docs/NATIVE_INTEGRATION_DESIGN.md §1-2) in the development repository: WireGuard/AmneziaWG
// are native if the "wireguard" firmware component is present, OR an NDM interface of type
// "Wireguard" exists (the NDM Wireguard type carries AmneziaWG params on Keenetic). KeeneticOS
// firmware also ships ipsec/openvpn/l2tp/etc. components — those are populated too when present
// (best-effort), but WG/AWG are the priority this iteration.
func decideKeenetic(in hostInputs) Capabilities {
	ver := strings.ToLower(in.ndmcVersion)
	iface := strings.ToLower(in.ndmcInterface)

	caps := Capabilities{
		Platform:        string(Keenetic),
		Native:          map[string]bool{},
		Installable:     map[string]string{},
		SingboxRequired: append([]string(nil), singboxRequired...),
		SingboxPresent:  in.tools["sing-box"],
	}

	// An NDM "Wireguard" interface type backs both vanilla WG and AmneziaWG on KeeneticOS.
	wgIface := ndmHasInterfaceType(iface, "wireguard")
	wgComponent := hasComponent(ver, "wireguard")
	if wgComponent || wgIface {
		caps.Native["wireguard"] = true
		caps.Native["amneziawg"] = true
	} else {
		// Keenetic WG/AWG are firmware components installed via the device's own component UI,
		// not opkg — recommend the firmware component name.
		caps.Installable["wireguard"] = "wireguard (firmware component)"
		caps.Installable["amneziawg"] = "wireguard (firmware component)"
	}

	// Other firmware-native protocols (best-effort; tests only assert WG/AWG). The component
	// names mirror `ndmc show version` on the reference router (docs §1).
	for proto, comp := range map[string]string{
		"ipsec":       "ipsec",
		"openvpn":     "openvpn",
		"l2tp":        "l2tp",
		"pptp":        "pptp",
		"openconnect": "openconnect",
	} {
		if hasComponent(ver, comp) {
			caps.Native[proto] = true
		}
	}

	// KeeneticOS has its own hardware NAT/PPE accelerator (firmware-managed, NOT an nftables knob).
	// Report it so the UI can inform the user and the offload gate never offers the inapplicable nft
	// flow-offload on Keenetic. The "ppe" token appears in `ndmc show version` component text.
	if hasComponent(ver, "ppe") {
		caps.Accel = Accel{Kind: "ppe", HW: true}
	}

	return withInstallCmds(caps, in.packageManager())
}

// packageManager picks the host's installer from the probed tools: apk (OpenWrt 24.10+) wins over
// opkg when both are present (a transitional system), else opkg, else "".
func (in hostInputs) packageManager() string {
	switch {
	case in.tools["apk"]:
		return "apk"
	case in.tools["opkg"]:
		return "opkg"
	default:
		return ""
	}
}

// installCmd builds the copy-paste install command for a package under the given manager (apk uses
// `add`, opkg uses `install`). Returns "" for an unknown manager or a non-package value (a name
// with a space, e.g. a Keenetic firmware-component note, isn't installable via apk/opkg).
func installCmd(manager, pkg string) string {
	if pkg == "" || strings.Contains(pkg, " ") {
		return ""
	}
	switch manager {
	case "apk":
		return "apk add " + pkg
	case "opkg":
		return "opkg install " + pkg
	default:
		return ""
	}
}

// withInstallCmds records the detected package manager and, for each real installable package, the
// exact install command for this host. Pure; called at the tail of every decide function.
// withLegacyWarnings populates Legacy for every protocol this host reports as native or installable.
// Applied centrally rather than per-platform so a new backend cannot forget it — the warning is a
// property of the protocol, not of the router that happens to carry it.
func withLegacyWarnings(caps Capabilities) Capabilities {
	for proto := range caps.Native {
		if w, ok := LegacyProtocolWarning[proto]; ok {
			if caps.Legacy == nil {
				caps.Legacy = map[string]string{}
			}
			caps.Legacy[proto] = w
		}
	}
	for proto := range caps.Installable {
		if w, ok := LegacyProtocolWarning[proto]; ok {
			if caps.Legacy == nil {
				caps.Legacy = map[string]string{}
			}
			caps.Legacy[proto] = w
		}
	}
	return caps
}

func withInstallCmds(caps Capabilities, manager string) Capabilities {
	caps = withLegacyWarnings(caps)
	caps.PackageManager = manager
	for proto, pkg := range caps.Installable {
		if cmd := installCmd(manager, pkg); cmd != "" {
			if caps.InstallCmds == nil {
				caps.InstallCmds = map[string]string{}
			}
			caps.InstallCmds[proto] = cmd
		}
	}
	return caps
}

// protoSet turns the /lib/netifd/proto/*.sh base names into a set keyed by the proto name with
// the ".sh" suffix stripped (e.g. "amneziawg.sh" -> "amneziawg").
//
// A nil input returns a NIL set, not an empty one. listProtoHandlers returns nil when the directory
// cannot be read, and the two answers must stay distinguishable: an empty non-nil set says "this
// router has no protocol handlers at all"; nil says the probe failed and should be retried. Native
// writers refuse both, but return different capability reasons/statuses.
func protoSet(names []string) map[string]bool {
	if names == nil {
		return nil
	}
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".sh")] = true
	}
	return set
}

// hasComponent reports whether the (lowercased) `ndmc show version` text lists the named firmware
// component.
//
// It matches a WHOLE token, after undoing ndmc's line wrapping. Both halves of that are needed, and
// both come from the operator's own Keenetic (KeeneticOS 5.01, `ndmc -c "show version"`):
//
//   - ndmc WRAPS the component list at a fixed column and splits names across the break. Three are
//     split in that device's own output — `nathelper-\n   sip`, `opkg-\n   kmod-netfilter-addons`,
//     `opkg-\n   kmod-video`. A substring check sees `nathelper-sip` as absent. None of the names
//     this file looks for happen to land on a boundary today, which is luck of position: the list
//     grows with every installed component, and `openconnect` is longer than `nathelper-sip`. The
//     answer would be "this router has no WireGuard" on a router that has it — the same shape of
//     wrong answer the Updater's kernel-carried row was fixed for.
//   - a substring also matches INSIDE another name. `ppe` is three letters and this file asks for
//     it; any future `ppe-foo`, or a name merely containing those letters, would report hardware
//     offload the router does not have.
//
// Only the WRAP is removed — a newline together with the indentation that continues the line — and
// then the text is split on the separators ndmc actually uses. Stripping every space instead glues
// the `components:` label onto the first name (`components:wireguard`) and glues a space-separated
// list into one long token; the first version did exactly that and the existing fixture caught it.
func hasComponent(loweredVersion, comp string) bool {
	comp = strings.ToLower(strings.TrimSpace(comp))
	if comp == "" {
		return false
	}
	unwrapped := ndmcWrap.ReplaceAllString(loweredVersion, "")
	for _, tok := range strings.FieldsFunc(unwrapped, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == ':'
	}) {
		if tok == comp {
			return true
		}
	}
	return false
}

// ndmcWrap matches ndmc's line wrapping: a newline plus the indentation that continues the line.
// Removing it rejoins both a name broken mid-token (`nathelper-\n   sip`) and a list broken between
// names (`ddns,\n   dhcpd`), which are the two shapes a live Keenetic prints.
var ndmcWrap = regexp.MustCompile(`\n[ \t]+`)

// ndmHasInterfaceType reports whether the (lowercased) `ndmc show interface` text declares an
// interface of the given type (e.g. type "Wireguard"). NDM prints "type: Wireguard" / "type =
// Wireguard" per interface block; matching the type token avoids false hits on an interface
// merely *named* like the type.
func ndmHasInterfaceType(loweredIface, typ string) bool {
	typ = strings.ToLower(typ)
	for _, line := range strings.Split(loweredIface, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "type") {
			continue
		}
		// Accept "type: wireguard", "type = wireguard", "type wireguard".
		if i := strings.Index(line, "type"); i >= 0 {
			rest := line[i+len("type"):]
			rest = strings.TrimLeft(rest, " \t:=")
			if strings.HasPrefix(rest, typ) {
				return true
			}
		}
	}
	return false
}

// DetectCapabilities does the host I/O — exec ndmc, read /proc/modules, stat the netifd proto
// dir and the CLIs — then hands the captured inputs to the pure decision function for the
// detected platform. Best-effort: every probe tolerates a missing tool / non-router host, so on
// a dev machine it returns a zero-but-valid Capabilities (Platform "unknown", empty Native/
// Installable, the fixed SingboxRequired list). Never panics.
func DetectCapabilities() Capabilities {
	caps, _ := DetectCapabilitiesObserved()
	return caps
}

// DetectCapabilitiesObserved is DetectCapabilities plus fixed, API-safe probe failures. The legacy
// wrapper remains best-effort for diagnostics, while a reviewed Apply consumes this form so an ndmc
// timeout or unreadable OpenWrt capability surface becomes unknown instead of definitive absence.
func DetectCapabilitiesObserved() (Capabilities, []string) {
	return DetectCapabilitiesObservedContext(context.Background())
}

// DetectCapabilitiesObservedContext is the reviewed-Apply variant of capability detection. Its
// Keenetic RCI commands inherit the caller's cancellation and share a hard upper time bound; the
// compatibility wrappers above retain the former background/best-effort behavior.
func DetectCapabilitiesObservedContext(ctx context.Context) (Capabilities, []string) {
	if ctx == nil {
		ctx = context.Background()
	}
	plat := Detect()
	var probeErrors []string

	in := hostInputs{
		tools: map[string]bool{
			"awg":      commandExists("awg"),
			"wg":       commandExists("wg"),
			"openvpn":  commandExists("openvpn"),
			"sing-box": commandExists("sing-box"),
			"apk":      commandExists("apk"),  // OpenWrt 24.10+ package manager
			"opkg":     commandExists("opkg"), // older OpenWrt + Entware/Keenetic
		},
	}

	switch plat {
	case OpenWrt:
		if data, err := os.ReadFile("/proc/modules"); err == nil {
			in.lsmod = string(data)
		} else {
			probeErrors = append(probeErrors, "OpenWrt module capability probe failed")
		}
		if protos, ok := listProtoHandlersOK("/lib/netifd/proto"); ok {
			in.netifdProtos = protos
		} else {
			probeErrors = append(probeErrors, "OpenWrt netifd protocol capability probe failed")
		}
		if _, err := os.Stat("/sys/module/nf_flow_table"); err == nil {
			in.flowtableSysfs = true // a built-in (non-loadable) flowtable still creates this sysfs dir
		}
		in.hwOffloadSysfs = detectHWOffloadSysfs()
		return decideOpenWrt(in), probeErrors
	case Keenetic:
		// Both ndmc calls belong to one observation and therefore share one five-second budget. Each
		// command is independently output/pipe bounded by runCapabilityProbeCommand as well.
		probeCtx, cancel := context.WithTimeout(ctx, capabilityProbeCommandTimeout)
		defer cancel()
		var err error
		if in.ndmcVersion, err = runCapabilityProbeCommand(probeCtx, "ndmc", "-c", "show version"); err != nil || strings.TrimSpace(in.ndmcVersion) == "" {
			probeErrors = append(probeErrors, "Keenetic component capability probe failed")
		}
		if in.ndmcInterface, err = runCapabilityProbeCommand(probeCtx, "ndmc", "-c", "show interface"); err != nil || strings.TrimSpace(in.ndmcInterface) == "" {
			probeErrors = append(probeErrors, "Keenetic interface capability probe failed")
		}
		return decideKeenetic(in), probeErrors
	default:
		// Unknown / dev host: still return the contract-valid shape with the proxy floor.
		return Capabilities{
			Platform:        string(Unknown),
			Native:          map[string]bool{},
			Installable:     map[string]string{},
			SingboxRequired: append([]string(nil), singboxRequired...),
			SingboxPresent:  in.tools["sing-box"],
		}, []string{"router platform capability probe could not identify the host"}
	}
}

// commandExists reports whether a CLI is on PATH (best-effort).
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

const (
	capabilityProbeCommandTimeout     = 5 * time.Second
	capabilityProbeCommandOutputLimit = 64 << 10
	capabilityProbeCommandWaitDelay   = 250 * time.Millisecond
)

// Fixed sentinels keep command paths, OS errors, and command output out of API-facing observations.
var (
	errCapabilityProbeCanceled = errors.New("capability probe command canceled")
	errCapabilityProbeTimeout  = errors.New("capability probe command timed out")
	errCapabilityProbeOutput   = errors.New("capability probe command output exceeded the safety limit")
	errCapabilityProbePipes    = errors.New("capability probe command pipes did not close")
	errCapabilityProbeFailed   = errors.New("capability probe command failed")
)

// runCmdTimeout is runCmd with an explicit deadline (seam for testing the timeout enforcement).
func runCmdTimeout(d time.Duration, name string, args ...string) string {
	out, err := runCapabilityCommandBounded(
		context.Background(), d, capabilityProbeCommandOutputLimit,
		capabilityProbeCommandWaitDelay, name, args...,
	)
	if err != nil {
		return ""
	}
	return out
}

func runCapabilityProbeCommand(ctx context.Context, name string, args ...string) (string, error) {
	return runCapabilityCommandBounded(
		ctx, capabilityProbeCommandTimeout, capabilityProbeCommandOutputLimit,
		capabilityProbeCommandWaitDelay, name, args...,
	)
}

// runCapabilityCommandBounded runs an argv-only command with bounded wall time, retained output and
// inherited-pipe drain time. Stderr shares the byte budget but is never retained or reflected.
func runCapabilityCommandBounded(
	ctx context.Context,
	timeout time.Duration,
	outputLimit int,
	waitDelay time.Duration,
	name string,
	args ...string,
) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output := newCapabilityProbeOutput(outputLimit, cancel)
	cmd := exec.CommandContext(runCtx, name, args...)
	cmd.Stdout = capabilityProbeWriter{output: output, retain: true}
	cmd.Stderr = capabilityProbeWriter{output: output}
	cmd.WaitDelay = waitDelay
	err := cmd.Run()

	// Classify only fixed facts. Output overflow deliberately cancels runCtx, so it must win over
	// the resulting context error. Partial stdout and raw exec errors are never returned.
	if output.exceededLimit() {
		return "", errCapabilityProbeOutput
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return "", errCapabilityProbeCanceled
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return "", errCapabilityProbeTimeout
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		return "", errCapabilityProbePipes
	}
	if err != nil {
		return "", errCapabilityProbeFailed
	}
	return output.stdoutString(), nil
}

type capabilityProbeOutput struct {
	mu        sync.Mutex
	remaining int
	stdout    []byte
	exceeded  bool
	cancel    context.CancelFunc
}

func newCapabilityProbeOutput(limit int, cancel context.CancelFunc) *capabilityProbeOutput {
	return &capabilityProbeOutput{remaining: limit, cancel: cancel}
}

type capabilityProbeWriter struct {
	output *capabilityProbeOutput
	retain bool
}

func (w capabilityProbeWriter) Write(p []byte) (int, error) {
	if w.output == nil {
		return len(p), nil
	}
	w.output.consume(p, w.retain)
	return len(p), nil
}

func (o *capabilityProbeOutput) consume(p []byte, retain bool) {
	o.mu.Lock()
	take := len(p)
	if take > o.remaining {
		take = o.remaining
	}
	if retain && take > 0 {
		o.stdout = append(o.stdout, p[:take]...)
	}
	o.remaining -= take
	shouldCancel := len(p) > take && !o.exceeded
	if len(p) > take {
		o.exceeded = true
	}
	o.mu.Unlock()
	if shouldCancel && o.cancel != nil {
		o.cancel()
	}
}

func (o *capabilityProbeOutput) exceededLimit() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.exceeded
}

func (o *capabilityProbeOutput) stdoutString() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return string(o.stdout)
}

// listProtoHandlers returns the base names of the *.sh netifd proto handlers under dir, or nil
// if the directory is absent (best-effort).
func listProtoHandlers(dir string) []string {
	names, _ := listProtoHandlersOK(dir)
	return names
}

func listProtoHandlersOK(dir string) ([]string, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, false
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) == ".sh" {
			names = append(names, e.Name())
		}
	}
	return names, true
}

// detectHWOffloadSysfs looks for a hardware flow-offload engine that leaves no trace in
// /proc/modules. Two positive signals, both cheap stats:
//
//   - /sys/module/nf_flow_table_hw — the generic hardware flowtable module, when loadable;
//   - /sys/kernel/debug/ppe*       — a MediaTek packet-processing engine, which on Filogic is part
//     of the built-in mtk_eth_soc driver and therefore never appears as a module.
//
// Only ever returns a POSITIVE finding. A false result means "not observed here", not "absent":
// debugfs is frequently unmounted, and reporting hardware as definitively missing on that basis
// would be the same overreach this function exists to correct.
func detectHWOffloadSysfs() bool {
	if _, err := os.Stat("/sys/module/nf_flow_table_hw"); err == nil {
		return true
	}
	matches, err := filepath.Glob("/sys/kernel/debug/ppe*")
	return err == nil && len(matches) > 0
}
