package platform

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Capabilities is the platform capability probe — which VPN/proxy protocols this router can
// carry on a kernel/firmware-native path RIGHT NOW, which ones it could carry after installing
// a package, and which proxy protocols mandatorily need the sing-box userspace core (no kernel
// path exists anywhere). It is the "detect" half of the detect→use→recommend design
// (docs/NATIVE_INTEGRATION_DESIGN.md §3a). All map keys are the lowercase proto strings.
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
}

// Proxy protocols have no kernel/firmware path on any platform, so sing-box is always required
// for them. This is the floor: run any of these and the userspace core must run.
var singboxRequired = []string{"vless", "vmess", "trojan", "shadowsocks", "hysteria2", "tuic"}

// hostInputs is everything the pure decision functions read from the live host, captured up
// front so the decision (decideOpenWrt / decideKeenetic) is a pure function unit-tested with
// synthetic samples — mirroring server.parseConntrack and netvpn.parseWgDump.
type hostInputs struct {
	// OpenWrt surfaces.
	lsmod        string          // `cat /proc/modules` / `lsmod` text
	netifdProtos []string        // base names from /lib/netifd/proto/*.sh (e.g. "amneziawg.sh")
	tools        map[string]bool // present CLIs: awg, wg, openvpn, sing-box

	// Keenetic surfaces.
	ndmcVersion   string // `ndmc -c "show version"` component text
	ndmcInterface string // `ndmc -c "show interface"` text
}

// decideOpenWrt builds the OpenWrt capability matrix from the captured host inputs. Pure.
//
// Rules (docs/NATIVE_INTEGRATION_DESIGN.md §1-2): AmneziaWG is native if the amneziawg kmod is
// loaded, OR the amneziawg netifd proto handler exists, OR the awg CLI is present. Plain
// WireGuard is native if the wireguard kmod is loaded, OR the wg CLI is present, OR the
// wireguard netifd proto handler exists — OR AmneziaWG is native: the amneziawg kmod is a
// WireGuard superset, so vanilla WG rides it ("WireGuard | native via amneziawg kmod" in the
// design matrix). That implication is ONE-WAY — plain WireGuard does not provide AmneziaWG's
// obfuscation, so WG-native must never back-imply AmneziaWG-native. When a proto has no native
// path, recommend the standard OpenWrt package to install instead.
func decideOpenWrt(in hostInputs) Capabilities {
	lsmod := strings.ToLower(in.lsmod)
	protos := protoSet(in.netifdProtos)

	caps := Capabilities{
		Platform:        string(OpenWrt),
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

	return withInstallCmds(caps, in.packageManager())
}

// decideKeenetic builds the Keenetic capability matrix from the NDM component + interface text.
// Pure.
//
// Rules (docs/NATIVE_INTEGRATION_DESIGN.md §1-2): WireGuard/AmneziaWG are native if the
// "wireguard" firmware component is present, OR an NDM interface of type "Wireguard" exists (the
// NDM Wireguard type carries AmneziaWG params on Keenetic). KeeneticOS firmware also ships
// ipsec/openvpn/l2tp/etc. components — those are populated too when present (best-effort), but
// WG/AWG are the priority this iteration.
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
	// names mirror `ndmc show version` on the Hopper SE (docs §1).
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
func withInstallCmds(caps Capabilities, manager string) Capabilities {
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
func protoSet(names []string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".sh")] = true
	}
	return set
}

// hasComponent reports whether the (lowercased) `ndmc show version` text lists the named
// firmware component. KeeneticOS prints components as space/comma-separated tokens; a substring
// check is robust to the surrounding formatting.
func hasComponent(loweredVersion, comp string) bool {
	return strings.Contains(loweredVersion, strings.ToLower(comp))
}

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
	plat := Detect()

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
		in.lsmod = readFile("/proc/modules")
		in.netifdProtos = listProtoHandlers("/lib/netifd/proto")
		return decideOpenWrt(in)
	case Keenetic:
		in.ndmcVersion = runCmd("ndmc", "-c", "show version")
		in.ndmcInterface = runCmd("ndmc", "-c", "show interface")
		return decideKeenetic(in)
	default:
		// Unknown / dev host: still return the contract-valid shape with the proxy floor.
		return Capabilities{
			Platform:        string(Unknown),
			Native:          map[string]bool{},
			Installable:     map[string]string{},
			SingboxRequired: append([]string(nil), singboxRequired...),
			SingboxPresent:  in.tools["sing-box"],
		}
	}
}

// commandExists reports whether a CLI is on PATH (best-effort).
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// readFile returns a file's contents, or "" if it can't be read (best-effort).
func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// runCmd runs a command and returns its combined stdout, or "" on any error (best-effort).
func runCmd(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// listProtoHandlers returns the base names of the *.sh netifd proto handlers under dir, or nil
// if the directory is absent (best-effort).
func listProtoHandlers(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) == ".sh" {
			names = append(names, e.Name())
		}
	}
	return names
}
