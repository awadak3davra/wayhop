// Package awg is the AmneziaWG component: which protocol generation a router can run, and by which
// path - the kernel module when it is new enough, the userspace amneziawg-go binary otherwise.
package awg

// Generation is an AmneziaWG protocol generation, as the kernel module declares it.
//
// It is read from the module itself - the generic-netlink family "amneziawg" and the version and
// highest attribute it registers - and never from a package version. Package versions are useless
// here: the OpenWrt kmod built from upstream tag v1.0.20260210 is generation 2 (WG_GENL_VERSION 2,
// with S3/S4/I1), and upstream's own amneziawg-go reports "0.0.20250522" at tag v3.1.20260828.
type Generation int

const (
	GenNone Generation = iota // no amneziawg family registered: the module is not loaded
	Gen1                      // genl v1: Jc/Jmin/Jmax, S1/S2, single-value H1..H4
	Gen2                      // genl v2: adds S3/S4, H ranges, I1..I5
	Gen30                     // genl v3, maxattr 32: adds HeaderProtectionKey
	Gen31                     // genl v3, maxattr 34+: adds RandomTrailers and DisableCookies
)

// Why maxattr and not the version alone: upstream v3.0 and v3.1 BOTH declare WG_GENL_VERSION 3, but
// only v3.1 accepts WGDEVICE_A_RANDOM_TRAILERS (33) and WGDEVICE_A_DISABLE_COOKIES (34). Trusting
// "version 3" would send a 3.1 config to a 3.0 module, which drops the parameters it does not know
// instead of refusing them - a tunnel that looks configured and is not. The family registers
// `.maxattr = WGDEVICE_A_MAX` (src/netlink.c), and WGDEVICE_A_MAX, counted from enum
// wgdevice_attribute in src/uapi/wireguard.h, is 25 at v1.0.20260210, 32 at v3.0.20260805 and 34 at
// v3.1.20260906.
const (
	maxAttrGen31 = 34
)

// UserspaceGeneration is the generation amneziawg-go runs: the build WayHop ships is pinned to
// upstream v3.1.20260828 (scripts/build-amneziawg-go.sh), whose UAPI takes every 3.1 setting.
const UserspaceGeneration = Gen31

// Classify maps what the kernel reports for the "amneziawg" family to a generation. A version 0
// means the family was not found. A future generation (version 4+) is treated as at least 3.1: new
// attributes are appended, so everything 3.1 knows it still accepts.
func Classify(version, maxAttr uint32) Generation {
	switch {
	case version >= 3 && maxAttr >= maxAttrGen31:
		return Gen31
	case version >= 3:
		return Gen30
	case version == 2:
		return Gen2
	case version == 1:
		return Gen1
	}
	return GenNone
}

func (g Generation) String() string {
	switch g {
	case Gen1:
		return "1"
	case Gen2:
		return "2"
	case Gen30:
		return "3.0"
	case Gen31:
		return "3.1"
	}
	return "none"
}

// Path is how an AmneziaWG interface will be brought up on this router.
type Path int

const (
	PathUnavailable Path = iota // neither a new-enough module nor a TUN device
	PathKernel                  // the loaded kernel module is new enough: ip link add type amneziawg
	PathUserspace               // amneziawg-go on /dev/net/tun
)

func (p Path) String() string {
	switch p {
	case PathKernel:
		return "kernel"
	case PathUserspace:
		return "userspace"
	}
	return "unavailable"
}

// Decision is the chosen path and the reason, in words the panel can show as they are.
type Decision struct {
	Path   Path
	Reason string
}

// Decide picks the path for an endpoint that needs generation `need`.
//
// The kernel module wins when it is new enough: it is faster and costs no flash. Otherwise userspace,
// which needs only /dev/net/tun - so it covers every KeeneticOS (NDM has no generation 3) and every
// OpenWrt whose kmod is older than the config or built for a different kernel. An older module is
// never "close enough": a generation-2 module handed a 3.1 config would drop what it cannot read.
func Decide(kernel Generation, tun bool, need Generation) Decision {
	if need <= GenNone {
		need = Gen1
	}
	if kernel >= need {
		return Decision{PathKernel, "the loaded AmneziaWG kernel module is generation " + kernel.String() +
			", enough for this configuration (needs " + need.String() + ")"}
	}
	if tun {
		why := "no AmneziaWG kernel module is loaded"
		if kernel != GenNone {
			why = "the loaded AmneziaWG kernel module is generation " + kernel.String() +
				" and this configuration needs " + need.String()
		}
		return Decision{PathUserspace, why + "; using amneziawg-go on /dev/net/tun"}
	}
	why := "no AmneziaWG kernel module is loaded"
	if kernel != GenNone {
		why = "the loaded AmneziaWG kernel module is generation " + kernel.String() +
			" and this configuration needs " + need.String()
	}
	return Decision{PathUnavailable, why + ", and /dev/net/tun is missing, so amneziawg-go cannot run either"}
}

// Probe is what a router can do for AmneziaWG, as measured.
type Probe struct {
	Kernel      Generation // classified from the two fields below
	GenlVersion uint32     // CTRL_ATTR_VERSION of the "amneziawg" family; 0 = not registered
	GenlMaxAttr uint32     // CTRL_ATTR_MAXATTR of the same family
	TUN         bool       // /dev/net/tun is a character device
	Err         string     // the netlink query itself failed - NOT the same as "no module"
}
