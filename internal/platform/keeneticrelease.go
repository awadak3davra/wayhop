package platform

import (
	"strconv"
	"strings"

	"wayhop/internal/awg"
)

// What KeeneticOS's NDM takes on `wireguard asc` depends on the firmware release, not on the
// WireGuard component: the component is older than the command, so a router can have WireGuard and
// no AmneziaWG at all (QA-127). The thresholds, and where they come from:
//
//   - 4.2: WireGuard with asc parameters appeared in KeeneticOS 4.2 Alpha 2
//     (docs.amnezia.org/documentation/instructions/old-keenetic-os-awg). Before it NDM has no
//     `wireguard asc` command, and the nine AmneziaWG 1 settings cannot be written at all.
//   - 5.1: the AmneziaWG 2 settings (S3/S4, H ranges, I1-I5) after the nine 1.x arguments - the
//     16-argument form keenetic.WireguardCommands writes - arrived in KeeneticOS 5.1 Alpha 3, as the
//     Keenetic forum's 5.1 Alpha 3 topic (forum.keenetic.ru, topic 27738) and an earlier revision of
//     docs.amnezia.org/documentation/instructions/keenetic-os-awg report it; KeeneticOS 5.0 rejects
//     an H range on import ("invalid H1 value"). These are community sources about pre-releases,
//     not an official changelog line: the official 5.2 changelog only fixes "certain ASC CPS
//     version 2.0 configurations" (5.2 Beta 1) and adds the 3.1 settings (5.2 Alpha 11), which
//     WayHop's writer does not emit.
//
// Only major.minor is compared. The stage and build fields of a long release string are not
// decoded, so the alpha builds before 4.2 Alpha 2 and 5.1 Alpha 3 count as the release they precede.
var (
	keeneticASCSince  = keeneticVersion{major: 4, minor: 2}
	keeneticASC2Since = keeneticVersion{major: 5, minor: 1}
)

type keeneticVersion struct{ major, minor int }

func (v keeneticVersion) atLeast(w keeneticVersion) bool {
	return v.major > w.major || (v.major == w.major && v.minor >= w.minor)
}

func (v keeneticVersion) String() string {
	return strconv.Itoa(v.major) + "." + strconv.Itoa(v.minor)
}

// parseKeeneticRelease reads major.minor from a KeeneticOS release as `show version` prints it:
// long (`4.01.C.7.0-0`, the minor zero-padded) or short (`4.1.7`). ok is false for anything else.
func parseKeeneticRelease(release string) (keeneticVersion, bool) {
	fields := strings.Split(strings.TrimSpace(release), ".")
	if len(fields) < 2 {
		return keeneticVersion{}, false
	}
	major, err := strconv.Atoi(fields[0])
	if err != nil || major < 0 {
		return keeneticVersion{}, false
	}
	minor, err := strconv.Atoi(fields[1])
	if err != nil || minor < 0 {
		return keeneticVersion{}, false
	}
	return keeneticVersion{major: major, minor: minor}, true
}

// KeeneticReleaseAWG is the newest AmneziaWG generation NDM's `wireguard asc` takes on a KeeneticOS
// release (Capabilities.FirmwareRelease): GenNone before 4.2, which has no `wireguard asc`; Gen1 up
// to 5.0; Gen2 from 5.1. It never answers above Gen2, which is as far as WayHop's NDM writer goes
// (keenetic.AWGGeneration). known is false for a release it cannot read, and a caller then keeps
// what it decided before the release was read.
func KeeneticReleaseAWG(release string) (generation awg.Generation, known bool) {
	v, ok := parseKeeneticRelease(release)
	switch {
	case !ok:
		return awg.GenNone, false
	case v.atLeast(keeneticASC2Since):
		return awg.Gen2, true
	case v.atLeast(keeneticASCSince):
		return awg.Gen1, true
	default:
		return awg.GenNone, true
	}
}

// ndmcField is the value of one `name: value` line of ndmc output, "" when there is none.
func ndmcField(text, name string) string {
	for _, line := range strings.Split(text, "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), name+":"); ok {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
