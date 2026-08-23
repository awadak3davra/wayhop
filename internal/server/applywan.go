package server

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// applywan.go answers one question for the Keenetic policy plane: which interface is the uplink?
//
// It matters because the plane MASQUERADEs marked traffic with `-o <wan>`. Get it wrong and return
// traffic is not translated, so every marked flow dies silently while the rules look installed.
// render_ipset.go defaults IpsetOptions.WanIface to "eth3", which is one developer's router — fine
// as a rendering default, not as production truth.
//
// The routing table is read from /proc/net/route rather than by shelling out to `ip route`: it is
// the same kernel state, needs no tool identity to be authenticated first, and cannot be influenced
// by PATH.

const procNetRoutePath = "/proc/net/route"

// probeWANInterface returns the uplink interface name from the main routing table.
//
// A router normally has exactly one default route and the answer is unambiguous. When WayHop's own
// plane is already installed there can be two, because a tunnel default sits alongside the
// NDM-managed WAN backstop; KeeneticOS deliberately gives that backstop the HIGHEST metric so
// tunnels win ordinary traffic (see internal/keenetic/kernel.go, "the NDM-managed WAN default
// (metric 1000) is the kernel backstop"). Selecting the highest-metric default therefore keeps
// returning the uplink even after WayHop has changed the table it is reading.
func probeWANInterface() (string, error) {
	file, err := os.Open(procNetRoutePath)
	if err != nil {
		return "", errExecutionCaptureUnavailable
	}
	defer file.Close()
	return parseWANInterface(file)
}

func parseWANInterface(r interface{ Read([]byte) (int, error) }) (string, error) {
	scanner := bufio.NewScanner(r)
	best := ""
	bestMetric := -1
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// Iface Destination Gateway Flags RefCnt Use Metric Mask …
		if len(fields) < 7 || fields[1] != "00000000" {
			continue
		}
		metric, err := strconv.Atoi(fields[6])
		if err != nil {
			continue
		}
		if metric > bestMetric {
			best, bestMetric = fields[0], metric
		}
	}
	if scanner.Err() != nil || best == "" || !validWANInterfaceName(best) {
		return "", errExecutionCaptureUnavailable
	}
	return best, nil
}

// validWANInterfaceName keeps a parsed name inside what a Linux interface may be called, so a
// malformed table can never reach a rendered `-o <iface>` argument.
func validWANInterfaceName(name string) bool {
	if name == "" || len(name) > 15 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_' || r == '@':
		default:
			return false
		}
	}
	return true
}
