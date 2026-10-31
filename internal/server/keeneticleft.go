package server

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"wayhop/internal/platform"
)

// A KeeneticOS tunnel WayHop created can be changed in the KeeneticOS web UI: a setting edited, a
// key regenerated. WayHop never overwrites or deletes such a tunnel. An Apply stops on it and says
// so; boot and a rollback leave it as it is and bring up everything else, and before this file that
// was a line in the log nobody reads - sing-box running, the tunnel not as configured, and nothing on
// any page saying why. The operator now hears of it twice: the notification webhook when a run first
// finds it, and the Diagnostics row, which looks at the router again each time it runs.

// keeneticLeftAsIs remembers which changed tunnels have already been alerted in this process, so a
// finding repeated at every converge is sent once.
type keeneticLeftAsIs struct {
	mu      sync.Mutex
	alerted []string
}

// noteKeeneticLeftAsIs takes a prepare's finding and alerts the tunnels it names for the first time.
func (s *Server) noteKeeneticLeftAsIs(ifaces []string) {
	r := &s.keeneticLeft
	r.mu.Lock()
	var fresh []string
	for _, iface := range ifaces {
		if !slices.Contains(r.alerted, iface) {
			fresh = append(fresh, iface)
		}
	}
	// What is no longer found is forgotten, so a tunnel changed again later is alerted again.
	r.alerted = slices.Clone(ifaces)
	r.mu.Unlock()
	if len(fresh) != 0 {
		slices.Sort(fresh)
		s.alert(fmt.Sprintf("WayHop: %s on the router no longer carries what WayHop created it with "+
			"(changed in KeeneticOS); it was left as it is.", strings.Join(fresh, ", ")))
	}
}

// keeneticLeftAsIsCheck is the Diagnostics row. It checks the router when it runs rather than
// repeating what the last Apply or boot found: a recorded finding stayed a warning after the operator
// had undone the change, and read as a pass when a tunnel was changed afterwards. The check is two
// reads, the running config and `show interface` (about 0.1 s on the router read), held to the blocks of
// the configuration that runs now by the same judgement prepare uses (exactKeeneticDrift).
func (s *Server) keeneticLeftAsIsCheck(ctx context.Context) healthRow {
	row := healthRow{ID: "keenetic_native_changed", Label: "WayHop's KeeneticOS tunnels are as it created them"}
	rev := s.liveRevision()
	if rev == nil {
		rev = s.committedRevision()
	}
	var blocks [][]string
	if rev != nil && rev.Materialization.known() {
		if target := rev.Materialization.nativeTarget(); target != nil && target.Platform == platform.Keenetic &&
			target.Keenetic != nil {
			blocks = target.Keenetic.Interfaces
		}
	}
	if len(blocks) == 0 {
		row.Status, row.Summary = "na", "the configuration that runs has no KeeneticOS tunnel of WayHop's own"
		return row
	}
	readConfig, readInterfaces := s.keeneticConfigReader, s.keeneticInterfacesReader
	if readConfig == nil {
		readConfig = readKeeneticRunningConfig
	}
	if readInterfaces == nil {
		readInterfaces = readKeeneticInterfaces
	}
	running, err := readConfig(ctx)
	if err != nil || strings.TrimSpace(running) == "" {
		row.Status, row.Summary = "na", "the router's configuration could not be read"
		return row
	}
	var live [][]string
	for _, block := range blocks {
		if _, found := ndmInterfaceSection(running, block[0]); found {
			live = append(live, block)
		}
	}
	listing, listErr := listingFor(ctx, readInterfaces, live)
	changed, unverified := exactKeeneticDrift(live, running, listing, listErr == nil)
	switch {
	case len(changed) != 0:
		row.Status = "warn"
		row.Summary = strings.Join(changed, ", ") + " changed outside WayHop and left as it is"
		row.Detail = "The settings or the key of these interfaces differ from what WayHop created them with, " +
			"changed in the KeeneticOS web UI for example. WayHop does not overwrite or delete them. At boot and " +
			"after a failed Apply it leaves them as they are and starts everything else; an Apply stops on them " +
			"before changing anything."
		row.Fix = "Undo the change in KeeneticOS, or delete the interface there and Apply again to have it created anew."
	case len(unverified) != 0:
		row.Status = "warn"
		row.Summary = "the key of " + strings.Join(unverified, ", ") + " could not be checked"
		row.Detail = "Their settings match what WayHop created, but the router's interface list (`show interface`), " +
			"which is the only place the key shows, could not be read."
	case len(live) == 0:
		row.Status, row.Summary = "na", "none of WayHop's KeeneticOS tunnels is on the router right now"
	default:
		row.Status, row.Summary = "pass", "every KeeneticOS tunnel WayHop created carries what it created it with"
	}
	return row
}
