package server

import (
	"context"
	"log"
	"strconv"
	"strings"

	"wayhop/internal/model"
	"wayhop/internal/pbr"
)

// kernelkeep.go keeps a runtime election across a reinstall of OpenWrt's nft plane.
//
// The plane's program seeds each egress table with `ip [-6] route replace default dev <iface> table
// <N>` (pbr.RenderIP), where <iface> is the compile-time pin: a group's first member with a device, a
// fastest list's first candidate. The whole program runs again on every Apply and whenever the
// reconcile loop finds the table gone (a fw4 reload), so each of those put the pin back over the
// member the elector had chosen: the list's flows moved to another tunnel (another NAT source, so
// they broke) and stayed there until the unit's next decision, up to a list's own interval away, and
// a list the elector had emptied because every tunnel is down got a dead tunnel's route back.
// KeeneticOS never had this: its program seeds with `ip route add … || true`.
//
// The rule is as narrow as the elector's own write. A seed is skipped only when the table belongs, in
// the plan being installed, to the same owner the elector runs it for, and the table still holds
// exactly what the elector last left in it: its candidate's link (still one of that owner's tunnels in
// the new plan), or nothing after an all-down clear (unless the list being applied stays on its last
// tunnel). Anything else is installed as the plan says, and the
// elector decides again on its next tick. After a daemon restart the elector knows nothing, so the
// first install seeds every table, as before.

// tableDefaultCommand reads `ip [-6] route replace default dev <iface> table <N>`, the one seed line
// RenderIP emits per interface egress and family.
func tableDefaultCommand(command string) (v6 bool, iface string, table int, ok bool) {
	f := strings.Fields(command)
	if len(f) > 1 && f[0] == "ip" && f[1] == "-6" {
		v6 = true
		f = append([]string{"ip"}, f[2:]...)
	}
	if len(f) != 8 || f[0] != "ip" || f[1] != "route" || f[2] != "replace" || f[3] != "default" || f[4] != "dev" || f[6] != "table" {
		return false, "", 0, false
	}
	n, err := strconv.Atoi(f[7])
	if err != nil || n <= 0 {
		return false, "", 0, false
	}
	return v6, f[5], n, true
}

// tableRefusesV6 reports the `unreachable default` the elector puts into a table whose member carries
// no IPv6 (writeTableUnreachableV6), in `ip -6 route show table all`:
//
//	unreachable default dev lo table 152 metric 1024 error -113 pref medium
func tableRefusesV6(dump string, table int) bool {
	want := strconv.Itoa(table)
	for _, line := range strings.Split(dump, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != "unreachable" || f[1] != "default" {
			continue
		}
		for i := 2; i+1 < len(f); i++ {
			if f[i] == "table" && f[i+1] == want {
				return true
			}
		}
	}
	return false
}

// electedHold is what the elector last left in one table.
type electedHold struct {
	iface string // its candidate's link; "" when it emptied the table (every tunnel down)
}

// electedHolds is, per table of plan the elector runs for the same owner, what it holds there now.
func (s *Server) electedHolds(plan *pbr.Plan) map[int]electedHold {
	if s == nil || plan == nil {
		return nil
	}
	owner := map[int]string{}
	// candidate is, per table, the devices the plan being installed lets that table hold. "Any
	// enabled tunnel of the plan" would let a member the Apply had just taken out of the group or the
	// list, its endpoint still enabled, keep the table until the next decision.
	candidate := map[int]map[string]bool{}
	// keepsLast is the tables whose list, in the profile being applied, stays on its last tunnel when
	// every tunnel is down: such a table is never kept EMPTY. The elector's last state
	// says what the policy was, not what it is now; an Apply from "by the provider" to "stay on the
	// last tunnel" made during an outage left the table empty, and the list on the provider, until a
	// tunnel answered.
	keepsLast := map[int]bool{}
	var profile *model.Profile
	if s.store != nil {
		p := s.store.Profile()
		profile = &p
	}
	for _, eg := range plan.Egresses {
		if eg.Kind != pbr.EgressInterface || eg.Table == 0 {
			continue
		}
		devs := eg.Devices()
		if len(eg.Ifaces) == 0 {
			// A plan stored before Compile recorded the devices: any enabled tunnel, as before.
			devs = plan.MasqIfaces
		}
		set := make(map[string]bool, len(devs))
		for _, d := range devs {
			set[d] = true
		}
		candidate[eg.Table] = set
		if id, isList := model.ListEgressID(eg.Tag); isList {
			owner[eg.Table] = eg.Tag
			if profile != nil {
				if rl := profile.RoutingListByID(id); rl != nil && model.EffectiveAllDown(profile, *rl) == model.OnAllDownKeep {
					keepsLast[eg.Table] = true
				}
			}
		} else {
			owner[eg.Table] = "group:" + eg.Tag
		}
	}
	holds := map[int]electedHold{}
	for _, st := range s.kernelElector().States() {
		if owner[st.Table] == "" || owner[st.Table] != st.Key.Owner {
			continue
		}
		switch {
		case st.Current != "" && candidate[st.Table][st.CurrentIface]:
			holds[st.Table] = electedHold{iface: st.CurrentIface}
		case st.CurrentIface == "" && st.List != nil && st.List.AllDown && st.List.OnAllDown != model.OnAllDownKeep && !keepsLast[st.Table]:
			holds[st.Table] = electedHold{}
		}
	}
	return holds
}

// electedRouteKeeper is the nft adapter's keep hook for an install of plan: it reports the seed lines
// to skip (see the file comment). nil when the elector holds nothing in this plan's tables. The tables
// are read once per family, on the first seed line that needs them; a family that cannot be read
// keeps nothing, because unread is not "as the elector left it".
func (s *Server) electedRouteKeeper(ctx context.Context, plan *pbr.Plan) func(string) bool {
	holds := s.electedHolds(plan)
	if len(holds) == 0 {
		return nil
	}
	type family struct {
		read   bool
		ok     bool
		tables map[int]string
		dump   string
	}
	fam := map[bool]*family{false: {}, true: {}}
	return func(command string) bool {
		v6, iface, table, ok := tableDefaultCommand(command)
		if !ok {
			return false
		}
		hold, held := holds[table]
		if !held {
			return false
		}
		f := fam[v6]
		if !f.read {
			f.read = true
			if dump, err := s.tableIO().read(ctx, v6); err == nil {
				f.ok, f.dump, f.tables = true, dump, parseTableDefaults(dump)
			}
		}
		if !f.ok {
			return false
		}
		live := f.tables[table]
		keep := false
		switch {
		case hold.iface == "":
			keep = live == "" // emptied on purpose: stay empty
		case live == hold.iface:
			keep = live != iface // the seed would move it; an equal seed is harmless and runs
		case v6 && live == "":
			keep = tableRefusesV6(f.dump, table) // the member carries no IPv6: its refusal stays
		}
		if keep {
			log.Printf("apply: kernel plane: table %d keeps %s, the tunnel elected at run time; the plan's %q is not re-seeded",
				table, orNone(hold.iface), command)
		}
		return keep
	}
}
