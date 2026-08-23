package netvpn

import (
	"errors"
	"fmt"
	"strings"
)

// openwrt_remove.go is the counterpart to the write path, and it exists in this shape because the
// end-to-end check on a real AX3000T found what the network-only removal left behind.
//
// RemoveUCI deletes the interface and its peer sections, which is what "remove the tunnel" sounds
// like it means. On the router it was not enough: after removing a tunnel that had been attached to
// the `vpn` zone, `uci get firewall.@zone[2].network` still listed it. A zone member naming an
// interface that no longer exists is not cosmetic — fw4 resolves zone members at reload, and the
// next operator to read that zone sees a tunnel that is not there.
//
// So removal has to undo BOTH halves of what the apply did, and the plan is built the same way: from
// a snapshot, with the commands visible before anything runs.
//
// One ordering point, measured rather than assumed: `ifdown` is issued BEFORE the config is
// committed, because netifd can only tear down an interface it can still find. Run afterwards it
// answers "Interface wrprobe0 not found" and does nothing. The teardown does eventually happen on
// its own — the device was gone when looked at a minute later — but "eventually, by a path we did
// not ask for" is not something to build a removal on.

// RemovalPlan is what taking an interface out of the configuration will do. It carries the same
// separation as Plan: Commands stage, Commit mutates, and nothing in Commands can change the device.
type RemovalPlan struct {
	Iface string

	// Commands stage the removal into uci's buffer. Safe to print and safe to show.
	Commands []string

	// Commit is the mutating tail: the ifdown, the commits, the reloads.
	Commit []string

	// Expected is the interface as it was when the plan was built; the applier refuses if the
	// router no longer matches it.
	Expected AWGInterface

	// Zones are the firewall zones that referenced this interface, by stable name.
	Zones []string

	Warnings []string
}

// BuildRemovalPlan produces the plan that removes name completely.
//
// uciNetwork and uciFirewall are the raw outputs of `uci show network` and `uci show firewall` taken
// at the same moment, for the same reason BuildPlan takes them: the plan is only valid against that
// snapshot, and making it an argument is what lets the applier check that it still holds.
func BuildRemovalPlan(name, uciNetwork, uciFirewall string) (RemovalPlan, error) {
	if name == "" {
		return RemovalPlan{}, fmt.Errorf("build removal plan: no interface name given")
	}
	cur, ok := ParseUCIShow(uciNetwork)[name]
	if !ok {
		return RemovalPlan{}, fmt.Errorf("build removal plan: %s is not in the configuration", name)
	}

	p := RemovalPlan{Iface: name, Expected: cur}
	p.Commands = RemoveUCI(name, len(cur.Peers))

	// Every zone that names this interface, not just the first. An interface can legitimately be
	// listed in more than one zone, and detaching only one would leave the rest dangling — the exact
	// failure this file exists to fix, one level in.
	var detached bool
	for _, z := range ParseFirewallZones(uciFirewall) {
		cmds := ZoneDetachCmds(z, name)
		if len(cmds) == 0 {
			continue
		}
		p.Commands = append(p.Commands, cmds...)
		p.Zones = append(p.Zones, z.Name)
		detached = true
	}
	if !detached {
		p.Warnings = append(p.Warnings,
			fmt.Sprintf("%s is not a member of any firewall zone, so nothing is detached", name))
	}

	// ifdown first: netifd can only tear down an interface that is still in the config it can read.
	p.Commit = append([]string{"ifdown " + name}, CommitCmds()...)
	if detached {
		p.Commit = append(p.Commit, FirewallCommitCmds()...)
	}
	return p, nil
}

// VerifyRemoved is the check run after the staged removal, against a fresh `uci show network` and
// `uci show firewall`. An empty result is the only evidence the removal did what it said; the
// commands exiting 0 is not — RemoveUCI's deletes are `-q` and a missing section is not an error.
func (p RemovalPlan) VerifyRemoved(freshNetwork, freshFirewall string) []Difference {
	var out []Difference
	if _, ok := ParseUCIShow(freshNetwork)[p.Iface]; ok {
		out = append(out, Difference{Field: "interface", Want: "absent", Got: "still present"})
	}
	for _, z := range ParseFirewallZones(freshFirewall) {
		for _, n := range z.Networks {
			if n == p.Iface {
				out = append(out, Difference{
					Field: "firewall zone " + z.Name,
					Want:  "no longer lists " + p.Iface,
					Got:   "still lists it",
				})
			}
		}
	}
	return out
}

// Apply removes the interface, refusing at every point where it cannot prove what it is about to do.
//
// Same sequence and same reasoning as Plan.Apply: nothing else may be staged (because the rollback
// discards the WHOLE config buffer, not just ours), the router must still match the snapshot the
// plan was built from, and the buffer is read back and checked before anything reaches the disk.
func (p RemovalPlan) Apply(r Runner) (ApplyResult, error) {
	var res ApplyResult
	sh := func(cmd string) (string, error) {
		res.Ran = append(res.Ran, cmd)
		return r.Run("", "sh", "-c", cmd)
	}

	for _, cfg := range []string{"network", "firewall"} {
		out, err := sh("uci changes " + cfg)
		if err != nil {
			return res, fmt.Errorf("remove %s: reading staged %s changes: %w", p.Iface, cfg, err)
		}
		if strings.TrimSpace(out) != "" {
			return res, fmt.Errorf("remove %s: %s has uncommitted changes; refusing, because rolling back "+
				"would discard them too:\n%s", p.Iface, cfg, scrubUCI(strings.TrimSpace(out)))
		}
	}

	netOut, err := sh("uci show network")
	if err != nil {
		return res, fmt.Errorf("remove %s: reading network config: %w", p.Iface, err)
	}
	cur, ok := ParseUCIShow(netOut)[p.Iface]
	if !ok {
		return res, fmt.Errorf("remove %s: it is no longer in the configuration; the plan is stale", p.Iface)
	}
	if diffs := DiffInterface(p.Expected, cur); len(diffs) > 0 {
		res.Preflight = diffs
		return res, fmt.Errorf("remove %s: the router no longer matches the plan (%d difference(s)); refusing",
			p.Iface, len(diffs))
	}

	for _, c := range p.Commands {
		if out, err := sh(c); err != nil {
			rb := p.revert(sh, &res)
			return res, errors.Join(fmt.Errorf("remove %s: %q failed%s: %w: %s",
				p.Iface, c, rollbackNote(res.Rollback), err, scrubUCI(strings.TrimSpace(out))), rb)
		}
	}

	freshNet, err1 := sh("uci show network")
	freshFw, err2 := sh("uci show firewall")
	if err1 != nil || err2 != nil {
		rb := p.revert(sh, &res)
		return res, errors.Join(fmt.Errorf("remove %s: could not read the staged result back%s: %w",
			p.Iface, rollbackNote(res.Rollback), errors.Join(err1, err2)), rb)
	}
	if diffs := p.VerifyRemoved(freshNet, freshFw); len(diffs) > 0 {
		res.Verify = diffs
		rb := p.revert(sh, &res)
		return res, errors.Join(fmt.Errorf("remove %s: the staged result is not a clean removal "+
			"(%d problem(s))%s", p.Iface, len(diffs), rollbackNote(res.Rollback)), rb)
	}

	for _, c := range p.Commit {
		if out, err := sh(c); err != nil {
			// Past the commit there is nothing to revert to — say so plainly rather than implying
			// the router was put back.
			return res, fmt.Errorf("remove %s: %q failed AFTER the change was committed; the router is "+
				"in a partly-applied state: %w: %s", p.Iface, c, err, strings.TrimSpace(out))
		}
	}
	res.Applied = true
	return res, nil
}

// revert discards both staging buffers: a removal stages into network and firewall together, so
// putting only one back is what leaves a zone naming an interface that is gone.
func (p RemovalPlan) revert(sh func(string) (string, error), res *ApplyResult) error {
	return revertConfigs(sh, res, "network", "firewall")
}
