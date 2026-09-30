package pm

import (
	"context"
	"fmt"
	"strings"
)

// Showing the command is not the same as showing what it does.
//
// Measured on the AX3000T: the plan for removing sing-box is one line, `apk del sing-box`, and the
// operator would read it and click. What actually happens is
//
//	(1/2) Purging sing-box (1.12.17-r1)
//	(2/2) Purging kmod-inet-diag (6.12.74-r1)
//
// — a kernel module goes too, and nothing in the preview said so. The preview exists for informed
// consent, so a preview that understates the effect is the defect it was built to prevent.
//
// Both managers can be asked without changing anything, and both were checked to leave the box
// untouched afterwards:
//
//	apk  add|del  --simulate <pkg>
//	opkg install|remove --noaction <pkg>
//
// Simulate takes the argv the PLAN already built rather than rebuilding it, so the simulation is
// necessarily of the same command the operator is about to approve. Reconstructing it here would
// create a second place for the two to drift apart, which is the whole failure ExecutePM's re-plan
// guard exists to catch.

// dryRunFlag is the flag that makes each manager describe rather than act.
func dryRunFlag(k Kind) (string, bool) {
	switch k {
	case Apk:
		return "--simulate", true
	case Opkg:
		return "--noaction", true
	}
	return "", false
}

// Simulate reports what argv WOULD do. argv must be a command this package built (its first token is
// the manager's own binary); anything else is refused rather than run.
func (m Manager) Simulate(ctx context.Context, argv []string) (string, error) {
	if len(argv) < 2 {
		return "", fmt.Errorf("pm: nothing to simulate")
	}
	flag, ok := dryRunFlag(m.Kind)
	if !ok {
		return "", fmt.Errorf("pm: no package manager detected")
	}
	if argv[0] != string(m.Kind) {
		// The argv came from somewhere other than this manager's planner. Running it would be running
		// an arbitrary command with a dry-run flag bolted on, which is not what this is for.
		return "", fmt.Errorf("pm: refusing to simulate %q with %s", argv[0], m.Kind)
	}
	// Only the verbs that change something are worth simulating, and only those are allowed through.
	// `upgrade` joined them with the apk update path: it is apk's own verb for moving an installed
	// package to the feed's build, and while the list did not carry it every upgrade plan failed its
	// "the effect could be previewed" check and blocked — the preview refusing the one command it
	// exists to describe.
	switch argv[1] {
	case "add", "del", "upgrade", "install", "remove":
	default:
		return "", fmt.Errorf("pm: %q is not an operation that changes anything", argv[1])
	}
	// Flag after the verb: both managers accept it there, and inserting it anywhere else risks it
	// being read as a package name.
	sim := append([]string{argv[1], flag}, argv[2:]...)
	out, err := m.run(ctx, argv[0], sim...)
	if err != nil {
		return out, fmt.Errorf("pm: simulating %s: %w", strings.Join(argv, " "), err)
	}
	return out, nil
}

// CollateralPackages pulls the OTHER packages a simulated removal would take with it.
//
// apk names them one per line as `(n/m) Purging <name> (<version>)`; opkg as
// `Removing package <name> from root...`. The package the operator asked about is not collateral, so
// it is excluded — a list that includes the thing you asked for buries the surprise in the expected.
func CollateralPackages(k Kind, simOut, asked string) []string {
	var out []string
	seen := map[string]bool{asked: true}
	for _, ln := range strings.Split(simOut, "\n") {
		ln = strings.TrimSpace(ln)
		var name string
		switch k {
		case Apk:
			// "(1/2) Purging sing-box (1.12.17-r1)" — also "Removing" on some paths.
			if i := strings.Index(ln, ") "); i >= 0 && strings.HasPrefix(ln, "(") {
				rest := strings.TrimSpace(ln[i+2:])
				for _, verb := range []string{"Purging ", "Removing ", "Deleting "} {
					if v, ok := strings.CutPrefix(rest, verb); ok {
						name, _, _ = strings.Cut(strings.TrimSpace(v), " ")
					}
				}
			}
		case Opkg:
			if v, ok := strings.CutPrefix(ln, "Removing package "); ok {
				name, _, _ = strings.Cut(strings.TrimSpace(v), " ")
			}
		}
		name = strings.TrimSpace(name)
		if name == "" || seen[name] || !ValidPkgName(name) {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}
