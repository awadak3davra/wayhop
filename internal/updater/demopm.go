package updater

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"wayhop/internal/pm"
)

// DemoPM gives demo mode a package manager to talk to.
//
// Without one there is nothing to see: the delegation UI only appears for an engine the package
// manager OWNS, the dev host and CI have neither opkg nor apk, and so the whole feature would render
// on no page anywhere. Every gate would walk the Updater route and pass over a control that was never
// drawn — a check whose subject is absent, which is the failure this project keeps finding in its own
// work. Demo mode already synthesizes traffic for exactly this reason.
//
// The answers are shaped like a real apk on the AX3000T, including the detail that caught a defect in
// the planner: `apk info --who-owns` reports the owner as name AND version glued together.
//
// Mutating verbs do NOT mutate. They return the line the package manager would print, so the flow can
// be exercised end to end, and they say "demo" so nobody reads the output as a real install. Demo
// mode must not touch host state — the same rule cidrrefresh.go already follows.
func DemoPM() pm.Manager { return pm.Manager{Kind: pm.Apk, Runner: demoRunner{}} }

type demoRunner struct{}

func (demoRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	argv := strings.Join(append([]string{name}, args...), " ")
	switch {
	case strings.Contains(argv, "info --who-owns"):
		// The path is whatever the caller asked about; echoing it back keeps the planner's
		// path-verification honest rather than short-circuiting it.
		path := args[len(args)-1]
		if !strings.EqualFold(filepath.Base(path), "sing-box") {
			return "ERROR: " + path + ": Could not find owner package", errors.New("exit status 1")
		}
		return path + " is owned by sing-box-1.12.17-r1", nil
	case strings.Contains(argv, "info -L"):
		return "sing-box-1.12.17-r1 contains:\nusr/bin/sing-box\nusr/share/sing-box/LICENSE\n", nil
	case strings.HasPrefix(argv, "apk list"):
		return "sing-box-1.12.17-r1 aarch64 {sing-box} (GPL-3.0-or-later) [installed]\n" +
			"sing-box-1.12.4-r2 aarch64 {sing-box} (GPL-3.0-or-later)\n" +
			"sing-box-1.11.15-r0 aarch64 {sing-box} (GPL-3.0-or-later)\n", nil
	case argv == "apk update":
		return "demo mode: package indexes were not changed", nil
	case strings.HasPrefix(argv, "apk add"), strings.HasPrefix(argv, "apk del"):
		return "demo mode: nothing was installed or removed. The command that would have run is: " + argv, nil
	}
	return "", nil
}
