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
	case strings.HasPrefix(argv, "apk list --installed"):
		// Asked separately from the catalogue below. The installed-version reader takes the first line
		// that matches the package, so answering this with the whole catalogue would report whichever
		// build happened to be printed first as the one on disk.
		return "sing-box-1.12.17-r1 aarch64 {sing-box} (GPL-3.0-or-later) [installed]\n", nil
	case strings.HasPrefix(argv, "apk list"):
		// The catalogue carries a build NEWER than the installed one. It used to hold only older ones,
		// which is the "ahead" state — an answer no real feed gives for long and the one state where the
		// package path has nothing to offer.
		//
		// This does NOT put the delegation UI on the demo page, and it is worth being exact about why:
		// the package status is only asked for an engine whose binary EXISTS at the configured path, and
		// a dev host has no sing-box there, so every row stays unmanaged whatever this answers. The
		// fixture is here for the demo that runs beside a real binary, and for the reader who would
		// otherwise take these three older builds for what a feed looks like.
		return "sing-box-1.12.17-r1 aarch64 {sing-box} (GPL-3.0-or-later) [installed]\n" +
			"sing-box-1.13.21-r1 aarch64 {sing-box} (GPL-3.0-or-later)\n" +
			"sing-box-1.12.4-r2 aarch64 {sing-box} (GPL-3.0-or-later)\n" +
			"sing-box-1.11.15-r0 aarch64 {sing-box} (GPL-3.0-or-later)\n", nil
	case strings.HasPrefix(argv, "apk query"):
		// The sizes the space assessment reads, in apk-tools 3 own JSON shape and with the AX3000T own
		// figures. The dev host has room for both builds at once, so demo mode plans the one-command
		// upgrade — the two-command path belongs to a router that cannot, and is covered by tests.
		return `[{"name":"sing-box","version":"1.12.17-r1","installed-size":40537528,"file-size":14485215},` +
			`{"name":"sing-box","version":"1.13.21-r1","installed-size":44466473,"file-size":15591117},` +
			`{"name":"sing-box","version":"1.12.4-r2","installed-size":40102400,"file-size":14300000},` +
			`{"name":"sing-box","version":"1.11.15-r0","installed-size":39900000,"file-size":14100000}]`, nil
	case argv == "apk update":
		return "demo mode: package indexes were not changed", nil
	case strings.HasPrefix(argv, "apk add"), strings.HasPrefix(argv, "apk del"),
		strings.HasPrefix(argv, "apk upgrade"):
		return "demo mode: nothing was installed or removed. The command that would have run is: " + argv, nil
	}
	return "", nil
}
