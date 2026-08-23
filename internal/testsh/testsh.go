// Package testsh locates a POSIX shell for the tests that parse generated shell scripts.
//
// Those tests skipped whenever `sh` was absent from PATH, and on the Windows dev box that is every
// run: Git for Windows ships sh.exe but does not put it on PATH. So the checks that keep a shell
// typo out of a VPS provisioning script only ever ran in CI — on the one platform where nobody reads
// the output while writing the code. A skip that fires on every run of the machine the code is
// written on is not coverage, it is a gap with a label on it.
package testsh

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
)

// winFallbacks are Git for Windows' two shipped locations. Git Bash is the documented dev shell for
// this repo, so its sh is part of the supported environment even though the installer leaves it off
// PATH. Narrow and explicit: a wide search would find some other program called sh.
var winFallbacks = []string{
	`C:\Program Files\Git\usr\bin\sh.exe`,
	`C:\Program Files\Git\bin\sh.exe`,
}

// ErrNotFound reports that no POSIX shell could be located.
var ErrNotFound = errors.New("testsh: no POSIX shell found (set WR_SH to one)")

// Find returns the path to a POSIX shell. WR_SH overrides everything, for a host that keeps its
// shell somewhere else.
func Find() (string, error) {
	if p := os.Getenv("WR_SH"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		return "", ErrNotFound
	}
	if p, err := exec.LookPath("sh"); err == nil {
		return p, nil
	}
	if runtime.GOOS == "windows" {
		for _, p := range winFallbacks {
			if _, err := os.Stat(p); err == nil {
				return p, nil
			}
		}
	}
	return "", ErrNotFound
}
