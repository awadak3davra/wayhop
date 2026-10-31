//go:build linux

package plugin

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"wayhop/internal/binstore"
)

// geteuid is os.Geteuid; tests stand in for a root daemon with it.
var geteuid = os.Geteuid

// runAs starts cmd as uid (and gid) when the daemon is root; otherwise it cannot, and leaves it.
func runAs(cmd *exec.Cmd, uid int) {
	if uid <= 0 || geteuid() != 0 {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credentialFor(uid)}
}

// credentialFor is uid and gid uid with no supplementary groups. NoSetGroups (what this used to set)
// skips setgroups, so the child kept the daemon's own groups: a daemon restarted from a root SSH
// shell carries group 0, and so did ciadpi and the Telegram bridge, both of which parse whatever
// the LAN sends them. An empty Groups makes Go call setgroups(0), which needs the same CAP_SETGID
// as the setgid that follows it, so it adds no way to fail. ciadpi loses nothing it used: its argv
// names no file (model.ByeDPIStrategy takes --hosts, --ipset and --fake-data inline only), and the
// binary it runs is staged world-readable (reachableFor).
func credentialFor(uid int) *syscall.Credential {
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(uid), Groups: []uint32{}}
}

// runServiceAs is runAs for a service (RunService), which also dies with the daemon: Pdeathsig has
// the kernel SIGKILL it when the daemon goes, however it goes - a SIGKILL, the OOM killer, a panic,
// log.Fatalf - none of which runs StopAll. Without it such a bridge outlived the daemon still serving
// its old secret until the next daemon's ReapStrays, and forever if no daemon came back.
//
// Pdeathsig follows the thread that started the child, not the process (Go issue 27505), and Go
// ends a thread only when a goroutine locked to it exits; WayHop locks none. Should that change, the
// cost is a bridge killed early, which Supervise starts again within a tick. Go sets it after the
// uid change, which would otherwise clear it.
func runServiceAs(cmd *exec.Cmd, uid int) {
	attr := &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if uid > 0 && geteuid() == 0 {
		attr.Credential = credentialFor(uid)
	}
	cmd.SysProcAttr = attr
}

// stageDir is where a binary that runs as another uid is copied; tests point it elsewhere.
var stageDir = binstore.DefaultRunDir

// reachableFor returns a path uid can execute bin from. A root daemon keeps its binaries where only
// root may look (a 0700 directory anywhere on the path is enough to stop the child at exec), so the
// binary is copied into a 0755 directory of its own first. Falling back to running it as root
// instead is not an option for ciadpi: in tun mode that is the loop its uid exists to break.
func reachableFor(bin string, uid int) (string, error) {
	if uid <= 0 || os.Geteuid() != 0 {
		return bin, nil
	}
	dir := filepath.Join(stageDir, "uid-"+strconv.Itoa(uid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("stage for uid %d: %w", uid, err)
	}
	for d := dir; d != filepath.Dir(d); d = filepath.Dir(d) {
		fi, err := os.Stat(d)
		if err != nil {
			return "", err
		}
		if fi.Mode().Perm()&0o001 == 0 {
			if d == dir || d == stageDir {
				if err := os.Chmod(d, 0o755); err != nil {
					return "", err
				}
				continue
			}
			return "", fmt.Errorf("stage for uid %d: %s is not reachable by other users", uid, d)
		}
	}
	dst := filepath.Join(dir, filepath.Base(bin))
	in, err := os.Open(bin)
	if err != nil {
		return "", err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return "", err
	}
	return dst, os.Rename(tmp, dst)
}
