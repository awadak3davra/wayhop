package updater

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// selfspace.go is what a WayHop self-update costs on the router's flash, and the room it makes first.
//
// It follows packaging/openwrt/install.sh, which upgrades the same binary in the same directory (that
// script's "space + leftovers" block), so the panel and the installer agree on what fits:
//
//   - the staging files an interrupted update or install leaves beside the binary are removed before
//     anything is measured: a 14 MiB partial .wayhop.new on a 60 MiB overlay is the room the next try
//     needs;
//   - the rollback copy is a HARD LINK to the running binary, so writing it costs nothing: when the
//     new binary is renamed over the old name, the old inode lives on as the .bak. The update then
//     needs room for the new binary alone, where it used to need the new binary plus a full copy of
//     the old one while the previous rollback copy still sat there (~31 MiB on the AX3000T, with
//     13-20 MiB free);
//   - the rollback copy it supersedes (.bak, or the .bak.gz the installer keeps on a full overlay)
//     counts as room, because it goes before the new binary is written.
//
// The running daemon keeps its own inode until it restarts, so unlike the installer it cannot free the
// old binary first: below "the new binary fits" the refusal names the installer, which can.

const (
	// selfMargin is the head-room left free after the swap (flash file systems need some), the
	// installer's MARGIN_KB.
	selfMargin = 2 << 20
	// selfStageAge is how old an installer staging file must be before it is anyone's leftover: an
	// install.sh run may be writing one right now. The installer uses the same 10 minutes for ours.
	selfStageAge = 10 * time.Minute
)

// selfStaging names the files an interrupted self-update or installer run leaves beside exePath.
// owned are written only by SelfUpdate under u.mu, so whoever holds the lock may remove them; the
// installer's are removed only once older than selfStageAge.
func selfStaging(exePath string) (owned, installer []string) {
	dir := filepath.Dir(exePath)
	owned = []string{filepath.Join(dir, ".wayhop.new"), exePath + ".bak.tmp", filepath.Join(dir, ".wayhop.linkprobe")}
	installer = []string{exePath + ".new", exePath + ".bak.new", exePath + ".bak.gz.new", exePath + ".rb"}
	return owned, installer
}

// selfLeftovers lists the staging files a self-update would remove now, with what each frees.
func selfLeftovers(exePath string, now time.Time) (paths []string, freed uint64) {
	owned, installer := selfStaging(exePath)
	add := func(p string, mustBeOld bool) {
		fi, err := os.Lstat(p)
		if err != nil || !fi.Mode().IsRegular() {
			return
		}
		if mustBeOld && now.Sub(fi.ModTime()) < selfStageAge {
			return
		}
		paths = append(paths, p)
		freed += freedBytes(fi)
	}
	for _, p := range owned {
		add(p, false)
	}
	for _, p := range installer {
		add(p, true)
	}
	return paths, freed
}

// reclaimSelfLeftovers removes what selfLeftovers lists and returns the paths it removed.
func reclaimSelfLeftovers(exePath string, now time.Time) []string {
	paths, _ := selfLeftovers(exePath, now)
	var removed []string
	for _, p := range paths {
		if os.Remove(p) == nil {
			removed = append(removed, p)
		}
	}
	return removed
}

// supersededRollbackBytes is what the rollback copy this update replaces gives back: exePath.bak when
// it is not the running binary's own inode, and the compressed exePath.bak.gz.
func supersededRollbackBytes(exePath string) uint64 {
	var n uint64
	cur, curErr := os.Stat(exePath)
	if fi, err := os.Lstat(exePath + ".bak"); err == nil && fi.Mode().IsRegular() && (curErr != nil || !os.SameFile(cur, fi)) {
		n += freedBytes(fi)
	}
	if fi, err := os.Lstat(exePath + ".bak.gz"); err == nil && fi.Mode().IsRegular() {
		n += freedBytes(fi)
	}
	return n
}

// freedBytes is what removing this name gives back: nothing while another name holds the inode.
func freedBytes(fi os.FileInfo) uint64 {
	used, links := fileUsage(fi)
	if links > 1 {
		return 0
	}
	return used
}

// canHardLink reports whether exePath's directory takes hard links, by making one and removing it.
func canHardLink(exePath string) bool {
	probe := filepath.Join(filepath.Dir(exePath), ".wayhop.linkprobe")
	_ = os.Remove(probe)
	if err := os.Link(exePath, probe); err != nil {
		return false
	}
	_ = os.Remove(probe)
	return true
}

// selfPlan is the flash pre-flight of one self-update: the room there is and what the update needs.
type selfPlan struct {
	avail uint64 // free on the binary's file system
	known bool   // avail was measured
	room  uint64 // avail + the staging leftovers + the superseded rollback copy
	need  uint64 // the new binary + selfMargin, + a full copy of the old one where links are impossible
	link  bool   // the rollback copy can be a hard link
}

func (p selfPlan) fits() bool { return !p.known || p.room >= p.need }

// planSelfSpace measures exePath's file system for a new binary of newBytes. leftovers is what the
// staging files removed first give back (0 once they are gone).
func (u *Updater) planSelfSpace(exePath string, newBytes, leftovers uint64) selfPlan {
	p := selfPlan{link: canHardLink(exePath)}
	p.avail, p.known = u.availAt(filepath.Dir(exePath))
	p.room = p.avail + leftovers + supersededRollbackBytes(exePath)
	p.need = newBytes + selfMargin
	if !p.link {
		if fi, err := os.Stat(exePath); err == nil {
			p.need += uint64(fi.Size())
		}
	}
	return p
}

// selfRefusal is what the operator reads when even the new binary alone does not fit. The panel cannot
// do better in place: the running daemon holds its own inode until it restarts. The installer can,
// stopping the daemon first and keeping the old binary compressed, so it is named, with its own need.
func selfRefusal(dir string, p selfPlan, oldBytes uint64) error {
	msg := fmt.Sprintf("not enough free space to self-update safely on %s (~%d MiB free counting the leftovers and the rollback copy this update replaces, need ~%d MiB for the new binary — free at least %d MiB more)",
		dir, p.room>>20, p.need>>20, shortfallMiB(p.room, p.need))
	if oldBytes > 0 {
		// The installer's compressed path: ~40% of the old binary as the rollback copy, the new binary in
		// the room the old one leaves. Estimated as the installer estimates it before compressing (55%).
		gz := oldBytes * 55 / 100
		need := gz + selfMargin
		if newB := p.need - selfMargin; newB > oldBytes {
			need += newB - oldBytes
		}
		if p.room < need {
			return fmt.Errorf("%s — free space, or update over SSH", msg)
		}
		return fmt.Errorf("%s — or re-run the installer over SSH (curl -fsSL https://github.com/awadak3davra/wayhop/releases/latest/download/bootstrap.sh | sh): it stops WayHop first and keeps the old binary compressed, which fits in ~%d MiB", msg, need>>20)
	}
	return fmt.Errorf("%s — free space, or update over SSH", msg)
}

// linkRollback makes exePath.bak the current binary: a hard link where the file system has them (no
// space: when the new binary is renamed over exePath, the old inode lives on under the .bak name),
// else a complete copy. Through a temp name either way, so a failure can neither leave a half-written
// .bak posing as a rollback nor destroy the previous one. The compressed copy it supersedes goes.
func linkRollback(exePath string) (linked bool, err error) {
	bakTmp := exePath + ".bak.tmp"
	_ = os.Remove(bakTmp)
	if lerr := os.Link(exePath, bakTmp); lerr == nil {
		linked = true
	} else {
		cur, rerr := os.ReadFile(exePath)
		if rerr != nil {
			return false, fmt.Errorf("read current binary for rollback backup: %w", rerr)
		}
		if werr := os.WriteFile(bakTmp, cur, 0o755); werr != nil {
			_ = os.Remove(bakTmp)
			return false, fmt.Errorf("write rollback backup: %w", werr)
		}
	}
	if rerr := os.Rename(bakTmp, exePath+".bak"); rerr != nil {
		_ = os.Remove(bakTmp)
		return false, fmt.Errorf("install rollback backup: %w", rerr)
	}
	_ = os.Remove(exePath + ".bak.gz")
	return linked, nil
}

// stageSelfInRAM picks where the download is staged: a fresh directory in the temp dir (tmpfs, RAM,
// on a router) when it can hold an estimated est bytes beside what the restart needs, so the binary
// is verified and measured EXACTLY before the flash is touched; "" means stage beside the binary.
func (u *Updater) stageSelfInRAM(est uint64, assetSize int64, assetName string) string {
	base := u.selfStageDir
	if base == "" {
		base = os.TempDir()
	}
	// A daemon that died mid-update left its staging directory in RAM; under u.mu no other is live.
	if old, _ := filepath.Glob(filepath.Join(base, "wayhop-selfupdate.*")); len(old) > 0 {
		for _, d := range old {
			if fi, err := os.Lstat(d); err == nil && fi.IsDir() && time.Since(fi.ModTime()) > selfStageAge {
				_ = os.RemoveAll(d)
			}
		}
	}
	avail, known := u.availAt(base)
	if !known || avail < est+(1<<20) {
		return ""
	}
	if mem, ok := availMemBytes(); ok && mem < updateMemNeed(assetSize, assetName)+est {
		return ""
	}
	d, err := os.MkdirTemp(base, "wayhop-selfupdate.")
	if err != nil {
		return ""
	}
	return d
}

// copyVerified copies src to dst (0755), flushed to the device, and proves the copy byte-identical by
// digest: on a nearly full flash a short write must never become the binary.
func copyVerified(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(dst)
		}
	}()
	hs := sha256.New()
	if _, err = io.Copy(io.MultiWriter(out, hs), in); err != nil {
		_ = out.Close()
		return err
	}
	if err = out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	f, err := os.Open(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	hd := sha256.New()
	if _, err = io.Copy(hd, f); err != nil {
		return err
	}
	if string(hd.Sum(nil)) != string(hs.Sum(nil)) {
		return errors.New("the copy on flash does not match the verified download")
	}
	return nil
}

// digestDeclared reports whether an asset declares the sha256 digest the mandatory check needs, so
// a self-update without one is refused before anything on disk is touched.
func digestDeclared(d string) bool {
	parts := strings.SplitN(d, ":", 2)
	return len(parts) == 2 && parts[0] == "sha256" && parts[1] != ""
}

// firstLine is the first line of a command's output, trimmed.
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// LinkRollback is linkRollback for the package-manager update, where the server keeps the rollback
// copy itself before apk replaces the binary (see the update supervisor).
func LinkRollback(exePath string) (bool, error) { return linkRollback(exePath) }

// ReclaimSelfLeftovers removes what interrupted updates and installs left beside exePath, as the
// self-update does before it measures; the package-manager update measures after it too.
func (u *Updater) ReclaimSelfLeftovers(exePath string) []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return reclaimSelfLeftovers(exePath, time.Now())
}

// SelfPMSpace is the flash pre-flight of a package-manager update of WayHop itself: the target
// build must fit beside the running one. The removal the engine plans allow ("replace") is not an
// option for the daemon running the panel, so where only that would fit the answer is blocked.
func (u *Updater) SelfPMSpace(ctx context.Context, st PackageStatus) PMSpace {
	sp := u.pmSpace(ctx, st.Package, st.Path, st.InstalledVersion, st.LatestVersion)
	if sp.Strategy == PMSpaceReplace {
		sp.Strategy = PMSpaceBlocked
		sp.ShortfallMiB = shortfallMiB(sp.Avail, sp.Need+pmWriteMargin)
	}
	return sp
}
