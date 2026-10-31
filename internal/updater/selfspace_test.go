package updater

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"wayhop/internal/pm"
)

// smallFS models a file system of capacity bytes that holds exactly the regular files in dir: the
// free space statfs would report there, recomputed on every call, so removing a leftover or replacing
// a rollback copy changes the answer the way it does on the router. A name that shares an inode with
// another (a hard link) is counted once. Directories in extra answer with their fixed value; anything
// else is unmeasured.
func smallFS(dir string, capacity uint64, extra map[string]uint64) func(string) (uint64, bool) {
	return func(d string) (uint64, bool) {
		if v, ok := extra[filepath.Clean(d)]; ok {
			return v, true
		}
		if filepath.Clean(d) != filepath.Clean(dir) {
			return 0, false
		}
		var used uint64
		var seen []os.FileInfo
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			fi, err := os.Lstat(filepath.Join(dir, e.Name()))
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			dup := false
			for _, s := range seen {
				if os.SameFile(s, fi) {
					dup = true
					break
				}
			}
			if dup {
				continue
			}
			seen = append(seen, fi)
			used += uint64(fi.Size())
		}
		if used >= capacity {
			return 0, true
		}
		return capacity - used, true
	}
}

// selfFixture is a router directory holding a running "OLD-BINARY", and a release whose tarball
// carries this test binary (runnable here, see TestMain) with a real digest.
type selfFixture struct {
	dir, exe string
	u        *Updater
	bin      []byte // the new binary's exact bytes
	est      uint64 // what the pre-flight estimates it at: 3x the tarball
}

const selfTestTag = "v0.2.0"

func newSelfFixture(t *testing.T) *selfFixture {
	t.Helper()
	bin := selfUpdateFakeBinary(t)
	tgz := updaterinstall_tarGz(t, "wayhop-0.2.0-amd64", "wayhop-amd64", bin)
	name := "wayhop-0.2.0-amd64-openwrt.tar.gz"
	url := "https://github.com/awadak3davra/wayhop/releases/download/" + selfTestTag + "/" + name
	rel := updaterinstall_releaseJSON(t, selfTestTag, []Asset{{Name: name, URL: url, Digest: updaterinstall_sha256(tgz), Size: int64(len(tgz))}})
	rt := &updaterinstall_rt{relPathSuffix: "/releases/tags/" + selfTestTag, relJSON: rel, assets: map[string][]byte{"/" + name: tgz}}
	dir := t.TempDir()
	exe := filepath.Join(dir, "wayhop")
	if err := os.WriteFile(exe, []byte("OLD-BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := New(dir, "amd64", nil)
	u.hc = &http.Client{Transport: rt}
	u.selfStageDir = t.TempDir()
	return &selfFixture{dir: dir, exe: exe, u: u, bin: bin, est: unpackedBytes(int64(len(tgz)), name)}
}

// used is what the fixture's directory holds now.
func (f *selfFixture) used(t *testing.T) uint64 {
	t.Helper()
	free, _ := smallFS(f.dir, 1<<62, nil)(f.dir)
	return 1<<62 - free
}

func (f *selfFixture) update() (string, error) {
	return f.u.SelfUpdate(context.Background(), "awadak3davra/wayhop", selfTestTag, f.exe)
}

func writeJunk(t *testing.T, p string, n int, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(p, make([]byte, n), 0o644); err != nil {
		t.Fatal(err)
	}
	if !mtime.IsZero() {
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
}

// The AX3000T case: room for the new binary, not for it AND a full copy of the old one. The swap used
// to need both (the 31 MiB refusal); with the rollback copy a hard link it needs the new one alone,
// and the .bak is the old binary's own inode.
func TestSelfUpdateFitsWithRoomForTheNewBinaryAlone(t *testing.T) {
	f := newSelfFixture(t)
	// A second name for the old inode, outside the swap, so it can be compared afterwards: a FileInfo
	// taken before the swap identifies the inode by path on Windows, and the path then names the new one.
	witness := filepath.Join(t.TempDir(), "old")
	if err := os.Link(f.exe, witness); err != nil {
		witness = filepath.Join(f.dir, ".old-witness")
		if err := os.Link(f.exe, witness); err != nil {
			t.Fatalf("no hard links in the test directory, which the rollback copy relies on: %v", err)
		}
	}
	f.u.WithAvail(smallFS(f.dir, f.used(t)+f.est+selfMargin+(1<<20), nil))
	if _, err := f.update(); err != nil {
		t.Fatalf("an update with room for the new binary was refused: %v", err)
	}
	if got, _ := os.ReadFile(f.exe); string(got) != string(f.bin) {
		t.Error("the binary is not the new build")
	}
	bak, err := os.Stat(f.exe + ".bak")
	if err != nil {
		t.Fatalf("no rollback copy: %v", err)
	}
	old, err := os.Stat(witness)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(old, bak) {
		t.Error("the rollback copy is a second copy, not the old binary's own inode (it costs a binary's worth of flash)")
	}
	if got, _ := os.ReadFile(f.exe + ".bak"); string(got) != "OLD-BINARY" {
		t.Errorf("the rollback copy holds %q, want the old binary", got)
	}
}

// The rollback copy this update replaces is room: it goes before the new binary is written.
func TestSelfUpdateCountsTheRollbackCopyItReplaces(t *testing.T) {
	f := newSelfFixture(t)
	writeJunk(t, f.exe+".bak", int(f.est), time.Time{}) // an older build kept from the last update
	writeJunk(t, f.exe+".bak.gz", 1<<20, time.Time{})   // and the installer's compressed copy
	// Free space alone is half of what the new binary needs.
	f.u.WithAvail(smallFS(f.dir, f.used(t)+(f.est+selfMargin)/2, nil))
	if _, err := f.update(); err != nil {
		t.Fatalf("an update that fits once the superseded rollback copy goes was refused: %v", err)
	}
	if got, _ := os.ReadFile(f.exe + ".bak"); string(got) != "OLD-BINARY" {
		t.Error("the rollback copy is not the binary that was replaced")
	}
	if _, err := os.Stat(f.exe + ".bak.gz"); !os.IsNotExist(err) {
		t.Error("the superseded compressed rollback copy was left behind")
	}
}

// Leftovers of interrupted updates go first and count as room; an installer staging file that may be
// being written right now (recent) is not anyone's leftover yet.
func TestSelfUpdateReclaimsLeftoversFirst(t *testing.T) {
	f := newSelfFixture(t)
	old := time.Now().Add(-time.Hour)
	writeJunk(t, filepath.Join(f.dir, ".wayhop.new"), 3<<20, time.Time{}) // a self-update that died mid-download
	writeJunk(t, f.exe+".bak.tmp", 2<<20, time.Time{})
	writeJunk(t, f.exe+".bak.new", 2<<20, old) // an install.sh run interrupted an hour ago
	writeJunk(t, f.exe+".new", 1<<20, time.Now())
	// Fits only once the 7 MiB of leftovers are gone.
	f.u.WithAvail(smallFS(f.dir, f.used(t)-(7<<20)+f.est+selfMargin, nil))
	if _, err := f.update(); err != nil {
		t.Fatalf("an update that fits once the leftovers go was refused: %v", err)
	}
	for _, p := range []string{f.exe + ".bak.tmp", f.exe + ".bak.new"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s was left behind", filepath.Base(p))
		}
	}
	if _, err := os.Stat(f.exe + ".new"); err != nil {
		t.Error("an installer staging file written moments ago was removed: an install may be writing it")
	}
}

// Even the new binary alone does not fit: refused before anything is written, with the number to free.
func TestSelfUpdateRefusalChangesNothing(t *testing.T) {
	f := newSelfFixture(t)
	f.u.WithAvail(smallFS(f.dir, f.used(t)+f.est/2, nil))
	_, err := f.update()
	if err == nil || !strings.Contains(err.Error(), "free at least") {
		t.Fatalf("want a refusal naming the MiB to free, got %v", err)
	}
	if got, _ := os.ReadFile(f.exe); string(got) != "OLD-BINARY" {
		t.Error("the binary changed")
	}
	for _, p := range []string{f.exe + ".bak", filepath.Join(f.dir, ".wayhop.new")} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s was written by a refused update", filepath.Base(p))
		}
	}
}

// Staged in RAM, the verified binary is measured EXACTLY before the flash is touched: room for the real
// binary but not for the 3x estimate is an update, where staging beside the binary must refuse it.
func TestSelfUpdateStagedInRAMDecidesOnTheExactSize(t *testing.T) {
	room := func(f *selfFixture) uint64 { return f.used(t) + uint64(len(f.bin)) + selfMargin + (512 << 10) }

	beside := newSelfFixture(t)
	if room(beside) >= beside.used(t)+beside.est+selfMargin {
		t.Fatal("fixture: the test binary compresses too little for the estimate to differ from its size")
	}
	beside.u.WithAvail(smallFS(beside.dir, room(beside), nil)) // the stage dir is unmeasured: no RAM staging
	if _, err := beside.update(); err == nil {
		t.Fatal("staged beside the binary, the estimate must decide — and it does not fit")
	}

	f := newSelfFixture(t)
	f.u.WithAvail(smallFS(f.dir, room(f), map[string]uint64{filepath.Clean(f.u.selfStageDir): 1 << 32}))
	if _, err := f.update(); err != nil {
		t.Fatalf("staged in RAM, the exact size fits and was refused: %v", err)
	}
	if got, _ := os.ReadFile(f.exe); string(got) != string(f.bin) {
		t.Error("the binary is not the new build")
	}
	if ents, _ := os.ReadDir(f.u.selfStageDir); len(ents) != 0 {
		t.Errorf("the RAM staging directory was left behind: %v", ents)
	}
}

// The page asks before the click; its answer must be the swap's.
func TestSelfFitAgreesWithSelfUpdate(t *testing.T) {
	f := newSelfFixture(t)
	f.u.WithAvail(smallFS(f.dir, f.used(t)+f.est+selfMargin+(1<<20), nil))
	fit, err := f.u.SelfFit(context.Background(), "awadak3davra/wayhop", selfTestTag, f.exe)
	if err != nil {
		t.Fatal(err)
	}
	if !fit.Fits || fit.Need != f.est+selfMargin {
		t.Errorf("fit = %+v, want it to fit with need %d (the new binary alone)", fit, f.est+selfMargin)
	}
	g := newSelfFixture(t)
	g.u.WithAvail(smallFS(g.dir, g.used(t)+g.est/2, nil))
	fit, err = g.u.SelfFit(context.Background(), "awadak3davra/wayhop", selfTestTag, g.exe)
	if err != nil {
		t.Fatal(err)
	}
	if fit.Fits || fit.ShortfallMiB == 0 {
		t.Errorf("fit = %+v, want a refusal with a shortfall", fit)
	}
	if _, err := g.update(); err == nil {
		t.Error("SelfFit refused what SelfUpdate then did")
	}
}

// apkOwnerRunner answers apk the way it answers on a router with the feed package installed: the
// payload under /usr/libexec is the package's, the published /usr/sbin path is nobody's.
type apkOwnerRunner struct{ payload string }

func (r apkOwnerRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	cmd := name + " " + strings.Join(args, " ")
	switch {
	case cmd == "apk info --who-owns "+r.payload:
		return r.payload + " is owned by wayhop-0.5.8-r1\n", nil
	case strings.HasPrefix(cmd, "apk info --who-owns "):
		return "ERROR: " + strings.TrimPrefix(cmd, "apk info --who-owns ") + ": Could not find owner package\n", errors.New("exit status 1")
	case cmd == "apk info -L wayhop":
		return "wayhop-0.5.8-r1 contains:\n" + strings.TrimPrefix(filepath.ToSlash(r.payload), "/") + "\n", nil
	case cmd == "apk list --installed wayhop":
		return "wayhop-0.5.8-r1 x86_64 {wayhop} [installed]\n", nil
	case cmd == "apk list --available wayhop":
		return "wayhop-0.5.8-r1 x86_64 {wayhop}\n", nil
	}
	return "", errors.New("unexpected " + cmd)
}

// On every apk install the running /usr/sbin/wayhop is a path apk does not own: the panel called it
// "not a package's", self-updated it, and the package database went on naming the old version.
func TestApkInstalledWayHopIsSeenAsThePackages(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "usr", "sbin", "wayhop")
	payload := filepath.Join(root, "usr", "libexec", "wayhop", "wayhop")
	for _, p := range []string{exe, payload} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("BIN"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	u := New(filepath.Dir(exe), "amd64", nil).WithPM(pm.Manager{Kind: pm.Apk, Runner: apkOwnerRunner{payload: payload}})
	owner, yes, err := u.selfManaged(exe)
	if err != nil || !yes || owner != "wayhop-0.5.8-r1" {
		t.Fatalf("selfManaged = %q %v %v, want the package that owns the payload", owner, yes, err)
	}
	var nm *NativeManagedError
	if _, err := u.SelfUpdate(context.Background(), "", selfTestTag, exe); !errors.As(err, &nm) {
		t.Errorf("SelfUpdate = %v, want the package-manager refusal", err)
	}
	if st := u.SelfPackageStatus(context.Background(), exe); !st.Managed || st.Path != payload {
		t.Errorf("SelfPackageStatus = %+v, want the payload's package", st)
	}

	// A tarball install (no payload beside it) stays the panel's to update.
	if err := os.Remove(payload); err != nil {
		t.Fatal(err)
	}
	if _, yes, err := u.selfManaged(exe); err != nil || yes {
		t.Errorf("with no package payload the binary was called a package's: %v %v", yes, err)
	}
}

// An engine install interrupted on a full overlay leaves its staging file holding the room the retry
// needs: it goes before the pre-flight measures.
func TestEngineInstallReclaimsItsOwnLeftovers(t *testing.T) {
	const tag = "v1.0.0"
	e := Engine{ID: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box"}
	name := "sing-box-1.0.0-linux-amd64.tar.gz"
	tgz := updaterinstall_tarGz(t, "sing-box-1.0.0-linux-amd64", e.BinName, []byte("SINGBOX"))
	rel := updaterinstall_releaseJSON(t, tag, []Asset{{Name: name, URL: "https://github.com/SagerNet/sing-box/releases/download/" + tag + "/" + name,
		Digest: updaterinstall_sha256(tgz), Size: int64(len(tgz))}})
	binDir := t.TempDir()
	u := New(binDir, "amd64", nil)
	u.hc = &http.Client{Transport: &updaterinstall_rt{relPathSuffix: "/releases/tags/" + tag, relJSON: rel, assets: map[string][]byte{"/" + name: tgz}}}
	leftover := filepath.Join(binDir, "sing-box.new.zip")
	writeJunk(t, leftover, 3<<20, time.Time{})
	need := peakInstallDisk(int64(len(tgz)), name, false)
	u.WithAvail(smallFS(binDir, need+(3<<20)-1, nil)) // fits only once the leftover is gone
	if _, err := u.Install(context.Background(), e, tag); err != nil {
		t.Fatalf("an install that fits once its own leftover goes was refused: %v", err)
	}
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Error("the staging file of the interrupted install was left behind")
	}
}

// A daemon that died mid-update left its RAM staging directory; the next update removes it (an old
// one only: a fresh one could be another process's, though u.mu rules that out in this one).
func TestSelfUpdateRemovesAnOldRAMStagingDir(t *testing.T) {
	f := newSelfFixture(t)
	stale := filepath.Join(f.u.selfStageDir, "wayhop-selfupdate.123")
	fresh := filepath.Join(f.u.selfStageDir, "wayhop-selfupdate.456")
	for _, d := range []string{stale, fresh} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		writeJunk(t, filepath.Join(d, "wayhop"), 1<<20, time.Time{})
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	f.u.WithAvail(smallFS(f.dir, f.used(t)+f.est+selfMargin+(1<<20), map[string]uint64{filepath.Clean(f.u.selfStageDir): 1 << 32}))
	if _, err := f.update(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Error("the staging directory a dead update left in RAM is still there")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("a recent staging directory was removed")
	}
}

// The pre-swap hook is where the server records the update for its supervisor: it must run after
// the new binary is verified and the rollback copy is in place, before the name changes hands, and an
// error from it must leave the old binary where it was.
func TestSelfUpdateWithRecordsBeforeTheSwap(t *testing.T) {
	f := newSelfFixture(t)
	f.u.WithAvail(smallFS(f.dir, f.used(t)+f.est+selfMargin+(1<<20), nil))
	var line string
	var bakThen, oldThen bool
	_, err := f.u.SelfUpdateWith(context.Background(), "awadak3davra/wayhop", selfTestTag, f.exe, func(l string) error {
		line = l
		_, e := os.Stat(f.exe + ".bak")
		bakThen = e == nil
		b, _ := os.ReadFile(f.exe)
		oldThen = string(b) == "OLD-BINARY"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if line != "wayhop 9.9.9 (self-update test stub)" {
		t.Errorf("the hook got %q, want the new build's --version line", line)
	}
	if !bakThen || !oldThen {
		t.Errorf("the hook ran with rollback copy=%v and old binary still in place=%v; want both", bakThen, oldThen)
	}

	g := newSelfFixture(t)
	g.u.WithAvail(smallFS(g.dir, g.used(t)+g.est+selfMargin+(1<<20), nil))
	_, err = g.u.SelfUpdateWith(context.Background(), "awadak3davra/wayhop", selfTestTag, g.exe, func(string) error { return errors.New("flash full") })
	if err == nil || !strings.Contains(err.Error(), "nothing was swapped") {
		t.Fatalf("a failing hook = %v, want the update aborted", err)
	}
	if b, _ := os.ReadFile(g.exe); string(b) != "OLD-BINARY" {
		t.Error("the binary was swapped although the update could not be recorded")
	}
	if _, err := os.Stat(filepath.Join(g.dir, ".wayhop.new")); !os.IsNotExist(err) {
		t.Error("the staged binary was left behind")
	}
}
