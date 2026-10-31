package updater

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"wayhop/internal/binstore"
)

// blockRecord makes the next record write fail, as a full flash would: the names a record is written
// under before it takes its own are taken by directories.
func blockRecord(t *testing.T, dir string) {
	t.Helper()
	for _, n := range []string{".amneziawg-go.version.new", ".amneziawg-go.version.next"} {
		if err := os.MkdirAll(filepath.Join(dir, n, "x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// A compressed install whose record cannot be written must leave the copy that ran before runnable.
// The gzip used to take the name and the unpacked binary to go before the record was written, so a
// kill, a power cut or a failed write there left a record describing nothing that exists: Unpack said
// ErrNotStored, the plugin found nothing, and every userspace AWG tunnel stayed down after the reboot.
func TestCompressedInstallThatCannotRecordKeepsTheRawBinary(t *testing.T) {
	u, e, gz := companionRig(t, []byte("AMNEZIAWG-GO-arm64"))
	raw := filepath.Join(u.BinDir, "amneziawg-go")
	u.WithAvail(avail(1 << 30))
	if _, err := u.Install(context.Background(), e, "v3.1.20260828"); err != nil {
		t.Fatal(err)
	}
	blockRecord(t, u.BinDir)
	u.WithAvail(avail(compressedNeed(int64(len(gz)))))
	if _, err := u.Install(context.Background(), e, "v3.1.20260828"); err == nil {
		t.Fatal("an install whose record could not be written reported success")
	}
	if !fileExists(raw) {
		t.Fatal("the unpacked binary that ran was removed, and the gzip that replaced it has no record")
	}
	if rec, ok := binstore.Read(u.BinDir, "amneziawg-go"); !ok || rec.Compressed {
		t.Errorf("record %+v, %v; want the raw binary's", rec, ok)
	}
}

// The same for a gzip replacing a gzip, the usual update once a router keeps it compressed: the old
// record stops matching the moment the new gzip takes the name.
func TestCompressedReinstallThatCannotRecordKeepsTheOldGzipRunnable(t *testing.T) {
	payload := []byte("AMNEZIAWG-GO-arm64")
	u, e, gz := companionRig(t, payload)
	u.WithAvail(avail(compressedNeed(int64(len(gz)))))
	if _, err := u.Install(context.Background(), e, "v3.1.20260828"); err != nil {
		t.Fatal(err)
	}
	// Recorded an hour ago, so the reinstall's gzip cannot share its modification time.
	packed := binstore.Stored(u.BinDir, "amneziawg-go", true)
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(packed, old, old); err != nil {
		t.Fatal(err)
	}
	if err := binstore.Write(u.BinDir, "amneziawg-go", "v3.1.20260828", true); err != nil {
		t.Fatal(err)
	}
	blockRecord(t, u.BinDir)
	if _, err := u.Install(context.Background(), e, "v3.1.20260828"); err == nil {
		t.Fatal("an install whose record could not be written reported success")
	}
	p, err := binstore.Unpack(u.BinDir, "amneziawg-go", u.RunDir)
	if err != nil {
		t.Fatalf("the stored gzip can no longer be unpacked to run: %v", err)
	}
	if b, _ := os.ReadFile(p); !bytes.Equal(b, payload) {
		t.Errorf("unpacked %q", b)
	}
}

// Installed raw over a compressed store, the copy unpacked into RAM to run is no longer what runs: the
// plugin prefers the raw binary. Left there, it holds 3-4 MB of tmpfs (the router's RAM) until reboot,
// and the footprint the panel shows stops counting it, since the record now says raw.
func TestRawInstallOverACompressedStoreDropsTheUnpackedCopy(t *testing.T) {
	u, e, gz := companionRig(t, []byte("AMNEZIAWG-GO-arm64"))
	u.WithAvail(avail(compressedNeed(int64(len(gz)))))
	if _, err := u.Install(context.Background(), e, "v3.1.20260828"); err != nil {
		t.Fatal(err)
	}
	running, err := binstore.Unpack(u.BinDir, "amneziawg-go", u.RunDir)
	if err != nil {
		t.Fatal(err)
	}
	u.WithAvail(avail(1 << 30))
	if _, err := u.Install(context.Background(), e, "v3.1.20260828"); err != nil {
		t.Fatal(err)
	}
	if rec, ok := binstore.Read(u.BinDir, "amneziawg-go"); !ok || rec.Compressed {
		t.Fatalf("record %+v, %v; want the raw install's", rec, ok)
	}
	for _, p := range []string{running, running + ".src"} {
		if fileExists(p) {
			t.Errorf("%s survived the raw install", p)
		}
	}
}
