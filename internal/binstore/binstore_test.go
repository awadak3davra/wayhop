package binstore

import (
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func gz(t *testing.T, payload []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	if _, err := zw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// store writes name.gz holding payload and records it compressed.
func store(t *testing.T, dir, name string, payload []byte, version string) {
	t.Helper()
	if err := os.WriteFile(Stored(dir, name, true), gz(t, payload), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, name, version, true); err != nil {
		t.Fatal(err)
	}
}

func TestWriteRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(Stored(dir, "bin", false), []byte("raw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, "bin", "v1", false); err != nil {
		t.Fatal(err)
	}
	if r, ok := Read(dir, "bin"); !ok || r.Version != "v1" || r.Compressed || r.SHA256 != "-" {
		t.Errorf("raw record %+v, %v", r, ok)
	}
	store(t, dir, "bin", []byte("payload"), "v2")
	r, ok := Read(dir, "bin")
	if !ok || r.Version != "v2" || !r.Compressed || len(r.SHA256) != 64 {
		t.Errorf("compressed record %+v, %v", r, ok)
	}
}

// A stored file replaced by other means - different size or time - is unrecorded, not the version
// installed before it.
func TestRead_ReplacedFileIsUnrecorded(t *testing.T) {
	dir := t.TempDir()
	store(t, dir, "bin", []byte("payload"), "v1")
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(Stored(dir, "bin", true), later, later); err != nil {
		t.Fatal(err)
	}
	if r, ok := Read(dir, "bin"); ok {
		t.Errorf("a touched store still reads as %+v", r)
	}
}

func TestUnpack(t *testing.T) {
	dir, run := t.TempDir(), t.TempDir()
	store(t, dir, "bin", []byte("first"), "v1")
	p, err := Unpack(dir, "bin", run)
	if err != nil || p != filepath.Join(run, "bin") {
		t.Fatalf("Unpack = %q, %v", p, err)
	}
	if b, _ := os.ReadFile(p); string(b) != "first" {
		t.Errorf("unpacked %q", b)
	}
	if fi, _ := os.Stat(p); runtime.GOOS != "windows" && fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("unpacked mode %v, want executable", fi.Mode().Perm())
	}
	// The same store again reuses the copy: nothing is rewritten.
	if err := os.WriteFile(p, []byte("reused"), 0o755); err != nil {
		t.Fatal(err)
	}
	if p2, err := Unpack(dir, "bin", run); err != nil || p2 != p {
		t.Fatalf("second Unpack = %q, %v", p2, err)
	}
	if b, _ := os.ReadFile(p); string(b) != "reused" {
		t.Errorf("an unchanged store was unpacked again (%q)", b)
	}
	// A new store is unpacked afresh.
	store(t, dir, "bin", []byte("second"), "v2")
	if _, err := Unpack(dir, "bin", run); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "second" {
		t.Errorf("a changed store was not unpacked again (%q)", b)
	}
}

// Corruption that keeps the size and the time - worn flash - is caught by the digest before anything
// is unpacked.
func TestUnpack_CorruptStoreIsRefused(t *testing.T) {
	dir, run := t.TempDir(), t.TempDir()
	store(t, dir, "bin", []byte(strings.Repeat("payload", 100)), "v1")
	gzPath := Stored(dir, "bin", true)
	fi, _ := os.Stat(gzPath)
	b, _ := os.ReadFile(gzPath)
	b[len(b)/2] ^= 0xff
	if err := os.WriteFile(gzPath, b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(gzPath, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, ok := Read(dir, "bin"); !ok {
		t.Fatal("precondition: size and time unchanged, so the record still describes the file")
	}
	if _, err := Unpack(dir, "bin", run); err == nil || !strings.Contains(err.Error(), "does not match its record") {
		t.Fatalf("a corrupt store unpacked: %v", err)
	}
	if _, err := os.Stat(filepath.Join(run, "bin")); !os.IsNotExist(err) {
		t.Error("something was unpacked from a corrupt store")
	}
}

func TestUnpack_NotStored(t *testing.T) {
	dir := t.TempDir()
	if _, err := Unpack(dir, "bin", t.TempDir()); !errors.Is(err, ErrNotStored) {
		t.Errorf("no record: %v", err)
	}
	if err := os.WriteFile(Stored(dir, "bin", false), []byte("raw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, "bin", "v1", false); err != nil {
		t.Fatal(err)
	}
	if _, err := Unpack(dir, "bin", t.TempDir()); !errors.Is(err, ErrNotStored) {
		t.Errorf("a binary stored as itself: %v", err)
	}
}

// A gzip that inflates past the cap is refused and leaves nothing in the tmpfs, which is the router's
// RAM.
func TestGunzip_Capped(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "bomb.gz")
	f, _ := os.Create(src)
	zw, _ := gzip.NewWriterLevel(f, gzip.BestCompression)
	zeros := make([]byte, 1<<20)
	for i := 0; i <= maxUnpacked>>20; i++ {
		_, _ = zw.Write(zeros)
	}
	_ = zw.Close()
	_ = f.Close()
	dst := filepath.Join(dir, "out")
	if err := Gunzip(src, dst); err == nil {
		t.Fatal("a gzip past the cap was unpacked")
	}
	for _, p := range []string{dst, dst + ".new"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s left behind", p)
		}
	}
}

func TestRemove(t *testing.T) {
	dir, run := t.TempDir(), t.TempDir()
	store(t, dir, "bin", []byte("x"), "v1")
	if _, err := Unpack(dir, "bin", run); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(Stored(dir, "bin", false), []byte("raw"), 0o755)
	Remove(dir, "bin", run)
	for _, p := range []string{Stored(dir, "bin", false), Stored(dir, "bin", true), filepath.Join(dir, ".bin.version"),
		filepath.Join(run, "bin"), filepath.Join(run, "bin.src")} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived Remove", p)
		}
	}
}

// exists reports whether p is there at all.
func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// Once a package owns the binary, only WayHop's compressed copy goes: the gzip, its record and the copy
// unpacked from it. The package's binary - in dir itself here, as on a router whose bin directory is
// the package's - is never touched.
func TestRemoveStaleCompressed(t *testing.T) {
	cases := []struct {
		name string
		// arrange lays out dir and run; it returns the paths that must survive and those that must go.
		arrange func(t *testing.T, dir, run string) (keep, gone []string)
	}{
		{"compressed store beside the package's binary", func(t *testing.T, dir, run string) ([]string, []string) {
			store(t, dir, "bin", []byte("wayhop build"), "v3.1.20260828")
			if _, err := Unpack(dir, "bin", run); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(Stored(dir, "bin", false), []byte("package build"), 0o755); err != nil {
				t.Fatal(err)
			}
			return []string{Stored(dir, "bin", false)},
				[]string{Stored(dir, "bin", true), recordPath(dir, "bin"), filepath.Join(run, "bin"), filepath.Join(run, "bin.src")}
		}},
		{"a raw record the package wrote over", func(t *testing.T, dir, run string) ([]string, []string) {
			if err := os.WriteFile(Stored(dir, "bin", false), []byte("wayhop build"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := Write(dir, "bin", "v1", false); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(Stored(dir, "bin", false), []byte("the package's longer build"), 0o755); err != nil {
				t.Fatal(err)
			}
			return []string{Stored(dir, "bin", false)}, []string{recordPath(dir, "bin")}
		}},
		{"a raw record that still describes its binary", func(t *testing.T, dir, run string) ([]string, []string) {
			if err := os.WriteFile(Stored(dir, "bin", false), []byte("wayhop build"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := Write(dir, "bin", "v1", false); err != nil {
				t.Fatal(err)
			}
			return []string{Stored(dir, "bin", false), recordPath(dir, "bin")}, nil
		}},
		{"an unpacked copy Unpack did not make", func(t *testing.T, dir, run string) ([]string, []string) {
			if err := os.WriteFile(filepath.Join(run, "bin"), []byte("someone else's"), 0o755); err != nil {
				t.Fatal(err)
			}
			return []string{filepath.Join(run, "bin")}, nil
		}},
		{"a gzip path that is not a file", func(t *testing.T, dir, run string) ([]string, []string) {
			if err := os.Mkdir(Stored(dir, "bin", true), 0o755); err != nil {
				t.Fatal(err)
			}
			return []string{Stored(dir, "bin", true)}, nil
		}},
		{"nothing stored", func(t *testing.T, dir, run string) ([]string, []string) { return nil, nil }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, run := t.TempDir(), t.TempDir()
			keep, gone := c.arrange(t, dir, run)
			removed, err := RemoveStaleCompressed(dir, "bin", run)
			if err != nil {
				t.Fatalf("RemoveStaleCompressed: %v", err)
			}
			for _, p := range keep {
				if !exists(p) {
					t.Errorf("%s was removed", p)
				}
			}
			for _, p := range gone {
				if exists(p) {
					t.Errorf("%s survived", p)
				}
			}
			if len(removed) != len(gone) {
				t.Errorf("reported %q, want the %d paths removed", removed, len(gone))
			}
			// Twice is the same as once.
			if again, err := RemoveStaleCompressed(dir, "bin", run); err != nil || len(again) != 0 {
				t.Errorf("second run: %q, %v", again, err)
			}
		})
	}
}

// runDir and dir may be one directory on an odd install; the binary there is still never the copy's.
func TestRemoveStaleCompressed_RunDirIsDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(Stored(dir, "bin", false), []byte("package build"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin.src"), []byte("marker\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := RemoveStaleCompressed(dir, "bin", dir); err != nil {
		t.Fatal(err)
	}
	if !exists(Stored(dir, "bin", false)) {
		t.Error("the package's binary was removed")
	}
}
