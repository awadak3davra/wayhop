package server

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"wayhop/internal/config"
	"wayhop/internal/updater"
)

// The mount table is the only evidence the page has about where an install may go. These assert the
// shapes that actually occur on the routers this runs on, because every wrong answer here sends an
// operator to storage that cannot keep what it is told to hold.

func TestParseMountsReadsTheKernelTable(t *testing.T) {
	// Measured shape: an Entware USB stick, the router's own overlay, a read-only squashfs and a
	// tmpfs. The last field pair (dump/pass) is present on real lines and ignored here.
	const table = "/dev/sda1 /opt ext4 rw,relatime 0 0\n" +
		"overlayfs:/overlay / overlay rw,noatime 0 0\n" +
		"/dev/mtdblock5 /rom squashfs ro,relatime 0 0\n" +
		"tmpfs /tmp tmpfs rw,nosuid 0 0\n" +
		"/dev/sdb1 /tmp/mnt/My\\040Disk vfat rw,relatime 0 0\n"
	got := parseMounts(table)
	if len(got) != 5 {
		t.Fatalf("parsed %d mounts, want 5: %+v", len(got), got)
	}
	if got[0].Device != "/dev/sda1" || got[0].Point != "/opt" || !got[0].RW {
		t.Fatalf("first mount = %+v", got[0])
	}
	if got[2].RW {
		t.Fatalf("a squashfs mounted ro must not read as writable: %+v", got[2])
	}
	// A stick formatted on a desktop routinely has a space in its label.
	if got[4].Point != "/tmp/mnt/My Disk" {
		t.Fatalf("escaped mount point = %q, want %q", got[4].Point, "/tmp/mnt/My Disk")
	}
}

func TestAttachedDevice(t *testing.T) {
	for dev, want := range map[string]bool{
		"/dev/sda1":          true,
		"/dev/sdb":           true,
		"/dev/mmcblk0p1":     true,
		"/dev/usbdisk1":      true,
		"/dev/mtdblock5":     false, // the router's own flash
		"overlayfs:/overlay": false,
		"tmpfs":              false, // RAM: free space that loses the binary at reboot
		"ubi0:rootfs":        false,
		"/dev/root":          false,
	} {
		if got := attachedDevice(dev); got != want {
			t.Fatalf("attachedDevice(%q) = %v, want %v", dev, got, want)
		}
	}
}

// The offer exists for one situation: the engine directory is on the router's small internal flash
// while a roomier disk is already mounted. It must name that disk — and must not name anything an
// install would be lost on or refused by.
func TestRoomElsewhere(t *testing.T) {
	const table = "overlayfs:/overlay / overlay rw,noatime 0 0\n" +
		"/dev/sda1 /opt ext4 rw,relatime 0 0\n" +
		"/dev/sda1 /opt/sbin ext4 rw,relatime 0 0\n" + // same device, bind-style second line
		"tmpfs /tmp tmpfs rw,nosuid 0 0\n" +
		"/dev/sdb1 /mnt/backup vfat ro,relatime 0 0\n" +
		"/dev/sdc1 /mnt/big ext4 rw,relatime 0 0\n"
	free := map[string]uint64{"/": 20 << 20, "/opt": 6 << 30, "/tmp": 200 << 20, "/mnt/backup": 8 << 30, "/mnt/big": 900 << 20}
	lookup := func(p string) (uint64, bool) { v, ok := free[p]; return v, ok }

	cur := storageTarget{Path: "/usr/sbin", Filesystem: "overlayfs:/overlay", FreeBytes: 20 << 20, FreeKnown: true}
	got := roomElsewhere(parseMounts(table), cur, lookup)

	var paths []string
	for _, g := range got {
		paths = append(paths, g.Path)
	}
	// /opt (6 GB) then /mnt/big (900 MB) — biggest first, so the first suggestion is the best one.
	if len(got) != 2 || got[0].Path != "/opt" || got[1].Path != "/mnt/big" {
		t.Fatalf("roomElsewhere = %v, want [/opt /mnt/big] biggest-first", paths)
	}
	if got[0].Filesystem != "/dev/sda1" || !got[0].External || !got[0].FreeKnown {
		t.Fatalf("first suggestion = %+v", got[0])
	}
	// One entry per DEVICE: /opt and /opt/sbin are the same stick, and offering it twice is noise.
	if len(got) > 1 && got[0].Filesystem == got[1].Filesystem {
		t.Fatalf("the same device was offered twice: %+v", got)
	}
}

func TestRoomElsewhereRefusesUnusableStorage(t *testing.T) {
	free := func(string) (uint64, bool) { return 8 << 30, true }
	cur := storageTarget{Path: "/usr/sbin", Filesystem: "overlayfs:/overlay", FreeBytes: 20 << 20, FreeKnown: true}

	for _, tc := range []struct{ name, line string }{
		// 8 GB of "free space" that is gone at the next reboot.
		{"tmpfs", "tmpfs /tmp tmpfs rw,nosuid 0 0"},
		// Nothing can be written there at all.
		{"read-only disk", "/dev/sdb1 /mnt/ro vfat ro,relatime 0 0"},
		// The router's own flash is what the offer exists to move away from.
		{"internal flash", "/dev/mtdblock5 /overlay jffs2 rw,relatime 0 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := roomElsewhere(parseMounts(tc.line+"\n"), cur, free); len(got) != 0 {
				t.Fatalf("roomElsewhere offered %+v", got)
			}
		})
	}

	// Storage no roomier than the current target is not an improvement worth naming.
	t.Run("no roomier than now", func(t *testing.T) {
		small := func(string) (uint64, bool) { return 10 << 20, true }
		if got := roomElsewhere(parseMounts("/dev/sda1 /opt ext4 rw,relatime 0 0\n"), cur, small); len(got) != 0 {
			t.Fatalf("roomElsewhere offered a smaller disk: %+v", got)
		}
	})

	// Space that could not be measured must not be presented as space.
	t.Run("unmeasurable", func(t *testing.T) {
		unknown := func(string) (uint64, bool) { return 0, false }
		if got := roomElsewhere(parseMounts("/dev/sda1 /opt ext4 rw,relatime 0 0\n"), cur, unknown); len(got) != 0 {
			t.Fatalf("roomElsewhere offered an unmeasured mount: %+v", got)
		}
	})

	// The disk the engine directory is ALREADY on is not somewhere else.
	t.Run("current device", func(t *testing.T) {
		on := storageTarget{Path: "/opt/sbin", Filesystem: "/dev/sda1", FreeBytes: 1 << 30, FreeKnown: true}
		if got := roomElsewhere(parseMounts("/dev/sda1 /opt ext4 rw,relatime 0 0\n"), on, free); len(got) != 0 {
			t.Fatalf("roomElsewhere offered the disk it is already on: %+v", got)
		}
	})
}

// The two platforms do not agree on what a package feed even looks like, and the card's "no
// candidate is usually a feed problem" hint is only useful if it can see both.
func TestPackageFeedsReadsBothFormats(t *testing.T) {
	t.Run("opkg lines", func(t *testing.T) {
		// Entware's own shape, plus a commented-out feed and the `dest`/`option` lines that share the file.
		const conf = "dest root /\n" +
			"src/gz entware http://bin.entware.net/aarch64-k3.10\n" +
			"src/gz keenetic http://bin.entware.net/aarch64-k3.10/keenetic\n" +
			"# src/gz disabled http://example.invalid/off\n" +
			"option check_signature\n"
		got := parseOpkgFeeds(conf)
		want := []string{"http://bin.entware.net/aarch64-k3.10", "http://bin.entware.net/aarch64-k3.10/keenetic"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("parseOpkgFeeds = %v, want %v", got, want)
		}
	})

	t.Run("apk lines", func(t *testing.T) {
		// OpenWrt 24.10's apk files are a plain URL list — no `src` keyword, which is why the
		// opkg-only reader reported "no feeds configured" beside a working apk.
		const list = "https://downloads.openwrt.org/releases/24.10.0/packages/aarch64_cortex-a53/base\n" +
			"# https://downloads.openwrt.org/releases/24.10.0/packages/aarch64_cortex-a53/luci\n" +
			"\n" +
			"@testing https://downloads.openwrt.org/snapshots/packages/aarch64_cortex-a53/base\n" +
			"not-a-url\n"
		got := parseApkFeeds(list)
		want := []string{
			"https://downloads.openwrt.org/releases/24.10.0/packages/aarch64_cortex-a53/base",
			"https://downloads.openwrt.org/snapshots/packages/aarch64_cortex-a53/base",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("parseApkFeeds = %v, want %v", got, want)
		}
	})

	// Discovery, not just parsing: an apk router keeps its feeds in a directory of .list files, and a
	// reader that only knew the opkg paths would find none of them.
	t.Run("discovery across both layouts", func(t *testing.T) {
		root := t.TempDir()
		write := func(rel, body string) {
			t.Helper()
			full := filepath.Join(root, rel)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		write("etc/opkg/distfeeds.conf", "src/gz base http://feeds.invalid/base\n")
		write("etc/apk/repositories.d/distfeeds.list", "https://feeds.invalid/apk-base\n")
		write("etc/apk/repositories.d/customfeeds.list", "https://feeds.invalid/apk-custom\nhttps://feeds.invalid/apk-base\n")
		write("etc/apk/repositories.d/README", "https://feeds.invalid/not-a-list\n")

		got := packageFeedsIn(root)
		want := []string{
			"http://feeds.invalid/base",
			"https://feeds.invalid/apk-custom", // customfeeds.list sorts before distfeeds.list
			"https://feeds.invalid/apk-base",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("packageFeedsIn = %v, want %v", got, want)
		}
		// The same URL listed twice is one feed: the card prints a COUNT, and counting it twice
		// misreports how many sources a missing package was actually looked for in.
		for i := range got {
			for j := range got {
				if i != j && got[i] == got[j] {
					t.Fatalf("duplicate feed reported: %v", got)
				}
			}
		}
	})

	// A router with neither layout reports nothing rather than failing.
	t.Run("nothing configured", func(t *testing.T) {
		if got := packageFeedsIn(t.TempDir()); len(got) != 0 {
			t.Fatalf("packageFeedsIn = %v, want none", got)
		}
	})
}

// One router, one package manager. The install-target card used to run its own exec.LookPath with
// opkg preferred, while pm.Detect — which the engine rows, the install buttons and every ownership
// check use — prefers apk. A box carrying both would be described two different ways on one page,
// and the card is the half that says where things land.
func TestStorageManagerMatchesTheRestOfTheSection(t *testing.T) {
	// The card also reports which connection downloads leave through, which it reads from the config —
	// so the fixture carries one rather than a bare struct that no running daemon ever has.
	s := &Server{updater: updater.New(t.TempDir(), "arm64", nil), cfg: config.Default()}
	facts := s.updaterStorageFacts()
	want := string(s.updater.PMKind())
	if want == "" {
		want = "none"
	}
	if facts.Manager != want {
		t.Fatalf("storage card reports %q while the section uses %q", facts.Manager, want)
	}
	// A named manager must carry the path it was found at; "none" must not invent one.
	if facts.Manager == "none" && facts.ManagerBin != "" {
		t.Fatalf("no package manager, but a binary path was reported: %q", facts.ManagerBin)
	}
}

// TestInstallFloorReachesThePage pins the one thing page-updater.js now depends on and cannot check
// for itself: it dropped its private 32 MB literal in favour of this field, and reads it with no
// fallback, so a zero here would silently stop the "Little room on internal flash" warning from ever
// being drawn on the routers that need it most. It must also be the same constant the Diagnostics
// battery scopes its verdict to — that agreement is the whole point of moving the number.
func TestInstallFloorReachesThePage(t *testing.T) {
	s, _ := sharehandlers_server(t)
	s.updater = updater.New(t.TempDir(), "aarch64", nil)
	facts := s.updaterStorageFacts()
	if facts.InstallFloorBytes == 0 {
		t.Fatal("install_floor_bytes is 0, so the Components page would never warn about a full flash")
	}
	if facts.InstallFloorBytes != componentInstallFloor {
		t.Fatalf("page gets %d but the battery scopes to %d — one disk, two answers again",
			facts.InstallFloorBytes, componentInstallFloor)
	}
	// And the battery must actually use it: at one byte under the floor the verdict may pass, but not
	// with the unqualified sentence.
	if _, summary, _ := diskVerdict(componentInstallFloor-1, true, 1<<20, componentInstallFloor); summary == "enough free space" {
		t.Errorf("battery still says %q just under the floor the page warns at", summary)
	}
}
