package server

import (
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"wayhop/internal/platform"
	"wayhop/internal/updater"
)

// updaterstorage.go answers the question the components section has to answer BEFORE it offers to
// install anything: where does this land, and is there room.
//
// A router is not a laptop. On KeeneticOS the package tree lives under /opt, which is Entware — and
// Entware is usually on a USB stick, not on the router's own flash: measured on a live box,
// /opt is a 7.3 GB /dev/sda1 with 6.7 GB free while the internal storage is 98 MB. On OpenWrt the
// same packages land on the overlay, which IS the internal flash and is routinely under 10 MB free.
// The same "Install" button therefore means two completely different risks, and a section that shows
// neither the target nor the free space is asking the operator to gamble with their router's flash.
//
// There are TWO targets, not one, because the page offers two kinds of install. A package manager
// writes under its own root; a release downloaded from GitHub is written beside the configured
// sing-box binary (server.go builds the updater with filepath.Dir(cfg.SingBox.Bin)), which is a path
// the operator can change on the Settings page. Reporting only the package root would put a
// reassuring free-space figure next to a directory half the installs never touch.

// componentInstallFloor is the free space below which nothing this panel offers can be installed at
// all — sing-box alone needs ~75 MiB free by the install path's own reckoning. It lives here, in Go,
// because TWO surfaces judge one disk with it and they were drifting apart: the Components page had
// it as a literal 32 MiB, and the Diagnostics battery, which asks the smaller question "can WayHop
// replace itself", answered a bare "enough free space" for anything above ~15 MiB. On a disk holding
// 20 MiB free the operator therefore read "enough free space" on one page and "Little room on
// internal flash" on the other, about the same filesystem, in the same panel. Neither number was
// wrong; the unqualified sentence was. One constant, sent to the page, keeps them answering
// together.
const componentInstallFloor = 32 << 20

// storageTarget is one place something can be installed to.
type storageTarget struct {
	Path       string `json:"path"`                 // where the writes go
	Filesystem string `json:"filesystem,omitempty"` // device backing it, when it can be read
	FreeBytes  uint64 `json:"free_bytes"`           //
	FreeKnown  bool   `json:"free_known"`           // false ⇒ "not measured", never shown as 0
	External   bool   `json:"external"`             // an attached disk rather than the router's own flash
}

// updaterStorage is the install-target picture for this platform.
type updaterStorage struct {
	Packages storageTarget `json:"packages"` // opkg/apk root
	Engines  storageTarget `json:"engines"`  // downloaded release binaries (beside the sing-box binary)
	// SameDisk is true when both land on the same filesystem — the ordinary case, and the one where
	// the page should say it once instead of printing the same figure twice.
	SameDisk bool `json:"same_disk"`
	// Roomier is attached storage with more space than the engine target, so "attach a USB disk" can
	// name the disk that is already attached instead of telling an operator to do what they did.
	Roomier []storageTarget `json:"roomier,omitempty"`
	// InstallFloorBytes is componentInstallFloor, sent so the page warns on the same number the
	// battery scopes its verdict to instead of carrying its own copy.
	InstallFloorBytes uint64 `json:"install_floor_bytes"`
	// EngineSetting is the setting that moves the engine directory. The advice "point it somewhere
	// with room" is only actionable if the panel says which lever that is; it is the same one the
	// install refusal names.
	EngineSetting string `json:"engine_setting,omitempty"`
	// DownloadVia is the saved outbound a download leaves through ("" = the router's ordinary path),
	// and DownloadIface is what that resolves to right now. Both, because they can disagree: a saved
	// tunnel that was deleted or disabled resolves to nothing, and the page must be able to say the
	// download will take the ordinary path after all rather than showing a choice that is not in force.
	DownloadVia   string `json:"download_via,omitempty"`
	DownloadIface string `json:"download_iface,omitempty"`
	// DownloadPaths is every outbound this router could actually bind a download to, answered here
	// rather than assembled by the page.
	//
	// The page built the list itself from the profile it happened to have, and that was wrong twice.
	// Opened cold — which is what an operator does when they want to install something — Components
	// had no profile yet, so the control offered ONLY the ordinary path and every tunnel was missing.
	// And it offered proxy endpoints (VLESS and the like), which have no kernel link, so choosing one
	// silently did nothing. Both are the same mistake: only the daemon knows which outbound resolves
	// to a link, so only the daemon should say.
	DownloadPaths []downloadPath `json:"download_paths,omitempty"`
	Note          string         `json:"note,omitempty"`        //
	Manager       string         `json:"manager,omitempty"`     // opkg | apk | none
	ManagerBin    string         `json:"manager_bin,omitempty"` //
	Feeds         []string       `json:"feeds,omitempty"`       // configured package sources, so "no candidate" is explicable
}

// handleUpdaterStorage reports the install targets for THIS platform with their free space and the
// package feeds. Read-only.
func (s *Server) handleUpdaterStorage(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.updaterStorageFacts())
}

func (s *Server) updaterStorageFacts() updaterStorage {
	st := updaterStorage{
		Packages: measureTarget(updaterInstallRoot(s.detectedPlatform())),
		Engines:  measureTarget(s.updater.BinDir),
	}
	// Compared by DEVICE, not by path: /opt and /opt/sbin are different directories on one disk, and
	// saying "two targets" about one filesystem is noise the operator has to resolve themselves.
	st.SameDisk = st.Packages.Filesystem != "" && st.Packages.Filesystem == st.Engines.Filesystem
	// Offered against the ENGINE target: that is the one a setting can move. The package root is
	// where opkg writes and no panel field relocates it.
	if b, err := os.ReadFile("/proc/self/mounts"); err == nil {
		st.Roomier = roomElsewhere(parseMounts(string(b)), st.Engines, updater.AvailBytes)
	}
	st.InstallFloorBytes = componentInstallFloor
	st.EngineSetting = "sing-box binary"
	switch s.detectedPlatform() {
	case platform.Keenetic:
		st.Note = "KeeneticOS installs add-ons into Entware under /opt, which normally lives on an " +
			"attached USB disk rather than the router's own flash."
	case platform.OpenWrt:
		st.Note = "OpenWrt installs packages onto the overlay — the router's INTERNAL flash. It is " +
			"small on most devices, and filling it can leave the router unbootable."
	}
	// The manager is whatever the REST of this section already decided it is. This card used to run
	// its own exec.LookPath, preferring opkg — while pm.Detect (which the engine rows, the install
	// buttons and every ownership check go through) prefers apk. On a box carrying both, one page
	// named two different package managers for one router. The lookup that remains is only for the
	// PATH to display; it can no longer choose.
	st.Manager = string(s.updater.PMKind())
	if st.Manager == "" {
		st.Manager = "none"
	} else if bin, err := exec.LookPath(st.Manager); err == nil {
		st.ManagerBin = bin
	}
	st.Feeds = packageFeeds()
	st.DownloadVia = s.config().Updater.DownloadVia
	// What the NEXT download would bind to, asked of the updater rather than recomputed here: the page
	// must state the path that is in force, and the updater is what holds it.
	st.DownloadIface = s.updater.BoundInterface()
	st.DownloadPaths = s.downloadPathChoices()
	return st
}

// downloadPath is one selectable outbound for a component download.
type downloadPath struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Group bool   `json:"group,omitempty"`
	// Iface is the link a download would bind to right now. Empty for a group whose members are all
	// down — it stays selectable, because a group is a standing choice and health changes, and the
	// page says whether the choice is in force.
	Iface string `json:"iface,omitempty"`
}

// downloadPathChoices lists the outbounds a download can leave through: every endpoint with a kernel
// link, and every group, since a group resolves to whichever member is healthy at the time.
//
// An endpoint an engine carries (VLESS, Hysteria2 …) is deliberately absent. Binding is a socket
// option and there is nothing to point it at, so offering one is offering a choice that cannot take
// effect — measured on the AX3000T, whose list included a VLESS exit beside the native tunnels.
func (s *Server) downloadPathChoices() []downloadPath {
	if s == nil || s.store == nil {
		return nil
	}
	profile := s.store.Profile()
	ifaceOf := kernelIfaceByEndpoint(&profile)
	out := make([]downloadPath, 0, len(ifaceOf)+len(profile.Groups))
	for i := range profile.Endpoints {
		e := &profile.Endpoints[i]
		if !e.Enabled {
			continue
		}
		if iface := ifaceOf[e.ID]; iface != "" {
			out = append(out, downloadPath{ID: e.ID, Name: nameOrID(e.Name, e.ID), Iface: iface})
		}
	}
	for i := range profile.Groups {
		g := &profile.Groups[i]
		// A group is offered when some member COULD be bound to, not when one happens to be healthy
		// right now: health changes under a standing choice, engine kind does not. A group whose
		// members are all carried by an engine can never resolve to a link, so offering it would be
		// the same empty choice as offering one of those members directly.
		bindable := false
		for _, id := range g.Members {
			if ifaceOf[id] != "" {
				bindable = true
				break
			}
		}
		if !bindable {
			continue
		}
		iface, _ := s.electHealthyMember(*g, ifaceOf)
		out = append(out, downloadPath{ID: g.ID, Name: nameOrID(g.Name, g.ID), Group: true, Iface: iface})
	}
	return out
}

func nameOrID(name, id string) string {
	if name != "" {
		return name
	}
	return id
}

func measureTarget(path string) storageTarget {
	t := storageTarget{Path: path}
	t.FreeBytes, t.FreeKnown = updater.AvailBytes(path)
	t.Filesystem, t.External = mountBacking(path)
	return t
}

// updaterInstallRoot is where this platform's package manager writes. Entware is /opt by definition;
// OpenWrt's opkg writes into the root overlay.
func updaterInstallRoot(p platform.Platform) string {
	if p == platform.Keenetic {
		return "/opt"
	}
	if _, err := os.Stat("/opt/bin/opkg"); err == nil {
		return "/opt"
	}
	return "/"
}

// mountEntry is one line of /proc/self/mounts, reduced to what an install decision needs.
type mountEntry struct {
	Device string
	Point  string
	FS     string
	RW     bool
}

// parseMounts reads the kernel's mount table. Split out from mountBacking so the selection rules
// below can be tested without a Linux host and without root — the router shapes that matter
// (Entware on a USB stick, an overlay on internal flash, a tmpfs that would lose the binary at the
// next reboot) are three lines of text, and asserting on them is the only way to be sure the page
// never points an operator at storage that cannot keep what it is told to hold.
func parseMounts(data string) []mountEntry {
	var out []mountEntry
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		// The kernel escapes spaces and tabs in device/mount paths as octal; a mount point with a
		// space in it is unusual on a router and unremarkable on a USB stick formatted elsewhere.
		e := mountEntry{Device: unescapeMount(f[0]), Point: unescapeMount(f[1]), FS: f[2]}
		for _, opt := range strings.Split(f[3], ",") {
			if opt == "rw" {
				e.RW = true
			}
		}
		out = append(out, e)
	}
	return out
}

func unescapeMount(s string) string {
	r := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return r.Replace(s)
}

// attachedDevice reports whether a device node looks like attached storage rather than the router's
// own flash. sd*/mmcblk*/usb* are disks somebody plugged in; ubi/mtd/overlay/root are the flash the
// router boots from, and tmpfs/ramfs are not storage at all.
func attachedDevice(dev string) bool {
	base := filepath.Base(dev)
	return strings.HasPrefix(base, "sd") || strings.HasPrefix(base, "mmcblk") || strings.HasPrefix(base, "usb")
}

// mountBacking reports the device behind a path and whether that device looks like attached storage
// rather than the router's own flash. Read from /proc/self/mounts, so it is the kernel's answer.
func mountBacking(path string) (device string, external bool) {
	b, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return "", false
	}
	best := ""
	for _, m := range parseMounts(string(b)) {
		if m.Point != "/" && !strings.HasPrefix(path+"/", m.Point+"/") && path != m.Point {
			continue
		}
		// The longest matching mount point is the one actually carrying the path.
		if len(m.Point) >= len(best) {
			best, device = m.Point, m.Device
		}
	}
	return device, attachedDevice(device)
}

// roomElsewhere lists attached storage with more room than the current install target.
//
// "Attach a USB disk" was the advice the install refusal already gave, and on a router that HAS one
// mounted it is worse than useless: the operator is told to solve a problem they solved, while the
// panel knows the mount point, the device and how much is free on it. This names them.
//
// Three exclusions, each because including it would point somewhere an install must not go:
// read-only mounts (nothing can be written), non-attached devices (the router's own flash is what we
// are moving away from), and anything that is not a real disk — a tmpfs has plenty of "free space"
// and loses the binary at the next reboot, which is the most expensive way to appear helpful.
func roomElsewhere(mounts []mountEntry, cur storageTarget, free func(string) (uint64, bool)) []storageTarget {
	var out []storageTarget
	seen := map[string]bool{}
	for _, m := range mounts {
		if !m.RW || !attachedDevice(m.Device) || m.Device == cur.Filesystem || seen[m.Device] {
			continue
		}
		avail, known := free(m.Point)
		// Unmeasurable, or no better than where we already are: not an option worth naming.
		if !known || (cur.FreeKnown && avail <= cur.FreeBytes) {
			continue
		}
		seen[m.Device] = true
		out = append(out, storageTarget{Path: m.Point, Filesystem: m.Device, FreeBytes: avail, FreeKnown: true, External: true})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FreeBytes > out[j].FreeBytes })
	return out
}

// packageFeeds lists the configured package sources. A component with "no candidate" is almost always
// a feed problem, and the section can only say so if it knows what the feeds are.
//
// TWO formats, because the platforms this runs on do not agree. Entware and older OpenWrt use opkg,
// whose config lines are `src/gz <name> <url>`. OpenWrt 24.10 and later use apk, whose repository
// files are a plain list of URLs — no `src` keyword at all. Reading only the opkg shape meant an apk
// router reported "no feeds configured" beside a working package manager, which turns the one hint
// this card gives about "no candidate" into a false one.
func packageFeeds() []string { return packageFeedsIn("") }

// packageFeedsIn is the same read rooted at a prefix, so the discovery — not just the parsing — is
// testable without the router's own /etc.
func packageFeedsIn(root string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(url string) {
		if url == "" || seen[url] {
			return
		}
		seen[url] = true
		out = append(out, url)
	}
	// opkg: /opt/etc is Entware's (Keenetic), /etc is OpenWrt's.
	for _, p := range []string{"/opt/etc/opkg.conf", "/etc/opkg.conf", "/etc/opkg/distfeeds.conf", "/etc/opkg/customfeeds.conf"} {
		for _, url := range parseOpkgFeeds(readTextFile(filepath.Join(root, p))) {
			add(url)
		}
	}
	// apk: a single Alpine-style file plus OpenWrt's split directory (distfeeds.list, customfeeds.list).
	apkFiles := []string{filepath.Join(root, "/etc/apk/repositories")}
	if entries, err := os.ReadDir(filepath.Join(root, "/etc/apk/repositories.d")); err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".list") {
				continue
			}
			apkFiles = append(apkFiles, filepath.Join(root, "/etc/apk/repositories.d", entry.Name()))
		}
	}
	sort.Strings(apkFiles)
	for _, p := range apkFiles {
		for _, url := range parseApkFeeds(readTextFile(p)) {
			add(url)
		}
	}
	return out
}

func readTextFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// parseOpkgFeeds reads `src[/gz] <name> <url>`. The URL is the LAST field: a feed name may contain
// no spaces, but the keyword varies (src, src/gz) and counting from the left would depend on it.
func parseOpkgFeeds(data string) []string {
	var out []string
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.HasPrefix(line, "src") {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 3 {
			out = append(out, f[len(f)-1])
		}
	}
	return out
}

// parseApkFeeds reads one repository URL per line. Comments and blanks are skipped, and so is
// anything that is not a URL — an apk file may carry an `@tag` prefix, and a bare word is not a feed.
func parseApkFeeds(data string) []string {
	var out []string
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "@") {
			// "@tag url" — the tag names a pinned repository; the URL is what this card reports.
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			line = f[1]
		}
		if !strings.Contains(line, "://") {
			continue
		}
		out = append(out, strings.Fields(line)[0])
	}
	return out
}
