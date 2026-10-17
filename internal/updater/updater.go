// Package updater manages the engine binaries wayhop orchestrates (sing-box, xray,
// mihomo, hysteria, dnscrypt-proxy, ...). It reports the installed version,
// queries upstream GitHub releases *through configurable mirrors* (GitHub is
// frequently blocked/throttled in censored regions), and installs a chosen
// version only after MANDATORY SHA-256 verification against a digest fetched
// over the direct GitHub API (a mirror carries the bytes but never the digest).
package updater

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"wayhop/internal/binstore"
	"wayhop/internal/netdiag"
	"wayhop/internal/pm"
)

// Engine describes a managed core binary and where to get it. Role tells the UI how
// the binary is actually used on THIS router so the Updater can foreground the ones
// the router runs and tuck the rest away:
//
//	core         — the sing-box proxy core
//	kernel-plugin— an engine driving a kernel iface (AmneziaWG)
//	socks-plugin — a long-running chained-SOCKS engine (olcRTC)
//	standalone   — a separate core wayhop does NOT run here; sing-box covers the
//	               protocol natively, so it's catalog-only (install only for a manual
//	               setup). The UI files these under "Advanced".
type Engine struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Repo        string   `json:"repo"`     // GitHub "owner/name"
	BinName     string   `json:"bin_name"` // installed filename
	Role        string   `json:"role"`     // core | kernel-plugin | socks-plugin | standalone
	VersionArgs []string `json:"-"`        // args that print the version
	SourceOnly  bool     `json:"source_only"`
	// Nightly marks an engine whose GitHub releases are all prerelease nightlies (no stable tag).
	// For update-detection the "latest version" is the DATE parsed from the newest release's NAME
	// (e.g. olcRTC's "olcRTC nightly 2026.07.23 (…)"), compared against the binary's stamped date —
	// LatestStable would otherwise only yield the opaque nightly-<sha> tag, uncomparable to the date.
	Nightly bool   `json:"nightly,omitempty"`
	Note    string `json:"note,omitempty"`
	// Provides is the protocol this engine exists to carry, named as the platform capability matrix
	// names it. It is set only where a KERNEL path for the same protocol can exist, because that is
	// the only case where it changes what the operator should do.
	//
	// The case that prompted it: a live AX3000T carries AmneziaWG in the kernel
	// (kmod-amneziawg + amneziawg-tools + luci-proto-amneziawg, module loaded), which is what actually
	// carries their tunnel. The Updater page nonetheless listed "AmneziaWG (userspace) — not
	// installed" and offered fifteen GitHub versions it would then refuse to install. Every word true,
	// and it reads as a missing component when nothing is missing.
	Provides string `json:"provides,omitempty"`
	// Companion is the asset-name prefix of a binary WayHop builds and attaches to its own releases
	// because its upstream publishes none (see companion.go). Repo is then WayHop's, and the versions
	// are the upstream ones written into the asset names.
	Companion string `json:"companion,omitempty"`
}

// RouterUsed reports whether the router actually runs this engine (vs catalog-only).
func (e Engine) RouterUsed() bool { return e.Role != "" && e.Role != "standalone" }

// Engines is the registry of cores wayhop can manage.
var Engines = []Engine{
	{ID: "sing-box", Name: "sing-box", Repo: "SagerNet/sing-box", BinName: "sing-box", Role: "core", VersionArgs: []string{"version"}},
	{ID: "mihomo", Name: "Mihomo (Clash.Meta)", Repo: "MetaCubeX/mihomo", BinName: "mihomo", Role: "standalone", VersionArgs: []string{"-v"}},
	{ID: "xray", Name: "Xray-core", Repo: "XTLS/Xray-core", BinName: "xray", Role: "standalone", VersionArgs: []string{"version"}},
	{ID: "hysteria", Name: "Hysteria 2", Repo: "apernet/hysteria", BinName: "hysteria", Role: "standalone", VersionArgs: []string{"version"}},
	{ID: "dnscrypt-proxy", Name: "dnscrypt-proxy", Repo: "DNSCrypt/dnscrypt-proxy", BinName: "dnscrypt-proxy", Role: "standalone", VersionArgs: []string{"-version"}},
	// Upstream publishes source tags only, so WayHop builds it at a pinned commit and attaches it to its
	// own releases (scripts/build-amneziawg-go.sh, companion.go). --version proves the downloaded binary
	// executes here before it replaces anything; the version it prints is upstream's stale constant,
	// which is why the installed version comes from the record Install writes instead.
	{ID: "amneziawg-go", Name: "AmneziaWG (userspace)", Repo: DefaultSelfRepo, BinName: "amneziawg-go", Role: "kernel-plugin",
		VersionArgs: []string{"--version"}, Provides: "amneziawg", Companion: "amneziawg-go-",
		Note: "AmneziaWG 3 in userspace, for routers whose kernel module is older than the config or absent. Built by WayHop from upstream amneziawg-go, which publishes no binaries, and attached to every WayHop release."},
	{ID: "olcrtc", Name: "olcRTC (WebRTC tunnel)", Repo: "awadak3davra/olcrtc", BinName: "olcrtc", Role: "socks-plugin", VersionArgs: []string{"version"}, Nightly: true,
		Note: "Anti-whitelist WebRTC-over-meet tunnel (Jitsi/Telemost/WbStream). Pulled from the awadak3davra/olcrtc fork, which daily auto-syncs upstream openlibrecommunity/olcrtc and publishes prebuilt `olcrtc-linux-<arch>` binaries (upstream ships none; the WebRTC stack is too heavy to build on the router)."},
}

// EngineByID returns the engine with the given id, or nil.
func EngineByID(id string) *Engine {
	for i := range Engines {
		if Engines[i].ID == id {
			return &Engines[i]
		}
	}
	return nil
}

// ghCacheEntry is one GitHub API body and when it was read.
type ghCacheEntry struct {
	at   time.Time
	body []byte
}

// Updater performs installed/latest/install operations.
type Updater struct {
	BinDir  string   // where binaries live, e.g. /opt/sbin
	RunDir  string   // tmpfs where a companion kept compressed is unpacked (binstore.DefaultRunDir)
	Arch    string   // wayhop arch token: amd64|arm64|arm|mipsle|mips
	Mirrors []string // URL prefixes tried in order; "" = direct
	// Offline answers release metadata from the built-in catalogue in offline.go instead of the
	// network. Set for the demo daemon so clicking through the panel — and the verification suite
	// that drives it — never depends on GitHub being reachable. See offline.go for why the seam is
	// here rather than in the handlers.
	Offline   bool
	hc        *http.Client
	bindIface func() string // names the interface downloads leave through; "" = the ordinary path
	pm        pm.Manager    // native package manager (opkg/apk); zero value None = no recognition
	// mu serializes Install + SelfUpdate. Both stage to FIXED paths (dst+".new" / ".wayhop.new")
	// opened O_TRUNC, so two concurrent updates — e.g. the auto-update loop racing a user-triggered
	// install, a single-user race — would interleave into one file and rename a corrupt binary into
	// place. The SHA-256 is computed over the download stream, not the file, so it can't catch that.
	// One shared *Updater per daemon ⇒ this in-process lock covers every call site.
	mu sync.Mutex
	// GitHub release metadata, kept briefly so one page render does not spend the router's whole
	// hourly allowance. See ghCacheTTL.
	ghMu    sync.Mutex
	ghCache map[string]ghCacheEntry
	// availBytes reads free space, as a seam. Production leaves it nil and the package function does
	// the statfs; a test sets it, because "this router has 20 MiB free" is the entire subject of the
	// low-space upgrade path and a test that has to fill the dev host's disk to reach it would never
	// be written. The alternative the gates forbid is a t.Skip on a host-dependent condition.
	availBytes func(dir string) (uint64, bool)
	// pmStatusMu serializes package-ownership/catalog reads. The Updater page loads the WayHop row
	// and engine rows concurrently; Entware opkg can reject even read-only commands while another
	// opkg process is inspecting its database. A single failed Owner call made a packaged sing-box
	// look unowned and removed every usable package-manager action from the page.
	pmStatusMu sync.Mutex
	// awgRun runs WayHop's AmneziaWG installer (awginstall.go), as a seam: nil runs it for real.
	awgRun AWGRunFunc
}

// New builds an Updater. An empty arch autodetects from the running binary
// (wayhop is built for the router's arch, so runtime.GOARCH is correct on-device).
func New(binDir, arch string, mirrors []string) *Updater {
	if arch == "" {
		arch = runtime.GOARCH // mipsle/mips/arm/arm64/amd64 line up with our tokens
	}
	mirrors = sanitizeMirrors(mirrors)
	if len(mirrors) == 0 {
		mirrors = []string{""}
	}
	// Per-phase timeouts, NOT a total Timeout: a total 30s deadline killed every asset download that
	// took longer (a multi-MB router binary over a slow link), even though the caller's ctx allowed
	// it. Bound connect/TLS/first-byte instead (catching a dead or wedged mirror) and let the body
	// read run as long as the request ctx permits; the size LimitReader still caps total bytes.
	return &Updater{BinDir: binDir, RunDir: binstore.DefaultRunDir, Arch: arch, Mirrors: mirrors, pm: pm.Detect(), hc: &http.Client{
		Transport: &http.Transport{
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}}
}

// BindVia makes every HTTP request this updater performs leave through the interface resolve names.
//
// The reason is the one that makes the whole components section work or not: the router's ordinary
// path to GitHub can be blocked, and then nothing can be installed — including the engine that would
// have carried the traffic around the block. Binding the socket (SO_BINDTODEVICE, root-only, which
// the daemon is) sends the release metadata AND the asset bytes through a tunnel that still works,
// while leaving the routing plane untouched: no marks, no tables, nothing to undo afterwards.
//
// resolve is consulted at DIAL time, not here, for two reasons. A group's healthy member changes
// while the daemon runs, and a path resolved once at startup would keep binding to a tunnel that has
// since died — the failure this setting exists to avoid. And the transport is then built once and
// never replaced, so a config write during a download cannot race the client out from under it.
//
// resolve returning "" means the ordinary path. A dialer that cannot bind fails the request rather
// than falling back silently: a download that quietly took the blocked path would look like a network
// fault and be retried forever.
func (u *Updater) BindVia(resolve func() string) *Updater {
	if u == nil {
		return u
	}
	if resolve == nil {
		resolve = func() string { return "" }
	}
	u.bindIface = resolve
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: func(network, address string, c syscall.RawConn) error {
		iface := resolve()
		if iface == "" {
			return nil
		}
		return netdiag.BindToDevice(iface)(network, address, c)
	}}
	u.hc = &http.Client{Transport: &http.Transport{
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		DialContext:           dialer.DialContext,
	}}
	return u
}

// BoundInterface reports what the next download would bind to ("" = the ordinary path), so the panel
// can state where the bytes will come from before anything is fetched.
func (u *Updater) BoundInterface() string {
	if u == nil || u.bindIface == nil {
		return ""
	}
	return u.bindIface()
}

// WithPM overrides the detected package manager (tests inject a mock; production uses Detect()).
func (u *Updater) WithPM(m pm.Manager) *Updater { u.pm = m; return u }

// WithAvail overrides the free-space reader (tests inject a nearly-full router; production leaves
// it alone and the statfs answers). The sibling of WithPM, and there for the same reason: the states
// this code exists to handle cannot be arranged on the machine running the test.
func (u *Updater) WithAvail(f func(dir string) (uint64, bool)) *Updater { u.availBytes = f; return u }

// PMKind is the detected package manager ("opkg"|"apk"|"") for UI display.
func (u *Updater) PMKind() pm.Kind { return u.pm.Kind }

// NativeManagedError is the typed refusal for a mutating operation on a PM-owned binary (or when
// ownership could not be verified). Handlers match it with errors.As to return 409 (a policy
// conflict, not a server failure) and to keep it OUT of the persisted last_error — the refusal is
// permanent state, not an install failure.
type NativeManagedError struct{ Msg string }

func (e *NativeManagedError) Error() string { return e.Msg }

// nativeManaged reports whether e's binary is a file OWNED by the native package manager. When
// true, wayhop must NOT direct-download over it (that clobbers the packaged binary — the
// /opt/bin/sing-box hazard) nor os.Remove it (that orphans the package DB); it defers to opkg/apk.
// The probe follows the SAME resolution the UI's Installed() uses: BinDir/BinName first, then a
// PATH lookup — so recognition can never disagree with the binary the panel is displaying. A
// non-nil err means the PM couldn't answer (db locked by a concurrent opkg/apk run, timeout):
// mutating callers fail CLOSED on it. No-op wherever no PM is present (dev/CI).
func (u *Updater) nativeManaged(e Engine) (owner string, yes bool, err error) {
	if !u.pm.Available() {
		return "", false, nil
	}
	path, exists := u.enginePath(e)
	if !exists {
		return "", false, nil // nothing here and nothing on PATH -> nothing to clobber/orphan
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return u.pm.Owner(ctx, path)
}

// NativeManaged is the exported form for the server/UI ("is this engine opkg/apk-owned here").
// A PM query failure reads as false here — the UI badge is advisory; the mutating paths do their
// own fail-closed check.
func (u *Updater) NativeManaged(e Engine) bool { _, yes, _ := u.nativeManaged(e); return yes }

// NativeManagedInfo is NativeManaged plus the owning package name, so the UI can say
// "managed by apk (package sing-box) — update it there" up front instead of after a failed click.
// The third return says whether the probe could answer AT ALL. Dropping it (this used to be
// `owner, yes, _ = u.nativeManaged(e)`) made an unanswerable probe indistinguishable from a
// confirmed "not owned by the package manager", and left the read path disagreeing with the write
// path: engineManagedErr below is deliberately fail-closed and refuses when it cannot verify
// ownership, while this one reported false and the UI happily drew Remove and Check buttons the
// panel would then refuse. Observed on the Keenetic, where opkg answers intermittently and the
// Updater page grew and lost those two buttons between identical page loads.
func (u *Updater) NativeManagedInfo(e Engine) (owner string, yes, known bool) {
	owner, yes, err := u.nativeManaged(e)
	return owner, yes, err == nil
}

// engineManagedErr converts a nativeManaged probe into the refusal error for a mutating verb
// ("install"/"remove"), nil when the mutation may proceed. Fail-closed: an unanswerable probe
// refuses too, instead of proceeding on a guess.
func (u *Updater) engineManagedErr(e Engine, verb string) error {
	owner, yes, err := u.nativeManaged(e)
	if err != nil {
		return &NativeManagedError{Msg: fmt.Sprintf("could not verify whether %s belongs to %s (package manager busy?) — retry in a moment: %v", e.ID, u.pm.Kind, err)}
	}
	if yes {
		return &NativeManagedError{Msg: fmt.Sprintf("%s is managed by %s here (package %q) — %s it with %s, not the panel: a panel %s would desync the package manager", e.ID, u.pm.Kind, owner, verb, u.pm.Kind, verb)}
	}
	return nil
}

// UninstallPrecheck reports (as an error) why e cannot be uninstalled from the panel, WITHOUT
// touching anything. The HTTP handler runs this BEFORE stopping the core/plugins, so a refusal can
// never leave a process stopped with nothing removed (the stop-then-refuse inversion).
func (u *Updater) UninstallPrecheck(e Engine) error {
	if e.SourceOnly {
		return fmt.Errorf("%s is built from source — there is no panel-installed binary to remove", e.ID)
	}
	if e.BinName == "" {
		return fmt.Errorf("%s has no removable binary", e.ID)
	}
	if err := u.engineManagedErr(e, "remove"); err != nil {
		return err
	}
	if e.Companion != "" && fileExists(binstore.Stored(u.BinDir, e.BinName, true)) {
		return nil // kept compressed: the gzip is the panel-installed copy
	}
	if _, err := os.Stat(filepath.Join(u.BinDir, e.BinName)); err != nil {
		if os.IsNotExist(err) {
			// Installed() may have resolved the binary via PATH (outside BinDir) — that copy was
			// not installed by the panel, so silently reporting "removed" would be a lie.
			return fmt.Errorf("%s has no panel-installed binary at %s — it is installed outside the panel (system package or manual copy); remove it there", e.ID, filepath.Join(u.BinDir, e.BinName))
		}
		return err
	}
	return nil
}

// selfManaged reports whether the running wayhop binary (exePath) is OWNED by the native package
// manager — i.e. installed from the wayhop-feed. When true, wayhop must not self-swap the binary
// (that fights opkg/apk's DB + sysupgrade keep-list); the user upgrades via the package manager.
// err = the PM couldn't answer; SelfUpdate fails closed on it.
func (u *Updater) selfManaged(exePath string) (owner string, yes bool, err error) {
	if !u.pm.Available() || exePath == "" {
		return "", false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return u.pm.Owner(ctx, exePath)
}

// sanitizeMirrors keeps only usable mirror prefixes: the "" sentinel (direct, no
// mirror) and absolute http:// or https:// prefixes. A user-set mirror that isn't a
// valid URL prefix is concatenated straight into download URLs, so an invalid one
// (e.g. "ghproxy.com" with no scheme, or a "file://" path) would yield a malformed
// or unsafe request — drop it with a log line instead, keeping the rest in order.
func sanitizeMirrors(mirrors []string) []string {
	out := make([]string, 0, len(mirrors))
	for _, m := range mirrors {
		if m == "" {
			out = append(out, m) // direct (no mirror) sentinel — always valid
			continue
		}
		if strings.HasPrefix(m, "http://") || strings.HasPrefix(m, "https://") {
			out = append(out, m)
			continue
		}
		log.Printf("updater: ignoring invalid mirror %q (must be an http:// or https:// prefix)", m)
	}
	return out
}

// Installed reports the on-disk state of an engine.
type Installed struct {
	Present bool   `json:"present"`
	Version string `json:"version"`
	Path    string `json:"path"`
	// Source says who put the binary there, where that is known: SourceRelease, SourcePackage or
	// SourceOther. Empty for an engine whose version the binary itself reports truthfully.
	Source string `json:"source,omitempty"`
}

// Where an installed binary came from.
const (
	SourceRelease = "release" // a WayHop release asset the panel installed and recorded (binstore)
	SourcePackage = "package" // a file opkg/apk owns; its version is the package database's
	SourceOther   = "other"   // present, put there by neither, so its version is unknown
)

// InstalledFor is Installed with the package manager's answer folded in. A binary opkg/apk owns is
// reported as the package's, at the package's version - for a companion that is the only truthful
// version there is: amneziawg-go's own --version prints upstream's stale constant, and the record
// the panel keeps describes only what the panel installed.
func (u *Updater) InstalledFor(e Engine, pkg PackageStatus) Installed {
	in := u.Installed(e)
	if !pkg.Managed {
		return in
	}
	in.Present, in.Source = true, SourcePackage
	if pkg.Path != "" {
		in.Path = pkg.Path
	}
	if e.Companion != "" || in.Version == "" {
		in.Version = pkg.InstalledVersion
	}
	return in
}

var verRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

func parseVersion(s string) string { return verRe.FindString(s) }

// ParseVersion extracts the first x.y.z from s (exported for cross-package reuse, e.g.
// the Init Server panel formatting a remote `sing-box version` line). "" if none.
func ParseVersion(s string) string { return parseVersion(s) }

// Installed locates the binary (in BinDir or PATH) and runs its version command. The lookup is
// enginePath's, shared with nativeManaged, so the panel, the ownership probe and the package plan
// can never name three different files for one engine. The version probe is binaryRunnable's;
// whether the binary executes is not this caller's question, so its error is dropped and an
// unrunnable binary simply reports no version.
func (u *Updater) Installed(e Engine) Installed {
	if e.Companion != "" {
		return u.companionInstalled(e)
	}
	path, exists := u.enginePath(e)
	if !exists {
		return Installed{Present: false}
	}
	v, _ := binaryRunnable(path, e.VersionArgs)
	return Installed{Present: true, Path: path, Version: v}
}

// binaryRunnable runs path's version command to confirm it EXECUTES on this arch, returning the
// parsed version. err is non-nil ONLY when the binary could not be executed at all (wrong arch /
// corrupt / missing loader): an ExitError (it ran but exited non-zero) and an empty/unparsed version
// are NOT errors, since some engines print their version to stderr or exit non-zero. Empty
// versionArgs is a no-op — nothing to probe.
func binaryRunnable(path string, versionArgs []string) (version string, err error) {
	if len(versionArgs) == 0 {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, runErr := exec.CommandContext(ctx, path, versionArgs...).CombinedOutput()
	v := parseVersion(string(out))
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			return v, fmt.Errorf("does not execute: %v", runErr)
		}
	}
	return v, nil
}

// --- GitHub releases (mirror-aware) ---------------------------------------

type Release struct {
	Tag        string  `json:"tag_name"`
	Name       string  `json:"name"`
	Prerelease bool    `json:"prerelease"`
	Assets     []Asset `json:"assets"`
}

type Asset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Digest string `json:"digest"` // "sha256:..." on newer GitHub API
	Size   int64  `json:"size"`
}

// apiGet fetches a GitHub API path, trying each mirror prefix in turn.
//
// Every attempt is recorded — source kind, redacted host, duration, category — and a total failure
// returns a *FetchError carrying all of them. The previous version kept only the last error, whose
// message embedded the full request URL: a mirror prefix is operator-supplied and can carry a token,
// so the one line the UI displayed was the one string that had to stay out of it.
//
// Each attempt gets its own deadline. Without one, a wedged mirror consumes the caller's whole
// budget and the sources behind it are never reached, which is a fallback that does not fall back.
func (u *Updater) apiGet(ctx context.Context, path string, v any) error {
	_, err := u.apiGetAttempts(ctx, path, v)
	return err
}

// apiGetAttempts is apiGet with the attempt list, for callers that show it (the self-update check).
func (u *Updater) apiGetAttempts(ctx context.Context, path string, v any) ([]Attempt, error) {
	base := "https://api.github.com" + path
	fe := &FetchError{What: "release metadata"}
	for _, m := range u.Mirrors {
		url := base
		if m != "" {
			url = strings.TrimRight(m, "/") + "/" + base
		}
		at := Attempt{Source: sourceKind(m), Host: redactHost(url)}
		started := time.Now()
		status, err := u.apiGetOnce(ctx, url, v)
		at.MS = time.Since(started).Milliseconds()
		at.Status = status
		if err == nil {
			at.Category = CatOK
			return append(fe.Attempts, at), nil
		}
		at.Category = categorize(err)
		if status != 0 && status != http.StatusOK {
			at.Category = CatHTTP
		}
		at.Detail = scrubErr(err)
		fe.Attempts = append(fe.Attempts, at)
	}
	return fe.Attempts, fe
}

// apiGetOnce is a single attempt against one URL. Returns the HTTP status when one was received, so
// the caller can tell "the server refused" from "nothing answered".
func (u *Updater) apiGetOnce(ctx context.Context, url string, v any) (int, error) {
	actx, cancel := withAttemptDeadline(ctx)
	defer cancel()

	req, err := http.NewRequestWithContext(actx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "wayhop-updater")
	resp, err := u.hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<20)) // bounded drain (keep-alive reuse) so a hostile mirror can't stream forever
		return resp.StatusCode, fmt.Errorf("status %d", resp.StatusCode)
	}
	// Cap the metadata body the same way download() caps asset bodies: a release/tags
	// list is a few KB, so 8 MiB is generous, but an unbounded Decode would let a
	// hostile or misbehaving mirror stream arbitrary bytes into RAM on a small-RAM router.
	err = json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(v)
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<20)) // bounded drain (keep-alive reuse) so a hostile mirror can't stream forever
	if err != nil {
		return resp.StatusCode, err
	}
	return resp.StatusCode, nil
}

// apiGetDirect fetches a GitHub API path over the DIRECT api.github.com endpoint ONLY — it never
// iterates u.Mirrors. The root self-update uses it for the digest-bearing release JSON so the binary
// (which MAY be downloaded through a mirror) is checked against a digest that GitHub's TLS
// authenticates: a mirror cannot forge BOTH the artifact and its declared checksum. If direct GitHub
// is unreachable (e.g. censored), the self-update fails closed rather than trust a mirror-supplied
// digest for a binary that will run as root — update over SSH / the bootstrap installer instead.
func (u *Updater) apiGetDirect(ctx context.Context, path string, v any) error {
	if body, ok := u.ghCached(path); ok {
		return json.Unmarshal(body, v)
	}
	url := "https://api.github.com" + path
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "wayhop-updater")
	resp, err := u.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<20))
		return fmt.Errorf("%s: %s", url, describeGHStatus(resp))
	}
	// Same 8 MiB decode cap as apiGet so a misbehaving endpoint can't stream unbounded into RAM.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, v); err != nil {
		return err
	}
	u.ghStore(path, body)
	return nil
}

// describeGHStatus turns a refusal into something an operator can act on.
//
// "status 403" is the answer GitHub gives when the ANONYMOUS request allowance for this router's
// public IP is used up — 60 an hour, shared by everything behind that address — and it reached the
// panel as a bare number that reads like a broken router. It is neither broken nor permanent, and the
// one fact that makes it bearable is when it lifts, which the response carries.
func describeGHStatus(resp *http.Response) string {
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			when := ""
			if sec, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil && sec > 0 {
				when = " until " + time.Unix(sec, 0).Format("15:04")
			}
			return "GitHub's hourly request allowance for this router's address is used up" + when +
				" — nothing is wrong with the router, and the panel keeps working from what it already knows"
		}
	}
	return fmt.Sprintf("status %d", resp.StatusCode)
}

// --- release-metadata cache ---------------------------------------------------------------------
//
// The anonymous GitHub API allows 60 requests an hour per public IP. Every visit to Components asked
// again — the size measurement alone is one call per engine per render — so a full verification run
// exhausted the allowance and the page then answered 502 for an hour. A household router behind one
// address does the same thing more slowly.
//
// The metadata being asked for barely moves: a release TAG is immutable, and the newest release
// changes at most daily. Ten minutes is well inside that and cuts a burst of identical questions to
// one. Only successful bodies are stored, so a refusal is never cached and never becomes the answer
// for the next ten minutes.
//
// It does NOT weaken the install digest. Install reads its SHA-256 from this same DIRECT endpoint
// (never a mirror), and a cached body is that direct answer, held briefly — for an immutable tag it
// is byte-identical to asking again. A release re-published inside the window would fail the digest
// check against the bytes actually downloaded, which is the safe direction.
//
// Bounded, because this runs on a router with a 64 MiB soft limit and each entry is a release body:
// expired entries are dropped on every write, and the map is capped. Without that, browsing a long
// version list would leave one body per tag resident for as long as the daemon runs.
const ghCacheTTL = 10 * time.Minute

// ghCacheMax is generous for the real pattern (one engine, a handful of tags in view) and small
// enough that the worst case is kilobytes rather than a slow leak.
const ghCacheMax = 32

func (u *Updater) ghCached(path string) ([]byte, bool) {
	u.ghMu.Lock()
	defer u.ghMu.Unlock()
	e, ok := u.ghCache[path]
	if !ok || time.Since(e.at) > ghCacheTTL {
		return nil, false
	}
	return e.body, true
}

func (u *Updater) ghStore(path string, body []byte) {
	u.ghMu.Lock()
	defer u.ghMu.Unlock()
	if u.ghCache == nil {
		u.ghCache = map[string]ghCacheEntry{}
	}
	now := time.Now()
	// Drop what has expired before adding: the cache is read by exact path, so an entry nobody asks
	// for again would otherwise sit there until the daemon restarts.
	for k, e := range u.ghCache {
		if now.Sub(e.at) > ghCacheTTL {
			delete(u.ghCache, k)
		}
	}
	// Still at the cap after pruning: evict the oldest. A cache that refused to store instead would
	// make the busiest moment — the one that needs it — the moment it stops working.
	for len(u.ghCache) >= ghCacheMax {
		oldest, at := "", time.Time{}
		for k, e := range u.ghCache {
			if oldest == "" || e.at.Before(at) {
				oldest, at = k, e.at
			}
		}
		delete(u.ghCache, oldest)
	}
	u.ghCache[path] = ghCacheEntry{at: now, body: body}
}

// Latest returns the newest release.
func (u *Updater) Latest(ctx context.Context, e Engine) (Release, error) {
	if e.Companion != "" {
		rs, err := u.List(ctx, e, 0)
		if err != nil {
			return Release{}, err
		}
		for _, r := range rs {
			if !r.Prerelease {
				return r, nil
			}
		}
		return Release{}, fmt.Errorf("no stable WayHop release carries %s", e.ID)
	}
	if u.Offline {
		rs := offlineReleases(e.Repo, u.Arch, 1)
		if len(rs) == 0 {
			return Release{}, fmt.Errorf("no release for %s in the demo catalogue", e.Repo)
		}
		return rs[0], nil
	}
	var r Release
	err := u.apiGet(ctx, "/repos/"+e.Repo+"/releases/latest", &r)
	return r, err
}

// List returns up to limit recent releases (newest first).
func (u *Updater) List(ctx context.Context, e Engine, limit int) ([]Release, error) {
	if limit <= 0 {
		limit = 15
	}
	if e.Companion != "" {
		rs, err := u.companionList(ctx, e, u.apiGet)
		if len(rs) > limit {
			rs = rs[:limit]
		}
		return rs, err
	}
	if u.Offline {
		return offlineReleases(e.Repo, u.Arch, limit), nil
	}
	var rs []Release
	err := u.apiGet(ctx, fmt.Sprintf("/repos/%s/releases?per_page=%d", e.Repo, limit), &rs)
	return rs, err
}

type tag struct {
	Name string `json:"name"`
}

// Tags lists recent git tags — used for source-only engines (e.g. amneziawg-go)
// that publish no release assets but still tag versions.
func (u *Updater) Tags(ctx context.Context, e Engine, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 15
	}
	var ts []tag
	if err := u.apiGet(ctx, fmt.Sprintf("/repos/%s/tags?per_page=%d", e.Repo, limit), &ts); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Name)
	}
	return out, nil
}

// validTagSegRe constrains each path SEGMENT of a release tag to characters that are
// unambiguous in a URL path (no '.'/'..' traversal, no query/fragment/space/control bytes),
// so a caller- or config-supplied tag can't traverse or inject into the api.github.com path.
var validTagSegRe = regexp.MustCompile(`^[A-Za-z0-9._+-]+$`)

// validateTag rejects an empty tag, empty/"."/".." path segments, and any character outside
// the allowed set. A single embedded '/' is permitted because some engines genuinely tag
// releases with a slash (e.g. apernet/hysteria's "app/v2.0.0"); the GitHub API addresses such
// a tag as .../releases/tags/app/v2.0.0, so the slash must survive (each segment is still
// PathEscaped at use). Leading/trailing/double slashes and "../" traversal are rejected.
func validateTag(tag string) error {
	if tag == "" {
		return fmt.Errorf("empty release tag")
	}
	segs := strings.Split(tag, "/")
	for _, s := range segs {
		if s == "" {
			return fmt.Errorf("invalid release tag %q: empty path segment (no leading/trailing/double slash)", tag)
		}
		if s == "." || s == ".." {
			return fmt.Errorf("invalid release tag %q: path traversal not allowed", tag)
		}
		if !validTagSegRe.MatchString(s) {
			return fmt.Errorf("invalid release tag %q: only letters, digits, . _ + - and a path-separating / are allowed", tag)
		}
	}
	return nil
}

// escapeTagPath validates tag and returns it with each '/'-separated segment PathEscaped,
// rejoined with '/'. Use for the .../releases/tags/<tag> path so reserved bytes in a segment
// can't alter the URL structure while a legitimate slashed tag (e.g. "app/v2.0.0") still
// resolves.
func escapeTagPath(tag string) (string, error) {
	if err := validateTag(tag); err != nil {
		return "", err
	}
	segs := strings.Split(tag, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/"), nil
}

func (u *Updater) release(ctx context.Context, e Engine, tag string) (Release, error) {
	if e.Companion != "" {
		return u.companionRelease(ctx, e, tag, u.apiGet)
	}
	esc, err := escapeTagPath(tag)
	if err != nil {
		return Release{}, err
	}
	if u.Offline {
		return offlineReleaseByTag(e.Repo, u.Arch, tag)
	}
	var r Release
	err = u.apiGet(ctx, "/repos/"+e.Repo+"/releases/tags/"+esc, &r)
	return r, err
}

// releaseDirect looks up a release over the DIRECT GitHub API (never a mirror) — used by the root
// self-update so the asset digest comes from an authenticated channel the mirror can't forge
// (see apiGetDirect).
func (u *Updater) releaseDirect(ctx context.Context, e Engine, tag string) (Release, error) {
	if e.Companion != "" {
		// The listing that carries the digest comes over the direct API too, for the same reason.
		return u.companionRelease(ctx, e, tag, u.apiGetDirect)
	}
	esc, err := escapeTagPath(tag)
	if err != nil {
		return Release{}, err
	}
	// Fit reaches GitHub through here, which is what made the demo depend on it. The digest argument
	// above is about WHERE a real lookup goes, not whether one happens at all.
	if u.Offline {
		return offlineReleaseByTag(e.Repo, u.Arch, tag)
	}
	var r Release
	err = u.apiGetDirect(ctx, "/repos/"+e.Repo+"/releases/tags/"+esc, &r)
	return r, err
}

// Install downloads the asset for u.Arch from the given release tag, verifies it against a MANDATORY
// sha256 digest fetched over the direct GitHub API (never a mirror), extracts the binary, and
// installs it atomically. A release with no digest, a mismatched digest, or reachable only over a
// plaintext http:// mirror is refused rather than installed — the binary runs as root. Returns the
// installed tag.
// enoughSpaceFor reports whether `avail` free bytes can safely hold a freshly-staged
// binary of binSize (+ a same-size backup when withBackup) plus a small margin. When
// the free space is unknown (known=false, e.g. the off-Linux build) it returns true —
// never block on a stat we couldn't take. This guards the small router overlay
// (~60 MB) against a swap that runs out of space mid-write and leaves a partial binary.
// shortfallMiB is how many MiB have to be freed before the pre-flight would let the install run.
// Rounded UP: freeing the floored difference leaves the guard refusing again, which would turn a
// number presented as an instruction into a second dead end.
// availAt is AvailBytes through the seam above.
func (u *Updater) availAt(dir string) (uint64, bool) {
	if u != nil && u.availBytes != nil {
		return u.availBytes(dir)
	}
	return AvailBytes(dir)
}

func shortfallMiB(avail, need uint64) uint64 {
	if need <= avail {
		return 0
	}
	return (need - avail + (1 << 20) - 1) >> 20
}

// flashRefusal is what the operator reads when the disk pre-flight refuses an engine install, kept
// in one place so it can be read and tested without a network round trip.
//
// The refusal itself is right — the AX3000T's overlay is 60.6 MiB with 23.9 free, and a ~31 MiB
// binary cannot be written into it by any method. What the sentence used to leave out is what to do
// about it: it printed two rounded figures and left the subtraction to the reader, then offered
// "mount external storage", which on its own changes nothing, because engines are installed into
// the directory of the CONFIGURED sing-box binary (server.go builds the updater with
// filepath.Dir(cfg.SingBox.Bin)) and mounting a disk does not move that. The path is an editable
// field on the Settings page, so the lever the old advice gestured at does exist — it is named here
// instead, along with the number that says when the first option has worked.
func flashRefusal(id, dir string, avail, need uint64) error {
	return fmt.Errorf("not enough free space to install %s in %s (~%d MiB free, need ~%d MiB for the unpacked binary — free at least %d MiB more there) — or point the “sing-box binary” setting at a directory with room, since the panel installs engines beside it, or install over SSH",
		id, dir, avail>>20, need>>20, shortfallMiB(avail, need))
}

// selfFlashRefusal is the same refusal for WayHop's own binary. Deliberately NOT carrying the
// sing-box-binary advice: this directory is the one the running daemon sits in, and no panel
// setting moves it — repeating that suggestion here would be pointing at a lever that is not
// connected to anything. The shortfall applies either way.
func selfFlashRefusal(dir string, avail, need uint64) error {
	return fmt.Errorf("not enough free space to self-update safely on %s (~%d MiB free, need ~%d MiB for the new binary + backup — free at least %d MiB more) — free space, mount external storage, or update over SSH",
		dir, avail>>20, need>>20, shortfallMiB(avail, need))
}

func enoughSpaceFor(avail uint64, known bool, binSize int, withBackup bool) bool {
	if !known {
		return true
	}
	mult := uint64(1)
	if withBackup {
		mult = 2
	}
	return avail >= uint64(binSize)*mult+(2<<20) // + 2 MiB margin
}

// updateMemNeed estimates the MemAvailable an install + engine restart needs to avoid OOM-killing
// the daemon or the running proxy core (which would drop the family's routing). The streaming
// install itself is light on RAM — the real risk is the RESTART, where the new process faults in
// ~the unpacked binary while the old one may still be resident — so we size the unpacked binary
// (unpackedBytes: 1x bare, 3x compressed) plus a floor that keeps the daemon + core + routing alive
// across the swap. Conservative by design: on a tight router it is far safer to refuse (free RAM /
// install over SSH) than to OOM mid-update and drop routing.
func updateMemNeed(assetSize int64, assetName string) uint64 {
	const restartFloor = 16 << 20
	return unpackedBytes(assetSize, assetName) + restartFloor
}

// enoughMemForUpdate reports whether `avail` bytes of MemAvailable can safely absorb the install +
// restart. Unknown avail (known=false, e.g. the off-Linux build) or unknown assetSize (older
// releases omit it) never blocks — we don't reject on a number we couldn't measure.
func enoughMemForUpdate(avail uint64, known bool, assetSize int64, assetName string) bool {
	if !known || assetSize <= 0 {
		return true
	}
	return avail >= updateMemNeed(assetSize, assetName)
}

func (u *Updater) Install(ctx context.Context, e Engine, tag string) (string, error) {
	if e.SourceOnly {
		return "", fmt.Errorf("%s has no prebuilt releases: %s", e.ID, e.Note)
	}
	u.mu.Lock() // serialize with any other Install/SelfUpdate (fixed staging paths) — see Updater.mu
	defer u.mu.Unlock()
	// If this engine's binary is OWNED by the native package manager, do NOT direct-download over it
	// — that clobbers the packaged binary and desyncs the package DB (the /opt/bin/sing-box hazard).
	// Defer to opkg/apk. Path-based (no name map trusted); a no-op wherever no PM is present.
	// FAIL-CLOSED: if the PM can't answer (db locked by a concurrent opkg/apk run), refuse + retry.
	if err := u.engineManagedErr(e, "update"); err != nil {
		return "", err
	}
	// Fetch the digest-bearing release JSON over the DIRECT GitHub API, never a mirror — the same
	// rule the root self-update follows (see SelfUpdate/releaseDirect). The staged binary is verified
	// against asset.Digest below and then runs with router privileges, so the digest MUST come from a
	// channel a mirror can't forge: a hostile or MITM'd mirror that could rewrite the binary could
	// also serve a matching forged digest, and a checksum from the same untrusted source is no trust
	// anchor at all. The mirror stays useful as pure TRANSPORT for the (large) asset bytes in
	// streamAssetToFile; it just no longer gets to define the tag, size, URL or digest. Fails closed
	// when direct GitHub is unreachable — an engine binary is not installed on an unverifiable metadata.
	rel, err := u.releaseDirect(ctx, e, tag)
	if err != nil {
		return "", fmt.Errorf("lookup %s %s: %w", e.ID, tag, err)
	}
	asset := pickAsset(rel.Assets, u.Arch)
	if asset == nil {
		return "", fmt.Errorf("no %s asset for arch %q in %s %s", e.ID, u.Arch, e.ID, tag)
	}
	if err := os.MkdirAll(u.BinDir, 0o755); err != nil {
		return "", err
	}
	// Flash pre-flight BEFORE downloading: streamAssetToFile writes the decompressed binary into
	// BinDir as it downloads. On a tiny router overlay a large core simply cannot fit, so refuse
	// early with an actionable message instead of failing mid-write. (Streaming retired the old
	// in-RAM compressed+decompressed peak, so RAM is no longer the binding constraint here.)
	compressed := false
	if avail, ok := u.availAt(u.BinDir); !enoughFlashFor(avail, ok, asset.Size, asset.Name, false) {
		// A companion ships as a gzip; where the unpacked binary does not fit, it can be kept as that
		// gzip and unpacked into RAM at each start (binstore). The refusal then names the smaller need,
		// since that is what would get it installed at all.
		if e.Companion == "" || isBareBinaryAsset(asset.Name) {
			return "", flashRefusal(e.ID, u.BinDir, avail, peakInstallDisk(asset.Size, asset.Name, false))
		}
		if avail < compressedNeed(asset.Size) {
			return "", companionFlashRefusal(e.ID, u.BinDir, avail, asset.Size)
		}
		compressed = true
	}
	// Memory pre-flight (the lock): streaming to disk is cheap, but the engine RESTART faults the new
	// binary in while the old may still be resident — on a tight router that OOM-kills the daemon or
	// sing-box and drops routing. Refuse early. No-op off Linux / when MemAvailable is unknown.
	if avail, ok := availMemBytes(); !enoughMemForUpdate(avail, ok, asset.Size, asset.Name) {
		return "", fmt.Errorf("not enough free memory to install %s safely (~%d MiB free, need ~%d MiB) — free RAM or install over SSH", e.ID, avail>>20, updateMemNeed(asset.Size, asset.Name)>>20)
	}
	if compressed {
		return u.installCompressed(ctx, e, rel, *asset)
	}
	dst := filepath.Join(u.BinDir, e.BinName)
	tmp := dst + ".new"
	// Digest MANDATORY (requireDigest=true): this binary runs as root, so — exactly like self-update —
	// a missing, malformed or mismatched sha256 fails the install closed rather than shipping an
	// unverifiable executable, and a plaintext http:// mirror is refused for the transport (a passive
	// on-path attacker could rewrite the bytes in flight). The digest it checks against came from the
	// DIRECT release lookup above, so it is an independent anchor, not a number the same mirror chose.
	// A release that simply has no digest (older assets predating GitHub's digest field) is refused
	// with an actionable message from verifyDigestSum rather than installed on trust.
	if err := u.streamAssetToFile(ctx, *asset, e.BinName, tmp, true); err != nil {
		return "", fmt.Errorf("download %s: %w", asset.Name, err)
	}
	// Re-verify BEFORE swapping: probe the STAGED binary's version command to confirm it executes on
	// this arch. A wrong-arch/corrupt asset can pass the digest yet fail to run (the "installed but
	// crash-loops on start" class). If it won't run, drop the staged file and keep the existing binary
	// untouched — no rollback needed because we never overwrote it. Skipped when e has no VersionArgs.
	v, verr := binaryRunnable(tmp, e.VersionArgs)
	if verr != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("downloaded %s but it %v — wrong arch or corrupt asset; the existing binary was left untouched, retry or install over SSH", e.ID, verr)
	}
	// TOCTOU re-check: the ownership gate above ran BEFORE a download that can take minutes on a
	// mirrored/censored link. If an admin ran `opkg install`/`apk add` for this engine meanwhile,
	// the rename below would clobber the freshly packaged binary — re-probe right before the swap.
	if err := u.engineManagedErr(e, "update"); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if e.Companion != "" {
		// A gzip kept from an earlier install on a fuller flash is no longer the copy that runs.
		_ = os.Remove(binstore.Stored(u.BinDir, e.BinName, true))
		// The binary's own --version is upstream's stale constant; the release says what this is.
		if err := binstore.Write(u.BinDir, e.BinName, rel.Tag, false); err != nil {
			log.Printf("wayhop: %s installed, but its version record could not be written: %v", e.ID, err)
		}
		return rel.Tag, nil
	}
	if v != "" {
		return v, nil // report the REAL running version, not just the release tag
	}
	return rel.Tag, nil
}

// Uninstall removes the engine binary this updater installed (BinDir/BinName). All preconditions
// live in UninstallPrecheck (SourceOnly, PM-owned refuse, absent-binary refuse — a binary the
// panel never installed must not report "removed"), which the HTTP handler ALSO runs before
// stopping any process. It only ever deletes inside BinDir, never a PATH-resolved system binary,
// so it can't nuke an OS-provided tool.
func (u *Updater) Uninstall(e Engine) error {
	if err := u.UninstallPrecheck(e); err != nil {
		return err
	}
	if e.Companion != "" {
		// Either stored form, its record, and the copy unpacked into RAM to run.
		binstore.Remove(u.BinDir, e.BinName, u.RunDir)
		return nil
	}
	dst := filepath.Join(u.BinDir, e.BinName)
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) { // IsNotExist: precheck raced a concurrent remove — gone is gone
		return fmt.Errorf("remove %s: %w", dst, err)
	}
	return nil
}

// dlCap bounds how many bytes download buffers in RAM: the asset's known size plus a small
// margin, so a misbehaving or hostile mirror can't stream far more than the expected archive
// into memory on a small-RAM router. Falls back to a flat ceiling when the size is unknown
// (older GitHub releases omit it).
func dlCap(size int64) int64 {
	if size > 0 {
		return size + 1<<20
	}
	return 96 << 20
}

func (u *Updater) download(ctx context.Context, rawURL string, maxBytes int64) ([]byte, error) {
	// Every path is remembered, not just the last one.
	//
	// This returned lastErr, and the default list ends with https://mirror.ghproxy.com/ — a host that
	// no longer exists: it does not resolve from a live Keenetic or from the dev machine.
	// So EVERY failed download, whatever actually went wrong, was reported as
	// "lookup mirror.ghproxy.com: no such host". Measured on the demo: three paths were tried
	// (direct, ghproxy.net, mirror.ghproxy.com) and the panel showed only the third, which sends the
	// operator to debug the DNS of a mirror they never chose while the interesting failure — the
	// direct download their ISP blocked — is the one that got dropped.
	var lastErr error
	var attempts []string
	for _, m := range u.Mirrors {
		url := rawURL
		if m != "" {
			url = strings.TrimRight(m, "/") + "/" + rawURL
		}
		note := func(err error) { lastErr = err; attempts = append(attempts, downloadPathLabel(m)+": "+err.Error()) }
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			note(err)
			continue
		}
		req.Header.Set("User-Agent", "wayhop-updater")
		resp, err := u.hc.Do(req)
		if err != nil {
			note(err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			note(fmt.Errorf("status %d", resp.StatusCode))
			continue
		}
		ct := resp.Header.Get("Content-Type")
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
		resp.Body.Close()
		if err != nil {
			note(err)
			continue
		}
		// A real release asset is an archive (gzip/zip/xz magic) or a raw ELF — never an
		// HTML/error page. A mirror in a censored region can answer 200 with an
		// interstitial/captcha/error page; without this check those bytes would be
		// installed verbatim as the "binary" (esp. for raw, non-archive assets, where the
		// archive parser can't catch it) and the next start would fail to exec it. Reject
		// and fall through to the next mirror.
		if looksLikeHTML(ct, b) {
			note(errors.New("response looks like an HTML/error page, not a binary asset"))
			continue
		}
		return b, nil
	}
	if len(attempts) > 1 {
		return nil, fmt.Errorf("all %d download paths failed — %s", len(attempts), strings.Join(attempts, "; "))
	}
	return nil, lastErr
}

// downloadPathLabel names one entry of u.Mirrors the way the operator configured it. The empty
// string is the direct download, and calling it "" in an error message names nothing.
func downloadPathLabel(mirror string) string {
	if mirror == "" {
		return "direct"
	}
	return strings.TrimRight(mirror, "/")
}

// looksLikeHTML reports whether a fetched asset is actually an HTML page (a mirror
// interstitial, captcha, or error page) rather than a real release asset. Real assets are
// archives or raw ELF binaries: none carry a text/html content-type or begin with an HTML/
// XML marker. The body check is conservative (a binary never starts with '<') so it cannot
// false-reject a legitimate download served with an odd content-type.
func looksLikeHTML(contentType string, b []byte) bool {
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		contentType = contentType[:i]
	}
	switch strings.ToLower(strings.TrimSpace(contentType)) {
	case "text/html", "application/xhtml+xml":
		return true
	}
	t := bytes.TrimSpace(b)
	return len(t) >= 2 && t[0] == '<' &&
		(t[1] == '!' || t[1] == 'h' || t[1] == 'H' || t[1] == '?')
}

// --- asset matching + extraction ------------------------------------------

var archTokens = map[string][]string{
	"amd64": {"amd64", "x86_64", "linux-64", "linux_64"},
	"arm64": {"arm64", "aarch64"},
	// Bare "arm" matches a suffix-less "-linux-arm" asset (e.g. hysteria-linux-arm);
	// the arm64/aarch64 guard in matchAsset keeps it from matching 64-bit names.
	"arm":    {"armv7", "arm32", "armhf", "armv6", "armv5", "arm"},
	"mipsle": {"mipsle", "mips32le", "mipsel"},
	"mips":   {"mips"},
}

// pickAsset selects the best-matching release asset for arch. For most arches any
// match is equivalent (first wins); for 32-bit arm it prefers the most specific
// build — explicit armv7/armhf/arm32 > a bare "-linux-arm" > armv6 > armv5 — so an
// ARMv7 router never settles for a slower lowest-common-denominator binary when a
// better one is published.
func pickAsset(assets []Asset, arch string) *Asset {
	var best *Asset
	bestScore := -1
	for i := range assets {
		if !matchAsset(assets[i].Name, arch) {
			continue
		}
		if sc := assetScore(assets[i].Name, arch); sc > bestScore {
			bestScore = sc
			best = &assets[i]
		}
	}
	return best
}

// assetScore ranks a matching asset. The C library dominates the ARM variant: a binary built for the
// wrong libc does not run at all, while an ARM variant mismatch is a performance or instruction-set
// question among binaries that at least load.
func assetScore(name, arch string) int {
	return libcScore(name)*10 + archVariantScore(name, arch)
}

// libcScore ranks an asset by the C library it expects.
//
// Both platforms WayHop runs on — OpenWrt and Entware on KeeneticOS — are musl. A glibc build has an
// ELF interpreter (/lib/ld-linux-*.so) that simply does not exist there, and the kernel reports that
// as ENOENT: measured on a live router, sing-box v1.13.19 installed and then refused to run
// with "fork/exec /opt/bin/sing-box.new: no such file or directory" — a file that was plainly there.
//
// This mattered only for arm64 because the old score treated every non-arm asset as equally good, so
// the FIRST match won, and GitHub happened to list sing-box's -glibc build ahead of the musl one.
// A static build is safest of all: it needs no interpreter on either kind of host.
func libcScore(name string) int {
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "static"):
		return 3
	case strings.Contains(n, "musl"):
		return 2
	case strings.Contains(n, "glibc"), strings.Contains(n, "-gnu"):
		return 0
	default:
		return 1 // unlabelled: sing-box's plain "-linux-arm64" IS the musl build
	}
}

func archVariantScore(name, arch string) int {
	if arch != "arm" {
		return 1 // any matching asset is equally good on this dimension
	}
	n := strings.ToLower(name)
	switch {
	case strings.Contains(n, "armv7"), strings.Contains(n, "armhf"), strings.Contains(n, "arm32"):
		return 3
	case strings.Contains(n, "armv6"):
		return 1
	case strings.Contains(n, "armv5"):
		return 0
	default:
		return 2 // bare "-linux-arm": ARMv7-safe baseline, better than v5/v6
	}
}

// matchAsset reports whether a release asset name is the Linux build for arch.
func matchAsset(name, arch string) bool {
	n := strings.ToLower(name)
	if !strings.Contains(n, "linux") {
		return false
	}
	for _, ext := range []string{".sha256", ".asc", ".sig", ".pem", ".dgst", ".txt", ".json"} {
		if strings.HasSuffix(n, ext) {
			return false
		}
	}
	// disambiguate near-collisions
	if arch == "arm" && (strings.Contains(n, "arm64") || strings.Contains(n, "aarch64")) {
		return false
	}
	if arch == "mips" && (strings.Contains(n, "mipsle") || strings.Contains(n, "mipsel") || strings.Contains(n, "mips32le") || strings.Contains(n, "mips64")) {
		return false
	}
	if arch == "amd64" && (strings.Contains(n, "arm") || strings.Contains(n, "mips")) {
		return false
	}
	for _, t := range archTokens[arch] {
		if strings.Contains(n, t) {
			return true
		}
	}
	return false
}

// extractBinary returns the wanted binary from an asset held in memory. It is the []byte
// convenience form of extractStreamTo (stream.go); the streaming install path uses the io.Writer
// form directly so it never buffers the decompressed binary. Kept for tests + small callers.
func extractBinary(assetName string, data []byte, binName string) ([]byte, error) {
	br := bytes.NewReader(data)
	var b bytes.Buffer
	if err := extractStreamTo(assetName, br, br, int64(len(data)), binName, &b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func fromGz(data []byte) ([]byte, error) {
	var b bytes.Buffer
	if err := fromGzStream(bytes.NewReader(data), &b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func fromTarGz(data []byte, binName string) ([]byte, error) {
	var b bytes.Buffer
	if err := fromTarGzStream(bytes.NewReader(data), binName, &b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func fromZip(data []byte, binName string) ([]byte, error) {
	br := bytes.NewReader(data)
	var b bytes.Buffer
	if err := fromZipStream(br, int64(len(data)), binName, &b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// verifyDigest checks data held in memory against a "sha256:<hex>" digest. A missing/!sha256 digest
// is a best-effort SKIP, so an engine release without one still installs. See verifyDigestSum
// (stream.go), which the streaming path calls with a sum computed as the asset streamed.
func verifyDigest(data []byte, digest string) error {
	sum := sha256.Sum256(data)
	return verifyDigestSum("sha256:"+hex.EncodeToString(sum[:]), digest, false)
}

// verifyDigestRequired is the SELF-UPDATE variant: a present, matching sha256 is MANDATORY because
// the WayHop binary runs as root after a swap, so we refuse to install one we couldn't verify. WR's
// own CI publishes every tarball as a GitHub Release asset, which GitHub auto-populates with a
// sha256 digest, so a real release always passes; an absent digest means the mirror channel is the
// only trust root and we decline.
func verifyDigestRequired(data []byte, digest string) error {
	sum := sha256.Sum256(data)
	return verifyDigestSum("sha256:"+hex.EncodeToString(sum[:]), digest, true)
}

// --- WayHop self-update -------------------------------------------------
//
// WayHop can update ITSELF (not just the engines it orchestrates) from its own
// CI release builds. The build workflow publishes per-arch tarballs named
// wayhop-<ver>-<arch>.tar.gz and wayhop-<ver>-<arch>-openwrt.tar.gz (the latter
// carries the procd init), each containing a wayhop-<arch> binary. Those names have
// no "linux" token, so the engine asset matcher does not apply — selfAsset handles them.

// DefaultSelfRepo is where WayHop fetches its OWN release builds when the config
// leaves Updater.SelfRepo empty (the maintainer's fork, CI-built on every v* tag).
const DefaultSelfRepo = "awadak3davra/wayhop"

// wayhopReleaseTagRe is the shape of a WayHop release tag: v<major>.<minor>.<patch>, optionally with a
// prerelease or package-revision suffix (v0.6.0-rc1, v0.5.5-r2) or build metadata.
var wayhopReleaseTagRe = regexp.MustCompile(`^v\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?(?:\+[0-9A-Za-z.-]+)?$`)

// IsWayHopReleaseTag reports whether tag names a WayHop build.
//
// The same release repository also carries awg-v* releases: AmneziaWG package sets for the feed
// (kmod, tools, LuCI, userspace packages), published with --latest=false. They are not WayHop builds,
// and every reader of WayHop's own releases must pass over them - the self-update, which would
// otherwise read "awg-v3.1.20260906-1" as version 3.1 and call it newer than any WayHop there is, and
// the companion listing, which reads amneziawg-go binaries out of WayHop releases only. The test is
// on the tag and not on the assets: an asset name that happens to match is no reason to trust a
// release that is not a WayHop build.
func IsWayHopReleaseTag(tag string) bool { return wayhopReleaseTagRe.MatchString(tag) }

// errNotWayHopTag refuses a self-update or self-fit to a tag that is not a WayHop build.
func errNotWayHopTag(tag string) error {
	return fmt.Errorf("%q is not a WayHop release (v<major>.<minor>.<patch>); this repository's awg-v* releases carry AmneziaWG packages, not WayHop", tag)
}

// selfAsset picks the WayHop release tarball for arch, preferring the OpenWrt
// package over the generic one. The leading "-"+arch avoids "arm" matching "arm64".
func selfAsset(assets []Asset, arch string) *Asset {
	var generic *Asset
	ow := "-" + arch + "-openwrt.tar.gz"
	gen := "-" + arch + ".tar.gz"
	for i := range assets {
		n := strings.ToLower(assets[i].Name)
		if !strings.HasPrefix(n, "wayhop-") {
			continue
		}
		if strings.HasSuffix(n, ow) {
			return &assets[i] // openwrt package wins
		}
		if strings.HasSuffix(n, gen) {
			generic = &assets[i]
		}
	}
	return generic
}

// SelfLatest returns the newest STABLE WayHop release carrying a tarball for this arch.
// Prereleases are SKIPPED — self-update runs as root and AutoUpdateLoop can install it
// unattended, so it must never auto-jump onto an -rc/-alpha (the engine path guards the same
// way via LatestStable) — and are used only as a fallback when no stable build exists yet. A
// specific prerelease can still be pinned via the explicit version in handleSelfUpdate.
// repo "" → DefaultSelfRepo.
func (u *Updater) SelfLatest(ctx context.Context, repo string) (Release, error) {
	if repo == "" {
		repo = DefaultSelfRepo
	}
	rels, err := u.List(ctx, Engine{Repo: repo}, 10)
	if err != nil {
		return Release{}, err
	}
	if r, ok := pickSelfRelease(rels, u.Arch); ok {
		return r, nil
	}
	return Release{}, fmt.Errorf("no wayhop %s asset in recent %s releases", u.Arch, repo)
}

// pickSelfRelease chooses the self-update target from a newest-first release list: the newest
// STABLE release that has an asset for arch, falling back to the newest prerelease with one only
// if no stable does. ok=false when no release carries an asset for arch. Pure (unit-tested).
func pickSelfRelease(rels []Release, arch string) (Release, bool) {
	var fallback *Release
	for i := range rels {
		if !IsWayHopReleaseTag(rels[i].Tag) || selfAsset(rels[i].Assets, arch) == nil {
			continue
		}
		if !rels[i].Prerelease {
			return rels[i], true
		}
		if fallback == nil {
			fallback = &rels[i]
		}
	}
	if fallback != nil {
		return *fallback, true
	}
	return Release{}, false
}

// SelfUpdate downloads WayHop release `tag` from repo, verifies it, SANITY-RUNS the
// new binary (`<bin> -version` must print a version), backs up the current executable
// (exePath+".bak", reboot-safe rollback), then atomically swaps it in. The caller must
// restart the service to run it (the running process keeps the old inode until then).
// The sanity-run guarantees a corrupt/wrong-arch download never replaces a working daemon.
func (u *Updater) SelfUpdate(ctx context.Context, repo, tag, exePath string) (string, error) {
	u.mu.Lock() // serialize with any other Install/SelfUpdate (fixed staging paths) — see Updater.mu
	defer u.mu.Unlock()
	// If wayhop itself was installed from the wayhop-feed (opkg/apk owns exePath), do NOT self-swap
	// the binary: that fights the package DB + sysupgrade keep-list and races the package's own
	// postinst restart (red-team R5). Defer to the PM. No-op on the normal GitHub-installed path.
	// FAIL-CLOSED on an unanswerable probe (PM db locked) — never self-swap on a guess.
	owner, yes, perr := u.selfManaged(exePath)
	if perr != nil {
		return "", &NativeManagedError{Msg: fmt.Sprintf("could not verify whether wayhop belongs to %s (package manager busy?) — retry in a moment: %v", u.pm.Kind, perr)}
	}
	if yes {
		return "", &NativeManagedError{Msg: fmt.Sprintf("wayhop is managed by %s here (package %q owns %s) — upgrade it with %s, not the panel: a self-swap would fight the package manager", u.pm.Kind, owner, exePath, u.pm.Kind)}
	}
	if repo == "" {
		repo = DefaultSelfRepo
	}
	if !IsWayHopReleaseTag(tag) {
		return "", errNotWayHopTag(tag)
	}
	// Fetch the digest-bearing release JSON over the DIRECT GitHub API, not a mirror: the binary is
	// verified against asset.Digest below, so the digest MUST come from a channel a mirror can't forge
	// (else a hostile mirror serves a backdoored tarball plus a matching forged digest and it runs as
	// root). Fails closed if direct GitHub is unreachable — see apiGetDirect.
	rel, err := u.releaseDirect(ctx, Engine{Repo: repo}, tag)
	if err != nil {
		return "", fmt.Errorf("lookup wayhop %s: %w", tag, err)
	}
	asset := selfAsset(rel.Assets, u.Arch)
	if asset == nil {
		return "", fmt.Errorf("no wayhop %s asset in %s", u.Arch, tag)
	}
	dir := filepath.Dir(exePath)
	// Flash pre-flight: the staged binary AND the .bak backup both land on exePath's filesystem.
	// On the tiny router overlay a swap that won't fit would otherwise fail mid-write — abort
	// cleanly, untouched. (Streaming retired the in-RAM peak, so flash is the binding constraint.)
	if avail, ok := AvailBytes(dir); !enoughFlashFor(avail, ok, asset.Size, asset.Name, true) {
		return "", selfFlashRefusal(dir, avail, peakInstallDisk(asset.Size, asset.Name, true))
	}
	// Memory pre-flight (the lock): self-update restarts the daemon, briefly holding old+new resident
	// alongside sing-box + routing — refuse on a tight router rather than risk an OOM that drops it.
	if avail, ok := availMemBytes(); !enoughMemForUpdate(avail, ok, asset.Size, asset.Name) {
		return "", fmt.Errorf("not enough free memory to self-update safely (~%d MiB free, need ~%d MiB) — free RAM or update over SSH", avail>>20, updateMemNeed(asset.Size, asset.Name)>>20)
	}
	staged := filepath.Join(dir, ".wayhop.new")
	// Stream the asset straight to the staged file (digest MANDATORY — the new binary runs as root):
	// no compressed/decompressed RAM buffer, so a self-update can't OOM the router mid-swap.
	if err := u.streamAssetToFile(ctx, *asset, "wayhop-"+u.Arch, staged, true); err != nil {
		return "", fmt.Errorf("download wayhop-%s: %w", u.Arch, err)
	}
	// Sanity-run BEFORE swapping — refuse a binary that won't execute on this arch.
	out, runErr := exec.CommandContext(ctx, staged, "-version").CombinedOutput()
	if runErr != nil || parseVersion(string(out)) == "" {
		_ = os.Remove(staged)
		return "", fmt.Errorf("staged wayhop binary failed its sanity check (corrupt or wrong arch): %v", runErr)
	}
	// Back up the current binary on the same filesystem, then atomically swap. The .bak is
	// the reboot-safe rollback, so it is MANDATORY: if we can't read the running binary or
	// write a COMPLETE backup, abort the swap rather than land a new daemon with no way back
	// (a self-update that strands the router is the worst outcome). Write via a temp + rename so
	// a failed backup write can neither leave a half-written .bak (poses as a valid rollback) NOR
	// destroy a prior good .bak from an earlier update (os.WriteFile would O_TRUNC it before failing).
	cur, err := os.ReadFile(exePath)
	if err != nil {
		_ = os.Remove(staged)
		return "", fmt.Errorf("read current binary for rollback backup: %w", err)
	}
	bakTmp := exePath + ".bak.tmp"
	if werr := os.WriteFile(bakTmp, cur, 0o755); werr != nil {
		_ = os.Remove(bakTmp)
		_ = os.Remove(staged)
		return "", fmt.Errorf("write rollback backup: %w", werr)
	}
	if werr := os.Rename(bakTmp, exePath+".bak"); werr != nil {
		_ = os.Remove(bakTmp)
		_ = os.Remove(staged)
		return "", fmt.Errorf("install rollback backup: %w", werr)
	}
	if err := os.Rename(staged, exePath); err != nil {
		_ = os.Remove(staged)
		return "", fmt.Errorf("swap binary: %w", err)
	}
	return rel.Tag, nil
}

// Compare answers two separate questions: is `latest` newer than `current`, and could that be
// decided at all.
//
// They were merged into a single bool, and "could not decide" came back as false — the same answer
// as "already up to date". The panel showed a reassuring "up to date" badge for a release whose tag
// it simply could not parse (a nightly or rolling tag), which is a claim nothing established.
// Auto-update still keys off Newer, where refusing to act on an undecidable comparison is right;
// what was wrong was reporting that refusal as a verdict.
func Compare(current, latest string) (newer, decided bool) {
	if _, ok := comparableVersion(latest); !ok {
		return false, false
	}
	return Newer(current, latest), true
}

// Newer reports whether release tag `latest` is a higher x.y.z[-rN] than `current`.
// Returns false when latest carries no parseable version (can't decide safely → no
// auto-update on an unversioned tag). Callers that DISPLAY the outcome should use Compare:
// this function cannot distinguish "not newer" from "unknown".
func Newer(current, latest string) bool {
	lv, ok := comparableVersion(latest)
	if !ok {
		return false
	}
	cv, ok := comparableVersion(current)
	if !ok {
		return true
	}
	for i := range lv {
		if cv[i] != lv[i] {
			return cv[i] < lv[i]
		}
	}
	return false
}

var comparableVersionRe = regexp.MustCompile(`(?:^|[^0-9])(\d+)\.(\d+)\.(\d+)(?:-r([1-9]\d*))?(?:$|[^0-9A-Za-z])`)

// comparableVersion recognises WayHop's immutable package revision suffix. The base release
// v0.5.5 is package revision 1; v0.5.5-r2 is a newer rebuild from a different, immutable source
// commit while the product version remains 0.5.5. Ordinary upstream x.y.z versions keep revision 1.
func comparableVersion(s string) ([4]int, bool) {
	match := comparableVersionRe.FindStringSubmatch(s)
	if match == nil {
		return [4]int{}, false
	}
	parts := [4]int{0, 0, 0, 1}
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(match[i+1])
		if err != nil {
			return [4]int{}, false
		}
		parts[i] = n
	}
	if match[4] != "" {
		n, err := strconv.Atoi(match[4])
		if err != nil {
			return [4]int{}, false
		}
		parts[3] = n
	}
	return parts, true
}
