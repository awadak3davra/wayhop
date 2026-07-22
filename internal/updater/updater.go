// Package updater manages the engine binaries wayhop orchestrates (sing-box, xray,
// mihomo, hysteria, dnscrypt-proxy, ...). It reports the installed version,
// queries upstream GitHub releases *through configurable mirrors* (GitHub is
// frequently blocked/throttled in censored regions), and installs a chosen
// version with SHA-256 verification when the release metadata provides it.
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
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

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
	Note        string   `json:"note,omitempty"`
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
	{ID: "amneziawg-go", Name: "AmneziaWG (userspace)", Repo: "amnezia-vpn/amneziawg-go", BinName: "amneziawg-go", Role: "kernel-plugin", SourceOnly: true,
		Note: "No prebuilt releases; build from source on-device (the PPA is blocked in RU)."},
	{ID: "olcrtc", Name: "olcRTC (WebRTC tunnel)", Repo: "awadak3davra/olcrtc", BinName: "olcrtc", Role: "socks-plugin", VersionArgs: []string{"version"},
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

// Updater performs installed/latest/install operations.
type Updater struct {
	BinDir  string   // where binaries live, e.g. /opt/sbin
	Arch    string   // wayhop arch token: amd64|arm64|arm|mipsle|mips
	Mirrors []string // URL prefixes tried in order; "" = direct
	hc      *http.Client
	pm      pm.Manager // native package manager (opkg/apk); zero value None = no recognition
	// mu serializes Install + SelfUpdate. Both stage to FIXED paths (dst+".new" / ".wayhop.new")
	// opened O_TRUNC, so two concurrent updates — e.g. the auto-update loop racing a user-triggered
	// install, a single-user race — would interleave into one file and rename a corrupt binary into
	// place. The SHA-256 is computed over the download stream, not the file, so it can't catch that.
	// One shared *Updater per daemon ⇒ this in-process lock covers every call site.
	mu sync.Mutex
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
	return &Updater{BinDir: binDir, Arch: arch, Mirrors: mirrors, hc: &http.Client{Timeout: 30 * time.Second}, pm: pm.Detect()}
}

// WithPM overrides the detected package manager (tests inject a mock; production uses Detect()).
func (u *Updater) WithPM(m pm.Manager) *Updater { u.pm = m; return u }

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
	if !u.pm.Available() || e.BinName == "" {
		return "", false, nil
	}
	path := filepath.Join(u.BinDir, e.BinName)
	if _, serr := os.Stat(path); serr != nil {
		p, lerr := exec.LookPath(e.BinName)
		if lerr != nil {
			return "", false, nil // nothing here and nothing on PATH -> nothing to clobber/orphan
		}
		path = p // mirror Installed()'s fallback: probe the binary the UI actually shows
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
func (u *Updater) NativeManagedInfo(e Engine) (owner string, yes bool) {
	owner, yes, _ = u.nativeManaged(e)
	return owner, yes
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

// SelfManaged is the exported form for the server/UI ("is wayhop itself opkg/apk-owned here").
func (u *Updater) SelfManaged(exePath string) bool { _, yes, _ := u.selfManaged(exePath); return yes }

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
}

var verRe = regexp.MustCompile(`\d+\.\d+\.\d+`)

func parseVersion(s string) string { return verRe.FindString(s) }

// ParseVersion extracts the first x.y.z from s (exported for cross-package reuse, e.g.
// the Init Server panel formatting a remote `sing-box version` line). "" if none.
func ParseVersion(s string) string { return parseVersion(s) }

// Installed locates the binary (in BinDir or PATH) and runs its version command.
func (u *Updater) Installed(e Engine) Installed {
	path := filepath.Join(u.BinDir, e.BinName)
	if _, err := os.Stat(path); err != nil {
		p, err2 := exec.LookPath(e.BinName)
		if err2 != nil {
			return Installed{Present: false}
		}
		path = p
	}
	in := Installed{Present: true, Path: path}
	if len(e.VersionArgs) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, _ := exec.CommandContext(ctx, path, e.VersionArgs...).CombinedOutput()
		in.Version = parseVersion(string(out))
	}
	return in
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
func (u *Updater) apiGet(ctx context.Context, path string, v any) error {
	base := "https://api.github.com" + path
	var lastErr error
	for _, m := range u.Mirrors {
		url := base
		if m != "" {
			url = strings.TrimRight(m, "/") + "/" + base
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("User-Agent", "wayhop-updater")
		resp, err := u.hc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<20)) // bounded drain (keep-alive reuse) so a hostile mirror can't stream forever
			resp.Body.Close()
			lastErr = fmt.Errorf("%s: status %d", url, resp.StatusCode)
			continue
		}
		// Cap the metadata body the same way download() caps asset bodies: a release/tags
		// list is a few KB, so 8 MiB is generous, but an unbounded Decode would let a
		// hostile or misbehaving mirror stream arbitrary bytes into RAM on a small-RAM router.
		err = json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(v)
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<20)) // bounded drain (keep-alive reuse) so a hostile mirror can't stream forever
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no mirrors configured")
	}
	return lastErr
}

// Latest returns the newest release.
func (u *Updater) Latest(ctx context.Context, e Engine) (Release, error) {
	var r Release
	err := u.apiGet(ctx, "/repos/"+e.Repo+"/releases/latest", &r)
	return r, err
}

// List returns up to limit recent releases (newest first).
func (u *Updater) List(ctx context.Context, e Engine, limit int) ([]Release, error) {
	if limit <= 0 {
		limit = 15
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
	esc, err := escapeTagPath(tag)
	if err != nil {
		return Release{}, err
	}
	var r Release
	err = u.apiGet(ctx, "/repos/"+e.Repo+"/releases/tags/"+esc, &r)
	return r, err
}

// Install downloads the asset for u.Arch from the given release tag, verifies it
// (when a digest is provided), extracts the binary, and installs it atomically.
// Returns the installed tag.
// enoughSpaceFor reports whether `avail` free bytes can safely hold a freshly-staged
// binary of binSize (+ a same-size backup when withBackup) plus a small margin. When
// the free space is unknown (known=false, e.g. the off-Linux build) it returns true —
// never block on a stat we couldn't take. This guards the small router overlay
// (~60 MB) against a swap that runs out of space mid-write and leaves a partial binary.
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
	rel, err := u.release(ctx, e, tag)
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
	if avail, ok := AvailBytes(u.BinDir); !enoughFlashFor(avail, ok, asset.Size, asset.Name, false) {
		return "", fmt.Errorf("not enough free space to install %s in %s (~%d MiB free, need ~%d MiB for the unpacked binary) — free space, mount external storage, or install over SSH", e.ID, u.BinDir, avail>>20, peakInstallDisk(asset.Size, asset.Name, false)>>20)
	}
	// Memory pre-flight (the lock): streaming to disk is cheap, but the engine RESTART faults the new
	// binary in while the old may still be resident — on a tight router that OOM-kills the daemon or
	// sing-box and drops routing. Refuse early. No-op off Linux / when MemAvailable is unknown.
	if avail, ok := availMemBytes(); !enoughMemForUpdate(avail, ok, asset.Size, asset.Name) {
		return "", fmt.Errorf("not enough free memory to install %s safely (~%d MiB free, need ~%d MiB) — free RAM or install over SSH", e.ID, avail>>20, updateMemNeed(asset.Size, asset.Name)>>20)
	}
	dst := filepath.Join(u.BinDir, e.BinName)
	tmp := dst + ".new"
	if err := u.streamAssetToFile(ctx, *asset, e.BinName, tmp, false); err != nil {
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
	var lastErr error
	for _, m := range u.Mirrors {
		url := rawURL
		if m != "" {
			url = strings.TrimRight(m, "/") + "/" + rawURL
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "wayhop-updater")
		resp, err := u.hc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("%s: status %d", url, resp.StatusCode)
			continue
		}
		ct := resp.Header.Get("Content-Type")
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		// A real release asset is an archive (gzip/zip/xz magic) or a raw ELF — never an
		// HTML/error page. A mirror in a censored region can answer 200 with an
		// interstitial/captcha/error page; without this check those bytes would be
		// installed verbatim as the "binary" (esp. for raw, non-archive assets, where the
		// archive parser can't catch it) and the next start would fail to exec it. Reject
		// and fall through to the next mirror.
		if looksLikeHTML(ct, b) {
			lastErr = fmt.Errorf("%s: response looks like an HTML/error page, not a binary asset", url)
			continue
		}
		return b, nil
	}
	return nil, lastErr
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

func assetScore(name, arch string) int {
	if arch != "arm" {
		return 1 // any matching asset is equally good
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
		if selfAsset(rels[i].Assets, arch) == nil {
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
	rel, err := u.release(ctx, Engine{Repo: repo}, tag)
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
		return "", fmt.Errorf("not enough free space to self-update safely on %s (~%d MiB free, need ~%d MiB for the new binary + backup) — free space, mount external storage, or update over SSH", dir, avail>>20, peakInstallDisk(asset.Size, asset.Name, true)>>20)
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

// Newer reports whether release tag `latest` is a higher x.y.z than `current`.
// Returns false when latest carries no parseable version (can't decide safely → no
// auto-update on an unversioned tag).
func Newer(current, latest string) bool {
	lv := parseVersion(latest)
	if lv == "" {
		return false
	}
	cv := parseVersion(current)
	if cv == "" {
		return true
	}
	return semverLess(cv, lv)
}

func semverLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		if x, y := numAt(pa, i), numAt(pb, i); x != y {
			return x < y
		}
	}
	return false
}

func numAt(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	n := 0
	for _, c := range parts[i] {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
	}
	return n
}
