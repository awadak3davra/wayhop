#!/bin/sh
# bootstrap.sh — one-command online installer for WayHop.
#
# Detects the router's CPU arch + platform (OpenWrt opkg / OpenWrt apk / Entware), resolves a
# release, downloads the matching tarball, VERIFIES its SHA-256 (mandatory), optionally verifies a
# signed manifest, unpacks to a private temp dir, and hands off to the real ./install.sh. Pure POSIX
# sh + curl-or-wget + tar. Cleans up on success and on error. Prints no secrets, no `set -x`.
#
# One command (recommended):
#   curl -fsSL https://github.com/awadak3davra/wayhop/releases/latest/download/bootstrap.sh | sh
# No curl? wget works:
#   wget -qO- https://github.com/awadak3davra/wayhop/releases/latest/download/bootstrap.sh | sh
#
# Environment / flags:
#   WAYHOP_VERSION=vX.Y.Z   or  --version vX.Y.Z   install a specific release (default: latest stable)
#   WAYHOP_PRERELEASE=1     or  --prerelease        allow the newest pre-release
#   WAYHOP_ARCH=<arch>      or  --arch <arch>       force arch: mipsle|mips|arm|arm64|amd64
#   WAYHOP_FLAVOUR=…        or  --openwrt|--entware force the build flavour (default: auto)
#   -- <install.sh flags…>                          forward the rest verbatim, e.g.  -- --port 8089
set -eu

REPO="awadak3davra/wayhop"
GH="https://github.com"
API="https://api.github.com"

# Embedded release-signing PUBLIC key (usign/signify format). When NON-EMPTY and a usign or signify
# verifier is present and the release ships SHA256SUMS.txt.sig, the manifest signature is verified —
# so a hostile mirror cannot swap the binary and its checksum together. Where no verifier exists
# (e.g. Keenetic/busybox), the MANDATORY SHA-256 over the GitHub-HTTPS download remains the integrity
# guarantee — it is always enforced. See docs/RELEASE_SIGNING.md.
RELEASE_PUBKEY="untrusted comment: WayHop package feed
RWRPIiBbFocxjpgLjnQqmDCLsl6UIxNQbLKar75vb/65X5BEh5lnqbxL"

FORCE_ARCH="${WAYHOP_ARCH:-}"
FORCE_TAG="${WAYHOP_VERSION:-}"
FLAVOUR="${WAYHOP_FLAVOUR:-}"        # "", "openwrt", or "entware"
PRERELEASE="${WAYHOP_PRERELEASE:-0}"

die()  { printf 'wayhop-bootstrap: %s\n' "$*" >&2; exit 1; }
info() { printf '  %s\n' "$*" >&2; }

# --- args (everything after a literal `--` is forwarded to install.sh) ---
while [ $# -gt 0 ]; do
  arg="$1"; shift
  case "$arg" in
    --arch=*)     FORCE_ARCH="${arg#*=}" ;;
    --arch)       [ $# -gt 0 ] || die "--arch needs a value"; FORCE_ARCH="$1"; shift ;;
    --version=*)  FORCE_TAG="${arg#*=}" ;;
    --version)    [ $# -gt 0 ] || die "--version needs a value"; FORCE_TAG="$1"; shift ;;
    --prerelease) PRERELEASE=1 ;;
    --openwrt)    FLAVOUR=openwrt ;;
    --entware)    FLAVOUR=entware ;;
    -h|--help)    sed -n '2,29p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0 ;;
    --)           break ;;
    *)            die "unknown option '$arg' (install.sh flags go after a literal --, e.g. -- --port 8089)" ;;
  esac
done

# --- must be root: install writes /opt/sbin (or /usr/sbin), the init dir, and kernel routing rules ---
if command -v id >/dev/null 2>&1 && [ "$(id -u)" != 0 ]; then
  die "must run as root (you are '$(id -un 2>/dev/null || echo non-root)'). On a router SSH you usually already are; otherwise: sudo sh -c 'curl … | sh'"
fi

# --- downloader: curl or wget (with a connect timeout so 'no internet' fails fast, not hangs) ---
if command -v curl >/dev/null 2>&1; then
  dl()  { curl -fsSL --connect-timeout 20 "$1" -o "$2"; }
  dlo() { curl -fsSL --connect-timeout 20 "$1"; }
elif command -v wget >/dev/null 2>&1; then
  dl()  { wget -q -T 20 -O "$2" "$1"; }
  dlo() { wget -q -T 20 -O- "$1"; }
else
  die "need curl or wget to download (install one: 'opkg install curl' or 'apk add curl')"
fi

# --- SHA-256 tool is MANDATORY — verification is never skipped ---
if command -v sha256sum >/dev/null 2>&1; then
  sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v openssl >/dev/null 2>&1; then
  sha256_of() { openssl dgst -sha256 "$1" | sed 's/.*= *//'; }
else
  die "no sha256sum or openssl found — cannot verify the download. Install one ('opkg install coreutils-sha256sum') and re-run."
fi

# --- CPU architecture. ARMv6/ARMv5 are REJECTED: the 'arm' build is ARMv7 (GOARM=7) and would SIGILL. ---
detect_arch() {
  m="$(uname -m 2>/dev/null || echo unknown)"
  case "$m" in
    armv7l|armv7)                     echo arm ;;
    armv6l|armv6|armv5l|armv5|armv4l) echo armv6-unsupported ;;
    arm)                              echo arm-ambiguous ;;
    aarch64|arm64)                    echo arm64 ;;
    x86_64|amd64)                     echo amd64 ;;
    i386|i486|i586|i686)              echo x86-unsupported ;;
    mips|mips64)
      bb="$(command -v busybox 2>/dev/null || echo /bin/busybox)"
      d="$(dd if="$bb" bs=1 skip=5 count=1 2>/dev/null | od -t u1 2>/dev/null | head -n1 | tr -s ' ' | cut -d' ' -f2)"
      # d=1 little-endian → mipsle; d=2 big-endian → mips; unreadable → the more common mipsle.
      [ "$d" = 2 ] && echo mips || echo mipsle ;;
    *) echo unknown ;;
  esac
}
ARCH="${FORCE_ARCH:-$(detect_arch)}"
case "$ARCH" in
  armv6-unsupported) die "ARMv6/ARMv5 CPU ($(uname -m)) is not supported — the published 'arm' build is ARMv7 and would crash (illegal instruction). No armv6 build is shipped." ;;
  arm-ambiguous)     die "uname reports a bare 'arm' — cannot tell ARMv6 from ARMv7 safely. Check the CPU (e.g. 'cat /proc/cpuinfo'); if it is genuinely ARMv7, re-run with --arch arm." ;;
  x86-unsupported)   die "32-bit x86 ($(uname -m)) is not supported (only x86_64/amd64)." ;;
  unknown)           die "could not detect CPU arch (uname -m=$(uname -m)); re-run with --arch mipsle|mips|arm|arm64|amd64" ;;
  mipsle|mips|arm|arm64|amd64) : ;;
  *) die "invalid --arch '$ARCH' (want mipsle|mips|arm|arm64|amd64)" ;;
esac

# --- platform + package manager, from the REAL environment (not a version string) ---
# OpenWrt: /etc/openwrt_release present AND no Keenetic /bin/ndmc. Entware: an /opt overlay (incl. Keenetic).
if [ -z "$FLAVOUR" ]; then
  if [ -f /etc/openwrt_release ] && [ ! -f /bin/ndmc ]; then FLAVOUR=openwrt; else FLAVOUR=entware; fi
fi
PM="unknown"
if [ "$FLAVOUR" = openwrt ]; then
  if command -v apk >/dev/null 2>&1 && [ -d /etc/apk ]; then PM="apk (OpenWrt 25.12+)"
  elif command -v opkg >/dev/null 2>&1; then PM="opkg (OpenWrt <=24.10)"; fi
elif command -v opkg >/dev/null 2>&1 && [ -d /opt ]; then PM="opkg (Entware /opt)"; fi
SUFFIX=""; [ "$FLAVOUR" = openwrt ] && SUFFIX="-openwrt"

# --- resolve the release tag: explicit version wins; else latest stable (or newest incl. pre-release) ---
if [ -n "$FORCE_TAG" ]; then
  case "$FORCE_TAG" in v*) TAG="$FORCE_TAG" ;; *) TAG="v$FORCE_TAG" ;; esac
elif [ "$PRERELEASE" = 1 ]; then
  info "resolving the newest release (including pre-releases)…"
  TAG="$(dlo "$API/repos/$REPO/releases" 2>/dev/null | grep '"tag_name"' | head -n1 | sed 's/.*"tag_name"[^"]*"//;s/".*//')"
else
  info "resolving the latest stable release…"
  TAG="$(dlo "$API/repos/$REPO/releases/latest" 2>/dev/null | grep '"tag_name"' | head -n1 | sed 's/.*"tag_name"[^"]*"//;s/".*//')"
fi
[ -n "$TAG" ] || die "could not resolve a release tag (GitHub API rate-limited, or no internet). Set WAYHOP_VERSION=vX.Y.Z, or check connectivity."
VER="${TAG#v}"
ASSET="wayhop-${VER}-${ARCH}${SUFFIX}.tar.gz"
BASE="$GH/$REPO/releases/download/$TAG"

# --- private temp dir; removed on ANY exit (success, error, interrupt) ---
TMP="$(mktemp -d 2>/dev/null || true)"
[ -n "$TMP" ] || { TMP="/tmp/wayhop-boot.$$"; (umask 077; mkdir -p "$TMP"); }
[ -d "$TMP" ] || die "could not create a temp dir"
trap 'rm -rf "$TMP" 2>/dev/null || true' EXIT INT TERM

info "platform=$FLAVOUR  pkg-manager=$PM  arch=$ARCH  release=$TAG"
info "downloading $ASSET …"
dl "$BASE/$ASSET" "$TMP/$ASSET" || die "download failed: $BASE/$ASSET
  → wrong arch? re-run with --arch. Asset missing from this release? open the release page or set WAYHOP_VERSION. No internet? check connectivity."

# --- MANDATORY SHA-256 (fail closed; never install an unverified file) ---
dl "$BASE/SHA256SUMS.txt" "$TMP/SHA256SUMS.txt" || die "this release ships no SHA256SUMS.txt — refusing to install unverified. Use a release that includes checksums."
WANT="$(grep -E "[ *]$ASSET\$" "$TMP/SHA256SUMS.txt" | head -n1 | cut -d' ' -f1)"
[ -n "$WANT" ] || die "$ASSET is not listed in SHA256SUMS.txt — refusing (asset/manifest mismatch, possible tampering)."
GOT="$(sha256_of "$TMP/$ASSET")"
[ "$WANT" = "$GOT" ] || die "SHA-256 MISMATCH for $ASSET — refusing to install a corrupt/tampered download.
  expected $WANT
  got      $GOT"
info "sha256 verified"

# --- signed-manifest check (defence against a mirror swapping binary+sums together). Verified with
# usign or signify (present on OpenWrt; openssl-free). Where neither exists (e.g. Keenetic/busybox),
# the MANDATORY SHA-256 over HTTPS above stays the integrity guarantee. A signature that is PRESENT
# but fails is fatal — that is active tampering, not a missing tool. ---
if [ -n "$RELEASE_PUBKEY" ]; then
  sigverify=""
  command -v signify >/dev/null 2>&1 && sigverify=signify
  [ -z "$sigverify" ] && command -v usign >/dev/null 2>&1 && sigverify=usign
  if [ -n "$sigverify" ] && dl "$BASE/SHA256SUMS.txt.sig" "$TMP/SHA256SUMS.txt.sig" 2>/dev/null; then
    printf '%s\n' "$RELEASE_PUBKEY" > "$TMP/release.pub"
    if "$sigverify" -V -q -p "$TMP/release.pub" -x "$TMP/SHA256SUMS.txt.sig" -m "$TMP/SHA256SUMS.txt" 2>/dev/null; then
      info "manifest signature verified ($sigverify)"
    else
      die "manifest SIGNATURE verification FAILED — the checksum file may be forged. Refusing to install."
    fi
  fi
fi

# --- unpack (only after verification) + hand off to the real, safe-on-a-live-router install.sh ---
mkdir -p "$TMP/x"
tar -xzf "$TMP/$ASSET" -C "$TMP/x" 2>/dev/null || die "extract failed (unexpected after a verified checksum)."
[ -f "$TMP/x/install.sh" ] || die "install.sh not found inside $ASSET (bad archive layout)."

# Pass the arch we actually downloaded (install.sh would otherwise re-detect, risking a MIPS LE/BE
# mismatch). We deliberately do NOT force -y: when there is no TTY (curl|sh) install.sh already runs
# non-interactively using each prompt's SAFE default — it moves WayHop to a free port if 8088 is busy
# and never disables a foreign service like lighttpd. A user's own flags after `--` win (last-wins).
set -- --arch "$ARCH" "$@"
info "handing off to install.sh …"
echo >&2
cd "$TMP/x"
set +e
sh ./install.sh "$@"
rc=$?
set -e
[ "$rc" = 0 ] || die "install.sh exited with code $rc — see the messages above."
exit 0
