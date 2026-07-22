#!/bin/sh
# bootstrap.sh — one-command online installer for WayHop.
#
# Detects your router's CPU arch + platform (OpenWrt vs Entware/Keenetic), downloads the
# matching tarball from the latest GitHub release, verifies its SHA-256, unpacks it to a
# private temp dir, and hands off to the real ./install.sh (the interactive, safe-on-a-
# live-router installer). Pure POSIX sh + curl-or-wget + tar; no extra deps.
#
# Copy-paste on the router over SSH:
#   curl -fsSLO https://github.com/awadak3davra/wayhop/releases/latest/download/bootstrap.sh && sh bootstrap.sh
# No curl? wget works too:
#   wget -qO bootstrap.sh https://github.com/awadak3davra/wayhop/releases/latest/download/bootstrap.sh && sh bootstrap.sh
#
# Flags:
#   --arch mipsle|mips|arm|arm64|amd64   force arch (skip auto-detect)
#   --version vX.Y.Z                     install a specific release (default: latest)
#   --openwrt | --entware                force the tarball flavour (default: auto)
#   -- <install.sh flags...>             forward the rest verbatim, e.g.  -- -y --port 8089
set -eu

REPO="awadak3davra/wayhop"
GH="https://github.com"
API="https://api.github.com"

FORCE_ARCH=""
FORCE_TAG=""
FLAVOUR=""   # "", "openwrt", or "entware"

die()  { printf 'bootstrap: %s\n' "$*" >&2; exit 1; }
info() { printf '  %s\n' "$*" >&2; }

# --- args (everything after a literal `--` is forwarded to install.sh) ---
while [ $# -gt 0 ]; do
  arg="$1"; shift
  case "$arg" in
    --arch=*)    FORCE_ARCH="${arg#*=}" ;;
    --arch)      [ $# -gt 0 ] || die "--arch needs a value"; FORCE_ARCH="$1"; shift ;;
    --version=*) FORCE_TAG="${arg#*=}" ;;
    --version)   [ $# -gt 0 ] || die "--version needs a value"; FORCE_TAG="$1"; shift ;;
    --openwrt)   FLAVOUR=openwrt ;;
    --entware)   FLAVOUR=entware ;;
    -h|--help)   sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --)          break ;;
    *)           die "unknown option '$arg' (install.sh flags go after a literal --, e.g. -- -y --port 8089)" ;;
  esac
done
# remaining "$@" is the install.sh passthrough

# --- downloader: curl or wget ---
if command -v curl >/dev/null 2>&1; then
  dl()  { curl -fsSL "$1" -o "$2"; }
  dlo() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
  dl()  { wget -qO "$2" "$1"; }
  dlo() { wget -qO- "$1"; }
else
  die "need curl or wget to download the release"
fi

# --- arch (mirrors install.sh detect_arch, incl. the MIPS endianness probe) ---
detect_arch() {
  case "$(uname -m)" in
    armv7l|armv6l|arm) echo arm ;;
    aarch64|arm64)     echo arm64 ;;
    x86_64|amd64)      echo amd64 ;;
    mips|mips64)
      bb="$(command -v busybox 2>/dev/null || echo /bin/busybox)"
      d="$(dd if="$bb" bs=1 skip=5 count=1 2>/dev/null | od -t u1 | head -n1 | tr -s ' ' | cut -d' ' -f2)"
      # d=1 little-endian, d=2 big-endian; when busybox is unreadable (d empty) default to the far
      # more common little-endian (mipsle, e.g. Keenetic/MT7621) rather than the rarer big-endian.
      [ "$d" = 2 ] && echo mips || echo mipsle ;;
    *) echo unknown ;;
  esac
}
ARCH="${FORCE_ARCH:-$(detect_arch)}"
[ "$ARCH" = unknown ] && die "could not detect arch (uname -m=$(uname -m)); re-run with --arch mipsle|mips|arm|arm64|amd64"

# --- flavour: OpenWrt native tarball vs Entware/Keenetic /opt tarball ---
if [ -z "$FLAVOUR" ]; then
  if [ -f /etc/openwrt_release ] && [ ! -f /bin/ndmc ]; then FLAVOUR=openwrt; else FLAVOUR=entware; fi
fi
SUFFIX=""; [ "$FLAVOUR" = openwrt ] && SUFFIX="-openwrt"

# --- resolve the release tag ---
if [ -n "$FORCE_TAG" ]; then
  TAG="$FORCE_TAG"
else
  info "resolving the latest release..."
  TAG="$(dlo "$API/repos/$REPO/releases/latest" | grep '"tag_name"' | head -n1 | sed 's/.*"tag_name"[^"]*"//;s/".*//')"
  [ -n "$TAG" ] || die "could not resolve the latest release tag (GitHub API rate limit?); pass --version vX.Y.Z"
fi
VER="${TAG#v}"
ASSET="wayhop-${VER}-${ARCH}${SUFFIX}.tar.gz"
BASE="$GH/$REPO/releases/download/$TAG"

# --- private temp dir (unique; never a shared /tmp/wr) ---
TMP="$(mktemp -d 2>/dev/null || true)"
[ -n "$TMP" ] || { TMP="/tmp/wayhop-boot.$$"; mkdir -p "$TMP"; }
[ -d "$TMP" ] || die "could not create a temp dir"
trap 'rm -rf "$TMP"' EXIT INT TERM

info "downloading $ASSET ($TAG)..."
dl "$BASE/$ASSET" "$TMP/$ASSET" || die "download failed: $BASE/$ASSET (wrong arch? try --arch)"

# --- verify SHA-256 against the release SHA256SUMS.txt (best-effort) ---
if command -v sha256sum >/dev/null 2>&1 && dl "$BASE/SHA256SUMS.txt" "$TMP/SHA256SUMS.txt" 2>/dev/null; then
  if grep -q " $ASSET\$" "$TMP/SHA256SUMS.txt"; then
    ( cd "$TMP" && grep " $ASSET\$" SHA256SUMS.txt | sha256sum -c - ) >/dev/null 2>&1 \
      || die "SHA-256 verification FAILED for $ASSET — refusing to install"
    info "sha256 verified"
  else
    info "note: $ASSET is not listed in SHA256SUMS.txt — skipping integrity check"
  fi
else
  info "note: skipping sha256 check (no sha256sum or no SHA256SUMS.txt in this release)"
fi

# --- unpack + hand off to the real installer ---
mkdir -p "$TMP/x"
tar -xzf "$TMP/$ASSET" -C "$TMP/x" || die "extract failed (corrupt download?)"
[ -f "$TMP/x/install.sh" ] || die "install.sh not found inside $ASSET"

info "platform=$FLAVOUR  arch=$ARCH  release=$TAG  —  handing off to install.sh"
echo >&2
cd "$TMP/x"
# Forward the arch we actually downloaded — install.sh would otherwise re-detect its own and,
# on a mismatch (the exact MIPS LE/BE case --arch exists for), fail to find the binary. A
# user-supplied `-- --arch X` still wins via install.sh's last-wins parsing.
set +e
sh ./install.sh --arch "$ARCH" "$@"
rc=$?
set -e
exit "$rc"
