#!/bin/sh
# build-awg-static.sh - build a fully static `awg` (amneziawg-tools) for every CPU WayHop ships the
# userspace AmneziaWG to, for the Entware packages (/opt/bin/awg).
#
# Why static and why zig: Entware's own toolchains are per-arch and its libc differs between
# generations; a static musl binary runs on any of them and on any kernel. zig cc carries clang and
# a musl for every target, so one pinned tarball (packaging/awg/VERSIONS, sha256-checked) builds all
# five without five cross toolchains.
#
# Why in a container: a pinned image, fixed paths and zig's own musl make the output depend only on
# the pins, so two runs give the same bytes (checked by the caller comparing SHA256SUMS).
#
# Targets are WayHop's Go arch tokens. arm is ARMv7-A with every FP feature removed (no VFP or NEON
# instruction at all, soft-float ABI), which is what Entware's armv7sf build expects; mips and mipsle
# are MIPS32r2 soft-float, as Entware's mips-3.4 and mipselsf-k3.4.
#
# RUNSTATEDIR is /tmp/wayhop, so `awg` looks for userspace devices in /tmp/wayhop/amneziawg - where
# WayHop's amneziawg-go serves its sockets (scripts/build-amneziawg-go.sh) - instead of upstream's
# /var/run/amneziawg. The patch in packaging/awg/patches/amneziawg-tools lets AWG_SOCKET_DIR, the
# variable amneziawg-go reads too, override that at run time (OpenWrt's netifd handler sets it).
# Kernel devices are found over netlink either way.
#
# Gotcha: CFLAGS and LDFLAGS go in as environment variables, not make arguments. The Makefile appends
# to CFLAGS (+=), and a command-line variable would silently override those appends.
#
# Usage: scripts/awg/build-awg-static.sh [outdir]       (default: dist/awg-static)
#   writes <outdir>/awg-<token> for amd64 arm64 arm mips mipsle, SHA256SUMS and MANIFEST.
#   AWG_CACHE_DIR=<dir>   keep the verified zig tarball there between runs (optional)
#   AWG_DOCKER_PREFIX=<p> container name prefix (default: wayhop)
#   AWG_BUILD_IMAGE=<ref> the build container (default: the digest-pinned debian:12 below)
#   --inside <outdir>     the build itself, as run in the container (needs curl, xz, make, git)
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
# shellcheck source=packaging/awg/VERSIONS
. "$repo/packaging/awg/VERSIONS"
BUILD_IMAGE="${AWG_BUILD_IMAGE:-debian:12@sha256:813017f3d62be4b5891a7acca6a01bdcd4b8513daa81b1ab99d3a50385b26931}"

# token  zig target  zig cpu ("-" = the target's baseline)
TARGETS="amd64:x86_64-linux-musl:-
arm64:aarch64-linux-musl:-
arm:arm-linux-musleabi:generic+v7a-vfp2-vfp2sp-vfp3-vfp3d16-vfp3d16sp-vfp3sp-vfp4-vfp4d16-vfp4d16sp-vfp4sp-fp64-d32-neon-fpregs-fpregs64-fp16
mips:mips-linux-musleabi:mips32r2
mipsle:mipsel-linux-musleabi:mips32r2"
AWG_CFLAGS="-Os -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -fno-unwind-tables"
AWG_LDFLAGS="-static -Wl,--gc-sections -s"
AWG_RUNSTATEDIR="/tmp/wayhop"

inside() {
  out="$1"
  for t in curl xz make git sha256sum tar; do
    command -v "$t" >/dev/null 2>&1 || { echo "build-awg-static: $t is missing" >&2; exit 1; }
  done
  mkdir -p "$out"
  work="$(mktemp -d "${TMPDIR:-/tmp}/awg-static.XXXXXX")"
  trap 'rm -rf "$work"' EXIT

  # zig: from the cache when it holds the pinned tarball, else downloaded; refused unless the sha256
  # is the pinned one either way.
  tarball="zig-x86_64-linux-$AWG_ZIG_VERSION.tar.xz"
  cache="${AWG_CACHE_DIR:-$work}"
  mkdir -p "$cache"
  if [ ! -f "$cache/$tarball" ] || [ "$(sha256sum < "$cache/$tarball" | cut -c1-64)" != "$AWG_ZIG_SHA256" ]; then
    curl -fsSL --retry 3 -o "$cache/$tarball.part" "$AWG_ZIG_URL"
    mv "$cache/$tarball.part" "$cache/$tarball"
  fi
  got="$(sha256sum < "$cache/$tarball" | cut -c1-64)"
  if [ "$got" != "$AWG_ZIG_SHA256" ]; then
    echo "build-awg-static: $tarball has sha256 $got, not the pinned $AWG_ZIG_SHA256 - refusing" >&2
    rm -f "$cache/$tarball"
    exit 1
  fi
  mkdir -p "$work/zig"
  tar -xJf "$cache/$tarball" -C "$work/zig" --strip-components=1
  zig="$work/zig/zig"
  # zig's caches stay in the work tree: the musl it builds per target is thousands of small files.
  export ZIG_GLOBAL_CACHE_DIR="$work/zig-cache" ZIG_LOCAL_CACHE_DIR="$work/zig-cache"
  [ "$("$zig" version)" = "$AWG_ZIG_VERSION" ] || { echo "build-awg-static: zig reports $("$zig" version), want $AWG_ZIG_VERSION" >&2; exit 1; }

  git -c core.autocrlf=false -c advice.detachedHead=false clone --quiet --depth 1 --branch "$AWG_TOOLS_TAG" "$AWG_TOOLS_REPO" "$work/tools"
  got="$(git -C "$work/tools" rev-parse HEAD)"
  if [ "$got" != "$AWG_TOOLS_COMMIT" ]; then
    echo "build-awg-static: tag $AWG_TOOLS_TAG resolves to $got, not the pinned $AWG_TOOLS_COMMIT - refusing" >&2
    exit 1
  fi
  # WayHop's patches, in name order, after the commit check; each one's sha256 goes into MANIFEST.
  # The OpenWrt SDK package applies the same files from its own patches/ directory, so a copy that
  # differs, or one only one side has, is refused rather than shipped as two different awg.
  : > "$work/patches"
  for p in "$repo/packaging/awg/patches/amneziawg-tools"/*.patch "$repo/packaging/awg/openwrt/amneziawg-tools/patches"/*.patch; do
    [ -e "$p" ] || continue
    n="$(basename "$p")"
    if ! cmp -s "$repo/packaging/awg/patches/amneziawg-tools/$n" "$repo/packaging/awg/openwrt/amneziawg-tools/patches/$n"; then
      echo "build-awg-static: $n differs between packaging/awg/patches/amneziawg-tools and the OpenWrt package's patches - refusing" >&2
      exit 1
    fi
  done
  for p in "$repo/packaging/awg/patches/amneziawg-tools"/*.patch; do
    [ -e "$p" ] || continue
    if ! git -C "$work/tools" apply --whitespace=nowarn - < "$p"; then
      echo "build-awg-static: $(basename "$p") does not apply to $AWG_TOOLS_TAG@$AWG_TOOLS_COMMIT - refusing" >&2
      exit 1
    fi
    echo "patch=$(basename "$p") sha256=$(sha256sum < "$p" | cut -c1-64)" >> "$work/patches"
  done
  # Without .git the Makefile's `git describe` finds nothing and the version comes from version.h,
  # so the binary does not depend on how the tree was fetched.
  rm -rf "$work/tools/.git"

  rm -f "$out"/awg-* "$out/SHA256SUMS" "$out/MANIFEST"
  echo "$TARGETS" | while IFS=: read -r token target cpu; do
    cc="$zig cc -target $target"
    [ "$cpu" = "-" ] || cc="$cc -mcpu=$cpu"
    make -C "$work/tools/src" clean >/dev/null
    if ! CC="$cc" CFLAGS="$AWG_CFLAGS" LDFLAGS="$AWG_LDFLAGS" RUNSTATEDIR="$AWG_RUNSTATEDIR" \
        make -C "$work/tools/src" wg > "$work/build-$token.log" 2>&1; then
      cat "$work/build-$token.log" >&2
      echo "build-awg-static: $token failed" >&2
      exit 1
    fi
    install -m 0755 "$work/tools/src/wg" "$out/awg-$token"
  done

  (
    cd "$out"
    sha256sum awg-* > SHA256SUMS
    {
      echo "tag=$AWG_TOOLS_TAG"
      echo "commit=$AWG_TOOLS_COMMIT"
      cat "$work/patches"
      echo "zig=$AWG_ZIG_VERSION sha256=$AWG_ZIG_SHA256"
      echo "cflags=$AWG_CFLAGS"
      echo "ldflags=$AWG_LDFLAGS"
      echo "runstatedir=$AWG_RUNSTATEDIR"
      echo "$TARGETS" | while IFS=: read -r token target cpu; do
        echo "target=$token zig=$target cpu=$cpu"
      done
      for f in awg-*; do
        echo "file=$f size=$(wc -c < "$f" | tr -d ' ') sha256=$(sha256sum "$f" | cut -c1-64)"
      done
    } > MANIFEST
  )
  [ -z "${AWG_OUT_OWNER:-}" ] || chown -R "$AWG_OUT_OWNER" "$out"
  cat "$out/MANIFEST"
  built="$(find "$out" -maxdepth 1 -name 'awg-*' -type f | wc -l | tr -d ' ')"
  echo "awg: $built arches built static from $AWG_TOOLS_TAG@$(echo "$AWG_TOOLS_COMMIT" | cut -c1-12) with zig $AWG_ZIG_VERSION"
  [ "$built" -eq 5 ] || { echo "build-awg-static: expected 5 arches, built $built" >&2; exit 1; }
}

if [ "${1:-}" = "--inside" ]; then
  inside "${2:?--inside needs an output directory}"
  exit 0
fi

OUT="${1:-dist/awg-static}"
command -v docker >/dev/null 2>&1 || { echo "build-awg-static: docker is required" >&2; exit 1; }
mkdir -p "$OUT"
out_abs="$(cd "$OUT" && pwd)"
# Docker on Windows (Git Bash) wants Windows paths, and MSYS must not rewrite the container side.
hostpath() { if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else printf '%s\n' "$1"; fi; }
cache_mount=""
cache_env=""
if [ -n "${AWG_CACHE_DIR:-}" ]; then
  mkdir -p "$AWG_CACHE_DIR"
  cache_mount="$(hostpath "$(cd "$AWG_CACHE_DIR" && pwd)"):/cache"
  cache_env="AWG_CACHE_DIR=/cache"
fi
# Hand the output back to the caller's user on Linux; Docker Desktop's Windows mounts have no owners.
owner=""
command -v cygpath >/dev/null 2>&1 || owner="$(id -u):$(id -g)"
name="${AWG_DOCKER_PREFIX:-wayhop}-awg-static-$$"
# The script and VERSIONS come from the read-only repo mount; the build itself runs in the
# container's own filesystem, never on the mount.
# shellcheck disable=SC2086  # the optional mount and env are empty or one word each
MSYS_NO_PATHCONV=1 docker run --rm --name "$name" \
  -v "$(hostpath "$repo"):/repo:ro" -v "$(hostpath "$out_abs"):/out" \
  ${cache_mount:+-v "$cache_mount"} ${cache_env:+-e "$cache_env"} \
  -e AWG_OUT_OWNER="$owner" "$BUILD_IMAGE" sh -euc '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq --no-install-recommends ca-certificates curl xz-utils make git >/dev/null
    sh /repo/scripts/awg/build-awg-static.sh --inside /out'
