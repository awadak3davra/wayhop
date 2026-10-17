#!/bin/sh
# build-userspace.sh - the userspace AmneziaWG 3.1 binaries for every CPU WayHop ships to, laid out
# the way the packers and CI read them (docs/AWG_FULL_INSTALL.md (development repository), "Output layout"):
#
#   <outdir>/userspace/<token>/amneziawg-go   lowmem-patched, static Go (scripts/build-amneziawg-go.sh)
#   <outdir>/userspace/<token>/awg            static musl amneziawg-tools (scripts/awg/build-awg-static.sh)
#   <outdir>/userspace/MANIFEST               both builds' provenance and every file's sha256
#   <outdir>/userspace/SHA256SUMS             "<sha256>  <token>/<name>" for every binary
#
# token is WayHop's Go arch token: amd64 arm64 arm mips mipsle.
#
# Usage: scripts/awg/build-userspace.sh [outdir]       (default: dist/awg)
#   GO=/path/to/go and the build-awg-static.sh variables (AWG_CACHE_DIR, AWG_DOCKER_PREFIX) pass through.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-dist/awg}"
mkdir -p "$OUT"
out_abs="$(cd "$OUT" && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/awg-userspace.XXXXXX")"
trap 'rm -rf "$work"' EXIT
work="$(cd "$work" && pwd)"

sh "$here/../build-amneziawg-go.sh" "$work/go"
sh "$here/build-awg-static.sh" "$work/awg"

dst="$out_abs/userspace"
rm -rf "$dst"
mkdir -p "$dst"
for token in amd64 arm64 arm mips mipsle; do
  mkdir -p "$dst/$token"
  # cp, then chmod: the binaries must be executable in the tree the packers read, whatever umask
  # or filesystem the build ran on.
  cp "$work/go/amneziawg-go-$token" "$dst/$token/amneziawg-go"
  cp "$work/awg/awg-$token" "$dst/$token/awg"
  chmod 0755 "$dst/$token/amneziawg-go" "$dst/$token/awg"
done
(
  cd "$dst"
  {
    sed 's/^/amneziawg-go./' "$work/go/MANIFEST" | grep -v '^amneziawg-go\.file='
    sed 's/^/awg./' "$work/awg/MANIFEST" | grep -v '^awg\.file='
    for f in */amneziawg-go */awg; do
      echo "file=$f size=$(wc -c < "$f" | tr -d ' ') sha256=$(sha256sum "$f" | cut -c1-64)"
    done
  } > MANIFEST
  # One spelling everywhere: a Windows sha256sum marks binary mode with "*".
  sha256sum ./*/amneziawg-go ./*/awg | sed 's#^\([0-9a-f]*\) [ *]\./#\1  #' > SHA256SUMS
)
n="$(find "$dst" -mindepth 2 -type f \( -name amneziawg-go -o -name awg \) | wc -l | tr -d ' ')"
echo "userspace: $n binaries in $dst"
[ "$n" -eq 10 ] || { echo "build-userspace: expected 10 binaries, have $n" >&2; exit 1; }
