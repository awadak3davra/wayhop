#!/bin/sh
# build-amneziawg-go.sh - build the AmneziaWG 3 userspace binary WayHop installs as an optional component.
#
# Why WayHop builds it at all: upstream amneziawg-go publishes source tags and NO binaries (no GitHub
# releases), so the updater carried it as SourceOnly and a router had no way to get it. The kernel
# module is no substitute everywhere - KeeneticOS has no generation-3 AmneziaWG in NDM at all, and an
# OpenWrt kmod has to match the running kernel build exactly. A static userspace binary runs on any
# kernel that has /dev/net/tun, which is every router WayHop supports.
#
# Why pinned to a tag AND a full commit: the CI step this replaces cloned upstream HEAD, so what it
# built was not reproducible and not what a router would install. A tag can be moved; the clone is
# refused unless HEAD is exactly the commit below, so the binary is only ever what was reviewed.
#
# Why these arches and flags: they are WayHop's own arch tokens and GOARM/GOMIPS values (see
# .github/workflows/build.yml), so the component always matches the daemon it installs beside. The
# flags are size-first because the target routers are small: -s -w drop the symbol and DWARF tables,
# -trimpath and an empty -buildid make the output reproducible for a given Go version.
#
# Why it also packs .gz release assets: the release workflow attaches them to every WayHop release,
# and the updater installs the component from there (internal/updater, Engine.Companion). Packing
# them here, in the run verify.mjs and CI make too, means the names the updater parses are the names
# every gate run produces - not a second spelling in the workflow that only a release would exercise.
#
# Usage: scripts/build-amneziawg-go.sh [outdir]      (default: dist/amneziawg-go)
#        GO=/path/to/go scripts/build-amneziawg-go.sh
set -eu

AWG_GO_REPO="https://github.com/amnezia-vpn/amneziawg-go"
AWG_GO_TAG="v3.1.20260828"
AWG_GO_COMMIT="b5928efb6ca19f0153958460c3d141f04abc5c2e"

# Where the binary serves its UAPI socket (internal/awg reads the same path). Upstream's default is
# /var/run/amneziawg, and amneziawg-go stops at startup when it cannot create that directory - passing
# the socket in by file descriptor does not avoid it, because UAPIListen still puts an inotify watch on
# the default path. /tmp is the directory measured writable tmpfs on both platforms (OpenWrt's
# /var/run is itself a symlink into it), so the socket goes there. Upstream made the variable for
# exactly this: "socketDirectory is variable because it is modified by a linker flag in
# wireguard-android" (ipc/uapi_unix.go).
AWG_GO_SOCKET_DIR="/tmp/wayhop/amneziawg"

OUT="${1:-dist/amneziawg-go}"
GO="${GO:-go}"

work="$(mktemp -d "${TMPDIR:-/tmp}/awg-go.XXXXXX")"
trap 'rm -rf "$work"' EXIT

git clone --quiet --depth 1 --branch "$AWG_GO_TAG" "$AWG_GO_REPO" "$work/src"
got="$(git -C "$work/src" rev-parse HEAD)"
if [ "$got" != "$AWG_GO_COMMIT" ]; then
  echo "build-amneziawg-go: tag $AWG_GO_TAG resolves to $got, not the pinned $AWG_GO_COMMIT - refusing" >&2
  exit 1
fi

mkdir -p "$OUT"
out_abs="$(cd "$OUT" && pwd)"
rm -f "$out_abs"/amneziawg-go-* "$out_abs/SHA256SUMS" "$out_abs/MANIFEST"

# token  GOARCH  GOARM  GOMIPS  - "-" means unset
for spec in "amd64 amd64 - -" "arm64 arm64 - -" "arm arm 7 -" "mips mips - softfloat" "mipsle mipsle - softfloat"; do
  # shellcheck disable=SC2086  # the spec is split on purpose
  set -- $spec
  token="$1" goarch="$2" goarm="$3" gomips="$4"
  (
    cd "$work/src"
    [ "$goarm" = "-" ] || export GOARM="$goarm"
    [ "$gomips" = "-" ] || export GOMIPS="$gomips"
    # Build the main package (.), NOT ./... - a transitive dependency (outline-sdk/x/smart) does not
    # cross-compile, and the amneziawg-go binary does not import it.
    CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" "$GO" build -trimpath \
      -ldflags "-s -w -buildid= -X github.com/amnezia-vpn/amneziawg-go/v3/ipc.socketDirectory=$AWG_GO_SOCKET_DIR" \
      -o "$out_abs/amneziawg-go-$token" .
  )
done

# Release assets, in the one shape the updater reads: <prefix><upstream version>-linux-<arch>.gz. The
# version is what the operator chooses in the panel; arm is named armv7 because GOARM=7 is what was
# built and pickAsset ranks that name first. gzip -n writes no name or timestamp, so the same binary
# always packs to the same bytes.
for pair in "amd64 amd64" "arm64 arm64" "arm armv7" "mips mips" "mipsle mipsle"; do
  # shellcheck disable=SC2086  # the pair is split on purpose
  set -- $pair
  gzip -n -9 -c "$out_abs/amneziawg-go-$1" > "$out_abs/amneziawg-go-$AWG_GO_TAG-linux-$2.gz"
done

(
  cd "$out_abs"
  sha256sum amneziawg-go-* > SHA256SUMS
  {
    echo "tag=$AWG_GO_TAG"
    echo "commit=$AWG_GO_COMMIT"
    echo "socket_dir=$AWG_GO_SOCKET_DIR"
    echo "go=$("$GO" env GOVERSION)"
    for f in amneziawg-go-*; do
      echo "file=$f size=$(wc -c < "$f" | tr -d ' ') sha256=$(sha256sum "$f" | cut -c1-64)"
    done
  } > MANIFEST
)
cat "$out_abs/MANIFEST"
# The count verify.mjs reads as evidence: a run that built fewer arches than WayHop ships is a failure,
# not a pass with a shorter list - and so is one that packed fewer release assets than it built.
built="$(ls "$out_abs"/amneziawg-go-* | grep -vc '\.gz$')"
packed="$(ls "$out_abs"/amneziawg-go-*-linux-*.gz | wc -l | tr -d ' ')"
echo "amneziawg-go: $built arches built from $AWG_GO_TAG@$(echo "$AWG_GO_COMMIT" | cut -c1-12), $packed packed as release assets"
[ "$built" -eq 5 ] || { echo "build-amneziawg-go: expected 5 arches, built $built" >&2; exit 1; }
[ "$packed" -eq 5 ] || { echo "build-amneziawg-go: expected 5 release assets, packed $packed" >&2; exit 1; }
